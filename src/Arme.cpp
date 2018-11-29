#include <Arme/Arme.h>

#define CAPSTONE_HAS_ARM
#define CAPSTONE_USE_SYS_DYN_MEM

#include <capstone/capstone.h>
#include <capstone/arm.h>

using namespace ArmGen;

namespace arme
{

static const ARMReg JIT_STATE_REG = ARMReg::R8;

#define SIGNEX(v, sb) ((v) | (((v) & (1 << (sb))) ? ~((1 << (sb))-1) : 0))

#pragma region ANALYST

void arm_analyst::init()
{
    cs_err err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);

    if (err != CS_ERR_OK)
    {
        assert(false && "Can't open the disassembler");
    }

    // Add more details to examine instruction
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

arm_analyst::arm_analyst(jit_callback &callback)
    : callback(callback)
{
    init();
}

cs_insn *arm_analyst::disassemble_instructions(const address addr, bool thumb)
{
    std::uint32_t op = callback.read_code32 ? callback.read_code32(callback.userdata, addr)
        : callback.read_mem32(callback.userdata, addr);
    auto count = cs_disasm(handle, reinterpret_cast<const std::uint8_t*>(&op), thumb ? 2 : 4, addr, 1,
        &insn);

    return insn;
}

arm_reg_usage arm_analyst::analysis_usage_reg(ArmGen::ARMReg reg, const address addr,
    const std::size_t insts, bool thumb)
{
    bool should_continue = true;
    address iter_addr = addr;
    std::size_t itered_insts = 0;

    while (should_continue && (itered_insts <= insts))
    {
        cs_insn *disres = disassemble_instructions(iter_addr, thumb);
        cs_detail *det = disres->detail;

        auto capstone_reg_to_jit_reg = [](int reg) {
            return static_cast<ARMReg>(reg - ARM_REG_R0);
        };

        for (auto i = 0; i < det->regs_read_count; i++)
        {
            if (capstone_reg_to_jit_reg(det->regs_read[i]) == reg)
            {
                return usage_input;
            }
        }

        for (auto i = 0; i < det->regs_write_count; i++)
        {
            if (capstone_reg_to_jit_reg(det->regs_write[i]) == reg)
            {
                return usage_clobbered;
            }
        }

        for (auto i = 0; i < det->groups_count; i++)
        {
            if (det->groups[i] == ARM_GRP_BRANCH_RELATIVE)
            {
                should_continue = false;
                break;
            }
        }

        iter_addr += disres->size;
        itered_insts++;
    }

    return arm_reg_usage::usage_unknown;
}

bool arm_analyst::is_reg_clobbered(ArmGen::ARMReg reg, const address addr,
    const std::size_t insts, bool thumb)
{
    return analysis_usage_reg(reg, addr, insts, thumb) == usage_clobbered;
}

bool arm_analyst::is_reg_used(ArmGen::ARMReg reg, const address addr,
    const std::size_t insts, bool thumb)
{
    return analysis_usage_reg(reg, addr, insts, thumb) == usage_input;
}

#pragma endregion

#pragma region REG_ALLOCATOR

static ARMReg *get_arm_reg_allocation_order(int &count)
{
    static ARMReg useable_regs[] = {
        R0, R1, R2, R3, R4, R5, R6, R7, R9, R12
    };

    count = sizeof(useable_regs) / sizeof(ARMReg);
    return useable_regs;
}

arm_register_allocator::arm_register_allocator(arm_analyst *analyst)
    : analyst(analyst)
{

}

void arm_register_allocator::spill_lock(ArmGen::ARMReg guest_reg)
{
    guest_map_regs[guest_reg].spilllock = true;
}

void arm_register_allocator::release_spill_lock(ArmGen::ARMReg guest_reg)
{
    guest_map_regs[guest_reg].spilllock = false;
}

void arm_register_allocator::release_all_spill_lock()
{
    for (auto i = R0; i <= R12; i = static_cast<ARMReg>(static_cast<int>(i) + 1))
    {
        release_spill_lock(i);
    }
}

void arm_register_allocator::flush_reg(arm_recompile_block *block, ArmGen::ARMReg guest_reg)
{
    if (guest_map_regs[guest_reg].host_reg == INVALID_REG ||
        host_map_regs[guest_map_regs[guest_reg].host_reg].mapped == false)
    {
        return;
    }

    ARMReg host_reg = guest_map_regs[guest_reg].host_reg;

    // Hey, we got the host reg here, let's move it to jit state corresponding register
    block->STR(host_reg, JIT_STATE_REG, offsetof(jit_state, regs) + (guest_reg - R0) * sizeof(std::uint32_t),
        true);

    // Now that we store it, let's discard the register
    discard_reg(guest_reg);
}

void arm_register_allocator::discard_reg(ARMReg guest_reg)
{
    if (guest_map_regs[static_cast<int>(guest_reg)].host_reg == INVALID_REG)
    {
        return;
    }

    host_map_regs[static_cast<int>(guest_map_regs[static_cast<int>(guest_reg)].host_reg)].mapped = false;
}

// The idea of this is:
// An input register is an register that is used for input.
// A clobbered register is an register that value will be override in the future.
// Any register that is seen as input or clobbered in an instruction is asap known of its usage.
// So until a certain point, if we seen that a register is not used for input, but value will be 
// overwrite in the future, we can spill over it.
bool arm_register_allocator::find_best_to_spill(bool unused_only, address addr, bool thumb, ArmGen::ARMReg &result,
    bool *clobbered)
{
    int count = 0;
    ARMReg *allocatable = get_arm_reg_allocation_order(count);
    
    const int lookahead_inst = 30;

    for (auto i = 0; i < count; i++)
    {
        ARMReg host_reg = allocatable[i];

        // The register is locked for spilling
        if (host_map_regs[static_cast<int>(host_reg)].mapped && 
            guest_map_regs[static_cast<int>(host_map_regs[static_cast<int>(host_reg)].mapped_reg)].spilllock)
        {
            continue;
        }

        if (analyst->is_reg_clobbered(host_map_regs[static_cast<int>(host_reg)].mapped_reg, addr, lookahead_inst, thumb))
        {
            // Awesome, we got one that can throw away (at least now)
            result = host_reg;
            *clobbered = true;

            return true;
        }

        if (unused_only && analyst->is_reg_used(host_map_regs[static_cast<int>(host_reg)].mapped_reg, addr, lookahead_inst, thumb))
        {
            continue;
        }

        *clobbered = false;
        return host_reg;
    }

    return false;
}

bool arm_register_allocator::allocate_free_spot(arm_recompile_block *block, ArmGen::ARMReg guest_reg, ArmGen::ARMReg &result)
{
    int count = 0;
    ARMReg *allocatable = get_arm_reg_allocation_order(count);

    // Operation 1: Find the register that hasn't been mapped yet
    for (auto i = 0; i < count; i++)
    {
        if (host_map_regs[allocatable[i]].mapped == false)
        {
            // Moving the state register to the host register
            block->LDR(allocatable[i], JIT_STATE_REG, offsetof(jit_state, regs) + static_cast<int>(guest_reg) * sizeof(std::uint32_t),
                true);

            // Let's map the register
            host_map_regs[allocatable[i]].mapped = true;
            host_map_regs[allocatable[i]].mapped_reg = guest_reg;

            guest_map_regs[guest_reg].host_reg = static_cast<ARMReg>(i);

            result = static_cast<ARMReg>(i);
            return true;
        }
    }

    return false;
}

ArmGen::ARMReg  arm_register_allocator::map_reg(arm_recompile_block *block,
    ArmGen::ARMReg guest_reg, address addr, bool thumb)
{
    if (guest_reg == R_SP)
    {
        return ARMReg::R11;
    }

    int greg_i = static_cast<int>(guest_reg);

    if (guest_map_regs[greg_i].host_reg != ARMReg::INVALID_REG && host_map_regs[guest_map_regs[greg_i].host_reg].mapped)
    {
        assert((guest_reg == host_map_regs[guest_map_regs[greg_i].host_reg].mapped_reg)
            && "Host vs Guest mapping out of sync!");

        return guest_map_regs[greg_i].host_reg;
    }

    ARMReg mapped_host_reg;
    bool res = false;
    bool clobbered = false;

    res = allocate_free_spot(block, guest_reg, mapped_host_reg);

    if (res)
    {
        return mapped_host_reg;
    }

    // Oh no, there is not any register left. Operation 2 spill begin!
    if (res = find_best_to_spill(true, addr, thumb, mapped_host_reg, &clobbered))
    {
        res = find_best_to_spill(true, addr, thumb, mapped_host_reg, &clobbered);
    }

    if (res)
    {
        if (clobbered)
        {
            discard_reg(host_map_regs[static_cast<int>(mapped_host_reg)].mapped_reg);
        }
        else
        {
            // Flush the register.
            flush_reg(block, mapped_host_reg);
        }

        res = allocate_free_spot(block, guest_reg, mapped_host_reg);
        assert(res && "Register is spilled, not supposed to fail");

        return mapped_host_reg;
    }

    assert(false && "Out of registers to allocate!");
    return ARMReg::INVALID_REG;
}

void arm_register_allocator::flush_all(arm_recompile_block *block)
{
    for (auto i = R0; i <= R12; i = static_cast<ARMReg>(static_cast<int>(i) + 1))
    {
        flush_reg(block, i);
    }
}

#pragma endregion

#pragma region VISITOR
static CCFlags  cs_cc_to_jit_cc(arm_cc cc)
{
    switch (cc)
    {
    case arm_cc::ARM_CC_AL:
    {
        return CCFlags::CC_AL;
    }

    case arm_cc::ARM_CC_EQ:
    {
        return CCFlags::CC_EQ;
    }

    case arm_cc::ARM_CC_NE:
    {
        return CCFlags::CC_NEQ;
    }

    case arm_cc::ARM_CC_GE:
    {
        return CCFlags::CC_GE;
    }

    case arm_cc::ARM_CC_GT:
    {
        return CCFlags::CC_GT;
    }

    case arm_cc::ARM_CC_LT:
    {
        return CCFlags::CC_LT;
    }

    case arm_cc::ARM_CC_LE:
    {
        return CCFlags::CC_LE;
    }

    case arm_cc::ARM_CC_HI:
    {
        return CCFlags::CC_HI;
    }

    case arm_cc::ARM_CC_HS:
    {
        return CCFlags::CC_HS;
    }

    case arm_cc::ARM_CC_LO:
    {
        return CCFlags::CC_LO;
    }

    case arm_cc::ARM_CC_LS:
    {
        return CCFlags::CC_LS;
    }

    case arm_cc::ARM_CC_MI:
    {
        return CCFlags::CC_MI;
    }

    case arm_cc::ARM_CC_PL:
    {
        return CCFlags::CC_PL;
    }

    case arm_cc::ARM_CC_VC:
    {
        return CCFlags::CC_VC;
    }

    case arm_cc::ARM_CC_VS:
    {
        return CCFlags::CC_VS;
    }

    default:
        break;
    }

    UNREACHABLE("No known CC flags");
}

static ARMReg cs_arm_reg_to_reg(arm_reg reg)
{
    switch (reg)
    {
    case ARM_REG_SP:
    {
        return ARMReg::R_SP;
    }

    case ARM_REG_PC:
    {
        return ARMReg::R_PC;
    }

    case ARM_REG_LR:
    {
        return ARMReg::R_LR;
    }

    default:
        break;
    }

    return static_cast<ARMReg>((reg - ARM_REG_R0) + ARMReg::R0);
}

static ARMReg cs_arm_op_to_reg(cs_arm_op &op)
{
    assert((op.type == ARM_OP_REG || op.type == ARM_OP_MEM) && "The Capstone operand is not an register!");

    arm_reg reg = (op.type == ARM_OP_MEM) ? op.mem.base : static_cast<arm_reg>(op.reg);
    return cs_arm_reg_to_reg(reg);
}

static Operand2 cs_arm_op_to_operand2(cs_arm_op &op)
{
    switch (op.type)
    {
    case ARM_OP_REG: 
    {
        ARMReg reg = cs_arm_op_to_reg(op);

        if (op.shift.type != ARM_SFT_INVALID)
        {
            // Try to initialize this first so runtime doesn't throw exception
            ShiftType st = static_cast<ShiftType>(0);

            switch (op.shift.type)
            {
            case ARM_SFT_ASR_REG:
            {
                st = ShiftType::ST_ASR;
                break;
            }

            case ARM_SFT_LSL_REG:
            {
                st = ShiftType::ST_LSL;
                break;
            }

            case ARM_SFT_LSR_REG:
            {
                st = ShiftType::ST_LSR;
                break;
            }

            case ARM_SFT_ROR_REG:
            {
                st = ShiftType::ST_ROR;
                break;
            }

            case ARM_SFT_RRX_REG:
            {
                st = ShiftType::ST_RRX;
                break;
            }

            default:
                break;
            }

            return Operand2(reg, st, op.shift.value);
        }
        else
        {
            return Operand2(reg);
        }

        break;
    }

    case ARM_OP_IMM:
    {
        return op.imm;
    }

    default:
        break;
    }

    UNREACHABLE("No proper method to translate Capstone operand to JIT's Operand2!");
}

void arm_instruction_visitor::init()
{
    cs_err err = cs_open(CS_ARCH_ARM, t_reg ? CS_MODE_THUMB : CS_MODE_ARM, &handler);

    if (err != CS_ERR_OK)
    {
        assert(false && "Can't open the disassembler");
    }

    // Add more details to examine instruction
    cs_option(handler, CS_OPT_DETAIL, CS_OPT_ON);
}

ARMReg arm_instruction_visitor::get_next_reg_from_cs(cs_arm *arm, bool increase)
{
    if (arm->op_count <= op_counter)
    {
        assert(false && "No more operand available to create a register");
    }

    return cs_arm_op_to_reg(arm->operands[increase ? op_counter++ : op_counter]);
}

Operand2 arm_instruction_visitor::get_next_op_from_cs(cs_arm *arm, bool increase)
{
    if (arm->op_count <= op_counter)
    {
        return Operand2();
    }

    return cs_arm_op_to_operand2(arm->operands[increase ? op_counter++ : op_counter]);
}

void arm_instruction_visitor::recompile_single_instruction(arm_recompiler *recompiler)
{
    auto insn = analyst->disassemble_instructions(loc.pc, t_reg);

    cs_detail *detail = insn->detail;
    cs_arm *arm = &(detail->arm);

    op_counter = 0;

    switch (insn->id)
    {
    case ARM_INS_MOV: 
    {
        recompiler->gen_arm32_mov(get_next_reg_from_cs(arm), get_next_op_from_cs(arm));
        break;
    }

    case ARM_INS_MVN:
    {
        recompiler->gen_arm32_mvn(get_next_reg_from_cs(arm), get_next_op_from_cs(arm));
        break;
    }

    case ARM_INS_ADD: 
    {
        // MSVC ARM code generation sometimes is buggy, arguments constructing is called backwards.
        auto dest = get_next_reg_from_cs(arm);
        auto source = get_next_reg_from_cs(arm);
        auto source2 = get_next_op_from_cs(arm);

        recompiler->gen_arm32_add(dest, source, source2);

        break;
    }

    case ARM_INS_TST:
    {
        recompiler->gen_arm32_tst(get_next_reg_from_cs(arm), get_next_op_from_cs(arm));
        break;
    }

    case ARM_INS_SUB:
    {
        // MSVC ARM code generation sometimes is buggy, arguments constructing is called backwards.
        auto dest = get_next_reg_from_cs(arm);
        auto source = get_next_reg_from_cs(arm);
        auto source2 = get_next_op_from_cs(arm);

        recompiler->gen_arm32_sub(dest, source, source2);
            
        break;
    }

    case ARM_INS_CMP:
    {
        recompiler->gen_arm32_cmp(get_next_reg_from_cs(arm), get_next_reg_from_cs(arm));
        break;
    }

    case ARM_INS_B: 
    {
        recompiler->gen_arm32_b(cs_cc_to_jit_cc(arm->cc), get_next_op_from_cs(arm));
        should_break = true;
        break;
    }

    case ARM_INS_BL:
    {
        recompiler->gen_arm32_bl(cs_cc_to_jit_cc(arm->cc), get_next_op_from_cs(arm));
        should_break = true;
        break;
    }

#define DECLARE_ALU_BASE(insn, func_name)      \
    case ARM_INS_##insn:            \
    {                               \
        auto r1 = get_next_reg_from_cs(arm);                    \
        auto r2 = get_next_reg_from_cs(arm, false);             \
        auto op = arm->operands[op_counter].mem.index != arm_reg::ARM_REG_INVALID ? Operand2(cs_arm_reg_to_reg(arm->operands[op_counter].mem.index), \
            ShiftType::ST_LSL, arm->operands[op_counter].mem.lshift) : arm->operands[op_counter].mem.disp;                              \
        recompiler->gen_arm32_ldr(r1, r2, op, arm->operands[op_counter].subtracted, arm->writeback                                      \
            , arm->operands[op_counter].imm & (2 << 9) ? true : false);                                                                 \
        break;                                                                                                                          \
    }

    DECLARE_ALU_BASE(STR, str)
    DECLARE_ALU_BASE(STRB, strb)
    DECLARE_ALU_BASE(STRH, strh)
    DECLARE_ALU_BASE(LDR, ldr)
    DECLARE_ALU_BASE(LDRB, ldrb)
    DECLARE_ALU_BASE(LDRH, ldrh)

    default:
    {
        assert(false, "Unimplemented instructions!");
        break;
    }
    }

    loc = loc.advance(insn->size);

    cycles_count++;
    cycles_count_since_last_cond++;
}

arm_instruction_visitor::arm_instruction_visitor(arm_analyst *analyst, jit_callback callback, address pc)
    : loc{ (pc & 1) ? pc - 1 : pc, 0, 0 }, analyst(analyst), callback(callback)
{
    t_reg = (pc & 1) ? true : false;
    init();
}

void arm_instruction_visitor::recompile(arm_recompiler *recompiler)
{
    cycles_count = 0;
    cycles_count_since_last_cond = 0;

    cpsr_write = false;
    should_break = false;

    // We should break when cpsr is modified (for example with BX instructions).
    while (!should_break && !cpsr_write)
    {
        recompile_single_instruction(recompiler);
    }
}

#pragma endregion

#pragma region RECOMPILE_BLOCK
void arm_recompile_block::ARMABI_save_all_registers()
{
    PUSH(9, ARMReg::R4, ARMReg::R5, ARMReg::R6, ARMReg::R7,
        ARMReg::R8, ARMReg::R9, ARMReg::R10, ARMReg::R11, ARMReg::R_LR);
}

void arm_recompile_block::ARMABI_load_all_registers()
{
    POP(9, ARMReg::R4, ARMReg::R5, ARMReg::R6, ARMReg::R7,
        ARMReg::R8, ARMReg::R9, ARMReg::R10, ARMReg::R11, ARMReg::R_LR);
}

void arm_recompile_block::ARMABI_call_function(void *func)
{
    PUSH(5, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R3, ARMReg::R_LR);
    MOVI2R(ARMReg::R14, reinterpret_cast<u32>(func));
    BL(ARMReg::R14);
    POP(5, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R3, ARMReg::R_LR);
}

void arm_recompile_block::ARMABI_call_function_c_promise_ret(void *func, std::uint32_t arg1)
{
    PUSH(1, ARMReg::R_LR);
    MOVI2R(ARMReg::R14, reinterpret_cast<u32>(func));
    MOVI2R(ARMReg::R0, arg1);
    BL(ARMReg::R14);
    POP(1, ARMReg::R_LR);
}

void arm_recompile_block::ARMABI_call_function_c(void *func, std::uint32_t arg1)
{
    PUSH(5, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R3, ARMReg::R_LR);
    MOVI2R(ARMReg::R14, reinterpret_cast<u32>(func));
    MOVI2R(ARMReg::R0, arg1);
    BL(ARMReg::R14);
    POP(5, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R3, ARMReg::R_LR);   
}

void arm_recompile_block::ARMABI_call_function_cc(void *func, std::uint32_t arg1, std::uint32_t arg2)
{
    PUSH(5, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R3, ARMReg::R_LR);
    MOVI2R(ARMReg::R14, reinterpret_cast<u32>(func));
    MOVI2R(ARMReg::R0, arg1);
    MOVI2R(ARMReg::R1, arg2);
    BL(ARMReg::R14);
    POP(5, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R3, ARMReg::R_LR);   
}

#pragma endregion

arm_recompiler::arm_recompiler(arm_analyst *analyst, jit_callback callback, arm_recompile_block &block)
    : block(&block), callback(callback), analyst(analyst), visitor(analyst, callback, 0), allocator(analyst)
{
    
}

ARMReg arm_recompiler::remap_arm_reg(ARMReg reg)
{
    switch (reg)
    {
    case ARMReg::R_SP:
    {
        return ARMReg::R11;
    }

    case ARMReg::R_LR:
    {
        return ARMReg::R10;
    }

    default:
        break;
    }

    return allocator.map_reg(block, reg, visitor.get_current_visiting_pc(), 
        visitor.is_thumb());
}

Operand2 arm_recompiler::remap_operand2(Operand2 op)
{
    if (op.GetType() == OpType::TYPE_REG)
    {
        ARMReg reg = static_cast<ARMReg>(op.Rm());

        switch (reg)
        {
        case ARMReg::R13:
        {
            return ARMReg::R11;
        }

        case ARMReg::R_LR:
        {
            return ARMReg::R10;
        }

        case ARMReg::R15:
        {
            return visitor.get_current_visiting_pc();
        }

        default:
            return allocator.map_reg(block, reg, visitor.get_current_visiting_pc(),
                visitor.is_thumb());
        }
    }

    return op;
}

void arm_recompiler::flush()
{
    allocator.flush_all(block);
   
    // Save SP
    block->STR(ARMReg::R11, JIT_STATE_REG, block->jsi.offset_reg + R_SP * sizeof(std::uint32_t),
        true);
    
    // Save LR
    block->STR(ARMReg::R10, JIT_STATE_REG, block->jsi.offset_reg + R_LR * sizeof(std::uint32_t),
        true);

    /** (From Dynarmic)
    * CPSR Bits
    * =========
    *
    * ARM CPSR flags
    * --------------
    * N    bit 31       Negative flag
    * Z    bit 30       Zero flag
    * C    bit 29       Carry flag
    * V    bit 28       oVerflow flag
    * Q    bit 27       Saturation flag
    * J    bit 24       Jazelle instruction set flag
    * GE   bits 16-19   Greater than or Equal flags
    * E    bit 9        Data Endianness flag
    * A    bit 8        Disable imprecise Aborts
    * I    bit 7        Disable IRQ interrupts
    * F    bit 6        Disable FIQ interrupts
    * T    bit 5        Thumb instruction set flag
    * M    bits 0-4     Processor Mode bits
    *
    */

    // We only need to update the flag one

    begin_gen_cpsr_update();

    gen_cpsr_update_n_flag();
    gen_cpsr_update_c_flag();
    gen_cpsr_update_z_flag();
    gen_cpsr_update_v_flag();

    end_gen_cpsr_update();
}

void arm_recompiler::save_pc_from_visitor()
{
    set_pc(visitor.get_current_visiting_pc());
}

void arm_recompiler::set_pc(ArmGen::ARMReg reg)
{
    block->STR(reg, JIT_STATE_REG, offsetof(jit_state, regs) + R15 * sizeof(std::uint32_t));
}

void arm_recompiler::set_pc(const std::uint32_t off)
{
    block->PUSH(1, ARMReg::R4);
    block->MOVI2R(ARMReg::R4, off);
    block->STR(ARMReg::R4, JIT_STATE_REG, offsetof(jit_state, regs) + R15 * sizeof(std::uint32_t));
    block->POP(1, ARMReg::R4);
}

void arm_recompiler::begin_gen_cpsr_update()
{
    block->PUSH(2, ARMReg::R4, ARMReg::R5);
    block->LDR(ARMReg::R4, JIT_STATE_REG, offsetof(jit_state, cpsr), true);
}

void arm_recompiler::end_gen_cpsr_update()
{
    block->STR(ARMReg::R4, JIT_STATE_REG, offsetof(jit_state, cpsr), true);
    block->POP(2, ARMReg::R4, ARMReg::R5);
}

void arm_recompiler::gen_cpsr_update_c_flag()
{
    // Use this to clear bit 29
    block->AND(ARMReg::R4, ARMReg::R4, 0xDFFFFFFF);

    block->SetCC(CCFlags::CC_CS);
    block->ORR(ARMReg::R4, ARMReg::R4, 1 << 29);
    block->SetCC(CCFlags::CC_AL);
}

void arm_recompiler::gen_cpsr_update_z_flag()
{
    // Use this to clear bit 30
    block->AND(ARMReg::R4, ARMReg::R4, 0xBFFFFFFF);

    // Z flag is set, we will ORR.
    block->SetCC(CCFlags::CC_EQ);
    block->ORR(ARMReg::R4, ARMReg::R4, 1 << 30);
    block->SetCC(CCFlags::CC_AL);
}

void arm_recompiler::gen_cpsr_update_n_flag()
{
    // Use this to clear bit 31
    block->AND(ARMReg::R4, ARMReg::R4, 0x7FFFFFFF);

    // N flag is set (negative), we will ORR.
    block->SetCC(CCFlags::CC_MI);
    block->ORR(ARMReg::R4, ARMReg::R4, 1 << 31);
    block->SetCC(CCFlags::CC_AL);
}

void arm_recompiler::gen_cpsr_update_v_flag()
{
    // Use this to clear bit 28
    block->AND(ARMReg::R4, ARMReg::R4, 0xEFFFFFFF);

    // V flag is set (overflow), we will ORR.
    block->SetCC(CCFlags::CC_VS);
    block->ORR(ARMReg::R4, ARMReg::R4, 1 << 28);
    block->SetCC(CCFlags::CC_AL);
}

void arm_recompiler::gen_arm32_mov(ARMReg reg, Operand2 op)
{
    block->MOV(reg, remap_operand2(op));
}

void arm_recompiler::gen_arm32_mvn(ARMReg reg, Operand2 op)
{
    block->MVN(reg, remap_operand2(op));
}

void arm_recompiler::gen_arm32_tst(ARMReg reg, Operand2 op)
{
}

void arm_recompiler::gen_arm32_teq(ARMReg reg, Operand2 op)
{
}

void arm_recompiler::begin_valid_condition_block(CCFlags cond)
{
    if (cond == CCFlags::CC_AL)
    {
        return;
    }

    b_addr = (u8*)block->GetCodePointer();

    // Generate a temp conditional instruction
    block->B_CC(cond, b_addr);
}

void arm_recompiler::end_valid_condition_block(CCFlags cond)
{
    if (cond == CCFlags::CC_AL)
    {
        return;
    }

    std::uint8_t *crr_addr = (u8*)block->GetCodePointer();
    block->SetCodePointer(b_addr);

    switch (cond)
    {
    case CCFlags::CC_EQ:
    {
        block->B_CC(CCFlags::CC_NEQ, crr_addr);
        break;
    }

    case CCFlags::CC_NEQ:
    {
        block->B_CC(CCFlags::CC_EQ, crr_addr);
        break;
    }

    case CCFlags::CC_GT:
    {
        block->B_CC(CCFlags::CC_LE, crr_addr);
        break;
    }

    case CCFlags::CC_GE:
    {
        block->B_CC(CCFlags::CC_LT, crr_addr);
        break;
    }

    case CCFlags::CC_LE:
    {
        block->B_CC(CCFlags::CC_GT, crr_addr);
        break;
    }

    case CCFlags::CC_LT:
    {
        block->B_CC(CCFlags::CC_GE, crr_addr);
        break;
    }

    default:
    {
        assert(false && "Unhandle CC Flags");
        break;
    }
    }

    block->SetCodePointer(crr_addr);
    save_pc_from_visitor();
}

void arm_recompiler::gen_arm32_b(CCFlags flag, Operand2 op)
{
    begin_valid_condition_block(flag);
    
    int adv = op.Imm24() >> 6;
    auto new_des = visitor.get_location_descriptor().advance(adv);

    set_pc(new_des.pc);
    
    gen_block_link();
    end_valid_condition_block(flag);
}

void arm_recompiler::gen_arm32_bl(CCFlags flag, ArmGen::Operand2 op)
{
    begin_valid_condition_block(flag);

    int adv = op.Imm24() >> 6;
    auto new_des = visitor.get_location_descriptor().advance(adv);

    block->MOV(ARMReg::R10, visitor.get_current_visiting_pc() + 4);
    set_pc(new_des.pc);

    gen_block_link();
    end_valid_condition_block(flag);
}

void arm_recompiler::gen_arm32_add(ARMReg reg1, ARMReg reg2, Operand2 op)
{
    if (reg2 == ARMReg::R15) 
    {
        if (op.GetType() == OpType::TYPE_IMM)
        {
            // Add them right away, and move this value to destination
            // register
            std::uint32_t val = visitor.get_current_visiting_pc() + 8 + op.Imm12() & 0b001111111111;
            block->MOV(reg1, val);

            return;
        }
        else
        {
            assert(false, "R15 is with another register!");
        }
    }

    if (op.GetType() == TYPE_REG)
    {
        allocator.spill_lock(reg2);
        allocator.spill_lock(static_cast<ARMReg>(op.Rm()));

        ARMReg source1 = remap_arm_reg(reg2);
        ARMReg source2 = remap_arm_reg(static_cast<ARMReg>(op.Rm()));

        allocator.release_all_spill_lock();

        block->ADD(remap_arm_reg(reg1), source1, source2);

        return;
    }

    block->ADD(remap_arm_reg(reg1), remap_arm_reg(reg2), op);
}

void arm_recompiler::gen_arm32_sub(ARMReg reg1, ARMReg reg2, Operand2 op)
{
    if (reg2 == ARMReg::R15)
    {
        if (op.GetType() == OpType::TYPE_IMM)
        {
            // Add them right away, and move this value to destination
            // register
            std::uint32_t val = visitor.get_current_visiting_pc() + 8 - op.Imm12() & 0b001111111111;
            block->MOV(reg1, val);
        }
        else
        {
            // ERROR
            assert(false, "R15 is with another register!");
        }
    }

    // Can remap them seperately. They has different usage
    if (op.GetType() == TYPE_REG)
    {
        allocator.spill_lock(reg2);
        allocator.spill_lock(static_cast<ARMReg>(op.Rm()));

        ARMReg source1 = remap_arm_reg(reg2);
        ARMReg source2 = remap_arm_reg(static_cast<ARMReg>(op.Rm()));

        allocator.release_all_spill_lock();
        block->SUB(remap_arm_reg(reg1), source1, source2);

        return;
    }

    block->SUB(remap_arm_reg(reg1), remap_arm_reg(reg2), op);
}

void arm_recompiler::gen_arm32_cmp(ARMReg reg1, Operand2 op)
{
    block->CMP(remap_arm_reg(reg1), remap_operand2(op));
}

void arm_recompiler::gen_arm32_cmn(ARMReg reg1, Operand2 op)
{
    block->CMN(remap_arm_reg(reg1), remap_operand2(op));
}

// R15 can't be used
void arm_recompiler::gen_arm32_mul(ARMReg reg1, ARMReg reg2, ARMReg reg3)
{
    block->MUL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3));
}

// TODO: gen MLA + MLS
void arm_recompiler::gen_arm32_umull(ARMReg reg1, ARMReg reg2, ARMReg reg3, ARMReg reg4)
{
    block->UMULL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3)
        , remap_arm_reg(reg4));
}

void arm_recompiler::gen_arm32_umulal(ARMReg reg1, ARMReg reg2, ARMReg reg3, ARMReg reg4)
{
    block->UMLAL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3)
        , remap_arm_reg(reg4));
}

void arm_recompiler::gen_arm32_smull(ARMReg reg1, ARMReg reg2, ARMReg reg3, ARMReg reg4)
{
    block->SMULL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3)
        , remap_arm_reg(reg4));
}    

void arm_recompiler::gen_arm32_smlal(ARMReg reg1, ARMReg reg2, ARMReg reg3, ARMReg reg4)
{
    block->SMLAL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3)
        , remap_arm_reg(reg4));
}

void arm_recompiler::gen_memory_write(void *func, ARMReg source, ARMReg base, Operand2 op, bool subtract, bool write_back,
    bool post_indexed)
{
    ARMReg mapped_source_reg = remap_arm_reg(source);

    if (op.GetType() == TYPE_REG)
    {
        allocator.spill_lock(base);
        allocator.spill_lock(static_cast<ARMReg>(op.Rm()));
    }

    ARMReg mapped_base_reg = remap_arm_reg(base);

    block->PUSH(5, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R4, ARMReg::R14);

    if (base == ARMReg::R_PC)
    {
        std::uint32_t addr = visitor.get_current_visiting_pc();

        if (!post_indexed)
        {
            addr += subtract ? -(s32)op.Imm12() : op.Imm12();
        }

        block->MOV(ARMReg::R4, addr);
    }
    else
    {
        // Move register 2 to reg4
        block->MOV(ARMReg::R4, mapped_base_reg);

        if (!post_indexed)
        {
            // Next, add them with base. The value will stay in R4
            if (subtract)
            {
                block->SUB(ARMReg::R4, ARMReg::R4, remap_operand2(op));
            }
            else
            {
                block->ADD(ARMReg::R4, ARMReg::R4, remap_operand2(op));
            }
        }
    }

    block->MOVI2R(ARMReg::R0, reinterpret_cast<u32>(callback.userdata));
    block->MOVI2R(ARMReg::R14, reinterpret_cast<u32>(func));
    block->MOV(ARMReg::R1, ARMReg::R4);
    block->MOV(ARMReg::R2, mapped_source_reg);

    block->BL(ARMReg::R14);

    if (write_back)
    {
        assert(base != ARMReg::R_PC);

        if (post_indexed)
        {
            // Next, add them with base. The value will stay in R4
            if (subtract)
            {
                block->SUB(ARMReg::R4, ARMReg::R4, remap_operand2(op));
            }
            else
            {
                block->ADD(ARMReg::R4, ARMReg::R4, remap_operand2(op));
            }
        }

        block->MOV(mapped_base_reg, ARMReg::R4);
    }

    if (op.GetType() == TYPE_REG)
    {
        allocator.release_all_spill_lock();
    }

    block->POP(5, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R4, ARMReg::R14);

}

void arm_recompiler::gen_memory_read(void *func, ARMReg dest, ARMReg base, Operand2 op, bool subtract, bool write_back,
    bool post_indexed)
{
    ARMReg mapped_dest_reg = remap_arm_reg(dest);

    if (op.GetType() == TYPE_REG)
    {
        allocator.spill_lock(base);
        allocator.spill_lock(static_cast<ARMReg>(op.Rm()));
    }

    ARMReg mapped_base_reg = remap_arm_reg(base);

    // Using local variable R4. Make sure we doesn't push this if the mapped dest is r4,
    // since it's going to be clobbered.
    if (mapped_dest_reg != ARMReg::R4)
    {
        block->PUSH(1, ARMReg::R4);
    }

    block->PUSH(3, ARMReg::R0, ARMReg::R1, ARMReg::R14);

    if (base == ARMReg::R_PC)
    {
        std::uint32_t addr = visitor.get_current_visiting_pc();

        if (!post_indexed)
        {
            addr += subtract ? -(s32)op.Imm12() : op.Imm12();
        }

        block->MOV(ARMReg::R4, addr);
    } 
    else
    {
        // Move register 2 to reg4
        block->MOV(ARMReg::R4, mapped_base_reg);

        if (!post_indexed)
        {
            // Next, add them with base. The value will stay in R4
            if (subtract)
            {
                block->SUB(ARMReg::R4, ARMReg::R4, remap_operand2(op));
            }
            else
            {
                block->ADD(ARMReg::R4, ARMReg::R4, remap_operand2(op));
            }
        }
    }

    // Nice, we now got the address in R1, let's move the userdata to r0,
    // function pointer in r14 and branch.
    block->MOVI2R(ARMReg::R0, reinterpret_cast<u32>(callback.userdata));
    block->MOV(ARMReg::R1, ARMReg::R4);
    block->MOVI2R(ARMReg::R14, reinterpret_cast<u32>(func));

    block->BL(ARMReg::R14);

    if (dest == ARMReg::R_PC)
    {
        set_pc(ARMReg::R0);
        gen_block_link();
    }
    else
    {    
        // We got the value in r0!
        block->MOV(mapped_dest_reg, ARMReg::R0);
    }

    if (write_back)
    {
        assert(base != ARMReg::R_PC);

        if (post_indexed)
        {
            // Next, add them with base. The value will stay in R4
            if (subtract)
            {
                block->SUB(ARMReg::R4, ARMReg::R4, remap_operand2(op));
            }
            else
            {
                block->ADD(ARMReg::R4, ARMReg::R4, remap_operand2(op));
            }
        }

        block->MOV(mapped_base_reg, ARMReg::R4);
    }

    if (op.GetType() == TYPE_REG)
    {
        allocator.release_all_spill_lock();
    }

    // Should be in order
    block->POP(3, ARMReg::R0, ARMReg::R1, ARMReg::R14);

    if (mapped_dest_reg != ARMReg::R4)
    {
        block->POP(1, ARMReg::R4);
    }
}

void arm_recompiler::gen_arm32_str(ARMReg reg1, ARMReg reg2, Operand2 base, bool subtract, bool write_back, bool post_index)
{
    gen_memory_write(callback.write_mem32, reg1, reg2, base, subtract, write_back, post_index);
}

void arm_recompiler::gen_arm32_ldr(ARMReg reg1, ARMReg reg2, Operand2 base, bool subtract, bool write_back, bool post_index)
{
    gen_memory_read(callback.read_mem32, reg1, reg2, base, subtract, write_back, post_index);
}

void arm_recompiler::gen_arm32_strb(ARMReg reg1, ARMReg reg2, Operand2 base, bool subtract, bool write_back, bool post_index)
{
    gen_memory_write(callback.write_mem8, reg1, reg2, base, subtract, write_back, post_index);
}

void arm_recompiler::gen_arm32_ldrb(ARMReg reg1, ARMReg reg2, Operand2 base, bool subtract, bool write_back, bool post_index)
{
    gen_memory_write(callback.read_mem8, reg1, reg2, base, subtract, write_back, post_index);
}

void arm_recompiler::gen_arm32_strh(ARMReg reg1, ARMReg reg2, Operand2 base, bool subtract, bool write_back, bool post_index)
{
    gen_memory_write(callback.write_mem16, reg1, reg2, base, subtract, write_back, post_index);
}

void arm_recompiler::gen_arm32_ldrh(ARMReg reg1, ARMReg reg2, Operand2 base, bool subtract, bool write_back, bool post_index)
{
    gen_memory_write(callback.read_mem16, reg1, reg2, base, subtract, write_back, post_index);
}

void arm_recompiler::gen_block_link()
{
    // Flush
    flush();

    // Adding cycles that runned from last branch
    block->ARMABI_call_function_cc(callback.add_cycles, reinterpret_cast<std::uint32_t>(callback.userdata),
        visitor.get_cycles_count_since_last_cond() + 1);

    visitor.get_cycles_count_since_last_cond() = 0;

    // After adding cycles, get the cycles remaing
    block->ARMABI_call_function_c_promise_ret(callback.get_remaining_cycles, reinterpret_cast<std::uint32_t>(callback.userdata));
    block->STR(ARMReg::R0, JIT_STATE_REG, block->jsi.offset_cycles_left, true);

    block->ARMABI_call_function_c_promise_ret(block->jit_rt_callback.get_next_block_addr, 
        reinterpret_cast<std::uint32_t>(block->jit_rt_callback.userdata));

    block->B(ARMReg::R0);
}

// Let's generate the dispatcher code
void arm_recompile_block::gen_run_code()
{
    run_code = get_func_as<run_code_func>();
    BeginWrite();

    ARMABI_save_all_registers();

    // The JIT state is passed to the current block
    // It should be stored in parameter 0.
    MOV(JIT_STATE_REG, ARMReg::R0);

    // Now, store the SP in R11
    LDR(ARMReg::R11, JIT_STATE_REG, jsi.offset_reg + R13 * sizeof(std::uint32_t), true);

    ARMABI_call_function_c_promise_ret(reinterpret_cast<void*>(callback.get_remaining_cycles),
        reinterpret_cast<std::uint32_t>(callback.userdata));

    // Store the remaining cycles to JIT state
    STR(ARMReg::R0, JIT_STATE_REG, jsi.offset_cycles_left, true);
    STR(ARMReg::R0, JIT_STATE_REG, jsi.offset_cycles_to_run, true);

    // This is where we will loop back if the ticks are still available
    void *loop_start = (void*)(GetCodePointer());

    // Next, lookup the block to run to. If we can't find, we can create new one
    ARMABI_call_function_c_promise_ret(reinterpret_cast<void*>(jit_rt_callback.get_next_block_addr),
        reinterpret_cast<std::uint32_t>(jit_rt_callback.userdata));

    // The address is in R0
    BL(ARMReg::R0);
    
    // Now check for the remaning ticks.
    LDR(ARMReg::R4, JIT_STATE_REG, jsi.offset_cycles_left, true);
    CMP(ARMReg::R4, 0);

    B_CC(CCFlags::CC_GT, loop_start);

    // Add ticks otherwise. Supposed no ?  
    /*
    LDR(ARMReg::R0, ARMReg::R10, jsi.offset_cycles_left, true);
    LDR(ARMReg::R1, ARMReg::R10, jsi.offset_cycles_to_run, true);

    SUB(ARMReg::R1, ARMReg::R1, ARMReg::R0);
    MOV(ARMReg::R0, reinterpret_cast<std::uint32_t>(callback.userdata));

    BL(reinterpret_cast<void*>(callback.add_cycles));
    */

    // Welp, we added cycles, looks like job is done. Time to load all registers and return
    ARMABI_load_all_registers();

    /* Now save them all in the states */

    BL(ARMReg::R_LR);
    
    AlignCodePage();
    EndWrite();
}

block_descriptor arm_recompiler::recompile(address addr)
{
    code_ptr code = reinterpret_cast<code_ptr>(block->AlignCodePage());

    block->BeginWrite();

    block->ARMABI_save_all_registers();

    block->LDR(ARMReg::R4, JIT_STATE_REG, block->jsi.offset_cycles_left, true);
    block->CMP(ARMReg::R4, 0);

    std::uint8_t *b_fail_ptr = (u8*)block->GetCodePointer();
    block->B_CC(CCFlags::CC_LE, b_fail_ptr);

    block_descriptor descriptor;
    descriptor.begin = location_descriptor{ visitor.get_current_visiting_pc(), 0, 0 };
    descriptor.entry_point = code;

    visitor.set_pc(addr);
    visitor.recompile(this);

    // Try to flush right away to avoid unrelated flags
    flush();

    // Come back to the place where we were supposed to end this if the ticks is not enough
    // Jump to the end of the block if not enough ticks is available
    std::uint8_t *crr_code = (u8*)block->GetCodePointer();
    block->SetCodePointer(b_fail_ptr);

    block->B_CC(CCFlags::CC_LE, crr_code);

    // Come back to the current, and emit load all registers
    block->SetCodePointer(crr_code);

    /* Dummy used to check if the branch has reached here yet
    block->MOV(ARMReg::R0, JIT_STATE_REG);
    block->ARMABI_call_function(callback.dummy);
    */

    block->ARMABI_load_all_registers();
    block->B(ARMReg::R14);
    
    descriptor.end = location_descriptor{ visitor.get_current_visiting_pc(), 0, 0 };
    descriptor.size = block->GetCodePointer() - reinterpret_cast<const std::uint8_t*>(code);

    block->AlignCodePage();
    block->EndWrite();

    return descriptor;
}

block_descriptor arm_recompiler::get_next_block(location_descriptor descriptor)
{
    auto find_res = blocks.find(descriptor.pc);

    if (find_res == blocks.end())
    {
        blocks.emplace(descriptor.pc, recompile(descriptor.pc));
        return blocks[descriptor.pc];
    }

    return find_res->second;
}

static code_ptr get_next_block_addr_jit(void *userdata)
{
    return jit::get_next_block_addr(userdata);
}

jit::jit(jit_callback callback)
    : callback(callback),
      block(state, callback, runtime_callback),
      analyst(callback),
      recompiler(&analyst, callback, block)
{
    runtime_callback.userdata = this;
    runtime_callback.get_next_block_addr = get_next_block_addr_jit;

    block.set_runtime_callback(runtime_callback);
    block.gen_run_code();
}

code_ptr jit::get_next_block_addr(void *userdata)
{
    jit *j = reinterpret_cast<jit*>(userdata);

    location_descriptor des;
    des.pc = j->state.regs[15];
    des.cpsr = j->state.cpsr;

    return j->recompiler.get_next_block(des).entry_point;
}

void jit::execute()
{
    state.should_stop = false;
    block.do_run_code(&state);
}

bool jit::stop()
{
    state.should_stop = true;
    return true;
}

void jit::reset()
{
    for (auto i = 0; i < 16; i++)
    {
        state.regs[i] = 0;
    }

    state.cpsr = 0xD3;
}

}