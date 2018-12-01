#include <Arme/Arme.h>

#define CAPSTONE_HAS_ARM
#define CAPSTONE_USE_SYS_DYN_MEM

#include <capstone/capstone.h>
#include <capstone/arm.h>

#ifdef _WIN32
#include <Windows.h>
#endif

#include <string>

using namespace ArmGen;

namespace arme
{

static const ARMReg JIT_STATE_REG = ARMReg::R8;

#define SIGNEX(v, sb) ((v) | (((v) & (1 << (sb))) ? ~((1 << (sb))-1) : 0))
#define ROL(n, i) ((n << i) | (n >> (32 - i))) >> 0
#define ROR(n, i) ((n >> i) | (n << (32 - i))) >> 0

static Operand2 encode_imm(std::uint32_t val)
{
    if (val > 0xFF)
    {
        //Operand2(val & 0xFF, (val >> 8) & 0xF) : val;
        for (int i = 0; i < 16; i++)
        {
            auto m = ROL(val, i * 2);
            if (m < 256)
            {
                val = (i << 8) | m;
                return Operand2(val & 0xFF, (val >> 8) & 0xF);
            }
        }

        // Fallthrough
    }

    return val;
}

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
    block->STR(host_reg, JIT_STATE_REG, offsetof(jit_state, regs) + (guest_reg - R0) * sizeof(std::uint32_t));

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
    // Stub return PC with PC
    if (guest_reg == R_PC)
    {
        return ARMReg::R_PC;
    }

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
        return encode_imm(op.imm);
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
    auto insn = analyst->disassemble_instructions(loc.pc - (t_reg ? 4 : 8), t_reg);
    crr_inst = callback.read_code32 ? callback.read_code32(callback.userdata, loc.pc - (t_reg ? 4 : 8))
        : callback.read_mem32(callback.userdata, loc.pc);

    //printf("[0x%08x] %s %s\n", insn->address, insn->mnemonic, insn->op_str);

    cs_detail *detail = insn->detail;
    cs_arm *arm = &(detail->arm);

    op_counter = 0;

    CCFlags ccflag = cs_cc_to_jit_cc(arm->cc);

    if (!t_reg)
    {
        // Do condition check if ARM. AL flag will returns imm
        recompiler->begin_valid_condition_block(ccflag);
    }

    switch (insn->id)
    {
    case ARM_INS_MOV:
    {
        auto dest = get_next_reg_from_cs(arm);
        auto op = get_next_op_from_cs(arm);

        recompiler->gen_arm32_mov(dest, op);
        break;
    }

    case ARM_INS_MVN:
    {
        auto dest = get_next_reg_from_cs(arm);
        auto op = get_next_op_from_cs(arm);

        recompiler->gen_arm32_mvn(dest, op);
        break;
    }

#define DECLARE_ALU_CALC(name, func_name)  \
    case ARM_INS_##name:                       \
    {                                       \
        auto dest = get_next_reg_from_cs(arm);  \
        auto source = get_next_reg_from_cs(arm);    \
        auto source2 = get_next_op_from_cs(arm);    \
        recompiler->gen_arm32_##func_name(dest, source, source2);   \
        break;          \
    }

    DECLARE_ALU_CALC(ADD, add)
    DECLARE_ALU_CALC(SUB, sub)
    DECLARE_ALU_CALC(AND, and)
    DECLARE_ALU_CALC(ORR, orr)
    DECLARE_ALU_CALC(BIC, bic)

    case ARM_INS_MSR:
    {
        // Skip through op1
        op_counter++;

        recompiler->gen_arm32_msr(get_next_op_from_cs(arm));
        break;
    }

    case ARM_INS_TST:
    {
        auto dest = get_next_reg_from_cs(arm);
        auto op = get_next_op_from_cs(arm);

        recompiler->gen_arm32_tst(dest, op);
        break;
    }

    case ARM_INS_CMP:
    {
        recompiler->gen_arm32_cmp(get_next_reg_from_cs(arm), get_next_reg_from_cs(arm));
        break;
    }

    case ARM_INS_B:
    {
        // Capstone disassemble imm as address
        recompiler->gen_arm32_b(arm->operands[op_counter].imm);
        should_break = true;
        break;
    }

    case ARM_INS_BX:
    {
        // Capstone disassemble imm as address
        recompiler->gen_arm32_bx(get_next_op_from_cs(arm));
        should_break = true;
        break;
    }

    case ARM_INS_BL:
    {
        recompiler->gen_arm32_bl(arm->operands[op_counter].imm);
        should_break = true;
        break;
    }

    case ARM_INS_BLX:
    {
        recompiler->gen_arm32_blx(get_next_op_from_cs(arm));
        should_break = true;
        break;
    }

    case ARM_INS_MRC:
    {
        std::uint8_t cp = arm->operands[op_counter++].imm;
        std::uint8_t op1 = arm->operands[op_counter++].imm;
        ARMReg rd = cs_arm_reg_to_reg(static_cast<arm_reg>(arm->operands[op_counter++].reg));
        std::uint8_t crn = arm->operands[op_counter++].imm;
        std::uint8_t crm = arm->operands[op_counter++].imm;
        std::uint8_t op2 = arm->operands[op_counter++].imm;

        recompiler->gen_arm32_mrc(cp, op1, rd, crn, crm, op2);
        break;
    }

    case ARM_INS_MCR:
    {
        std::uint8_t cp = arm->operands[op_counter++].imm;
        std::uint8_t op1 = arm->operands[op_counter++].imm;
        ARMReg rd = cs_arm_reg_to_reg(static_cast<arm_reg>(arm->operands[op_counter++].reg));
        std::uint8_t crn = arm->operands[op_counter++].imm;
        std::uint8_t crm = arm->operands[op_counter++].imm;
        std::uint8_t op2 = arm->operands[op_counter++].imm;

        recompiler->gen_arm32_mcr(cp, op1, rd, crn, crm, op2);
        break;
    }

#define DECLARE_ALU_BASE(insn, func_name)      \
    case ARM_INS_##insn:            \
    {                               \
        auto r1 = get_next_reg_from_cs(arm);                    \
        auto r2 = get_next_reg_from_cs(arm, false);             \
        auto op = arm->operands[op_counter].mem.index != arm_reg::ARM_REG_INVALID ? Operand2(cs_arm_reg_to_reg(arm->operands[op_counter].mem.index), \
            ShiftType::ST_LSL, arm->operands[op_counter].mem.lshift) : encode_imm(arm->operands[op_counter].mem.disp);                              \
        recompiler->gen_arm32_##func_name(r1, r2, op, arm->operands[op_counter].subtracted, arm->writeback                                      \
            , arm->operands[op_counter].imm & (2 << 9) ? true : false);                                                                 \
        break;                                                                                                                          \
    }

#define DECLARE_LDM_BASE(inst, ascending, inc_before)   \
    case ARM_INS_##inst:                                            \
    {                                                               \
        auto base = get_next_reg_from_cs(arm);                      \
        std::vector<ARMReg> receive_regs;                           \
        for (int i = 1; i < arm->op_count; i++)                     \
        {                                                           \
            receive_regs.push_back(get_next_reg_from_cs(arm));      \
        }                                                           \
        recompiler->gen_arm32_ldm(base, &receive_regs[0], receive_regs.size(), ascending, inc_before, arm->writeback);   \
        break;                                                                                                  \
    }

#define DECLARE_STM_BASE(inst, ascending, inc_before)   \
    case ARM_INS_##inst:                                            \
    {                                                               \
        auto base = get_next_reg_from_cs(arm);                      \
        std::vector<ARMReg> source_regs;                            \
        for (int i = 1; i < arm->op_count; i++)                     \
        {                                                           \
            source_regs.push_back(get_next_reg_from_cs(arm));      \
        }                                                                                                              \
        recompiler->gen_arm32_stm(base, &source_regs[0], source_regs.size(), ascending, inc_before, arm->writeback);   \
        break;                                                                                                         \
    }

    DECLARE_LDM_BASE(LDMDA, false, false)
    DECLARE_LDM_BASE(LDMDB, false, true)
    DECLARE_LDM_BASE(LDMIB, true, true)
    DECLARE_LDM_BASE(LDM, true, false)

    DECLARE_STM_BASE(STMIB, true, true)
    DECLARE_STM_BASE(STM, true, false)
    DECLARE_STM_BASE(STMDA, false, false)
    DECLARE_STM_BASE(STMDB, false, true)

    DECLARE_ALU_BASE(STR, str)
    DECLARE_ALU_BASE(STRB, strb)
    DECLARE_ALU_BASE(STRH, strh)
    DECLARE_ALU_BASE(LDR, ldr)
    DECLARE_ALU_BASE(LDRB, ldrb)
    DECLARE_ALU_BASE(LDRH, ldrh)

    default:
    {
        assert(false && "Unimplemented instructions!");
        break;
    }
    }

    if (!t_reg)
    {
        recompiler->end_valid_condition_block(ccflag);
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

static void update_cpsr_mode(void *rawstate, std::uint8_t sysreg, std::uint32_t val, std::uint32_t mask)
{
    jit_state *state = reinterpret_cast<jit_state*>(rawstate);
    std::uint32_t *psr = nullptr;

    switch (sysreg)
    {
    case 0x0:
    {
        psr = &(state->cpsr);
        break;
    }

    case 0x11:
    {
        psr = &(state->fiq[7]);
        break;
    }

    case 0x12:
    {
        psr = &(state->irq[2]);
        break;
    }

    case 0x13:
    {
        psr = &(state->svc[2]);
        break;
    }

    case 0x17:
    {
        psr = &(state->abt[2]);
        break;
    }

    case 0x1B:
    {
        psr = &(state->und[2]);
        break;
    }

    default: 
    {
        assert(false);
        break;
    }
    }

    auto oldpsr = *psr;
    *psr &= ~mask;
    *psr |= (val & mask);

    if (sysreg == 0)
    {
        u32 temp;
        #define SWAP(a, b)  temp = a; a = b; b = temp;

        switch (oldpsr & 0x1F)
        {
        case 0x11:
            SWAP(state->regs[8], state->fiq[0]);
            SWAP(state->regs[9], state->fiq[1]);
            SWAP(state->regs[10], state->fiq[2]);
            SWAP(state->regs[11], state->fiq[3]);
            SWAP(state->regs[12], state->fiq[4]);
            SWAP(state->regs[13], state->fiq[5]);
            SWAP(state->regs[14], state->fiq[6]);
            break;

        case 0x12:
            SWAP(state->regs[13], state->irq[0]);
            SWAP(state->regs[14], state->irq[1]);
            break;

        case 0x13:
            SWAP(state->regs[13], state->svc[0]);
            SWAP(state->regs[14], state->svc[1]);
            break;

        case 0x17:
            SWAP(state->regs[13], state->abt[0]);
            SWAP(state->regs[14], state->abt[1]);
            break;

        case 0x1B:
            SWAP(state->regs[13], state->und[0]);
            SWAP(state->regs[14], state->und[1]);
            break;

        default:
        {
            assert(false);
            break;
        }
        }

        switch (state->cpsr & 0x1F)
        {
        case 0x11:
            SWAP(state->regs[8], state->fiq[0]);
            SWAP(state->regs[9], state->fiq[1]);
            SWAP(state->regs[10], state->fiq[2]);
            SWAP(state->regs[11], state->fiq[3]);
            SWAP(state->regs[12], state->fiq[4]);
            SWAP(state->regs[13], state->fiq[5]);
            SWAP(state->regs[14], state->fiq[6]);
            break;

        case 0x12:
            SWAP(state->regs[13], state->irq[0]);
            SWAP(state->regs[14], state->irq[1]);
            break;

        case 0x13:
            SWAP(state->regs[13], state->svc[0]);
            SWAP(state->regs[14], state->svc[1]);
            break;

        case 0x17:
            SWAP(state->regs[13], state->abt[0]);
            SWAP(state->regs[14], state->abt[1]);
            break;

        case 0x1B:
            SWAP(state->regs[13], state->und[0]);
            SWAP(state->regs[14], state->und[1]);
            break;

        default:
        {
            assert(false);
            break;
        }
        }
    }
}

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
            return visitor.get_current_pc();
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

void arm_recompiler::gen_arm32_mcr(const std::uint8_t coproc, const std::uint8_t op1,
    ArmGen::ARMReg rs, const std::uint8_t crn, const std::uint8_t crm,
    const std::uint8_t op2)
{
    ARMReg mapped_source = remap_arm_reg(rs);

    block->PUSH(5, R0, R1, R2, R3, R14);
    block->MOVI2R(ARMReg::R0, reinterpret_cast<u32>(callback.userdata));
    block->MOVI2R(ARMReg::R2, (crn << 8) | (crn << 4) | op1);
    block->MOVI2R(ARMReg::R14, reinterpret_cast<u32>(callback.cp_read));
    block->MOVI2R(ARMReg::R1, coproc);
    mapped_source != R3 ? block->MOV(ARMReg::R3, mapped_source) : 0;

    block->BL(ARMReg::R14);

    block->POP(5, R0, R1, R2, R3, R14);
}

void arm_recompiler::gen_arm32_msr(Operand2 op)
{
    u32 mask = 0;
    u32 inst = visitor.get_current_instruction_binary();

    if (inst & (1 << 16)) mask |= 0x000000FF;
    if (inst & (1 << 17)) mask |= 0x0000FF00;
    if (inst & (1 << 18)) mask |= 0x00FF0000;
    if (inst & (1 << 19)) mask |= 0xFF000000;

    if (!(inst & (1 << 22)))
        mask &= 0xFFFFFFDF;

    block->PUSH(5, R0, R1, R2, R3, R14); 
    block->MOV(R2, remap_operand2(op));

    block->MOVI2R(R3, mask);

    block->AND(R0, R3, 0x1F);
    block->CMP(R0, 0x10);

    block->SetCC(CC_EQ);
    block->AND(R3, R3, encode_imm(0xFFFFFF00));
    block->SetCC(CC_AL);
    
    if (inst & (1 << 22)) 
    {
        block->LDR(R1, JIT_STATE_REG, offsetof(jit_state, cpsr));
        block->AND(R1, R1, 0x1F);
    }
    else 
    {
        block->MOV(R1, 0);
    }

    block->MOV(R0, JIT_STATE_REG);
    block->MOVI2R(R14, reinterpret_cast<u32>(update_cpsr_mode));

    block->BL(R14);
    block->POP(4, R0, R1, R2, R3, R14);
}

void arm_recompiler::gen_arm32_mrc(const std::uint8_t coproc, const std::uint8_t op1,
    ArmGen::ARMReg rd, const std::uint8_t crn, const std::uint8_t crm,
    const std::uint8_t op2)
{
    ARMReg dest_mapped = remap_arm_reg(rd);
    
    switch (dest_mapped)
    {
    case R0:
        block->PUSH(3, R1, R2, R14);
        break;

    case R1:
        block->PUSH(3, R0, R2, R14);
        break;

    case R2:
        block->PUSH(3, R0, R1, R14);
        break;

    default:
        block->PUSH(4, R0, R1, R2, R14);
        break;
    }

    block->MOVI2R(ARMReg::R0, reinterpret_cast<u32>(callback.userdata));
    block->MOVI2R(ARMReg::R2, (crn << 8) | (crn << 4) | op1);
    block->MOVI2R(ARMReg::R14, reinterpret_cast<u32>(callback.cp_read));
    block->MOVI2R(ARMReg::R1, coproc);

    block->BL(ARMReg::R14);

    if (rd == R_PC)
    {
        set_pc(R0);
        gen_block_link();
    }

    else
    {
        dest_mapped != R0 ? block->MOV(dest_mapped, R0) : 0;
    }

    switch (dest_mapped)
    {
    case R0:
        block->POP(3, R1, R2, R14);
        break;

    case R1:
        block->POP(3, R0, R2, R14);
        break;

    case R2:
        block->POP(3, R0, R1, R14);
        break;

    default:
        block->POP(4, R0, R1, R2, R14);
        break;
    }
}

void arm_recompiler::save_pc_from_visitor()
{
    set_pc(visitor.get_current_pc());
}

void arm_recompiler::set_pc(ArmGen::ARMReg reg, bool exchange)
{
    block->STR(reg, JIT_STATE_REG, offsetof(jit_state, regs) + R15 * sizeof(std::uint32_t));

    if (exchange)
    {
        block->PUSH(2, R4, R5);
        block->LDR(R5, JIT_STATE_REG, offsetof(jit_state, cpsr));

        // Clear the thumb bit if there is one
        block->BIC(R5, R5, 0x20);

        block->AND(R4, reg, 1);
        block->CMP(R4, 1);

        block->SetCC(CC_EQ);
        block->ORR(R5, R5, 0x20);
        block->SetCC(CC_AL);

        block->STR(R5, JIT_STATE_REG, offsetof(jit_state, cpsr));

        block->POP(2, R4, R5);
    }
}

void arm_recompiler::set_pc(const std::uint32_t off, bool exchange)
{
    block->PUSH(1, ARMReg::R4);
    block->MOVI2R(ARMReg::R4, off);

    if (exchange)
    {
        block->PUSH(1, R5);
        block->LDR(R5, JIT_STATE_REG, offsetof(jit_state, cpsr));

        // Clear the thumb bit if there is one
        block->BIC(R5, R5, 0x20);

        // If Thumb
        if (off & 1)
        {
            block->ORR(R5, R5, 0x20);
        }

        block->STR(R5, JIT_STATE_REG, offsetof(jit_state, cpsr));
        block->POP(1, R5);
    }

    block->STR(ARMReg::R4, JIT_STATE_REG, offsetof(jit_state, regs) + R15 * sizeof(std::uint32_t));
    block->POP(1, ARMReg::R4);
}

void arm_recompiler::begin_gen_cpsr_update()
{
    block->PUSH(4, ARMReg::R4, ARMReg::R5, ARMReg::R6, ARMReg::R7);
    block->LDR(ARMReg::R4, JIT_STATE_REG, offsetof(jit_state, cpsr), true);
    block->MOV(ARMReg::R6, ARMReg::R4);
}

void arm_recompiler::end_gen_cpsr_update()
{
    block->STR(ARMReg::R4, JIT_STATE_REG, offsetof(jit_state, cpsr), true);
    block->POP(4, ARMReg::R4, ARMReg::R5, ARMReg::R6, ARMReg::R7);
}

void arm_recompiler::gen_cpsr_update_c_flag()
{
    // Use this to clear bit 29
    block->BIC(ARMReg::R4, ARMReg::R4, encode_imm(1 << 29));

    block->SetCC(CCFlags::CC_CS);
    block->ORR(ARMReg::R4, ARMReg::R4, encode_imm(1 << 29));
    block->SetCC(CCFlags::CC_AL);
}

void arm_recompiler::gen_cpsr_update_z_flag()
{
    // Use this to clear bit 30
    block->BIC(ARMReg::R4, ARMReg::R4, encode_imm(1 << 30));

    // Z flag is set, we will ORR.
    block->SetCC(CCFlags::CC_EQ);
    block->ORR(ARMReg::R4, ARMReg::R4, encode_imm(1 << 30));
    block->SetCC(CCFlags::CC_AL);
}

void arm_recompiler::gen_cpsr_update_n_flag()
{
    // Use this to clear bit 31
    block->BIC(ARMReg::R4, ARMReg::R4, encode_imm(1 << 31));

    // N flag is set (negative), we will ORR.
    block->SetCC(CCFlags::CC_MI);
    block->ORR(ARMReg::R4, ARMReg::R4, encode_imm(1 << 31));
    block->SetCC(CCFlags::CC_AL);
}

void arm_recompiler::gen_cpsr_update_v_flag()
{
    // Use this to clear bit 28
    block->BIC(ARMReg::R4, ARMReg::R4, encode_imm(1 << 28));

    // V flag is set (overflow), we will ORR.
    block->SetCC(CCFlags::CC_VS);
    block->ORR(ARMReg::R4, ARMReg::R4, encode_imm(1 << 28));
    block->SetCC(CCFlags::CC_AL);
}

void arm_recompiler::gen_arm32_mov(ARMReg reg, Operand2 op)
{
    auto new_dest_reg = remap_arm_reg(reg);
    auto new_op = remap_operand2(op);

    block->MOV(new_dest_reg, new_op);
}

void arm_recompiler::gen_arm32_mvn(ARMReg reg, Operand2 op)
{
    auto new_dest_reg = remap_arm_reg(reg);
    block->MVN(new_dest_reg, remap_operand2(op));
}

void arm_recompiler::gen_arm32_tst(ARMReg reg, Operand2 op)
{
    auto new_dest_reg = remap_arm_reg(reg);
    block->TST(new_dest_reg, remap_operand2(op));
}

void arm_recompiler::gen_arm32_teq(ARMReg reg, Operand2 op)
{
    auto new_dest_reg = remap_arm_reg(reg);
    block->TEQ(new_dest_reg, remap_operand2(op));
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

    case CCFlags::CC_PL:
    {
        block->B_CC(CCFlags::CC_MI, crr_addr);
        break;
    }

    case CCFlags::CC_MI:
    {
        block->B_CC(CCFlags::CC_PL, crr_addr);
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

void arm_recompiler::gen_arm32_b(address addr)
{   
    set_pc(addr);
    gen_block_link();
}

void arm_recompiler::gen_arm32_bl(address addr)
{
    auto ret_addr = visitor.get_current_visiting_pc() +
        (visitor.is_thumb() ? 1 : 4);
    
    // Only increase 1 if the current is thumb.
    block->MOVI2R(remap_arm_reg(R_LR), ret_addr);

    set_pc(addr);
    gen_block_link();
}

void arm_recompiler::gen_arm32_bx(ArmGen::Operand2 op)
{
    if (op.GetType() == TYPE_REG)
    {
        // Set PC
        set_pc(remap_arm_reg(static_cast<ARMReg>(op.Rm())), true);
        gen_block_link();
    }
    else
    {
        set_pc(op.GetData(), true);
        gen_block_link();
    }
}

void arm_recompiler::gen_arm32_blx(ArmGen::Operand2 op)
{
    auto ret_addr = visitor.get_current_visiting_pc() +
        (visitor.is_thumb() ? 1 : 4);

    block->MOVI2R(remap_arm_reg(R_LR), ret_addr);

    if (op.GetType() == TYPE_REG)
    {
        // Set PC
        set_pc(remap_arm_reg(static_cast<ARMReg>(op.Rm())));
        gen_block_link();
    }
    else
    {
        set_pc(op.GetData());
        gen_block_link();
    }
}

void arm_recompiler::gen_arm32_add(ARMReg reg1, ARMReg reg2, Operand2 op)
{
    if (reg2 == ARMReg::R15) 
    {
        if (op.GetType() == OpType::TYPE_IMM)
        {
            // Add them right away, and move this value to destination
            // register
            std::uint32_t val = visitor.get_current_pc() + op.GetData();
            block->MOVI2R(reg1, val);

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
            std::uint32_t val = visitor.get_current_pc() + op.GetData();
            block->MOVI2R(reg1, val);
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
    allocator.spill_lock(reg2);
    allocator.spill_lock(reg3);

    block->MUL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3));

    allocator.release_all_spill_lock();
}

// TODO: gen MLA + MLS
void arm_recompiler::gen_arm32_umull(ARMReg reg1, ARMReg reg2, ARMReg reg3, ARMReg reg4)
{
    allocator.spill_lock(reg2);
    allocator.spill_lock(reg3);
    allocator.spill_lock(reg4);

    block->UMULL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3)
        , remap_arm_reg(reg4));

    allocator.release_all_spill_lock();
}

void arm_recompiler::gen_arm32_umulal(ARMReg reg1, ARMReg reg2, ARMReg reg3, ARMReg reg4)
{
    allocator.spill_lock(reg2);
    allocator.spill_lock(reg3);
    allocator.spill_lock(reg4);

    block->UMLAL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3)
        , remap_arm_reg(reg4));

    allocator.release_all_spill_lock();
}

void arm_recompiler::gen_arm32_smull(ARMReg reg1, ARMReg reg2, ARMReg reg3, ARMReg reg4)
{
    allocator.spill_lock(reg2);
    allocator.spill_lock(reg3);
    allocator.spill_lock(reg4);

    block->SMULL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3)
        , remap_arm_reg(reg4));

    allocator.release_all_spill_lock();
}    

void arm_recompiler::gen_arm32_smlal(ARMReg reg1, ARMReg reg2, ARMReg reg3, ARMReg reg4)
{
    allocator.spill_lock(reg2);
    allocator.spill_lock(reg3);
    allocator.spill_lock(reg4);

    block->SMLAL(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_arm_reg(reg3)
        , remap_arm_reg(reg4));

    allocator.release_all_spill_lock();
}

void arm_recompiler::gen_arm32_bic(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 op)
{
    if (op.GetType() == TYPE_REG)
    {
        allocator.spill_lock(reg2);
        allocator.spill_lock(static_cast<ARMReg>(op.GetData()));
    }

    block->BIC(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_operand2(op));

    if (op.GetType() == TYPE_REG)
    {
        allocator.release_all_spill_lock();
    }
}

void arm_recompiler::gen_arm32_and(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 op)
{
    if (op.GetType() == TYPE_REG)
    {
        allocator.spill_lock(reg2);
        allocator.spill_lock(static_cast<ARMReg>(op.GetData()));
    }

    block->AND(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_operand2(op));

    if (op.GetType() == TYPE_REG)
    {
        allocator.release_all_spill_lock();
    }
}

void arm_recompiler::gen_arm32_orr(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 op)
{
    if (op.GetType() == TYPE_REG)
    {
        allocator.spill_lock(reg2);
        allocator.spill_lock(static_cast<ARMReg>(op.GetData()));
    }

    block->ORR(remap_arm_reg(reg1), remap_arm_reg(reg2), remap_operand2(op));

    if (op.GetType() == TYPE_REG)
    {
        allocator.release_all_spill_lock();
    }
}

void arm_recompiler::gen_arm32_stm(ArmGen::ARMReg base, ArmGen::ARMReg *target, const int count, bool ascending,
    bool inc_before, bool write_back)
{
    allocator.spill_lock(base);
    ARMReg remapped_base = remap_arm_reg(base);

    // Two case.
    // First: The base is not R1, in that case preserve R1
    // Second: Base is R1. If we don't need write back, then preserve it to make it back to original state later.
    bool should_push_pop_r = (remapped_base != ARMReg::R1) || (remapped_base == ARMReg::R1 && !write_back);

    if (should_push_pop_r)
    {
        block->PUSH(1, ARMReg::R1);
    }

    if (base == R_PC)
    {
        // Must assert that it's not requesting writeback
        assert(!write_back && "Write back operation on PC is not permitted");
        block->MOV(ARMReg::R1, visitor.get_current_pc());
    }
    else
    {
        block->MOV(ARMReg::R1, remap_arm_reg(base));
    }

    // If ascending, each time stored, add it by 4
    int add_offset = (ascending ? 4 : -4);
    
    // Don't need to spilllock
    for (int i = 0; i < count; i++)
    {
        ARMReg mapped_reg = remap_arm_reg(target[i]);
        assert(mapped_reg != INVALID_REG);

        if (inc_before)
        {
            block->ADD(ARMReg::R1, ARMReg::R1, add_offset);
        }

        block->PUSH(3, ARMReg::R0, ARMReg::R2, ARMReg::R14);

        // Don't waste time moving if the mapped register is already r2
        // Calling this before storing all arguments so that if the mapped register is r0, the value
        // won't go clobbered.
        mapped_reg != ARMReg::R2 ? block->MOV(ARMReg::R2, mapped_reg) : 0;

        // Hey, calling store on this.
        block->MOVI2R(ARMReg::R0, reinterpret_cast<u32>(callback.userdata));
        block->MOVI2R(ARMReg::R14, reinterpret_cast<u32>(callback.write_mem32));

        block->BL(ARMReg::R14);
        block->POP(3, ARMReg::R0, ARMReg::R2, ARMReg::R14);

        if (!inc_before)
        {
            block->ADD(ARMReg::R1, ARMReg::R1, add_offset);
        }
    }

    // If write back:
    // If the mapped base is R1, we don't need to do anything
    if (write_back && remapped_base != ARMReg::R1)
    {
        block->MOV(remapped_base, ARMReg::R1);
    }

    if (should_push_pop_r)
    {
        block->POP(1, ARMReg::R1);
    }

    allocator.release_spill_lock(base);
}

void arm_recompiler::gen_arm32_ldm(ArmGen::ARMReg base, ArmGen::ARMReg *target, const int count, bool ascending,
    bool inc_before, bool write_back)
{
    allocator.spill_lock(base);
    ARMReg remapped_base = remap_arm_reg(base);

    // Two case.
    // First: The base is not R1, in that case preserve R1
    // Second: Base is R1. If we don't need write back, then preserve it to make it back to original state later.
    bool should_push_pop_r = (remapped_base != ARMReg::R1) || (remapped_base == ARMReg::R1 && !write_back);

    if (should_push_pop_r)
    {
        block->PUSH(1, ARMReg::R1);
    }

    if (base == R_PC)
    {
        // Must assert that it's not requesting writeback
        assert(!write_back && "Write back operation on PC is not permitted");
        block->MOV(ARMReg::R1, visitor.get_current_pc());
    }
    else
    {
        block->MOV(ARMReg::R1, remapped_base);
    }

    // If ascending, each time loaded, add it by -4
    int add_offset = (ascending ? -4 : 4);
    std::vector<ARMReg> mapped_regs;

    bool should_move_new_addr = write_back;

    // Don't need to spilllock
    for (int i = count - 1; i >= 0; i--)
    {
        ARMReg mapped_reg = remap_arm_reg(target[i]);
        assert(mapped_reg != INVALID_REG);
        
        if (base == target[i])
        {
            should_move_new_addr = false;
        }

        mapped_regs.push_back(mapped_reg);
    }

    bool should_r1_loaded_from_garbage = false;
    bool should_gen_block_link = false;

    for (const auto &mapped_reg: mapped_regs)
    {
        if (inc_before)
        {
            block->ADD(ARMReg::R1, ARMReg::R1, add_offset);
        }

        (mapped_reg == ARMReg::R0) ? block->PUSH(1, ARMReg::R0) :
            block->PUSH(2, ARMReg::R0, ARMReg::R14);

        // Hey, calling store on this.
        block->MOVI2R(ARMReg::R0, reinterpret_cast<u32>(callback.userdata));
        block->MOVI2R(ARMReg::R14, reinterpret_cast<u32>(callback.write_mem32));

        block->BL(ARMReg::R14);

        // Hey moving
        switch (mapped_reg)
        {
        case ARMReg::R1:
        {
            // Oh no, this is really unexpected. 
            // There is a solution for this, which is costly but solve the problem
            // A garbage storage would be perfect for this.
            should_r1_loaded_from_garbage = true;
            block->STR(ARMReg::R0, JIT_STATE_REG, offsetof(jit_state, gar), true);

            break;
        }

        case ARMReg::R0:
        {
            break;
        }

        case ARMReg::R15:
        {
            // Write to PC directly
            set_pc(mapped_reg);
            should_gen_block_link = true;

            break;
        }

        default:
        {
            block->MOV(mapped_reg, ARMReg::R0);
            break;
        }
        }

        (mapped_reg == ARMReg::R0) ? block->POP(1, ARMReg::R14) : block->POP(2, ARMReg::R0, ARMReg::R14);

        if (!inc_before)
        {
            block->ADD(ARMReg::R1, ARMReg::R1, add_offset);
        }
    }

    // If write back:
    // If the mapped base is R1, we don't need to do anything
    if (remapped_base != ARMReg::R1 && should_move_new_addr)
    {
        block->MOV(remapped_base, ARMReg::R1);
    }

    should_push_pop_r ? block->POP(1, ARMReg::R1) : 0;
    should_r1_loaded_from_garbage ? block->LDR(ARMReg::R1, JIT_STATE_REG, offsetof(jit_state, gar), true) : 0;
    should_gen_block_link ? gen_block_link() : 0;

    allocator.release_spill_lock(base);
}

void arm_recompiler::gen_memory_write(void *func, ARMReg source, ARMReg base, Operand2 op, bool subtract, bool write_back,
    bool post_indexed)
{
    ARMReg mapped_source_reg = remap_arm_reg(source);

    assert((base != R15) && "Can't write to PC");

    if (op.GetType() == TYPE_REG)
    {
        allocator.spill_lock(base);
        allocator.spill_lock(static_cast<ARMReg>(op.Rm()));
    }

    ARMReg mapped_base_reg = remap_arm_reg(base);
    
    bool should_preserve_r4 = (mapped_base_reg != R4) || (!write_back && mapped_base_reg == R4);

    if (should_preserve_r4)
    {
        block->PUSH(1, ARMReg::R4);
    }

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

    write_back && (mapped_base_reg == R0) ? block->PUSH(3, ARMReg::R1, ARMReg::R2, ARMReg::R14) :
        block->PUSH(4, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R14);

    // Move this first.
    mapped_source_reg != ARMReg::R2 ? block->MOV(ARMReg::R2, mapped_source_reg) : 0;

    block->MOVI2R(ARMReg::R0, reinterpret_cast<u32>(callback.userdata));
    block->MOVI2R(ARMReg::R14, reinterpret_cast<u32>(func));
    block->MOV(ARMReg::R1, ARMReg::R4);

    block->BL(ARMReg::R14);

    write_back && (mapped_base_reg == R0) ? block->POP(3, ARMReg::R1, ARMReg::R2, ARMReg::R14) :
        block->POP(4, ARMReg::R0, ARMReg::R1, ARMReg::R2, ARMReg::R14);

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

    if (should_preserve_r4)
    {
        block->POP(1, ARMReg::R4);
    }
}

void arm_recompiler::gen_memory_read(void *func, ARMReg dest, ARMReg base, Operand2 op, bool subtract, bool write_back,
    bool post_indexed)
{
    ARMReg mapped_dest_reg = remap_arm_reg(dest);

    if (base == ARMReg::R_PC)
    {
        std::uint32_t addr = visitor.get_current_pc();

        if (!post_indexed)
        {
            addr += subtract ? -(s32)op.Imm12() : op.Imm12();
        }

        // Read memory right away
        auto val = callback.read_mem32(callback.userdata, addr);
        block->MOVI2R(mapped_dest_reg, val);

        return;
    }

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
    block->ARMABI_call_function_c_promise_ret(callback.get_remaining_cycles, 
        reinterpret_cast<std::uint32_t>(callback.userdata));

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

    visitor.set_pc(addr);

    block_descriptor descriptor;
    descriptor.begin = location_descriptor{ visitor.get_current_visiting_pc(), 0, 0 };
    descriptor.entry_point = code;

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