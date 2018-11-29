#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <unordered_map>
#include <memory>

#include "ArmEmitter.h"

#define UNREACHABLE(msg) assert(false && msg)

// Foward declaration
typedef size_t csh;

struct cs_insn;
struct cs_arm;

namespace arme
{
 
using address = std::uint32_t;
using code_ptr = const void*;

typedef std::uint8_t (*read_mem8_func)(void*, address);
typedef std::uint16_t (*read_mem16_func)(void*, address);
typedef std::uint32_t (*read_mem32_func)(void*, address);

typedef void          (*write_mem8_func)(void*, address, std::uint8_t);
typedef void          (*write_mem16_func)(void*, address, std::uint16_t);
typedef void          (*write_mem32_func)(void*, address, std::uint32_t);

typedef void            (*unhandled_instruction_func)(void*);
typedef std::uint32_t   (*get_remaining_cycles_func)(void*);
typedef void            (*add_cycles_func)(void*, std::uint32_t);

typedef std::uint32_t            (*cp_read_func)(void*, std::uint32_t);
typedef void                     (*cp_write_func)(void*, std::uint32_t, std::uint32_t);

typedef void                     (*dummy_func)(void*);
typedef read_mem32_func            read_code32_func;

struct location_descriptor
{
    address         pc;
    std::uint32_t   cpsr;
    std::uint32_t   fpcsr;

    location_descriptor advance(int amount)
    {
        return location_descriptor{ pc + amount, cpsr, fpcsr };
    }
};

struct jit_callback
{
    void                   *userdata;

    read_mem8_func          read_mem8;
    read_mem16_func         read_mem16;
    read_mem32_func         read_mem32;
    
    write_mem8_func         write_mem8;
    write_mem16_func        write_mem16;
    write_mem32_func        write_mem32;

    // Called when translating instructions, will fallback to read_mem32
    // if this is not supply
    read_code32_func        read_code32;

    cp_read_func            cp_read;
    cp_write_func           cp_write;

    get_remaining_cycles_func   get_remaining_cycles;
    add_cycles_func             add_cycles;

    dummy_func                  dummy;
};

typedef code_ptr     (*get_next_block_addr_func)(void*);

struct jit_runtime_callback
{
    void    *userdata;

    get_next_block_addr_func    get_next_block_addr;
};

struct arm_recompile_block;
struct arm_analyst;

// Usuable regs: r0 -> r9, r12

struct arm_register_allocator
{
private:
    struct arm_host_reg_info
    {
        bool mapped = false;
        ArmGen::ARMReg mapped_reg = ArmGen::INVALID_REG;
    };

    struct arm_guest_reg_info
    {
        bool spilllock = false;
        ArmGen::ARMReg host_reg = ArmGen::INVALID_REG;
    };

    std::array<arm_host_reg_info, 16> host_map_regs;
    std::array<arm_guest_reg_info, 16> guest_map_regs;

    arm_analyst *analyst;

    bool allocate_free_spot(arm_recompile_block *block, ArmGen::ARMReg guest_reg, ArmGen::ARMReg &result);

    bool  find_best_to_spill(bool unused_only, address addr, bool thumb, ArmGen::ARMReg &result
        , bool *clobbered);

public:
    explicit arm_register_allocator(arm_analyst *analyst);

    ArmGen::ARMReg  map_reg(arm_recompile_block *block, 
        ArmGen::ARMReg guest_reg, address addr, bool thumb);

    /*! \brief Flush all registers to the host state.
     *         Also reset all the mapped registers
     *
    */
    void flush_all(arm_recompile_block *block);

    void discard_reg(ArmGen::ARMReg guest_reg);

    void flush_reg(arm_recompile_block *block, ArmGen::ARMReg guest_reg);

    void spill_lock(ArmGen::ARMReg guest_reg);
    void release_spill_lock(ArmGen::ARMReg guest_reg);

    void release_all_spill_lock();
};

#pragma region ANALYST

enum arm_reg_usage
{
    usage_unknown,
    usage_input,
    usage_clobbered
};

struct arm_analyst
{
private:
    csh         handle;
    cs_insn    *insn;

    jit_callback callback;

    void init();

public:
    explicit arm_analyst(jit_callback &callback);

    cs_insn *disassemble_instructions(const address addr, bool thumb);
    arm_reg_usage   analysis_usage_reg(ArmGen::ARMReg reg, const address addr,
        const std::size_t insts, bool thumb);

    bool is_reg_clobbered(ArmGen::ARMReg reg, const address addr,
        const std::size_t insts, bool thumb);
    bool is_reg_used(ArmGen::ARMReg reg, const address addr,
        const std::size_t insts, bool thumb);
};

#pragma endregion

#pragma region INSTRUCTION_VISITOR
struct arm_recompile_block;
struct arm_recompiler;

struct arm_instruction_visitor
{
private:
    std::uint32_t   cycles_count;
    std::uint32_t   cycles_count_since_last_cond;

    location_descriptor loc;

    bool                t_reg;

    csh                 handler;
    cs_insn            *insn;
    jit_callback        callback;

    arm_analyst        *analyst;

    std::uint16_t op_counter = 0;

    bool should_break = true;
    bool cpsr_write = false;

public:
    bool is_thumb() const
    {
        return t_reg;
    }

    cs_insn &get_current_instruction()
    {
        return *insn;
    }

    location_descriptor &get_location_descriptor()
    {
        return loc;
    }

    void init();

    ArmGen::ARMReg get_next_reg_from_cs(cs_arm *arm, bool increase = true);
    ArmGen::Operand2 get_next_op_from_cs(cs_arm *arm, bool increase = true);

    void recompile_single_instruction(arm_recompiler *recompiler);
    void recompile(arm_recompiler *recompiler);
    
    explicit arm_instruction_visitor(
        arm_analyst *analyst, jit_callback callback, address pc);

    void set_pc(address pc)
    {
        loc.pc = (pc & 1) ? pc - 1 : pc;
        t_reg = (pc & 1) ? true : false;
    }

    std::uint32_t &get_cycles_count()
    {
        return cycles_count;
    }

    std::uint32_t &get_cycles_count_since_last_cond()
    {
        return cycles_count_since_last_cond;
    }

    std::uint32_t get_current_visiting_pc() const
    {
        return loc.pc;
    }
};
#pragma endregion

struct jit_state 
{
    std::uint32_t cycles_to_run;
    std::uint32_t cycles_left;

    bool          should_stop;

    std::uint32_t           regs[16];
    std::uint32_t           cpsr;
    std::uint32_t           fiq[8];
    std::uint32_t           svc[3];
    std::uint32_t           abt[3];
    std::uint32_t           irq[3];
    std::uint32_t           und[3];
};

struct jit_state_information
{
    std::size_t offset_cycles_to_run;
    std::size_t offset_cycles_left;
    std::size_t offset_reg;

    explicit jit_state_information(jit_state &state)
        : offset_cycles_to_run(offsetof(jit_state, cycles_to_run)),
          offset_cycles_left(offsetof(jit_state, cycles_left)),
          offset_reg(offsetof(jit_state, regs))
    {

    }
};

struct arm_recompile_block : public ArmGen::ARMXCodeBlock
{
private:
    friend class arm_recompiler;

    location_descriptor      descriptor;
    std::uint32_t            orginal_size;

    jit_runtime_callback     jit_rt_callback;
    jit_callback             callback;

    jit_state_information     jsi;

    typedef void (*run_code_func)(void*);
    run_code_func     run_code;

public:
    explicit arm_recompile_block(jit_state &state, jit_callback &cb, jit_runtime_callback &rt_cb
        , bool gen_right_away = false)
        : jsi(state), callback(cb), jit_rt_callback(rt_cb)
    {
        AllocCodeSpace(35000);

        if (gen_right_away)
        {
            gen_run_code();
        }
    }

    void set_runtime_callback(jit_runtime_callback &cb)
    {
        jit_rt_callback = cb;
    }

    void gen_run_code();

    void ARMABI_call_function(void *func);
    void ARMABI_call_function_c(void *func, std::uint32_t arg1);
    void ARMABI_call_function_cc(void *func, std::uint32_t arg1, std::uint32_t arg2);

    void ARMABI_call_function_c_promise_ret(void *func, std::uint32_t arg1);

    void ARMABI_save_all_registers();
    void ARMABI_load_all_registers();

    template <typename T>
    T get_func_as()
    {
        return reinterpret_cast<T>(AlignCodePage());
    }

    void do_run_code(void *jit_state)
    {
        run_code(jit_state);
    }
};

struct block_descriptor
{
    location_descriptor begin;
    location_descriptor end;

    code_ptr            entry_point;
    std::size_t         size;
};

// Mapped registers:
// r0-r9 used as default on ARM
// r11 for stack pointer
// r10 for JIT information pointer
// cpsr is reused
struct arm_recompiler
{
    arm_recompile_block      *block;
    jit_callback             callback;

    arm_analyst              *analyst;
    arm_register_allocator    allocator;
    arm_instruction_visitor   visitor;

    std::unordered_map<address, block_descriptor> blocks;

    block_descriptor get_next_block(location_descriptor descriptor);

    void set_active_block(arm_recompile_block &new_block)
    {
        block = &new_block;
    }

    explicit arm_recompiler(arm_analyst *analyst, jit_callback callback, arm_recompile_block &block);

    std::uint8_t  *b_addr;

    ArmGen::ARMReg remap_arm_reg(ArmGen::ARMReg reg);
    ArmGen::Operand2 remap_operand2(ArmGen::Operand2 op);

    void begin_valid_condition_block(CCFlags cond);
    void end_valid_condition_block(CCFlags cond);

    void gen_block_link();

    void gen_arm32_b(CCFlags flag, ArmGen::Operand2 op);
    void gen_arm32_bl(CCFlags flag, ArmGen::Operand2 op);

    void begin_gen_cpsr_update();
    void end_gen_cpsr_update();

    void save_pc_from_visitor();

    void set_pc(ArmGen::ARMReg reg);
    void set_pc(const std::uint32_t off);

    void gen_cpsr_update_c_flag();
    void gen_cpsr_update_z_flag();
    void gen_cpsr_update_n_flag();
    void gen_cpsr_update_v_flag();

    void gen_arm32_mov(ArmGen::ARMReg reg, ArmGen::Operand2 op);
    void gen_arm32_mvn(ArmGen::ARMReg reg, ArmGen::Operand2 op);
    void gen_arm32_tst(ArmGen::ARMReg reg, ArmGen::Operand2 op);
    void gen_arm32_teq(ArmGen::ARMReg reg, ArmGen::Operand2 op);
    void gen_arm32_add(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 op);
    void gen_arm32_sub(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 op);
    void gen_arm32_cmp(ArmGen::ARMReg reg1, ArmGen::Operand2 op);
    void gen_arm32_cmn(ArmGen::ARMReg reg1, ArmGen::Operand2 op);

    // R15 can't be used
    void gen_arm32_mul(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::ARMReg reg3);

    // TODO: gen MLA + MLS
    void gen_arm32_umull(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::ARMReg reg3, ArmGen::ARMReg reg4);
    void gen_arm32_umulal(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::ARMReg reg3, ArmGen::ARMReg reg);
    void gen_arm32_smull(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::ARMReg reg3, ArmGen::ARMReg reg4);
    void gen_arm32_smlal(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::ARMReg reg3, ArmGen::ARMReg reg4);

    void gen_arm32_str(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 base, bool subtract = false, 
        bool write_back = false, bool post_index = false);
    void gen_arm32_ldr(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 op, bool subtract = false,
        bool write_back = false, bool post_index = false);
    
    void gen_arm32_strb(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 base, bool subtract = false, 
        bool write_back = false, bool post_index = false);
    void gen_arm32_ldrb(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 op, bool subtract = false, 
        bool write_back = false, bool post_index = false);
    
    void gen_arm32_strh(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 base, bool subtract = false,
        bool write_back = false, bool post_index = false);

    void gen_arm32_ldrh(ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 base, bool subtract = false, 
        bool write_back = false, bool post_index = false);

    void gen_memory_write(void *func, ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 base, bool subtract = false,
        bool write_back = false, bool is_post_index = false);
    void gen_memory_read(void *func, ArmGen::ARMReg reg1, ArmGen::ARMReg reg2, ArmGen::Operand2 base, bool subtract = false,
        bool write_back = false, bool is_post_index = false);

    void flush();

    block_descriptor recompile(address addr);
};

struct jit
{
public:
    jit_callback            callback;
    jit_runtime_callback    runtime_callback;

    arm_recompiler          recompiler;
    arm_recompile_block     block;

    arm_analyst             analyst;
    jit_state               state;

    static code_ptr get_next_block_addr(void *userdata);

    explicit jit(jit_callback callback);

    void execute();
    bool stop();
    void reset();
};

}