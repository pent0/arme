#include "Runner.h"
#include <catch.hpp>
 
TEST_CASE("Simple CPSR check", "COND")
{
    Reset();
    cbd.ticks_left = 2;

    jit->state.regs[15] = 1020;
    jit->state.regs[14] = 1020;
    jit->state.regs[13] = 124;

    jit->state.regs[0] = 120;

    write_memory32(&cbd, 1020, 0xE2400078);     // SUB R0, R0, 120
    write_memory32(&cbd, 1024, 0xE3500000);     // CMP R0, 0
    write_memory32(&cbd, 1028, 0xE12FFF1E);     // BX LR

    jit->execute();

    auto zero_set = jit->state.cpsr & (1 << 30);

    REQUIRE(zero_set);
}

TEST_CASE("Add if negative condition", "COND")
{
    Reset();
    cbd.ticks_left = 3;

    jit->state.regs[15] = 1020;
    jit->state.regs[14] = 1020;
    jit->state.regs[13] = 124;

    jit->state.regs[0] = 120;

    write_memory32(&cbd, 1020, 0xE2400078);     // SUB R0, R0, 120
    write_memory32(&cbd, 1028, 0xE3500000);     // CMP R0, 0
    write_memory32(&cbd, 1032, 0x02800064);     // ADDEQ R0, R0, #100
    write_memory32(&cbd, 1036, 0xE12FFF1E);     // BX LR

    jit->execute();

    REQUIRE(jit->state.regs[0] == 100);
}

TEST_CASE("Normal sub and add if less than", "COND")
{
    Reset();
    cbd.ticks_left = 3;

    jit->state.regs[15] = 1020;
    jit->state.regs[14] = 1020;
    jit->state.regs[13] = 124;

    jit->state.regs[0] = 120;

    write_memory32(&cbd, 1020, 0xE3500090);     // CMP R0, #144
    write_memory32(&cbd, 1028, 0xC2800078);     // ADDGT r0, r0, #120
    write_memory32(&cbd, 1032, 0xB280000A);     // ADDLT R0, R0, #10
    write_memory32(&cbd, 1036, 0xE2400032);     // SUB R0, R0, #50
    write_memory32(&cbd, 1040, 0xE12FFF1E);     // BX LR

    jit->execute();

    int a = 5;

    REQUIRE(jit->state.regs[0] == 80);
}