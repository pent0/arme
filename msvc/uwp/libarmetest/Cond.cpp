#include "Runner.h"
#include <catch.hpp>
 
TEST_CASE("Simple CPSR check", "COND")
{
    Reset();
    cbd.ticks_left = 2;

    jit->state.regs[15] = 1020;
    jit->state.regs[14] = 1048;
    jit->state.regs[13] = 124;

    jit->state.regs[0] = 120;

    write_memory32(&cbd, 1020, 0xE2400078);     // SUB R0, R0, 120
    write_memory32(&cbd, 1024, 0xE3500000);     // CMP R0, 0
    write_memory32(&cbd, 1028, 0xE12FFF1E);     // BX LR

    jit->execute();

    auto zero_set = jit->state.cpsr & (1 << 31);

    int a = 5;

    REQUIRE(zero_set);
}