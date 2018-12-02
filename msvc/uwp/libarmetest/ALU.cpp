#include <Arme/Arme.h>
#include <catch.hpp>

#include "Runner.h"

#include <memory>

TEST_CASE("LDR with PC", "ALU")
{
    Reset();

    cbd.ticks_left = 2;
    jit->state.regs[15] = 1024;
    jit->state.regs[14] = 1024;

    write_memory32(&cbd, 1040, 256);
    write_memory32(&cbd, 1044, 512);

    write_memory32(&cbd, 1024, 0xE59F0008);     // LDR R0, [PC, #8]
    write_memory32(&cbd, 1028, 0xE59F1008);     // LDR R1, [PC, #8]
    write_memory32(&cbd, 1032, 0xE12FFF1E);     // BX LR

    jit->execute();

    REQUIRE(jit->state.regs[0] == 256);
    REQUIRE(jit->state.regs[1] == 512);
}

TEST_CASE("LDR with PC to PC", "ALU")
{
    Reset();

    cbd.ticks_left = 5;
    jit->state.regs[15] = 1024;
    jit->state.regs[14] = 1028;

    write_memory32(&cbd, 1040, 1016);
    write_memory32(&cbd, 1044, 512);

    write_memory32(&cbd, 1016, 0xE3A07069);     // MOV r7, 105
    write_memory32(&cbd, 1020, 0xE12FFF1E);     // BX LR
    write_memory32(&cbd, 1024, 0xE59FF008);     // LDR PC, [PC, #8]
    write_memory32(&cbd, 1028, 0xE59F1008);     // LDR R1, [PC, #8]
    write_memory32(&cbd, 1032, 0xE12FFF1E);     // BX LR

    // Execute should be:
    // Load PC at address 1024 + 8 + 8 = 1040 <=> 1016
    // PC jumps to 1016, r7 = 105 and branch to 1028
    // R1 = 1028 + 8 + 8 = 512
    // End 5 ticks

    jit->execute();

    REQUIRE(jit->state.regs[7] == 105);
    REQUIRE(jit->state.regs[1] == 512);
}

TEST_CASE("LDR with writeback", "ALU")
{
    Reset();

    cbd.ticks_left = 2;
    jit->state.regs[15] = 1024;
    jit->state.regs[14] = 1024;
    jit->state.regs[6] = 2040;
    jit->state.regs[7] = 2;

    write_memory32(&cbd, 2048, 956);
    write_memory32(&cbd, 2052, 1024);
    write_memory32(&cbd, 1024, 0xE5B62008);     // LDR R2, [R6, #8]!
    write_memory32(&cbd, 1028, 0xE4163006);     // LDR R3, [R6], #-6
    write_memory32(&cbd, 1032, 0xE12FFF1E);     // BX LR

    jit->execute();

    REQUIRE(jit->state.regs[2] == 956);
    REQUIRE(jit->state.regs[3] == 956);
    REQUIRE(jit->state.regs[6] == 2042);
}

TEST_CASE("LDR register without writeback", "ALU")
{
    Reset();
    cbd.ticks_left = 2;

    jit->state.regs[15] = 1038;
    jit->state.regs[14] = 1038;
    jit->state.regs[4] = 1058;
    jit->state.regs[5] = 1054;

    write_memory32(&cbd, 1070, 9250);
    write_memory32(&cbd, 1038, 0xE594300C);     // LDR R3, [R4, #0xC]
    write_memory32(&cbd, 1042, 0xE5950010);     // LDR R0, [R5, #0x10]
    write_memory32(&cbd, 1046, 0xE12FFF1E);     // BX LR

    jit->state.cycles_left = 2;
    jit->execute();

    REQUIRE(jit->state.regs[0] == 9250);
    REQUIRE(jit->state.regs[3] == 9250);
    REQUIRE(jit->state.regs[5] == 1054);
}