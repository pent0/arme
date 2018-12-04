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

TEST_CASE("LDR with writeback (post and pre)", "ALU")
{
    Reset();

    cbd.ticks_left = 3;
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

TEST_CASE("STR register without writeback", "ALU")
{
    Reset();
    cbd.ticks_left = 2;

    jit->state.regs[15] = 1038;
    jit->state.regs[14] = 1038;
    jit->state.regs[4] = 96500;
    jit->state.regs[5] = 1054;

    write_memory32(&cbd, 1038, 0xE2844F7D);     // ADD R4, R4, 500
    write_memory32(&cbd, 1042, 0xE5854004);     // STR R4, [R5, #4]
    write_memory32(&cbd, 1046, 0xE12FFF1E);     // BX LR

    jit->execute();

    std::uint32_t result = read_memory32(&cbd, 1058);

    REQUIRE(result == 97000);
    REQUIRE(jit->state.regs[5] == 1054);
}

TEST_CASE("STR register with writeback", "ALU")
{
    Reset();
    cbd.ticks_left = 4;

    jit->state.regs[15] = 1038;
    jit->state.regs[14] = 1038;
    jit->state.regs[4] = 96500;
    jit->state.regs[5] = 1054;

    write_memory32(&cbd, 1038, 0xE2844F7D);     // ADD R4, R4, 500
    write_memory32(&cbd, 1042, 0xE5A54004);     // STR R4, [R5, #4]!
    write_memory32(&cbd, 1046, 0xE2444064);     // SUB R4, R4, 100
    write_memory32(&cbd, 1050, 0xE2855004);     // ADD R5, R5, #4
    write_memory32(&cbd, 1054, 0xE405400C);     // STR R4, [R5], #-12
    write_memory32(&cbd, 1058, 0xE12FFF1E);     // BX LR

    jit->execute();

    std::uint32_t result = read_memory32(&cbd, 1058);
    std::uint32_t result2 = read_memory32(&cbd, 1062);

    REQUIRE(result == 97000);
    REQUIRE(result2 == 96900);
    REQUIRE(jit->state.regs[5] == 1050);
}

TEST_CASE("STM/LDM (descending + FD)")
{
    Reset();
    cbd.ticks_left = 1;

    jit->state.regs[15] = 1024;
    jit->state.regs[14] = 1024;
    jit->state.regs[13] = 2040;

    write_memory32(&cbd, 2052, 156);
    write_memory32(&cbd, 2048, 12);
    write_memory32(&cbd, 2044, 2055);
    write_memory32(&cbd, 2040, 10424);

    write_memory32(&cbd, 1024, 0xE8BD000F);     // LDMFD SP!, { R0 - R3 }
    write_memory32(&cbd, 1028, 0xE12FFF1E);     // BX LR

    jit->execute();

    REQUIRE(jit->state.regs[0] == 10424);
    REQUIRE(jit->state.regs[1] == 2055);
    REQUIRE(jit->state.regs[2] == 12);
    REQUIRE(jit->state.regs[3] == 156);
    REQUIRE(jit->state.regs[13] == 2056);
}