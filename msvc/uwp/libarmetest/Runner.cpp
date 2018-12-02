#include "Runner.h"

#define CATCH_CONFIG_RUNNER
#include <catch.hpp>
#include <internal/catch_session.h>

std::unique_ptr<arme::jit> jit;
callback_data              cbd;

void InitTestings()
{
    arme::jit_callback callback;
    callback.write_mem16 = write_memory16;
    callback.write_mem32 = write_memory32;
    callback.write_mem8 = write_memory8;
    callback.read_mem16 = read_memory16;
    callback.read_mem32 = read_memory32;
    callback.read_mem8 = read_memory8;
    callback.userdata = &cbd;
    callback.add_cycles = add_ticks;
    callback.get_remaining_cycles = get_remaining_ticks;
    callback.read_code32 = nullptr;
    callback.dummy = dummy;

    jit = std::make_unique<arme::jit>(callback);
}

void Reset()
{
    jit->reset();
    std::fill(cbd.memory.begin(), cbd.memory.end(), 0);
    cbd.ticks_left = 0;
}

int RunTests()
{
    Catch::Session session;
    Catch::ConfigData config;

    config.showDurations = Catch::ShowDurations::Always;
    config.useColour = Catch::UseColour::No;
    config.outputFilename = "%debug";

    session.useConfigData(config);
    return session.run();
}