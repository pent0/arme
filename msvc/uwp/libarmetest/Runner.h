#pragma once

#include <Arme/Arme.h>
#include <array>

struct callback_data
{
    std::array<std::uint8_t, 4096> memory;
    std::size_t                    ticks_left;
};

extern std::unique_ptr<arme::jit> jit;
extern callback_data              cbd;

void InitTestings();
int RunTests();
void Reset();

static void dummy(void *userdata)
{
    int a = 5;
}

static void write_memory8(void *userdata, arme::address addr, std::uint8_t w)
{
    callback_data *data = reinterpret_cast<callback_data*>(userdata);
    data->memory[addr] = w;
}

static void write_memory16(void *userdata, arme::address addr, std::uint16_t w)
{
    callback_data *data = reinterpret_cast<callback_data*>(userdata);
    *reinterpret_cast<std::uint16_t*>(&(data->memory[addr])) = w;
}

static void write_memory32(void *userdata, arme::address addr, std::uint32_t w)
{
    callback_data *data = reinterpret_cast<callback_data*>(userdata);
    *reinterpret_cast<std::uint32_t*>(&(data->memory[addr])) = w;
}

static std::uint8_t read_memory8(void *userdata, arme::address addr)
{
    callback_data *data = reinterpret_cast<callback_data*>(userdata);
    return data->memory[addr];
}

static std::uint16_t read_memory16(void *userdata, arme::address addr)
{
    callback_data *data = reinterpret_cast<callback_data*>(userdata);
    return *reinterpret_cast<std::uint16_t*>(&(data->memory[addr]));
}

static std::uint32_t read_memory32(void *userdata, arme::address addr)
{
    callback_data *data = reinterpret_cast<callback_data*>(userdata);
    return *reinterpret_cast<std::uint32_t*>(&(data->memory[addr]));
}

static void add_ticks(void *userdata, std::uint32_t ticks)
{
    callback_data *data = reinterpret_cast<callback_data*>(userdata);

    if (ticks > data->ticks_left) {
        data->ticks_left = 0;
        return;
    }

    data->ticks_left -= ticks;
}

static std::uint32_t get_remaining_ticks(void *userdata)
{
    callback_data *data = reinterpret_cast<callback_data*>(userdata);
    return data->ticks_left;
}