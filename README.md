ARM2ARM recompiler for melonds

I work on this with my UWP port. Please try to compile Capstone with ARM only and as C++ code.
Incomplete instructions emitter, will work on soon, but Dynarmic example kinda works.

Small example that works:

```cpp
#include <Arme/Arme.h>

struct callback_data
{
    std::array<char, 2048> memory;
    std::uint32_t ticks_left;
};

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

int main()
{
    callback_data cbd;

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

    cbd.ticks_left = 1;

    arme::jit dejit{ callback };
    dejit.state.regs[15] = 0;
    dejit.state.regs[0] = 1;
    dejit.state.regs[1] = 2;

    write_memory32(&cbd, 0, 0xE0811000);    // ADD r0, r0, r1
    write_memory32(&cbd, 4, 0xEA000000);    // B +-0

    dejit.execute();

    assert((dejit.state.regs[0] == 3) && "Unexpected value");
}
```
