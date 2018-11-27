//
// App.xaml.cpp
// Implementation of the App class.
//

#include "pch.h"
#include "MainPage.xaml.h"

#include <Arme/Arme.h>

using namespace uwp;

using namespace Platform;
using namespace Windows::ApplicationModel;
using namespace Windows::ApplicationModel::Activation;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Interop;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;

/// <summary>
/// Initializes the singleton application object.  This is the first line of authored code
/// executed, and as such is the logical equivalent of main() or WinMain().
/// </summary>
App::App()
{
    InitializeComponent();
    Suspending += ref new SuspendingEventHandler(this, &App::OnSuspending);
}

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

static void dummy(void *userdata)
{
    arme::jit_state *data = reinterpret_cast<arme::jit_state*>(userdata);
    int a = 5;
}

/// <summary>
/// Invoked when the application is launched normally by the end user.  Other entry points
/// will be used such as when the application is launched to open a specific file.
/// </summary>
/// <param name="e">Details about the launch request and process.</param>
void App::OnLaunched(Windows::ApplicationModel::Activation::LaunchActivatedEventArgs^ e)
{
    auto rootFrame = dynamic_cast<Frame^>(Window::Current->Content);

    // Do not repeat app initialization when the Window already has content,
    // just ensure that the window is active
    if (rootFrame == nullptr)
    {
        // Create a Frame to act as the navigation context and associate it with
        // a SuspensionManager key
        rootFrame = ref new Frame();

        rootFrame->NavigationFailed += ref new Windows::UI::Xaml::Navigation::NavigationFailedEventHandler(this, &App::OnNavigationFailed);

        if (e->PreviousExecutionState == ApplicationExecutionState::Terminated)
        {
            // TODO: Restore the saved session state only when appropriate, scheduling the
            // final launch steps after the restore is complete

        }

        if (e->PrelaunchActivated == false)
        {
            if (rootFrame->Content == nullptr)
            {
                // When the navigation stack isn't restored navigate to the first page,
                // configuring the new page by passing required information as a navigation
                // parameter
                rootFrame->Navigate(TypeName(MainPage::typeid), e->Arguments);
            }
            // Place the frame in the current Window
            Window::Current->Content = rootFrame;
            // Ensure the current window is active
            Window::Current->Activate();
        }
    }
    else
    {
        if (e->PrelaunchActivated == false)
        {
            if (rootFrame->Content == nullptr)
            {
                // When the navigation stack isn't restored navigate to the first page,
                // configuring the new page by passing required information as a navigation
                // parameter
                rootFrame->Navigate(TypeName(MainPage::typeid), e->Arguments);
            }
            // Ensure the current window is active
            Window::Current->Activate();
        }
    }

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
    callback.dummy = dummy;

    cbd.ticks_left = 2;

    arme::jit dejit{ callback };
    dejit.state.regs[15] = 0;
    dejit.state.regs[0] = 1;
    dejit.state.regs[1] = 2;
    dejit.state.regs[13] = 1016;

    write_memory32(&cbd, 1024, 25);

    write_memory32(&cbd, 0, 0xE0811000);    // ADD r0, r0, r1
    write_memory32(&cbd, 4, 0xE59D2008);    // LDR r2, [sp, #8]
    write_memory32(&cbd, 8, 0xEA000000);    // B +-0

    dejit.execute();

    assert((dejit.state.regs[0] == 3) && "Unexpected value");
}

/// <summary>
/// Invoked when application execution is being suspended.  Application state is saved
/// without knowing whether the application will be terminated or resumed with the contents
/// of memory still intact.
/// </summary>
/// <param name="sender">The source of the suspend request.</param>
/// <param name="e">Details about the suspend request.</param>
void App::OnSuspending(Object^ sender, SuspendingEventArgs^ e)
{
    (void) sender;  // Unused parameter
    (void) e;   // Unused parameter

    //TODO: Save application state and stop any background activity
}

/// <summary>
/// Invoked when Navigation to a certain page fails
/// </summary>
/// <param name="sender">The Frame which failed navigation</param>
/// <param name="e">Details about the navigation failure</param>
void App::OnNavigationFailed(Platform::Object ^sender, Windows::UI::Xaml::Navigation::NavigationFailedEventArgs ^e)
{
    throw ref new FailureException("Failed to load Page " + e->SourcePageType.Name);
}