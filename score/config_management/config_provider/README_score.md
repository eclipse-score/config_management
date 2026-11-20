# ConfigProvider

ConfigProvider is a library that offers an API to access parameter data stored in the ConfigDaemon app. To retrieve a parameter value, the user must know ParameterSet's name to which the parameter belongs and its respective type.

## How to use

Below you will see description and short snippet showing how to use the ConfigProvider library. If it's not working please take a look at unit_test and sctf tests, they should be alwways up to date.

### Creation of ConfigProvider

Create a `ConfigProvider` with either `ConfigProviderFactory` or `ConfigProviderBuilder`. The factory remains available for existing callers. The builder provides a fluent alternative for new code.

#### ConfigProviderFactory

Existing applications can continue to create a `ConfigProvider` with `ConfigProviderFactory::Create()`. For example:

```c++
#include "score/config_management/config_provider/code/config_provider/factory/factory_socal_r20_11.h"

score::config_management::config_provider::ConfigProviderFactory config_provider_factory;
auto config_provider = config_provider_factory.Create<Port>(
    {}, std::chrono::milliseconds(0U), score::cpp::pmr::get_default_resource());
```

#### ConfigProviderBuilder

Production code can instantiate `ConfigProviderBuilderImpl<Port>` from `score/config_management/config_provider/code/config_provider/builder/details/config_provider_builder_impl.h`, where `Port` is the application's generated `InternalConfigProvider` service port type. Each builder can build one `ConfigProvider`. `Build(token)` returns an `score::cpp::pmr::unique_ptr<ConfigProvider>`.

- `WithConnectionTimeout(timeout)`
- `WithMemoryResource(memory_resource)`
- `WithAvailabilityNotificationCallback(callback)`
- `WithMaxSamplesLimit(max_samples_limit)`
- `WithPollingCycleInterval(polling_cycle_interval)`
- `WithRequiredParameterSets(names)`
- `Build(token)`

Where:

- token: stop token provided by user.
- timeout: maximum time in milliseconds that `Build()` waits for the ConfigProvider service to connect. Service discovery continues after this timeout. Set it to 0 to return without waiting.
- memory_resource: `score::pmr::memory_resource*` provided by the user.
- callback: will be called when the ConfigProvider service is created and becomes available.
- max_samples_limit: Maximum number of ParameterSets which can be retrieved from `ConfigDaemon` during one cycle of PollingRoutine.
- polling_cycle_interval: Time interval between PollingRoutine cycles in milliseconds.

Example:

```c++
#include "score/config_management/config_provider/code/config_provider/builder/details/config_provider_builder_impl.h"

score::config_management::config_provider::ConfigProviderBuilderImpl<Port> config_provider_builder;
bool callback_is_called_upon_found{false};
AvailabilityNotificationCallback callback{
    [&callback_is_called_upon_found]() noexcept { callback_is_called_upon_found = true; }};
auto config_provider = config_provider_builder.WithConnectionTimeout(std::chrono::milliseconds(0U))
                           .WithMemoryResource(score::cpp::pmr::get_default_resource())
                           .WithAvailabilityNotificationCallback(std::move(callback))
                           .Build({});
```

### Buffer size allocation

`GetParameterSet` is a semi-dynamic mw::com method (see the [design rationale](detailed_design/design_rational_of_migration_to_mw_com_ipc.md)). Its shared memory pool must hold the requested ParameterSet name and the returned payload, and the pool size is fixed when the proxy is created. The factory therefore reads `buffer_size_report.json` and sizes the pool as follows.

- The payload size is the largest buffer size among the ParameterSets in `initial_parameter_set_name_list`. It is never smaller than `kMinParameterSetContentBufferSize`.
- The name size is the longest name in `initial_parameter_set_name_list`.
- One extra byte is added for each of the two as a null terminator budget.

If `initial_parameter_set_name_list` is not provided (deprecated overloads), every ParameterSet in the report is considered.

The report is produced by the [buffer_size_calculator](../tools/buffer_size_calculator/README.md) and deployed with the ConfigDaemon config files to `/platform/opt/ConfigDaemon/etc/buffer_size_report.json` (`kDefaultBufferSizeReportPath`).

Error handling:

- A name in `initial_parameter_set_name_list` without an entry in the report is logged and ignored.
- If the report is missing or malformed, the error is logged and ConfigProvider still starts with the minimum payload size and a name size of 0. In this case `GetParameterSet` fails for each call, so the report must be present in production.

### InitialQualifierState

To find out the value of InitialQualifierState can be used:

- ConfigProvider::GetInitialQualifierState(timeout): This method tries to get the InitialQualifierState from the ConfigDaemon through the InternalConfigProvider interface. If the service is not available, it will return the 'undefined' state directly. Otherwise, it will request and wait for a valid InitialQualifierState from the ConfigDaemon. This method accepts an optional argument, `timeout`, that adjusts the maximum time it will wait. The default maximum wait time is one second. Also as soon as the service becomes available, ConfigProvider tries to get the InitialQualifierState from the ConfigDaemon in advance, to provide this information faster for any future ConfigProvider::GetInitialQualifierState(timeout) requests.

Example:

```c++
auto initial_qualifier_state = config_provider->GetInitialQualifierState(std::chrono::milliseconds{1000});
```

NOTE: Callback method is not supported for InitialQualifierState.

### IsAvailableNotification callback

Calling this callback indicates that the `InternalConfigProvider` service got found, the subscription to `LastUpdatedParameterSet` was successful and that ParameterSets can be accessed from now on.

### ParameterSet Callback Registration

To get/subcribe ParameterSet can be used:

- `ConfigProvider::GetParameterSet(set_name, timeout)`:  This method tries to get ParameterSet from ConfigDaemon through the InternalConfigProvider interface. If the service is not available, it will return an error directly. Otherwise, it will request and wait for the ParameterSet from the ConfigDaemon. This method accepts an optional argument, `timeout`, that adjusts the maximum time it will wait. The default maximum wait time is one second.

- `ConfigProvider::OnChangedParameterSet(set_name, callback)`: This method will set a callback for the ParameterSet named `set_name`.
  This means that `callback` will be called when the ParameterSet with name `set_name` is changed.

Example:

```c++
auto parameter_set_result = config_provider->GetParameterSet("set_name", std::chrono::milliseconds{1000});
if (parameter_set_result.has_value())
{
    auto parameter_set = parameter_set_result.value();
    auto subscription_result = config_provider->OnChangedParameterSet(
        "set_name",
        [&parameter_set](std::shared_ptr<const ParameterSet> value) noexcept
    {
        parameter_set = value;
    });
}
else
{
    // LOG_ERROR;
}
```

### Tests

- Unit
  - Path:
    - `score/config_management/config_provider/code/config_provider/details/config_provider_impl_test.cpp`
    - `score/config_management/config_provider/code/config_provider/factory/factory_mw_com_test.cpp`
    - `score/config_management/config_provider/code/config_provider/factory/buffer_size_report_test.cpp`
    - `score/config_management/config_provider/code/config_provider/factory/semi_dynamic_single_instantiation_strategy_test.cpp`
    - `score/config_management/config_provider/code/parameter_set/parameter_set_test.cpp`
    - `score/config_management/config_provider/code/proxies/details/internal_config_provider_impl_test.cpp`
  - Cmd: `bazel test //score/config_management/config_provider:unit_tests_host`

#### Bazel

On your target add the following dependencies.\
`"//score/config_management/config_provider"`\
For unit tests of your own code, use `"//score/config_management/config_provider:config_provider_factory_for_unit_test"` to inject a fake discovery strategy without a mw::com runtime.

ConfigProvider visibility is:
 `"//visibility:public",`

### Testing

We provide a mock class it generates dummy data automatically. Below you can find an example on how to use it.

#### Bazel

Add the following target to your unit_test: `"score/config_management/config_provider/code/config_provider:config_provider_mock"`.

Visibility for the target is: `"//visibility:public",`.
