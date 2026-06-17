# ConfigProvider

ConfigProvider is a library that offers an API to access parameter data stored in the ConfigDaemon app. To retrieve a parameter value, the user must know ParameterSet's name to which the parameter belongs and its respective type.

## How to use

Below you will see description and short snippet showing how to use the ConfigProvider library. If it's not working please take a look at unit_test and sctf tests, they should be alwways up to date.

### Creation of ConfigProvider

ConfigProvider instance can be instantiated by its own factory class located at `score/config_management/config_provider/code/config_provider/factory/factory_socal_r20_11.h` with
one of the following methods

- `ConfigProviderFactory::Create(token, timeout, memory_resource, callback)`
- `ConfigProviderFactory::Create(token, timeout, max_samples_limit, polling_cycle_interval, memory_resource, callback`

Where:

- token: stop token provided by user.
- timeout: represents the time delay in ms that factory will wait for ConfigProvider service to be discovered. The service discovery will continue automatically, if the service could not be discovered within given timeout. If no delay is needed this parameter should be set to 0.
- memory_resource: std::pmr::memory_resource provided by user.
- callback: will be called when the ConfigProvider service is created and becomes available.
- max_samples_limit: Maximum number of ParameterSets which can be retrieved from `ConfigDaemon` during one cycle of PollingRoutine.
- polling_cycle_interval: Time interval between PollingRoutine cycles in milliseconds.

Example:

```c++
score::config_management::config_provider::ConfigProviderFactory config_provider_factory;
bool callback_is_called_upon_found{false};
IsAvailableNotificationCallback callback{
    [&callback_is_called_upon_found]() noexcept { callback_is_called_upon_found = true; }};
auto config_provider = config_provider_factory.Create<Port>(
    {}, std::chrono::milliseconds(0U), score::cpp::pmr::get_default_resource(), std::move(callback));
```

### InitialQualifierState

To find out the value of InitialQualifierState can be used:

- ConfigProvider::GetInitialQualifierState(timeout): This method tries to get the InitialQualifierState from the ConfigDaemon through the InternalConfigProvider interface. If the service is not available, it will return the 'undefined' state directly. Otherwise, it will request and wait for a valid InitialQualifierState from the ConfigDaemon. This method accepts an optional argument, `timeout`, that adjusts the maximum time it will wait. The default maximum wait time is one second. Also as soon as the service becomes available, ConfigProvider tries to get the InitialQualifierState from the ConfigDaemon in advance, to provide this information faster for any future ConfigProvider::GetInitialQualifierState(timeout) requests.

Example:

```c++
auto initial_qualifier_state = config_provider.GetInitialQualifierState();
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
auto parameter_set_result = config_provider.GetParameterSet("set_name");
if (parameter_set_result.has_value())
{
    Result<std::shared_ptr<const ParameterSet>> parameter_set = parameter_set_result.value();
    bool subscription_result = config_provider.OnChangedParameterSet(
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
    - `score/config_management/config_provider/code/parameter_set/parameter_set_test.cpp`
    - `score/config_management/config_provider/code/proxies/details/mw_com/internal_config_provider_impl_test.cpp`
  - Cmd: `bazel test //score/config_management/config_provider:unit_tests_host`

#### Bazel

On your target add the following dependencies.\
`"//score/config_management/config_provider"`

ConfigProvider visibility is:
 `"//visibility:public",`

### Testing

We provide a mock class it generates dummy data automatically. Below you can find an example on how to use it.

#### Bazel

Add the following target to your unit_test: `"score/config_management/config_provider/code/config_provider:config_provider_mock"`.

Visibility for the target is: `"//visibility:public",`.
