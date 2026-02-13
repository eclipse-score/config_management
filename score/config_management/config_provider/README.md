# ConfigProvider

ConfigProvider is a library that offers an API to access parameter data stored in the ConfigDaemon app. To retrieve a parameter value, the user must know ParameterSet's name to which the parameter belongs and its respective type.

## How to use

Below you will see description and short snippet showing how to use the ConfigProvider library. If it's not working please take a look at unit_test and sctf tests, they should be alwways up to date.

### Creation of ConfigProvider

ConfigProvider instance can be instantiated by its own factory class located at `score/config_management/ConfigProvider/code/config_provider/factory/factory_socal_r20_11.h` with
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

There are two additional methods `ConfigProviderFactory::Create(...)` that can be used if you need to enable the Persistent caching.
More details about these methods, as well as about the Persistent caching, can be found in the `Persistent caching mechanism` chapter.

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
In the case where persistent caching is enabled, this also indicates that the cached parameters already updated with the actual parameters from `ConfigDaemon`.

### ParameterSet Callback Registration

To get/subcribe ParameterSet can be used:

- `ConfigProvider::GetParameterSet(set_name, timeout)`:  This method tries to get ParameterSet. If persistent cache is enabled, ConfigProvider would first try to find ParameterSet from the cache. If the ParameterSet is not cached, ConfigProvider would try to get it from ConfigDaemon through the InternalConfigProvider interface. If the service is not available, it will return an error directly. Otherwise, it will request and wait for the ParameterSet from the ConfigDaemon. This method accepts an optional argument, `timeout`, that adjusts the maximum time it will wait. The default maximum wait time is one second.

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

### Get amount of cached parameter sets

In order to find out, how many parameter sets are currently cached in ConfigProvider's in-memory cache, we can use `GetCachedParameterSetsCount` method. This method is especially useful with [persistent caching](#persistent-caching-mechanism) enabled, when we need to know how many previously cached parameter sets were successfully loaded from the key-value storage managed by ConfigProvider.

```c++
std::cout << "Number of currently cached parameter sets: " << config_provider.GetCachedParameterSetsCount() << std::endl;
```

### Tests

- Unit
  - Path:
    - `score/config_management/ConfigProvider/code/config_provider/details/config_provider_impl_test.cpp`
    - `score/config_management/ConfigProvider/code/config_provider/factory/factory_mw_com_test.cpp`
    - `score/config_management/ConfigProvider/code/parameter_set/parameter_set_test.cpp`
    - `score/config_management/ConfigProvider/code/proxies/details/mw_com/internal_config_provider_impl_test.cpp.cpp`
  - Cmd: `bazel test --config=spp_memcheck //score/config_management/ConfigProvider:unit_tests_host`

#### Bazel

On your target add the following dependencies.\
`"//score/config_management/ConfigProvider:ConfigProvider"`

ConfigProvider visibility is:
 `"//visibility:public",`

### Persistent caching mechanism

Provides the ability to access parameter data before it is retrieved from the ConfigDaemon application.
This mechanism is optional. In order to use it, the client application must have KVS storage configured.

ParameterSets will be stored between lifecycles via persistent memory.
All ParameterSets obtained during the first run after flashing will be cached.
A ParameterSet obtained during the lifecycle will be cached if it is different from the existing one.

NOTE: Only a ParameterSet with qualifier equal to `ParameterSetQualifier::kQualified` will be cached.

Overview of persistent caching sequences can be found [here](https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/swh/safe-posix-score/config_management/ConfigProvider/detailed_design/persistent_cache.uxf)

#### Enable caching

To enable persistent caching, follow these steps:

Create instance of Persistency by its own factory class located at `score/config_management/ConfigProvider/code/persistency/factory/persistency_factory.h`
with method `PersistencyFactory::Create<KeyValueStorageType>(handle, memory_resource)`, where:

- KeyValueStorageType: in 99% it will be an `mw::per::KeyValueStorage`, but due to application-specific dependency it needs to be supplied on user side
- handle: a valid handle to mw::per::KeyValueStorage(return value of mw::per::OpenKeyValueStorage call)
- memory_resource: std::pmr::memory_resource provided by user.

Create instance of ConfigProvider by its own factory class located at `score/config_management/ConfigProvider/code/config_provider/factory/factory.h`
with one of the following methods:

- `ConfigProviderFactory::Create(token, persistency, memory_resource, callback)`
- `ConfigProviderFactory::Create(token, persistency, max_samples_limit, polling_cycle_interval, callback)`

Where:

- token: stop token provided by user.
- persistency: Persistency instance created via `PersistencyFactory::Create<KeyValueStorageType>(handle, memory_resource)` method.
- memory_resource: std::pmr::memory_resource provided by user.
- callback: will be called when the ConfigProvider service is created and becomes available.
- max_samples_limit: Maximum number of ParameterSets which can be retrieved from `ConfigDaemon` during one cycle of PollingRoutine.
- polling_cycle_interval: Time interval between PollingRoutine cycles in milliseconds.

Example:

```c++
    score::config_management::config_provider::PersistencyFactory persistency_factory;
    const auto kvs_is = ::mw::core::InstanceSpecifier{KeyValueStorageRPort};
    auto kvs_handle = ::mw::per::OpenKeyValueStorage(kvs_is);
    auto persistency = persistency_factory.Create<mw::per::KeyValueStorage>(
        kvs_handle, score::cpp::pmr::get_default_resource());

    score::config_management::config_provider::ConfigProviderFactory config_provider_factory;
    bool callback_is_called_upon_found{false};
    IsAvailableNotificationCallback callback{
        [&callback_is_called_upon_found]() noexcept { callback_is_called_upon_found = true; }};
    auto config_provider = config_provider_factory.Create<Port>(
        {}, std::move(persistency), score::cpp::pmr::get_default_resource(), std::move(callback));
```

#### ParameterSet Access

Cached parameter sets can be retrieved from a ConfigProvider instance as soon as it is created via `ConfigProviderFactory::Create(token, persistency, ...)` method.
During the execution of this method, all parameter sets that were stored in KVS will be loaded into the in-memory cache.

ParameterSet can be received from ConfigProvider by using the following methods:

- `ConfigProvider::GetParameterSet(set_name)`: This method tries to get a single ParameterSet. If persistent cache is enabled, ConfigProvider would first try to find ParameterSet from the cache. If the ParameterSet is not cached, ConfigProvider would try to get it from ConfigDaemon through the InternalConfigProvider interface. If the service is not available, it will return an error directly. Otherwise, it will request and wait for the ParameterSet from the ConfigDaemon. This method accepts an optional argument, `timeout`, that adjusts the maximum time it will wait. The default maximum wait time is one second.

- `ConfigProvider::GetParameterSetsByNameList(set_names, timeout)`: This method tries to get multiple ParameterSets by providing a list of ParameterSet names. It returns a map containing the requested ParameterSets that were successfully retrieved. The method accepts a vector of ParameterSet names and an optional timeout parameter. This is more efficient than calling `GetParameterSet` multiple times when you need several ParameterSets. This method accepts an optional argument, `timeout`, that adjusts the maximum time it will wait for each ParameterSet in the list. The default maximum wait time is one second.

The result of these calls will be:

- Cached ParameterSet(s) if the service is unavailable and ParameterSet data exists in KVS.
- Error, if the service is unavailable and ParameterSet data does not exist in KVS.
- Actual parameter set(s) if the service is available.

It is user's responsibility to evaluate `ParameterSetQualifier` of the requested `ParameterSet`.

Example for single ParameterSet:

```c++
auto parameter_set_result = config_provider.GetParameterSet("set_name");
if (parameter_set_result.has_value())
{
    Result<std::shared_ptr<const ParameterSet>> parameter_set = parameter_set_result.value();
    auto set_qualifier = parameter_set_result.value()->GetQualifier();
}
```
Example for multiple ParameterSets:

```c++
score::cpp::pmr::vector<score::cpp::string_view> set_names = {"set_name_1", "set_name_2", "set_name_3"};
auto parameter_sets_map = config_provider.GetParameterSetsByNameList(set_names, std::chrono::milliseconds(2000));

for (const auto& [set_name, parameter_set_result] : parameter_sets_map)
{
    if (parameter_set_result.has_value())
    {
        auto parameter_set = parameter_set_result.value();
        auto set_qualifier = parameter_set->GetQualifier();
        // Use the parameter set...
    }
    else
    {
        // Handle error for this specific parameter set
        // LOG_ERROR for set_name
    }
}
```

NOTE: All cached ParameterSets will be qualified with `ParameterSetQualifier::kUnqualified` until an update will be received from `ConfigDaemon`.

#### Testing

We provide a mock class it generates dummy data automatically. Below you can find an example on how to use it.

#### Bazel

Add the following target to your unit_test: `"score/config_management/ConfigProvider/code/config_provider:config_provider_mock",`.

Visibility for the target is: `"//visibility:public",`.
