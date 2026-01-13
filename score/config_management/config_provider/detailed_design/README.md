# Detailed Design of ConfigProvider Library

This document describes the design of the `ConfigProvider library`.

## Static Representation

The following diagram depicts the relationship between the classes that are used in the config provider library.
![config provider library classes](https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/swh/safe-posix-platform/score/config_management/ConfigProvider/detailed_design/assets/generated/config_library_static_architecture.puml)

## Parameter Access

Main purpose of `ConfigProvider library` is to expose `Parameter Set`s to user application and provide an access to `Parameter` as typed value. Following diagram gives a static view on ownership and access to parameters.

<details>
<summary>Click to expand Parameter Set static description</summary>

![Parameter Set static description](https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/swh/safe-posix-platform/score/config_management/ConfigProvider/detailed_design/assets/generated/config_library_static_architecture.puml)

</details>

Following sequence diagram describes the principle of `GetParameterAs()` method of `ParameterSet` class to access a typed value of a parameter by its name.

![GetParameterAs sequence diagram](https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/swh/safe-posix-platform/score/config_management/ConfigProvider/detailed_design/assets/parameter_set_sequence_diagram.puml)

The activity diagram below is related to handling of parameters given as 1D and 2D arrays.

<details>
<summary>Click to expand array activity</summary>

![Array activity diagram](https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/swh/safe-posix-platform/score/config_management/ConfigProvider/detailed_design/assets/process_array_activity_diagram.uxf)

</details>

## Communication Pattern for ParameterSet Updates

Due to performance optimization policy, the ConfigProvider lib will internally use polling as communication pattern for its `mw::com` events. The lib does not set any runtime processing mode for event or polling usage explicitly, but it performs polling by utilizing the respective AUTOSAR APIs. These are available both in case the `mw::com` runtime processing mode is set to polling or event-driven mode. This means that no usage of a `SetReceiveHandler()` takes place internally.

The ConfigProvider lib creates an additional thread for its polling action `LastUpdatedParameterSetHandler()`. Such one is either triggered by users via method `CheckParameterSetUpdates()` or by the ConfigProvider lib itself with a predefined frequency as default. In that scope, user applications are still required to perform the polling of the `mw::com` runtime themselves (cf. `mw::com::runtime::ProcessPolling()`) in a frequency satisfying their own particular needs. User applications are also expected to provide the size of any receive queue needed for the processing of events.

A communication lifecycle may consist of three logical phases: "Startup", "Get cached parameters" and "Get updated parameters".

The "Startup" phase includes instantiation of a proxy for `InternalConfigProvider` service by means of `Create()` and an asynchronous user notification upon service found via `IsAvailableNotificationCallback()`. Polling for parameter updates may start by invoking `CheckParameterSetUpdates()` after having received the service availability notification.
As no parameter values are available initially, they have to be queried first using the `GetParameterSet()` or `GetParameterSetsByNameList()` method. A `GetInitialQualifierState()` call will provide the overall state of coding parameters. To receive any updates of a `ParameterSet` during the lifecycle, a callback can be registered using `OnChangedParameterSet()` method.

During the "Get cached parameters" phase, a previously cached `ParameterSet` can be queired using the `GetParameterSet()` method at any time. A ParameterSet is cached during execution of `GetParameterSet()` or `GetParameterSetsByNameList()` in case the cache was empty or upon `CheckParameterSetUpdates()` in case any updates have been received.

"Get updated parameters" phase includes a query for `ParameterSet` updates initiated by `CheckParameterSetUpdates()`. If any updates of a `ParameterSet` got reported, the updated values will be queried and cached. Subsequently, a callbacks for updated `ParameterSet`s (if registered beforehand) will be invoked to notify the user about the new parameter values.

The following diagram displays the description above.

![Polling mode support](https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/swh/safe-posix-platform/score/config_management/ConfigProvider/detailed_design/assets/polling_mode.uxf)

## Persistent Parameter Cache

For current moment Persistent Parameter Cache can't be used as there are no implementation for data storage.

## External dependencies

|Dependency|Type|Components|Purpose|
|----------|----|----------|-------|
|//score/config_management/config_daemon/code/data_model:parameter_set_qualifier|Static library|//score/config_management/ConfigProvider/code/parameter_set:parameter_set|Qualification of parameters|
|//platform/aas/mw/log:log|Static library|multiple|Logging framework|
|//platform/aas/mw/service|Static library|multiple|Framework for handling mw::com service discovery|
|//platform/aas/mw/storage/key_value_storage|Optional static library|multiple|Wrapper around mw::per KVS used to persists cached parameter sets|
|@score_baselibs//score/json:json|Static library|multiple|Framework allowing to use json parser and to perform various attribute parsing and writing operations|
|@score_baselibs//score/result:result|Static library|multiple|Enhance error handling with [result type](https://en.wikipedia.org/wiki/Result_type)|
|@score_baselibs//score/concurrency:interruptible_wait|Static library|WaitForWrapperImpl class|Used to conditionally waits for stop_requested on token stop_source or expired timeout|
|@amp//:amp|Static library|Multiple class|AMP extends the C++ Standard Library with modules that are not included in the C++ Standard Library or cannot be used due to embedded restrictions|
|@score_baselibs//score/concurrency:condition_variable|Static library|//score/config_management/ConfigProvider/code/proxies/details:internal_config_provider_impl_mw_com|This library is used as an extension of std::condition_variable_any with support to get woken up via score::cpp::stop_token. [Refer InterruptibleConditionalVariableBasic for more info](broken_link_g/swh/ddad_platform/blob/master/aas/lib/concurrency/condition_variable.h)|
