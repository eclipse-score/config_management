# Detailed Design of Application ConfigDaemon

## Table of Contents
- [1. Introduction](#1-introduction)
- [2. Description of Interfaces](#2-description-of-interfaces)
  - [2.1 Application Interfaces](#21-application-interfaces)
  - [2.2 IInternalConfigProvider](#22-internalconfigprovider)
  - [2.3 ConfigCalibration](#23-configcalibration)
- [3. Application Design](#3-application-design)
  - [3.1. Parameter Data Model](#31-parameter-data-model)
  - [3.2 ConfigProvider Library](#32-configprovider-library)
- [4. Component Level Design](#4-component-level-design)
- [5. Data storage architecture](#5-data-storage-architecture)
- [6. Initialization Sequences](#6-initialization-sequences)
  - [6.1. Constructing and runtime interaction of the ConfigDaemon provided services](#61-constructing-and-runtime-interaction-of-the-configdaemon-provided-services)
- [7. InitialQualifierState](#7-initialqualifierstate)
  - [7.1. Relation of InitialQualifierState and Parameter Set Qualifier](#71-relation-of-initialqualifierstate-and-parameter-set-qualifier)
- [8. External dependencies](#8-external-dependencies)

## 1. Introduction

ConfigDaemon application implements a unified interface for parameter accesses by user applications.

<!-- [More about SCORE specific usage](./README_SCORE.md#1-introduction) -->

[Table of Contents](#table-of-contents)

## 2. Description of Interfaces

### 2.1 Application Interfaces

`ConfigDaemon` interacts with following applications according to the diagram below:

- `User Adaptive Application` to provide read access to parameter sets

<!-- [More about plugin specific interfaces](./README_SCORE.md#21-plugins-interfaces) -->

### 2.2 InternalConfigProvider

The interface `InternalConfigProvider` provides read access to parameter sets for a `User Adaptive Application` in a generic manner using a key-value principle with `parameter_set_name` as a key and `parameter_set` as a returned value.

See the [fidl](../adaptive_model/interfaces/InternalConfigProvider.fidl) file for the interface definition.

`ConfigDaemon` exposes it via mw::com. Therefore, a proxy will be generated on the application side. The handling of this proxy shall be abstracted by the `ConfigProvider` library, which is part of a `User Adaptive Application`. Thus, an original user functionality should not come in direct contact with `InternalConfigProvider`, making its eventual changes easier to rollout.

The class diagram below depict the relationship between the classes that are used in creating the `InternalConfigProvider` service:

<details>
<summary>Click to expand internal config provider service skeleton</summary>

<img alt="internal config provider service skeleton" src="https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/eclipse-score/baselibs/refs/heads/main/score/config_management/config_daemon/detailed_design/class_diagrams/generated/config_daemon_provided_services_class_diagram.puml">

</details>
<br>

<!-- [More about SCORE specific usage](./README_SCORE.md#22-internalconfigprovider) -->

### 2.3 ConfigCalibration

The interface `ConfigCalibration` provides write access to parameter sets for a `User Adaptive Application` in a generic manner using a key-value principle with `parameter_set_name` as a key and `parameter_set` as a value.

See the [fidl](../adaptive_model/interfaces/ConfigCalibration.fidl) file for the interface definition.

`ConfigDaemon` exposes it via mw::com. Therefore, a proxy will be generated on the application side.

The class diagram below depict the relationship between the classes that are used in creating the `ConfigCalibration` service:

<details>
<summary>Click to expand config calibration service skeleton</summary>

![config calibration service skeleton](https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/swh/safe-posix-platform/score/config_management/config_daemon/detailed_design/calibration/assets/calibration_plugin_class_diagram.uxf)

</details>
<br>


[Table of Contents](#table-of-contents)

## 3. Application Design

The `ConfigDaemon` application sets up a generic framework which can provide configuation data to `Adaptive Application`. As shown in the figure below, the application is responsible for:

- provision of a main function and integration into the middleware application lifecycle,
- instantiation of plugins,
- instantiation of data model as `ParameterSetCollection`,
- offering of the interface `InternalConfigProvider` for parameter access.

<details>
<summary>Click to expand CfgD static architecture</summary>

<img alt="ConfigDaemon application" src="https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/eclipse-score/baselibs/refs/heads/main/score/config_management/config_daemon/detailed_design/class_diagrams/generated/config_daemon_static_architecture.puml">

</details>
<br>

`ReadOnlyParameterSetCollection` is present as part of the interface of `IInternalConfigProvider`, offering notification registration support. `InternalConfigProvider` could gain an intelligence to decide which users are going to get notification support (user applications) and which not (tools).

<!-- [More about SCORE specific design](./README_SCORE.md#3-application-design) -->

### 3.1. Parameter Data Model

The diagram mentioned above contains a description for the parameter data model represented by the class `ParameterSetCollection`. In a nutshell `ParameterSetCollection` is a map of maps, meaning that it has a map of `ParameterSet`s accessible by their names as keys, being in their turn a map of `Parameter`s accessible by name as well. As container std::unordered_map type is preferred because the order of elements is not important and average constant-time complexity is acceptable, thus this saves resources skipping unnecessary sorting of a (sorted) map. The usage of a map as data model for all the parameters implies the uniqueness of names for `ParameterSet`s and `Parameter`s. For a name as key a polymorphic memory resource score::cpp::pmr::string is used for the case if a customer memory pool (typically with a deterministic memory control) for string objects exists.

<!-- [More about SCORE specific usage](./README_SCORE.md#31-parameter-data-model) -->

`ParameterSetCollection` is a class responsible for storing parameters sets and it's the only way of getting and manipulating them. It inherits `IReadOnlyParameterSetCollection` interface used by clients and `IParameterSetCollection` inteface used by the plugin. The class usage is thread-safe, as every public method is protected by a mutex.

Allowed operations on the `ParameterSetCollection` class:
* Inserting new parameter to the parameter set
* Inserting new parameter set
* Updating parameter in parameter set
* Reading whole parameter set as JSON string

Internally parameter set is represented as `ParameterSet` class, but it's not exposed as a public interface and is only supposed to exist inside the `ParameterSetCollection` class.

Parameter Data Model can sent errors as result of public methods which is described in `Error` class:
* kParameterMissedError - "Parameter Missed error"
* kConvertingError - "Converting error"
* kParsingError - "Parsing error"
* kParameterSetNotFound - "Parameter set not found"
* kParametersNotFound - "Parameters not found"
* kParentParameterDataNotfound - "Parent ParameterData not found"
* kParameterSetNotCalibratable - "Parameter Set is not calibratable"
* kParameterAlreadyExists - "Parameter with input name already exists"

### 3.2 ConfigProvider Library

A user application obtains a possibility to access parameters by invocation of a `ConfigProvider` library provided by `ConfigDaemon` as shown in the figure below. Its user facing part exposes a ParameterSet class with a public method GetParameterAs() to read a typed parameter as a part of a parameter set and a public method OnChange() for notifications on a related parameter set changed by `ConfigDaemon`.

A connection to ConfigDaemon is established by means of `IInternalConfigProvider` interface as mentioned [above](./README.md#22-internalconfigprovider).

<!-- [ConfigProvider Extended Details](./README_SCORE.md#34-configprovider-library) -->

[Table of Contents](#table-of-contents)

## 4. Component Level Design

The diagram below demonstrates the composition principle of `ConfigDaemon` and `User Adaptive Application`s. The entire communication path between the business logic using a parameter and a parameter stored is encapsulated by `ConfigDaemon` and `ConfigProvider` library. Thus, a user is not directly confronted with the kind of IPC implementation or parameter representation and handling by the interface `IInternalConfigProvider`.

<details>
<summary>Click to expand SW component view</summary>

<img alt="SW component view" src="https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/eclipse-score/baselibs/refs/heads/main/score/config_management/config_daemon/detailed_design/assets/component_view.puml">

</details>
<br>

[Table of Contents](#table-of-contents)

## 5. Data storage architecture

In `ConfigDaemon` a JSON format is used for the internal housekeeping of data.

The filesystem and JSON file handling tools are accessed via the `JsonHelper` class.

<!-- [More about SCORE specific usage](./README_SCORE.md#4-data-storage-architecture) -->

[Table of Contents](#table-of-contents)

## 6. Initialization Sequences

The following diagram represents the startup procedure for ConfigDaemon application and a user application consuming a parameter service. This design assumes a fixed order of application startup the way that ConfigDaemon application is always started prior to a user application. Doing so it is ensured that parameters are always available at the start of user application. It also implies the possibility to use a synchronous FindService() method for parameter service discovery.

As user applications' business logic is abstracted from the parameter subscription procedure by the `ConfigProvider` library, it might try to access a parameter value before subscription. In this case `GetParameterAs()` access method would not be able to provide a value. Therefore a business logic has to check the result of `GetParameterAs()` to have a value, which is false if a parameter is not available (yet).

All startup activities of `ConfigDaemon` are distributed over 2 phases. During the first phase, Construction of plugins and population of data model with parameters and their values take place. At this point of time it is ensured, that no data is requested from outside. This prevents race conditions and saves a synchronization effort. Having set up the data model completely the initialization is done. At the following second phase the `InternalConfigProvider` service is offered to provide access to the parameter data, as the data model is completely populated.

<details>
<summary>Click to expand startup procedure</summary>

<img alt="Startup procedure" src="https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/eclipse-score/baselibs/refs/heads/main/score/config_management/config_daemon/detailed_design/sequence_diagrams/generated/startup_procedure.puml">

</details>
<br>

<!-- [More about SCORE specific usage](./README_SCORE.md#6-initialization-sequences) -->

### 6.1. Constructing and runtime interaction of the ConfigDaemon provided services

The below sequence diagram show the interaction between the ConfigDaemon application, the mw::service and mw::com to construct and offer the ConfigDaemon provided services:

<details>
<summary>Click to expand ConfigDaemon provided services initialization</summary>

<img alt="ConfigDaemon provided services initialization" src="https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/eclipse-score/baselibs/refs/heads/main/score/config_management/config_daemon/detailed_design/sequence_diagrams/config_daemon_provided_services_sequence_diagrams_initialization.puml">

</details>
<br>

The below sequence diagram show the interaction between the ConfigDaemon application provided services and the component clients in the runtime:

<details>
<summary>Click to expand ConfigDaemon provided services runtime interaction</summary>

<img alt="ConfigDaemon provided services runtime interaction" src="https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/eclipse-score/baselibs/refs/heads/main/score/config_management/config_daemon/detailed_design/sequence_diagrams/config_daemon_provided_services_sequence_diagrams_runtime_behaviour.puml">

</details>
<br>

[Table of Contents](#table-of-contents)

## 7. InitialQualifierState

Possible states:

- Undefined
- InProgress
- Qualifying
- Default
- Unqualified
- Qualified

The most critical state is `Qualified`, when `InitialQualifierState` assumes this value, applications consuming the data are allowed to assume parameters are safe to be used. As stated in our `Safety Goal`, we shall never provide corrupted or disqualified data when `InitialQualifierState=Qualified`

<!-- [Details for InitialQualifierState](./README_SCORE.md#7-initialqualifierstate) -->

### 7.1. Relation of InitialQualifierState and Parameter Set Qualifier

`InitialQualifierState` as an overall qualifier for coding data is mapped to the `ParameterSetQualifier`, which is contained in every single `ParameterSet`. Following diagram shows the mapping order in detail.

<details>
<summary>Click to expand InitialQualifierState mapping to Parameter Set Qualifier</summary>

<img alt="ParameterSetQualifier mapping" src="https://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/eclipse-score/baselibs/refs/heads/main/score/config_management/config_daemon/detailed_design/assets/parameter_set_qualifier_mapping.puml">

</details>
<br>

<!-- [Extended Details](./README_SCORE.md#71-relation-of-initialqualifierstate-and-parameter-set-qualifier) -->

[Table of Contents](#table-of-contents)

## 8. External dependencies

|Dependency|Type|Components|Purpose|Analysis|
|----------|----|----------|-------|----------|
|//platform/aas/mw/log:log<br>|Static library|Multiple Classes|logging framework| QM usage only. |
|//platform/aas/mw/service:service<br> //platform/aas/mw/service:factory<br> //platform/aas/mw/service:proxy_future<br> //platform/aas/mw/service/mw:com<br> //platform/aas/mw/service:provided_service_container<br> |Static library|Multiple Classes|framework for handling mw::com interface management| Used for service discovery, if not working as expected no communication will be established which will lead to safe state.|
|@score-baselibs//score/result:result<br> |Static library|Multiple Classes|Enhance error handling with [result type](https://en.wikipedia.org/wiki/Result_type)| QM usage of error messages. Safety related usage in terms of data flow control is sufficiently verified by unit testing. |
|@amp//:amp<br>|Static library|Multiple Classes|AMP extends the C++ Standard Library with modules that are not included in the C++ Standard Library or cannot be used due to embedded restrictions| Safety qualified libraries with ASIL usage. |
|@score-baselibs//score/filesystem:filesystem<br>|Static lib  rary|Multiple Classes|Used to enable unit-testability of filesystem interactions and abstract low-level POSIX interactions | All (safety relevant) files are checksum protected. |
|@score-baselibs//score/json:json<br> @score-baselibs//score/json:json_impl<br>|Static library|Multiple Classes|This library is used to load a JSON document from a file, and access elements from a JSON object. It also allows the use of a JSON parser to perform various attribute parsing operations | Wrapper around Vector (safe) vajson|
|//platform/aas/mw/lifecycle:lifecycle<br>|Static library|Multiple Classes| This library provides application base class from which application developers shall subclass their own application.| Safety qualified library with ASIL usage. |
|//score/language/safecpp/scoped_function:move_only_scoped_function |Static library|//score/config_management/config_daemon/code/app/details| Used for Plugin Deinitialization | QM usage only. |

<!-- [Extended Dependencies](./README_SCORE.md#8-external-dependencies) -->

[Table of Contents](#table-of-contents)
