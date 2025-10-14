# ConfigDaemon
`ConfigDaemon` application implements a unified interface for parameter accesses by user applications. It is responsible for:
- provision of a main function and integration into the middleware application lifecycle.
- instantiation of plugins.
- instantiation of data model as `ParameterSetCollection`.
- offering of the `InternalConfigProvider` service for parameter access.

## How to use
In order to use ConfigDaemon, you need to follow a few steps:
* Create Plugin
* Create PluginFactory
* Create PluginCreator
* Add Plugin to ConfigDaemon

### Plugin
Create your own plugin by inheriting the `IPlugin` interface located in `ConfigDaemon/code/plugins/plugin.h`. Implement the methods of the interface. These methods will be executed by `ConfigDaemon`:
* `InstantSetup` - during the initialization phase.
* `Execute` - in the main/run phase.
* `Cleanup` - during the shutdown phase.

```c++
static constexpr const std::int32_t kError{0};
static constexpr const std::int32_t kSuccess{1};

class Foo
{
  public:
    std::int32_t Run();
    void Stop();
};

class Bar
{
  public:
    std::int32_t Execute();
    void Finish();
}

class Plugin final : public IPlugin
{
  public:
    explicit Plugin(std::unique_ptr<IPluginFactory> factory) noexcept;

    std::int32_t InstantSetup() override;
    std::int32_t Execute(std::shared_ptr<IParamSetMapping> param_set_mapping,
                         std::shared_ptr<data_model::IParameterSetCollection> parameterset_collection,
                         LastUpdatedParameterSetSender cbkSendLastUpdatedParameterSet,
                         InitialQualifierStateSender cbkUpdateInitialQualifierState,
                         score::cpp::stop_token stop_token) override;
    void Cleanup() override;

  private:
    std::unique_ptr<IPluginFactory> factory_;
    std::shared_ptr<Foo> foo_;
    std::unique_ptr<Bar> bar_;
};

Plugin::Plugin(std::unique_ptr<IPluginFactory> factory) noexcept
    : factory_{std::move(factory)}
{
}

std::int32_t Plugin::InstantSetup()
{
  foo_ = factory_->CreateFoo();
  if (foo_ == nullptr)
  {
    // LogError
    return kError;
  }

  bar_ = factory_->CreateBar();
  if (bar_ == nullptr)
  {
    // LogError
    return kError;
  }

  return kSuccess;
}

std::int32_t Plugin::Execute(std::shared_ptr<IParamSetMapping> param_set_mapping,
                             std::shared_ptr<data_model::IParameterSetCollection> parameterset_collection,
                             LastUpdatedParameterSetSender cbkSendLastUpdatedParameterSet,
                             InitialQualifierStateSender cbkUpdateInitialQualifierState,
                             score::cpp::stop_token stop_token)
{
  const auto foo_run_result = foo_->Run();
  if (foo_run_result == kError)
  {
    // LogError
    return foo_run_result;
  }

  const auto bar_execute_result = bar_->Execute();
  if (bar_execute_result == kError)
  {
    // LogError
    return bar_execute_result;
  }

  return kSuccess;
}

void Plugin::Cleanup()
{
  if (foo_ != nullptr)
  {
    foo_->Stop();
  }

  if (bar_ != nullptr)
  {
    bar_->Finish();
  }
}
```

### PluginFactory
Create your own PluginFactory. It will be responsible for creating the objects necessary for the plugin to work.

```c++
class Foo;
class Bar;

class IPluginFactory
{
  public:
    IPluginFactory() = default;
    virtual ~IPluginFactory() = default;
    virtual std::shared_ptr<Foo> CreateFoo() const = 0;
    virtual std::unique_ptr<Bar> CreateBar() const = 0;
};

class PluginFactory final : public IPluginFactory
{
  public:
    PluginFactory() = default;
    ~PluginFactory() override = default;
    std::shared_ptr<Foo> CreateFoo() const override;
    std::unique_ptr<Bar> CreateBar() const override;
};
```

### PluginCreator
Create your own PluginCreator. It must be inherited from the `IPluginCreator` located at `ConfigDaemon/code/plugins/plugin_creator.h`. It is needed to unify the process of creating/executing `Plugins` in the `ConfigDaemon` scope.

```c++
class PluginCreator final : public IPluginCreator
{
  public:
    PluginCreator() = default;
    ~PluginCreator() = default;

    std::shared_ptr<IPlugin> CreatePlugin() override;
};

std::shared_ptr<IPlugin> PluginCreator::CreatePlugin()
{
    auto plugin_factory = std::make_unique<PluginFactory>();
    return std::make_shared<Plugin>(std::move(plugin_factory));
}
```

### Add PluginCreator to PluginCollector
Create an instance of your `PluginCreator` and add it to the `PluginCreators` vector in the `PluginCollector` constructor located at `ConfigDaemon/code/plugins/plugin_collector/details/plugin_collector_impl_user.cpp`.
```c++
plugin_creators_.emplace_back(std::make_unique<coding::PluginCreator>());
```

Add a dependency for your `PluginCreator` library to the BUILD file located at `ConfigDaemon/code/plugins/plugin_collector/details/BUILD`.

### Build Switch
To switch the build to the score variant, you must run the build with the optional build flag added:
```bash
bazel build //score/config_management/config_daemon/code/app/details:app --//score/config_management/config_daemon/code/plugins/plugin_collector/details:score_variant=true
```
