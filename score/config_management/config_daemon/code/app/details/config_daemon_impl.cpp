// *******************************************************************************
// Copyright (c) 2025, 2026 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0
// *******************************************************************************
#include "score/config_management/config_daemon/code/app/details/config_daemon_impl.h"
#include "score/concurrency/interruptible_wait.h"
#include "score/filesystem/error.h"
#include "score/json/json_parser.h"
#include "score/os/stat.h"
#include "score/utils/src/scoped_operation.h"

#include <score/utility.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{

namespace
{
constexpr const std::int32_t kExitCodeSuccess{0};
constexpr const std::int32_t kExitCodeFailure{1};

}  // namespace

ConfigDaemon::ConfigDaemon(std::unique_ptr<IFactory> factory) noexcept
    : IConfigDaemon{},
      logger_{mw::log::CreateLogger(std::string_view{"App"})},
      factory_{std::move(factory)},
      parameterset_collection_{factory_->CreateParameterSetCollection()},
      fault_event_reporter_{factory_->CreateFaultEventReporter()},
      plugins_{}
{
    logger_.LogDebug() << "ConfigDaemon::" << __func__;
    // 0x7F(hexadecimal) is equivalent to 0177(octal) in UNix permissions
    const auto result = os::Stat::instance().umask(os::IntegerToMode(0x7FU));
    if (not result.has_value())
    {
        logger_.LogError() << "ConfigDaemon::" << __func__
                           << "Failed to set umask for ConfigDaemon process: " << result.error().ToString();
    }
}

std::int32_t ConfigDaemon::Initialize(const ApplicationContext& context)
{
    score::cpp::ignore = context;
    logger_.LogInfo() << "ConfigDaemon::" << __func__;

    const auto prepare_plugins_result = PreparePlugins();
    if (prepare_plugins_result == kExitCodeFailure)
    {
        return prepare_plugins_result;
    }

    for (const auto& plugin : plugins_)
    {
        if (plugin == nullptr)
        {
            logger_.LogError() << "ConfigDaemon::" << __func__ << "Plugin is nullptr";
            return kExitCodeFailure;
        }

        const auto init_plugin_result = plugin->Initialize();
        if (init_plugin_result.has_value() == false)
        {
            logger_.LogWarn() << "ConfigDaemon::" << __func__
                              << "Plugin.Initialize() failed:" << init_plugin_result.error();
            return kExitCodeFailure;
        }
    }

    provided_services_container_ = factory_->CreateInternalConfigProviderService(parameterset_collection_);
    if (provided_services_container_.NumServices() == 0U)
    {
        logger_.LogError() << "ConfigDaemon::" << __func__
                           << "ProviderServicesContainer doesn't contain any InternalConfigProviderService";
        return kExitCodeFailure;
    }
    fault_event_reporter_->Initialize();

    return kExitCodeSuccess;
}

std::int32_t ConfigDaemon::Run(const score::cpp::stop_token& token)
{
    logger_.LogInfo() << "ConfigDaemon::" << __func__;

    utils::ScopedOperation<> deinitialize_plugin_instance([this, &logger = logger_]() noexcept {
        logger.LogInfo() << "ConfigDaemon::" << __func__ << "Exiting plugin execution scope";

        for (const auto& plugin : plugins_)
        {
            // LCOV_EXCL_START Can't be covered by unit tests. It has already been checked for nullptr
            // earlier in the Initialize method, and there is no way to set it to nullptr in the test.
            if (plugin != nullptr)
            {
                plugin->Deinitialize();
            }
            // LCOV_EXCL_STOP
        }
    });
    for (const auto& plugin : plugins_)
    {
        // LCOV_EXCL_START Can't be covered by unit tests. It has already been checked for nullptr
        // earlier in the Initialize method, and there is no way to set it to nullptr in the test.
        if (plugin == nullptr)
        {
            logger_.LogError() << "ConfigDaemon::" << __func__ << "Plugin is nullptr";
            return kExitCodeFailure;
        }
        // LCOV_EXCL_STOP

        auto initial_qualifier_state_sender = factory_->CreateInitialQualifierStateSender(provided_services_container_);
        if (initial_qualifier_state_sender.empty())
        {
            logger_.LogError() << "ConfigDaemon::" << __func__
                               << "Failed to create InitialQualifierStateSender callback";
            return kExitCodeFailure;
        }
        auto last_updated_parameter_set_sender =
            factory_->CreateLastUpdatedParameterSetSender(provided_services_container_);

        if (last_updated_parameter_set_sender.empty())
        {
            logger_.LogError() << "ConfigDaemon::" << __func__
                               << "Failed to create LastUpdatedPramaterSetSender callback";
            return kExitCodeFailure;
        }

        const auto plugin_run_result = plugin->Run(parameterset_collection_,
                                                   std::move(last_updated_parameter_set_sender),
                                                   std::move(initial_qualifier_state_sender),
                                                   token,
                                                   fault_event_reporter_);
        if (plugin_run_result == kExitCodeFailure)
        {
            logger_.LogError() << "ConfigDaemon::" << __func__ << "Plugin.Run() failed";
            return kExitCodeFailure;
        }
    }

    logger_.LogInfo() << "ConfigDaemon::" << __func__ << "InternalConfigProviderService offered.";
    provided_services_container_.StartServices();

    score::concurrency::wait_until_stop_requested(token);

    logger_.LogInfo() << "ConfigDaemon::" << __func__ << "Stop requested";
    provided_services_container_.StopServices();

    return kExitCodeSuccess;
}

std::int32_t ConfigDaemon::PreparePlugins()
{
    auto plugin_collector = factory_->CreatePluginCollector();
    if (plugin_collector == nullptr)
    {
        logger_.LogError() << "ConfigDaemon::" << __func__ << "factory could not create PluginCollector";
        return kExitCodeFailure;
    }

    plugins_ = plugin_collector->CreatePlugins();
    logger_.LogDebug() << "ConfigDaemon::" << __func__ << "Created " << plugins_.size() << " plugins.";

    return kExitCodeSuccess;
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
