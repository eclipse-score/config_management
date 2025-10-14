// *******************************************************************************
// Copyright (c) 2025 Contributors to the Eclipse Foundation
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

#include "score/config_management/config_daemon/code/plugins/plugin_collector/details/plugin_collector_impl.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{

PluginCollector::PluginCollector() noexcept
    : plugin_creators_{}, logger_{mw::log::CreateLogger(std::string_view{"PCol"})}
{
    // Add your plugings creator to plugin_creators_ here.
}

std::vector<std::shared_ptr<IPlugin>> PluginCollector::CreatePlugins()
{
    logger_.LogDebug() << "PluginCollector::" << __func__;
    std::vector<std::shared_ptr<IPlugin>> plugins;

    if (plugin_creators_.empty())
    {
        logger_.LogError() << "PluginCollector::" << __func__ << " No PluginCrators provided";
        return plugins;
    }

    for (const auto& plugin_creator : plugin_creators_)
    {
        auto plugin = plugin_creator->CreatePlugin();
        if (nullptr == plugin)
        {
            logger_.LogError() << "PluginCollector::" << __func__ << " Failed to create Plugin";
            plugins.clear();
            return plugins;
        }
        plugins.push_back(std::move(plugin));
    }

    logger_.LogInfo() << "PluginCollector::" << __func__ << " Plugins creation finished";
    return plugins;
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
