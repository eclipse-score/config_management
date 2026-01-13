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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_PLUGIN_COLLECTOR_DETAILS_PLUGIN_COLLECTOR_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_PLUGIN_COLLECTOR_DETAILS_PLUGIN_COLLECTOR_IMPL_H

#include "score/mw/log/logger.h"

#include "score/config_management/config_daemon/code/plugins/plugin_collector/plugin_collector.h"
#include "score/config_management/config_daemon/code/plugins/plugin_creator.h"

#include <memory>
#include <vector>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class PluginCollector final : public IPluginCollector
{
  public:
    PluginCollector() noexcept;

    ~PluginCollector() override = default; /* KW_SUPPRESS:MISRA.VIRTUAL.NOVIRTUAL: valid use*/
    PluginCollector(const PluginCollector&) = delete;
    PluginCollector(PluginCollector&&) = delete;
    PluginCollector& operator=(const PluginCollector&) = delete;
    PluginCollector& operator=(PluginCollector&&) = delete;

    std::vector<std::shared_ptr<IPlugin>> CreatePlugins() override;

  private:
    std::vector<std::unique_ptr<IPluginCreator>> plugin_creators_;
    mw::log::Logger& logger_;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_PLUGIN_COLLECTOR_DETAILS_PLUGIN_COLLECTOR_IMPL_H
