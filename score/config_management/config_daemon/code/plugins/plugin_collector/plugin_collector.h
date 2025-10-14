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

#ifndef CODE_PLUGINS_PLUGIN_COLLECTOR_PLUGIN_COLLECTOR_H
#define CODE_PLUGINS_PLUGIN_COLLECTOR_PLUGIN_COLLECTOR_H

#include "score/config_management/config_daemon/code/plugins/plugin.h"

#include "vector"

namespace score
{
namespace config_management
{
namespace config_daemon
{

class IPluginCollector
{
  public:
    IPluginCollector() = default;
    IPluginCollector(IPluginCollector&&) = delete;
    IPluginCollector(const IPluginCollector&) = delete;
    IPluginCollector& operator=(IPluginCollector&&) = delete;
    IPluginCollector& operator=(const IPluginCollector&) = delete;
    virtual ~IPluginCollector() = default;

    virtual std::vector<std::shared_ptr<IPlugin>> CreatePlugins() = 0;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_PLUGINS_PLUGIN_COLLECTOR_PLUGIN_COLLECTOR_H
