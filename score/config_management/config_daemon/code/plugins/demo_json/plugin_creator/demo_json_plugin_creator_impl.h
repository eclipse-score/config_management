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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_DEMO_JSON_PLUGIN_CREATOR_DEMO_JSON_PLUGIN_CREATOR_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_DEMO_JSON_PLUGIN_CREATOR_DEMO_JSON_PLUGIN_CREATOR_IMPL_H

#include "score/config_management/config_daemon/code/plugins/plugin_creator.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace demo_json
{

class DemoJsonPluginCreatorImpl final : public IPluginCreator
{
  public:
    DemoJsonPluginCreatorImpl() = default;
    ~DemoJsonPluginCreatorImpl() = default;

    std::shared_ptr<IPlugin> CreatePlugin() override;
};

}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_DEMO_JSON_PLUGIN_CREATOR_DEMO_JSON_PLUGIN_CREATOR_IMPL_H
