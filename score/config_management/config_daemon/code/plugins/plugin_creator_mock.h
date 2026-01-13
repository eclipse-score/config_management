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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_PLUGIN_CREATOR_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_PLUGIN_CREATOR_MOCK_H

#include "score/config_management/config_daemon/code/plugins/plugin_creator.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class PluginCreatorMock final : public IPluginCreator
{
  public:
    ~PluginCreatorMock() = default;

    MOCK_METHOD(std::shared_ptr<IPlugin>, CreatePlugin, (), (override));
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_PLUGINS_PLUGIN_CREATOR_MOCK_H
