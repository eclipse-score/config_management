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
#include "score/config_management/config_daemon/code/plugins/demo_json/plugin_creator/demo_json_plugin_creator_impl.h"

#include "score/config_management/config_daemon/code/plugins/demo_json/details/demo_json_plugin_impl.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace demo_json
{

std::shared_ptr<IPlugin> DemoJsonPluginCreatorImpl::CreatePlugin()
{
    return std::make_shared<DemoJsonPluginImpl>();
}

}  // namespace demo_json
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
