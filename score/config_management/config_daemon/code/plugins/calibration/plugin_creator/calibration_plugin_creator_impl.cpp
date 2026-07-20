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
#include "score/config_management/config_daemon/code/plugins/calibration/plugin_creator/calibration_plugin_creator_impl.h"
#include "score/config_management/config_daemon/code/plugins/calibration/details/calibration_impl.h"
#include "score/config_management/config_daemon/code/plugins/calibration/factory/details/factory_impl.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

std::shared_ptr<IPlugin> CalibrationPluginCreatorImpl::CreatePlugin()
{
    auto calibration_plugin_factory = std::make_unique<FactoryImpl>();
    return std::make_shared<CalibrationImpl>(std::move(calibration_plugin_factory));
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
