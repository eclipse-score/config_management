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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_PARAMETER_LOADER_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_PARAMETER_LOADER_MOCK_H

#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/parameter_loader.h"
#include "platform/aas/mw/diag/dtc/dtc.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class ParameterLoaderMock final : public ParameterLoader
{
  public:
    MOCK_METHOD(bool,
                LoadParameterData,
                (const std::shared_ptr<data_model::IParameterSetCollection> parameter_data),
                (override));
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_PARAMETER_LOADER_MOCK_H
