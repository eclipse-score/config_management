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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_CONFIG_CALIBRATION_SERVICE_REACTOR_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_CONFIG_CALIBRATION_SERVICE_REACTOR_H

#include "score/result/result.h"

#include <score/string_view.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class ConfigCalibrationServiceReactor
{
  public:
    virtual ~ConfigCalibrationServiceReactor() = default;
    ConfigCalibrationServiceReactor() noexcept = default;
    ConfigCalibrationServiceReactor(ConfigCalibrationServiceReactor&&) noexcept = delete;
    ConfigCalibrationServiceReactor(const ConfigCalibrationServiceReactor&) noexcept = delete;
    ConfigCalibrationServiceReactor& operator=(ConfigCalibrationServiceReactor&&) noexcept = delete;
    ConfigCalibrationServiceReactor& operator=(const ConfigCalibrationServiceReactor&) noexcept = delete;

    virtual Result<void> UpdateParameterSet(const score::cpp::string_view parameter_set_name,
                                            const score::cpp::string_view parameter_set) noexcept = 0;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_CONFIG_CALIBRATION_SERVICE_REACTOR_H
