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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_CONFIG_CALIBRATION_SERVICE_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_CONFIG_CALIBRATION_SERVICE_H

#include "bmw/platform/config_daemon/portinterfaces/configcalibration/configcalibration_skeleton.h"
#include "score/config_management/config_daemon/code/plugins/calibration/services/config_calibration_service_reactor.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

using ConfigCalibrationSkeleton = portinterfaces::configcalibration::skeleton::ConfigCalibrationSkeleton;
using Output = portinterfaces::configcalibration::skeleton::methods::UpdateParameterSet::Output;
using UpdateParameterSetResult = portinterfaces::UpdateParameterSetResult;

class ConfigCalibrationService final : public ConfigCalibrationSkeleton
{
  public:
    explicit ConfigCalibrationService(
        ConfigCalibrationSkeleton::ConstructionToken&& token,
        const std::shared_ptr<ConfigCalibrationServiceReactor> config_calibration_service_reactor);

    ::mw::core::Future<Output> UpdateParameterSet(const ::ara::diag::string& parameter_set_name,
                                                   const ::ara::diag::string& parameter_set) noexcept override;

  private:
    static UpdateParameterSetResult ConvertErrorTypeToUpdateParameterSetResult(const score::result::Error& error);

    std::shared_ptr<ConfigCalibrationServiceReactor> config_calibration_service_reactor_;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_CONFIG_CALIBRATION_SERVICE_H
