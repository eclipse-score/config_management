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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_DETAILS_CONFIG_CALIBRATION_SERVICE_REACTOR_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_DETAILS_CONFIG_CALIBRATION_SERVICE_REACTOR_IMPL_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/plugins/calibration/services/config_calibration_service_reactor.h"
#include "score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer/calibration_update_observer.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class ConfigCalibrationServiceReactorImpl final : public ConfigCalibrationServiceReactor
{
  public:
    explicit ConfigCalibrationServiceReactorImpl(
        const std::shared_ptr<data_model::IParameterSetCollection> parameter_data,
        LastUpdatedParameterSetSender last_updated_parameter_set_sender,
        const std::shared_ptr<CalibrationUpdateObserver> calibration_update_observer) noexcept;

    Result<void> UpdateParameterSet(const score::cpp::string_view parameter_set_name,
                                    const score::cpp::string_view parameter_set) noexcept override;

  private:
    Result<void> ConvertDataModelErrorToUpdateParameterSetError(const score::result::Error& error);

    std::shared_ptr<data_model::IParameterSetCollection> parameter_data_;
    LastUpdatedParameterSetSender last_updated_parameter_set_sender_;
    std::shared_ptr<CalibrationUpdateObserver> calibration_update_observer_;
    bool dtc_already_set_to_failed_;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_SERVICES_DETAILS_CONFIG_CALIBRATION_SERVICE_REACTOR_IMPL_H
