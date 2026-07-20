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
#include "score/config_management/config_daemon/code/plugins/calibration/services/config_calibration_service.h"
#include "score/config_management/config_daemon/code/plugins/calibration/services/error/update_parameter_set_error_domain.h"
#include "score/mw/log/logging.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

ConfigCalibrationService::ConfigCalibrationService(
    ConfigCalibrationSkeleton::ConstructionToken&& token,
    const std::shared_ptr<ConfigCalibrationServiceReactor> config_calibration_service_reactor)
    : ConfigCalibrationSkeleton(std::move(token)),
      config_calibration_service_reactor_(config_calibration_service_reactor)
{
}

::mw::core::Future<Output> ConfigCalibrationService::UpdateParameterSet(
    const ::ara::diag::string& parameter_set_name,
    const ::ara::diag::string& parameter_set) noexcept
{
    mw::core::Promise<Output> ret_val;
    auto update_parameter_set_result = config_calibration_service_reactor_->UpdateParameterSet(
        {parameter_set_name.data(), parameter_set_name.size()}, {parameter_set.data(), parameter_set.size()});
    if (!update_parameter_set_result.has_value())
    {
        ret_val.set_value({ConvertErrorTypeToUpdateParameterSetResult(update_parameter_set_result.error())});
    }
    else
    {
        ret_val.set_value({UpdateParameterSetResult::kOk});
    }

    return ret_val.get_future();
}

UpdateParameterSetResult ConfigCalibrationService::ConvertErrorTypeToUpdateParameterSetResult(
    const score::result::Error& error)
{
    UpdateParameterSetResult result = UpdateParameterSetResult::kUnknownError;
    switch (*error)
    {
        case static_cast<result::ErrorCode>(UpdateParameterSetError::kParsingError):
            result = UpdateParameterSetResult::kParsingError;
            break;
        case static_cast<result::ErrorCode>(UpdateParameterSetError::kParameterSetNotFound):
            result = UpdateParameterSetResult::kParameterSetNotFound;
            break;
        case static_cast<result::ErrorCode>(UpdateParameterSetError::kParametersNotFound):
            result = UpdateParameterSetResult::kParametersNotFound;
            break;
        case static_cast<result::ErrorCode>(UpdateParameterSetError::kSendLastUpdatedParameterSetFailed):
            result = UpdateParameterSetResult::kSendLastUpdatedParameterSetFailed;
            break;
        case static_cast<result::ErrorCode>(UpdateParameterSetError::kParameterSetNotCalibratable):
            result = UpdateParameterSetResult::kParameterSetNotCalibratable;
            break;
        default:
            result = UpdateParameterSetResult::kUnknownError;
            break;
    }
    return result;
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
