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
#include "score/config_management/config_daemon/code/plugins/calibration/services/details/config_calibration_service_reactor_impl.h"
#include "score/config_management/config_daemon/code/data_model/error/error.h"
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
using DataModelError = data_model::DataModelError;

ConfigCalibrationServiceReactorImpl::ConfigCalibrationServiceReactorImpl(
    const std::shared_ptr<data_model::IParameterSetCollection> parameter_data,
    LastUpdatedParameterSetSender last_updated_parameter_set_sender,
    const std::shared_ptr<runtime_calibration::CalibrationUpdateObserver> calibration_update_observer) noexcept
    : ConfigCalibrationServiceReactor(),
      parameter_data_(parameter_data),
      last_updated_parameter_set_sender_(std::move(last_updated_parameter_set_sender)),
      calibration_update_observer_(calibration_update_observer),
      dtc_already_set_to_failed_(false)
{
}

Result<void> ConfigCalibrationServiceReactorImpl::UpdateParameterSet(const score::cpp::string_view parameter_set_name,
                                                                     const score::cpp::string_view parameter_set) noexcept
{
    if (parameter_data_ == nullptr)
    {
        mw::log::LogError() << __func__ << "ParameterData is nullptr";
        return MakeUnexpected(UpdateParameterSetError::kUnknownError, "ParameterData is nullptr");
    }
    if (last_updated_parameter_set_sender_.empty())
    {
        mw::log::LogError() << __func__ << "LastUpdateParameterSender callback is empty";
        return MakeUnexpected(UpdateParameterSetError::kUnknownError, "LastUpdateParameterSender callback is empty");
    }
    if ((calibration_update_observer_ != nullptr) && (dtc_already_set_to_failed_ == false))
    {
        if (calibration_update_observer_->ReportParameterUpdate())
        {
            dtc_already_set_to_failed_ = true;
        }
        else
        {
            mw::log::LogError() << __func__ << "Failed to set calibration values changed primary dtc to Failed";
        }
    }

    auto set_qualifier_result = parameter_data_->SetParameterSetQualifier(
        parameter_set_name, score::config_management::config_daemon::ParameterSetQualifier::kModified);
    if (!set_qualifier_result.has_value())
    {
        mw::log::LogError() << __func__ << "failed to set parameter set qualifer to kModified for set"
                            << parameter_set_name << ", with error:" << set_qualifier_result.error().Message();
        return Unexpected{set_qualifier_result.error()};
    }

    auto update_parameter_set_result = parameter_data_->UpdateParameterSet(parameter_set_name, parameter_set);
    if (!update_parameter_set_result.has_value())
    {
        mw::log::LogError() << __func__ << "Failed to update parameter set:" << parameter_set_name
                            << "with error:" << update_parameter_set_result.error().UserMessage();
        return ConvertDataModelErrorToUpdateParameterSetError(update_parameter_set_result.error());
    }
    else if (!std::invoke(last_updated_parameter_set_sender_, parameter_set_name.data()))
    {
        mw::log::LogError() << __func__ << "Failed to update parameter set:" << parameter_set_name
                            << "due to SendLastUpdatedParameterSet failed";
        return MakeUnexpected(UpdateParameterSetError::kSendLastUpdatedParameterSetFailed,
                              "Failed to send last updated parameter set.");
    }

    return update_parameter_set_result;
}

Result<void> ConfigCalibrationServiceReactorImpl::ConvertDataModelErrorToUpdateParameterSetError(
    const score::result::Error& error)
{
    // This is false positive. The `return` statement in this case
    // clause unconditionally exits the function, making an additional `break` statement redundant.
    // coverity[autosar_cpp14_m6_4_3_violation]
    switch (*error)
    {
        // coverity[autosar_cpp14_m6_4_5_violation]
        case static_cast<result::ErrorCode>(DataModelError::kParsingError):
            return MakeUnexpected(UpdateParameterSetError::kParsingError, error.Message());
        // coverity[autosar_cpp14_m6_4_5_violation]
        case static_cast<result::ErrorCode>(DataModelError::kParameterSetNotFound):
            return MakeUnexpected(UpdateParameterSetError::kParameterSetNotFound, error.Message());
        // coverity[autosar_cpp14_m6_4_5_violation]
        case static_cast<result::ErrorCode>(DataModelError::kParametersNotFound):
            return MakeUnexpected(UpdateParameterSetError::kParametersNotFound, error.Message());
        // coverity[autosar_cpp14_m6_4_5_violation]
        case static_cast<result::ErrorCode>(DataModelError::kParameterSetNotCalibratable):
            return MakeUnexpected(UpdateParameterSetError::kParameterSetNotCalibratable, error.Message());
        // coverity[autosar_cpp14_m6_4_5_violation]
        default:
            return MakeUnexpected(UpdateParameterSetError::kUnknownError, "Unknown Error!");
    }
}
}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
