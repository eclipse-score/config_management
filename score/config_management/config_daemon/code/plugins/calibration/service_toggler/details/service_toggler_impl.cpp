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
#include "score/config_management/config_daemon/code/plugins/calibration/service_toggler/details/service_toggler_impl.h"
#include "score/mw/log/logging.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

ServiceTogglerImpl::ServiceTogglerImpl(
    std::unique_ptr<score::mw::service::ProvidedServicesBase> calibration_service) noexcept
    : ServiceToggler(), calibration_enabled_previous_{false}, calibration_service_{std::move(calibration_service)}
{
}

void ServiceTogglerImpl::ToggleInterface(const bool calibration_enabled) noexcept
{
    if (calibration_service_ == nullptr)
    {
        mw::log::LogWarn() << __func__ << "Service is not available";
        return;
    }

    if (calibration_enabled_previous_ == calibration_enabled)
    {
        mw::log::LogInfo() << __func__ << "Service is already enabled/disabled";
        return;
    }
    calibration_enabled_previous_ = calibration_enabled;

    if (calibration_enabled == true)
    {
        mw::log::LogInfo() << __func__ << "Starting CalibrationService";
        calibration_service_->StartAll();
    }
    else
    {
        mw::log::LogInfo() << __func__ << "Stopping CalibrationService";
        calibration_service_->StopAll();
    }
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
