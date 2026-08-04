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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_DETAILS_FACTORY_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_DETAILS_FACTORY_IMPL_H

#include "score/config_management/config_daemon/code/plugins/calibration/factory/factory.h"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/param_set_mapping.hpp"
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

constexpr auto kInstanceSpecMonitorCalibrationIntegrityError =
    "ConfigDaemon/ConfigDaemon_RootSwc/DiagnosticMonitorCalibrationIntegrityErrorPPort";
constexpr auto kInstanceSpecEventCalibrationIntegrityError =
    "ConfigDaemon/ConfigDaemon_RootSwc/DiagnosticEventCalibrationIntegrityErrorRPort";

constexpr auto kInstanceSpecMonitorCalibrationDefaultValuesInUse =
    "ConfigDaemon/ConfigDaemon_RootSwc/DiagnosticMonitorCalibrationDefaultValueInUsePPort";
constexpr auto kInstanceSpecEventCalibrationDefaultValuesInUse =
    "ConfigDaemon/ConfigDaemon_RootSwc/DiagnosticEventCalibrationDefaultValueInUseRPort";

class SecureDebugPort
{
  public:
    constexpr static auto Get()
    {
        return "ConfigDaemon/ConfigDaemon_RootSwc/SecureDebugRPort";
    }
};
class FactoryImpl : public Factory
{
  public:
    FactoryImpl() noexcept = default;

    CalibrationProxies CreateCalibrationProxies() const override;

    std::unique_ptr<score::mw::service::ProvidedServicesBase> CreateCalibrationService(
        const std::shared_ptr<score::config_management::config_daemon::data_model::IParameterSetCollection> parameter_data,
        LastUpdatedParameterSetSender last_updated_parameter_set_sender,
        const std::shared_ptr<runtime_calibration::CalibrationUpdateObserver> calibration_update_observer)
        const override;

    std::shared_ptr<ServiceToggler> CreateServiceToggler(
        std::unique_ptr<score::mw::service::ProvidedServicesBase> calibration_service) const override;

    std::shared_ptr<runtime_calibration::CalibrationUpdateObserver> CreateCalibrationUpdateObserver() const override;
    std::unique_ptr<score::mw::diag::DTC> CreateClearableDtcIntegrityError() const override;
    std::unique_ptr<score::mw::diag::DTC> CreateClearableDtcDefaultValuesInUse() const override;
    std::shared_ptr<ParameterLoader> CreateParameterLoader(
        std::unique_ptr<score::Result<json::Any>> calibration_data,
        const std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping,
        std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter,
        std::unique_ptr<score::mw::diag::DTC> dtc_integrity_error,
        std::unique_ptr<score::mw::diag::DTC> dtc_default_values_in_use) const override;
    mw::service::OptionalProxyData<ISecureDebug> CreateSecureDebugFuture(
        CalibrationProxies::Container& proxy_container) override;

    std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> CreateParamSetMapping() const override;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_DETAILS_FACTORY_IMPL_H
