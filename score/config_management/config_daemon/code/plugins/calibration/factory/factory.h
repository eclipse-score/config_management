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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_FACTORY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_FACTORY_H

#include "score/mw/service/provided_service_container.h"
#include "score/mw/service/proxy_data.h"
#include "score/mw/service/proxy_needs.h"

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"
#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/details/parameter_loader_impl.h"
#include "score/config_management/config_daemon/code/plugins/calibration/service_toggler/service_toggler.h"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/param_set_mapping.hpp"
#include "score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer/calibration_update_observer.h"
#include "score/config_management/config_daemon/code/proxies/secure_debug/i_secure_debug.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"
#include "platform/aas/mw/diag/dtc/dtc.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

using CalibrationProxies = mw::service::ProxyNeeds<mw::service::Optional<ISecureDebug>>;

class Factory
{
  public:
    Factory() noexcept;
    virtual ~Factory() noexcept;
    Factory(const Factory&) = delete;
    Factory(Factory&&) = delete;
    Factory& operator=(const Factory&) = delete;
    Factory& operator=(Factory&&) = delete;

    virtual CalibrationProxies CreateCalibrationProxies() const = 0;
    virtual std::unique_ptr<score::mw::service::ProvidedServicesBase> CreateCalibrationService(
        const std::shared_ptr<score::config_management::config_daemon::data_model::IParameterSetCollection> parameter_data,
        LastUpdatedParameterSetSender last_updated_parameter_set_sender,
        const std::shared_ptr<CalibrationUpdateObserver> calibration_update_observer) const = 0;

    virtual std::shared_ptr<ServiceToggler> CreateServiceToggler(
        std::unique_ptr<score::mw::service::ProvidedServicesBase> calibration_service) const = 0;

    virtual std::shared_ptr<CalibrationUpdateObserver> CreateCalibrationUpdateObserver() const = 0;
    virtual std::unique_ptr<score::mw::diag::DTC> CreateClearableDtcIntegrityError() const = 0;
    virtual std::unique_ptr<score::mw::diag::DTC> CreateClearableDtcDefaultValuesInUse() const = 0;
    virtual std::shared_ptr<ParameterLoader> CreateParameterLoader(
        std::unique_ptr<score::Result<json::Any>> calibration_data,
        const std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping,
        std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter,
        std::unique_ptr<score::mw::diag::DTC> dtc_integrity_error,
        std::unique_ptr<score::mw::diag::DTC> dtc_default_values_in_use) const = 0;
    virtual mw::service::OptionalProxyData<ISecureDebug> CreateSecureDebugFuture(
        CalibrationProxies::Container& proxy_container) = 0;

    virtual std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> CreateParamSetMapping() const = 0;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_FACTORY_FACTORY_H
