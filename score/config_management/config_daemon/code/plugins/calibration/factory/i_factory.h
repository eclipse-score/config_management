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
#ifndef CODE_PLUGINS_CALIBRATION_FACTORY_I_FACTORY_H
#define CODE_PLUGINS_CALIBRATION_FACTORY_I_FACTORY_H

#include "score/mw/service/provided_service_container.h"
#include "score/mw/service/proxy_data.h"
#include "score/mw/service/proxy_needs.h"

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"
#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/parameter_loader.h"
#include "score/config_management/config_daemon/code/plugins/calibration/service_toggler/service_toggler.h"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/param_set_mapping.hpp"
#include "score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer/calibration_update_observer.h"
#include "score/config_management/config_daemon/code/proxies/secure_debug/i_secure_debug.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"
namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

using CalibrationProxies = mw::service::ProxyNeeds<mw::service::Optional<ISecureDebug>>;

class IFactory
{
  public:
    IFactory() noexcept;
    virtual ~IFactory() noexcept;
    IFactory(const IFactory&) = delete;
    IFactory(IFactory&&) = delete;
    IFactory& operator=(const IFactory&) = delete;
    IFactory& operator=(IFactory&&) = delete;

    virtual CalibrationProxies CreateCalibrationProxies() const = 0;
    virtual std::unique_ptr<score::mw::service::ProvidedServicesBase> CreateCalibrationService(
        const std::shared_ptr<score::config_management::config_daemon::data_model::IParameterSetCollection> parameter_data,
        LastUpdatedParameterSetSender last_updated_parameter_set_sender,
        const std::shared_ptr<runtime_calibration::CalibrationUpdateObserver> calibration_update_observer) const = 0;

    virtual std::shared_ptr<ServiceToggler> CreateServiceToggler(
        std::unique_ptr<score::mw::service::ProvidedServicesBase> calibration_service) const = 0;

    virtual std::shared_ptr<runtime_calibration::CalibrationUpdateObserver> CreateCalibrationUpdateObserver() const = 0;
    virtual std::shared_ptr<ParameterLoader> CreateParameterLoader(
        std::unique_ptr<score::Result<json::Any>> calibration_data,
        const std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping,
        std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter) const = 0;
    virtual mw::service::OptionalProxyData<ISecureDebug> CreateSecureDebugFuture(
        CalibrationProxies::Container& proxy_container) = 0;

    virtual std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> CreateParamSetMapping() const = 0;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_PLUGINS_CALIBRATION_FACTORY_I_FACTORY_H
