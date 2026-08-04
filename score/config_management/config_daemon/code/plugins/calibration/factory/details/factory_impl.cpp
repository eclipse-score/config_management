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
#include "score/config_management/config_daemon/code/plugins/calibration/factory/details/factory_impl.h"

#include "score/config_management/config_daemon/code/plugins/calibration/service_toggler/details/service_toggler_impl.h"
#include "score/config_management/config_daemon/code/plugins/calibration/services/config_calibration_service.h"
#include "score/config_management/config_daemon/code/plugins/calibration/services/details/config_calibration_service_reactor_impl.h"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/details/param_set_mapping_impl.hpp"
#include "score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer/details/calibration_update_observer_impl.h"
#include "score/config_management/config_daemon/code/proxies/secure_debug/secure_debug.h"
#include "score/json/json_parser.h"
#include "platform/aas/mw/diag/dtc/details/dtc_factory_impl.h"
#include "score/mw/service/backend/ara/adaptive_immediate_instantiation_strategy.h"
#include "score/mw/service/backend/ara/provided_service_builder.h"
#include "score/mw/service/proxy_needs_factory.h"

#include <score/utility.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

/* KW_SUPPRESS_START:AUTOSAR.STYLE.SINGLE_STMT_PER_LINE: No more than one statement on one line */
namespace
{
constexpr auto kConfigCalibrationServiceId = "ConfigDaemon/ConfigDaemon_RootSwc/ConfigCalibrationAppPPort";
}  // namespace
/* KW_SUPRRESS_END:AUTOSAR.STYLE.SINGLE_STMT_PER_LINE */

std::unique_ptr<score::mw::service::ProvidedServicesBase> FactoryImpl::CreateCalibrationService(
    const std::shared_ptr<score::config_management::config_daemon::data_model::IParameterSetCollection> parameter_data,
    LastUpdatedParameterSetSender last_updated_parameter_set_sender,
    const std::shared_ptr<runtime_calibration::CalibrationUpdateObserver> calibration_update_observer) const
{
    const ::mw::core::InstanceSpecifier instance_specifier{kConfigCalibrationServiceId};
    auto preconstruct_result = ConfigCalibrationSkeleton::Preconstruct(instance_specifier);
    if (preconstruct_result.HasValue())
    {
        auto service_reactor = std::make_unique<ConfigCalibrationServiceReactorImpl>(
            parameter_data, std::move(last_updated_parameter_set_sender), calibration_update_observer);
        mw::service::ProvidedServiceBuilder builder{};

        score::cpp::ignore =
            builder.With<ConfigCalibrationService>(std::move(preconstruct_result.Value()), std::move(service_reactor));

        auto services = builder.GetServices();
        return std::make_unique<decltype(services)>(std::move(services));
    }
    else
    {
        return nullptr;
    }
}

CalibrationProxies FactoryImpl::CreateCalibrationProxies() const
{
    using SecureDebugProxyStrategy = mw::service::
        AdaptiveImmediateInstantiationStrategy<ISecureDebug, SecureDebug, SecureDebug::AdaptiveProxy, SecureDebugPort>;

    return ::score::mw::service::ProxyNeedsFactory<CalibrationProxies>::Create<SecureDebugProxyStrategy>();
}

std::shared_ptr<ServiceToggler> FactoryImpl::CreateServiceToggler(
    std::unique_ptr<score::mw::service::ProvidedServicesBase> calibration_service) const
{
    return std::make_shared<ServiceTogglerImpl>(std::move(calibration_service));
}

std::shared_ptr<runtime_calibration::CalibrationUpdateObserver> FactoryImpl::CreateCalibrationUpdateObserver() const
{
    return std::make_shared<runtime_calibration::CalibrationUpdateObserverImpl>();
}

std::unique_ptr<score::mw::diag::DTC> FactoryImpl::CreateClearableDtcIntegrityError() const
{
    auto dtc_factory = std::make_unique<score::mw::diag::DtcFactoryImpl>();
    auto dtc = dtc_factory->CreateClearableDTC(
        kInstanceSpecMonitorCalibrationIntegrityError, kInstanceSpecEventCalibrationIntegrityError, {});
    dtc->ReenterDTCAfterItWasCleared();
    return dtc;
}

std::unique_ptr<score::mw::diag::DTC> FactoryImpl::CreateClearableDtcDefaultValuesInUse() const
{
    auto dtc_factory = std::make_unique<score::mw::diag::DtcFactoryImpl>();
    auto dtc = dtc_factory->CreateClearableDTC(
        kInstanceSpecMonitorCalibrationDefaultValuesInUse, kInstanceSpecEventCalibrationDefaultValuesInUse, {});
    dtc->ReenterDTCAfterItWasCleared();
    return dtc;
}

std::shared_ptr<ParameterLoader> FactoryImpl::CreateParameterLoader(
    std::unique_ptr<score::Result<json::Any>> calibration_data,
    const std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping,
    std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter,
    std::unique_ptr<score::mw::diag::DTC> dtc_integrity_error,
    std::unique_ptr<score::mw::diag::DTC> dtc_default_values_in_use) const
{
    return std::make_shared<calibration::ParameterLoaderImpl>(std::move(calibration_data),
                                                              parameter_set_mapping,
                                                              std::move(fault_event_reporter),
                                                              std::move(dtc_integrity_error),
                                                              std::move(dtc_default_values_in_use));
}

mw::service::OptionalProxyData<ISecureDebug> FactoryImpl::CreateSecureDebugFuture(
    CalibrationProxies::Container& proxy_container)
{
    return proxy_container.Extract<mw::service::Optional<score::config_management::config_daemon::ISecureDebug>>();
}
std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> FactoryImpl::CreateParamSetMapping() const
{
    return std::make_shared<coding::ParamSetMapping>(std::make_shared<json::JsonParser>());
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
