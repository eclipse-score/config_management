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

#include "score/hash/code/core/factory/impl/safe_hash_calculator_factory.h"
#include "platform/aas/mw/service/backend/mw_com/provided_service_builder.h"
#include "platform/aas/mw/service/backend/mw_com/provided_service_decorator.h"
#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/factory/details/factory_impl.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/details/fault_event_reporter_score_impl.h"
#include "score/config_management/config_daemon/code/json_helper/details/json_helper_impl.h"
#include "score/config_management/config_daemon/code/plugins/plugin_collector/details/plugin_collector_impl.h"
#include "score/config_management/config_daemon/code/services/details/internal_config_provider_service_reactor_impl.h"
#include "score/config_management/config_daemon/code/services/details/mw_com/internal_config_provider_service_impl.h"

#include <score/utility.hpp>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

namespace
{

const auto kICPServiceInstanceSpecifierName =
    mw::com::InstanceSpecifier::Create("ConfigDaemon/ConfigDaemon_RootSwc/InternalConfigProviderAppPPort").value();
}  // namespace

Factory::Factory()
    : IFactory{},
      json_helper_{std::make_shared<common::JsonHelper>()},
      hash_calculator_factory_{std::make_shared<hash::SafeHashCalculatorFactory>()}
{
}

mw::service::ProvidedServiceContainer Factory::CreateInternalConfigProviderService(
    const std::shared_ptr<data_model::IParameterSetCollection> read_only_parameter_data_interface) const
{
    mw::service::ProvidedServiceBuilder builder{};
    auto service_reactor =
        std::make_unique<InternalConfigProviderServiceReactorImpl>(read_only_parameter_data_interface);

    score::Result<InternalConfigProviderService> icp_creation_result =
        InternalConfigProviderService::Create(std::move(service_reactor), kICPServiceInstanceSpecifierName);

    if (icp_creation_result.has_value())
    {
        score::cpp::ignore = builder.With<InternalConfigProviderService>(std::move(icp_creation_result).value());
    }
    else
    {
        mw::log::LogError() << "Failed to create InternalConfigProviderService:" << icp_creation_result.error();
    }
    return builder.GetServices();
}

LastUpdatedParameterSetSender Factory::CreateLastUpdatedParameterSetSender(
    mw::service::ProvidedServiceContainer& services)
{
    auto* const provided_service_container =
        services.GetServices<mw::service::backend::mw_com::ProvidedServiceBuilder::DecoratorType>();
    if ((provided_service_container != nullptr) && provided_service_container->Has<IInternalConfigProviderService>())
    {
        return [internal_config_provider_service{provided_service_container->Get<IInternalConfigProviderService>()}](
                   const std::string_view parameter_set_name) noexcept -> bool {
            return internal_config_provider_service->SendLastUpdatedParameterSet(parameter_set_name);
        };
    }
    return {};
}

InitialQualifierStateSender Factory::CreateInitialQualifierStateSender(mw::service::ProvidedServiceContainer& services)
{
    auto* const provided_service_container =
        services.GetServices<mw::service::backend::mw_com::ProvidedServiceBuilder::DecoratorType>();
    if ((provided_service_container != nullptr) && provided_service_container->Has<IInternalConfigProviderService>())
    {
        return [internal_config_provider_service{provided_service_container->Get<IInternalConfigProviderService>()}](
                   const config_daemon::InitialQualifierState initial_qualifier_state) noexcept -> void {
            internal_config_provider_service->SetInitialQualifierState(initial_qualifier_state);
        };
    }
    return {};
}

std::shared_ptr<data_model::IParameterSetCollection> Factory::CreateParameterSetCollection() const
{
    return std::make_shared<data_model::ParameterSetCollection>();
}

std::unique_ptr<IPluginCollector> Factory::CreatePluginCollector() const
{
    return std::make_unique<PluginCollector>();
}

std::shared_ptr<fault_event_reporter::IFaultEventReporter> Factory::CreateFaultEventReporter() const
{
    return std::make_shared<fault_event_reporter::FaultEventReporter>();
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
