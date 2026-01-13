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

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/factory/details/factory_impl.h"

#include <score/utility.hpp>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

Factory::Factory() : IFactory{}, json_helper_{}, hash_calculator_factory_{} {}

ProvidedServiceContainer Factory::CreateInternalConfigProviderService(
    const std::shared_ptr<data_model::IParameterSetCollection> read_only_parameter_data_interface) const
{
    score::cpp::ignore = read_only_parameter_data_interface;
    return ProvidedServiceContainer{};
}

LastUpdatedParameterSetSender Factory::CreateLastUpdatedParameterSetSender(ProvidedServiceContainer& services)
{
    score::cpp::ignore = services;
    return {};
}

InitialQualifierStateSender Factory::CreateInitialQualifierStateSender(ProvidedServiceContainer& services)
{
    score::cpp::ignore = services;
    return {};
}

std::shared_ptr<data_model::IParameterSetCollection> Factory::CreateParameterSetCollection() const
{
    return std::make_shared<data_model::ParameterSetCollection>();
}

std::unique_ptr<IPluginCollector> Factory::CreatePluginCollector() const
{
    // return std::make_unique<PluginCollector>();
    return nullptr;
}

std::shared_ptr<fault_event_reporter::IFaultEventReporter> Factory::CreateFaultEventReporter() const
{
    return nullptr;
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
