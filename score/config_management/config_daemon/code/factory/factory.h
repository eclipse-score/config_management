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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_FACTORY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_FACTORY_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/factory/service_container_selector.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"
#include "score/config_management/config_daemon/code/plugins/plugin_collector/plugin_collector.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"

#include <score/memory.hpp>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class IFactory
{
  public:
    IFactory() = default;
    virtual ~IFactory() = default;
    IFactory(IFactory&&) = delete;
    IFactory(const IFactory&) = delete;

    IFactory& operator=(IFactory&&) = delete;
    IFactory& operator=(const IFactory&) = delete;

    virtual ProvidedServiceContainer CreateInternalConfigProviderService(
        const std::shared_ptr<data_model::IParameterSetCollection> read_only_parameter_data_interface) const = 0;
    virtual LastUpdatedParameterSetSender CreateLastUpdatedParameterSetSender(ProvidedServiceContainer& services) = 0;
    virtual InitialQualifierStateSender CreateInitialQualifierStateSender(ProvidedServiceContainer& services) = 0;

    virtual std::shared_ptr<data_model::IParameterSetCollection> CreateParameterSetCollection() const = 0;

    virtual std::unique_ptr<IPluginCollector> CreatePluginCollector() const = 0;
    virtual std::shared_ptr<fault_event_reporter::IFaultEventReporter> CreateFaultEventReporter() const = 0;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_FACTORY_FACTORY_H
