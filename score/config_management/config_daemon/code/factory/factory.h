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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_FACTORY_FACTORY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_FACTORY_FACTORY_H

#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/parameter_set_storage.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_manager.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"
#include "score/config_management/config_daemon/code/plugins/plugin_collector/plugin_collector.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"
#include "score/mw/service/provided_services_container.h"

#include <vector>

#include <score/memory.hpp>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class Factory
{
  public:
    Factory() = default;
    virtual ~Factory() = default;
    Factory(Factory&&) = delete;
    Factory(const Factory&) = delete;

    Factory& operator=(Factory&&) = delete;
    Factory& operator=(const Factory&) = delete;

    virtual mw::service::ProvidedServicesContainer CreateInternalConfigProviderService(
        const std::shared_ptr<data_model::IParameterSetCollection> read_only_parameter_data_interface) const = 0;
    virtual LastUpdatedParameterSetSender CreateLastUpdatedParameterSetSender(
        mw::service::ProvidedServicesContainer& services) = 0;

    virtual std::shared_ptr<data_model::IParameterSetCollectionManager> CreateParameterSetCollectionManager(
        std::vector<std::shared_ptr<IPlugin>>& plugins) const = 0;

    virtual std::unique_ptr<IPluginCollector> CreatePluginCollector() const = 0;
    virtual std::shared_ptr<fault_event_reporter::IFaultEventReporter> CreateFaultEventReporter() const = 0;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_FACTORY_FACTORY_H
