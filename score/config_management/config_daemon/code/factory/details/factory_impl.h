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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_FACTORY_DETAILS_FACTORY_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_FACTORY_DETAILS_FACTORY_IMPL_H

#include "score/config_management/config_daemon/code/factory/factory.h"
#include "score/config_management/config_daemon/code/factory/infrastructure_factory.h"

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class FactoryImpl final : public Factory
{
  public:
    FactoryImpl();
    ~FactoryImpl() override = default;
    FactoryImpl(FactoryImpl&&) = delete;
    FactoryImpl(const FactoryImpl&) = delete;

    FactoryImpl& operator=(FactoryImpl&&) = delete;
    FactoryImpl& operator=(const FactoryImpl&) = delete;

    mw::service::ProvidedServicesContainer CreateInternalConfigProviderService(
        const std::shared_ptr<data_model::IParameterSetCollection> read_only_parameter_data_interface) const override;
    LastUpdatedParameterSetSender CreateLastUpdatedParameterSetSender(
        mw::service::ProvidedServicesContainer& services) override;
    InitialQualifierStateSender CreateInitialQualifierStateSender(
        mw::service::ProvidedServicesContainer& services) override;

    std::shared_ptr<data_model::IParameterSetCollectionManager> CreateParameterSetCollectionManager(
        std::vector<std::shared_ptr<IPlugin>>& plugins) const override;
    std::shared_ptr<fault_event_reporter::IFaultEventReporter> CreateFaultEventReporter() const override;

    std::unique_ptr<IPluginCollector> CreatePluginCollector() const override;

  private:
    std::unique_ptr<InfrastructureFactory> infrastructure_factory_;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_FACTORY_DETAILS_FACTORY_IMPL_H
