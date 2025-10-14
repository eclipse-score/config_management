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

#ifndef CODE_SERVICES_DETAILS_MW_COM_INTERNAL_CONFIG_PROVIDER_SERVICE_IMPL_H
#define CODE_SERVICES_DETAILS_MW_COM_INTERNAL_CONFIG_PROVIDER_SERVICE_IMPL_H

#include "score/mw/log/logger.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces/read_only_parameterset_collection.h"
#include "score/config_management/config_daemon/code/services/details/mw_com/generated_service/internal_config_provider_type.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_reactor.h"
#include <score/string_view.hpp>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class InternalConfigProviderService final : public IInternalConfigProviderService
{
  public:
    static score::Result<InternalConfigProviderService> Create(
        std::shared_ptr<InternalConfigProviderServiceReactor> internal_config_provider_service_reactor,
        const mw::com::InstanceSpecifier& instance_specifier);

    void SetInitialQualifierState(const config_daemon::InitialQualifierState initial_qualifier_state) noexcept override;
    bool SendLastUpdatedParameterSet(const std::string_view parameter_set_name) noexcept override;

    void StartService() override;
    void StopService() override;

  private:
    explicit InternalConfigProviderService(
        std::shared_ptr<InternalConfigProviderServiceReactor> internal_config_provider_service_reactor,
        InternalConfigProviderSkeleton icp_skeleton);
    const std::shared_ptr<InternalConfigProviderServiceReactor> internal_config_provider_service_reactor_;
    InternalConfigProviderSkeleton icp_skeleton_;
    config_daemon::InitialQualifierState initial_qualifier_state_;
    mw::log::Logger& logger_;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_SERVICES_DETAILS_MW_COM_INTERNAL_CONFIG_PROVIDER_SERVICE_IMPL_H
