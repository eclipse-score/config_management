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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_SERVICES_DETAILS_INTERNAL_CONFIG_PROVIDER_SERVICE_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_SERVICES_DETAILS_INTERNAL_CONFIG_PROVIDER_SERVICE_IMPL_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces/read_only_parameterset_collection.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_reactor.h"
#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"
#include "score/mw/log/logger.h"
#include <score/string_view.hpp>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

using InternalConfigProviderSkeleton = score::mw::com::AsSkeleton<InternalConfigProviderInterface>;

class InternalConfigProviderService final : public IInternalConfigProviderService
{
  public:
    static score::Result<std::unique_ptr<InternalConfigProviderService>> Create(
        std::shared_ptr<InternalConfigProviderServiceReactor> internal_config_provider_service_reactor,
        const score::mw::com::InstanceSpecifier& instance_specifier);
    InternalConfigProviderService(InternalConfigProviderService&&) noexcept = delete;
    InternalConfigProviderService(const InternalConfigProviderService&) noexcept = delete;

    void SetInitialQualifierState(const config_daemon::InitialQualifierState initial_qualifier_state) noexcept override;
    bool SendLastUpdatedParameterSet(const std::string_view parameter_set_name) noexcept override;

    Result<void> Start() override;
    void Stop() noexcept override;

    explicit InternalConfigProviderService(
        std::shared_ptr<InternalConfigProviderServiceReactor> internal_config_provider_service_reactor,
        InternalConfigProviderSkeleton icp_skeleton);

  private:
    const std::shared_ptr<InternalConfigProviderServiceReactor> internal_config_provider_service_reactor_;
    InternalConfigProviderSkeleton icp_skeleton_;
    config_daemon::InitialQualifierState initial_qualifier_state_;
    mw::log::Logger& logger_;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_SERVICES_DETAILS_INTERNAL_CONFIG_PROVIDER_SERVICE_IMPL_H
