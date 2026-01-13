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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_DETAILS_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_DETAILS_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_IMPL_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces/read_only_parameterset_collection.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_reactor.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{

class InternalConfigProviderServiceReactorImpl final : public InternalConfigProviderServiceReactor
{
  public:
    explicit InternalConfigProviderServiceReactorImpl(
        std::shared_ptr<data_model::IReadOnlyParameterSetCollection> read_only_parameter_data_interface);
    score::Result<score::cpp::pmr::string> GetParameterSet(const std::string_view parameter_set_name) override;

  private:
    const std::shared_ptr<data_model::IReadOnlyParameterSetCollection> read_only_parameter_data_interface_;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_DETAILS_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_IMPL_H
