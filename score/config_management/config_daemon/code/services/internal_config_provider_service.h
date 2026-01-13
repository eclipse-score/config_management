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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_H

#include "platform/aas/mw/service/provided_service.h"
#include "score/config_management/config_daemon/code/types/initial_qualifier_state/initial_qualifier_state.h"
#include <score/callback.hpp>
#include <string>

namespace score
{
namespace config_management
{
namespace config_daemon
{

using LastUpdatedParameterSetSender = score::cpp::callback<bool(const std::string_view), 64U>;
using InitialQualifierStateSender = score::cpp::callback<void(const InitialQualifierState), 64U>;

class IInternalConfigProviderService : public ::score::mw::service::ProvidedService
{
  public:
    IInternalConfigProviderService() noexcept = default;
    virtual ~IInternalConfigProviderService() noexcept = default;

    virtual void SetInitialQualifierState(const InitialQualifierState initial_qualifier_state) noexcept = 0;
    virtual bool SendLastUpdatedParameterSet(const std::string_view parameter_set_name) noexcept = 0;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_H
