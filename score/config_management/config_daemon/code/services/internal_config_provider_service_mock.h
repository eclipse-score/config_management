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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_MOCK_H

#include "score/config_management/config_daemon/code/services/internal_config_provider_service.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
class InternalConfigProviderServiceMock final : public IInternalConfigProviderService
{
  public:
    InternalConfigProviderServiceMock() = default;
    InternalConfigProviderServiceMock(InternalConfigProviderServiceMock&&) noexcept = delete;
    InternalConfigProviderServiceMock(const InternalConfigProviderServiceMock&) noexcept = delete;
    InternalConfigProviderServiceMock& operator=(InternalConfigProviderServiceMock&&) noexcept = delete;
    InternalConfigProviderServiceMock& operator=(const InternalConfigProviderServiceMock&) noexcept = delete;
    virtual ~InternalConfigProviderServiceMock() noexcept = default;

    MOCK_METHOD(void, StartService, (), (override));
    MOCK_METHOD(void, StopService, (), (override));

    MOCK_METHOD(void, SetInitialQualifierState, (const InitialQualifierState), (noexcept, override));
    MOCK_METHOD(bool, SendLastUpdatedParameterSet, (const std::string_view), (noexcept, override));
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_MOCK_H
