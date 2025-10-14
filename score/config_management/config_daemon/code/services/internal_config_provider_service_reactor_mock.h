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

#ifndef CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_MOCK_H
#define CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_MOCK_H

#include "score/config_management/config_daemon/code/services/internal_config_provider_service_reactor.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class InternalConfigProviderServiceReactorMock : public InternalConfigProviderServiceReactor
{
  public:
    InternalConfigProviderServiceReactorMock() = default;
    InternalConfigProviderServiceReactorMock(InternalConfigProviderServiceReactorMock&&) noexcept = delete;
    InternalConfigProviderServiceReactorMock(const InternalConfigProviderServiceReactorMock&) noexcept = delete;
    InternalConfigProviderServiceReactorMock& operator=(InternalConfigProviderServiceReactorMock&&) noexcept = delete;
    InternalConfigProviderServiceReactorMock& operator=(const InternalConfigProviderServiceReactorMock&) noexcept =
        delete;
    ~InternalConfigProviderServiceReactorMock() noexcept override = default;

    MOCK_METHOD(score::Result<score::cpp::pmr::string>,
                GetParameterSet,
                (const std::string_view parameter_set_name),
                (noexcept, override));
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_MOCK_H
