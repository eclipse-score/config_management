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

#ifndef CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_H
#define CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_H

#include "score/result/result.h"

#include <score/string.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class InternalConfigProviderServiceReactor
{
  public:
    InternalConfigProviderServiceReactor() = default;
    InternalConfigProviderServiceReactor(InternalConfigProviderServiceReactor&&) noexcept = delete;
    InternalConfigProviderServiceReactor(const InternalConfigProviderServiceReactor&) noexcept = delete;
    InternalConfigProviderServiceReactor& operator=(InternalConfigProviderServiceReactor&&) noexcept = delete;
    InternalConfigProviderServiceReactor& operator=(const InternalConfigProviderServiceReactor&) noexcept = delete;
    virtual ~InternalConfigProviderServiceReactor() noexcept = default;

    virtual score::Result<score::cpp::pmr::string> GetParameterSet(const std::string_view parameter_set_name) = 0;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_SERVICES_INTERNAL_CONFIG_PROVIDER_SERVICE_REACTOR_H
