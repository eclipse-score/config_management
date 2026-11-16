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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PROXIES_DETAILS_INTERNAL_CONFIG_PROVIDER_PROXY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PROXIES_DETAILS_INTERNAL_CONFIG_PROVIDER_PROXY_H

#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"

namespace score
{
namespace config_management
{
namespace config_provider
{

using InternalConfigProviderProxy =
    ::score::mw::com::AsProxy<score::config_management::config_daemon::InternalConfigProviderInterface>;

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PROXIES_DETAILS_INTERNAL_CONFIG_PROVIDER_PROXY_H
