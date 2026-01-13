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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_DETAILS_MW_COM_GENERATED_SERVICE_INTERNAL_CONFIG_PROVIDER_TYPE_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_DETAILS_MW_COM_GENERATED_SERVICE_INTERNAL_CONFIG_PROVIDER_TYPE_H

#include "score/mw/com/types.h"

#include <cstdint>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace mw_com_icp_types
{

using ParameterSetName = std::array<std::uint8_t, 41>;

enum class InitialQualifierState : std::uint8_t
{
    kUndefined = 0,
    kInProgress = 1,
    kDefault = 2,
    kQualifying = 3,
    kUnqualified = 4,
    kQualified = 5
};

}  // namespace mw_com_icp_types
template <typename Trait>
class InternalConfigProviderInterface : public Trait::Base
{
  public:
    using Trait::Base::Base;
    typename Trait::template Event<mw_com_icp_types::ParameterSetName> last_updated_parameterset{
        *this,
        "last_updated_parameterset"};

    typename Trait::template Field<mw_com_icp_types::InitialQualifierState> initial_qualifier_state{
        *this,
        "initial_qualifier_state"};
};

using InternalConfigProviderSkeleton = mw::com::AsSkeleton<InternalConfigProviderInterface>;

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_SERVICES_DETAILS_MW_COM_GENERATED_SERVICE_INTERNAL_CONFIG_PROVIDER_TYPE_H
