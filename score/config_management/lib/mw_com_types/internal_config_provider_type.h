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

#ifndef SCORE_CONFIG_MANAGEMENT_LIB_MW_COM_TYPES_INTERNAL_CONFIG_PROVIDER_TYPE_H
#define SCORE_CONFIG_MANAGEMENT_LIB_MW_COM_TYPES_INTERNAL_CONFIG_PROVIDER_TYPE_H

#include "score/config_management/lib/mw_com_types/runtime_sized_array.h"
#include "score/memory/shared/polymorphic_offset_ptr_allocator.h"
#include "score/mw/com/types.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace mw_com_icp_types
{

using config_management::mw_com_types::RuntimeSizedArray;

/// Maximum parameter set name length for the event (including null terminator).
/// This is a fixed size for the ParameterSetNameEvent array used by the
/// last_updated_parameter_set event.
constexpr std::size_t kMaxParameterSetNameSize{41U};

/// Sentinel written into ParameterSetContent by the skeleton (internal_config_provider_service_impl.cpp) when the
/// requested parameter set name does not exist. The proxy (internal_config_provider_impl.cpp) checks for this
/// value and returns ConfigProviderError::kParameterSetNotFound instead of attempting JSON parsing.
constexpr std::string_view kParameterSetNotFoundContent{"Key not found"};

/// Sentinel written into ParameterSetContent by the skeleton when the requested parameter set's serialized JSON
/// content does not fit into the buffer allocated by the proxy for this call. The proxy checks for this value and
/// returns ConfigProviderError::kParameterSetPayloadTooLarge instead of attempting JSON parsing.
constexpr std::string_view kParameterSetPayloadTooLargeContent{"Payload too large"};

/// Smallest payload buffer size BufferSizeReport::GetMaxBufferSizeInfo() may ever return (see buffer_size_report.h):
/// large enough to hold either sentinel above plus a null terminator, regardless of how small every real parameter
/// set's payload is.
constexpr std::size_t kMinParameterSetContentBufferSize{
    std::max(kParameterSetNotFoundContent.size(), kParameterSetPayloadTooLargeContent.size()) + 1U};

using ArrayValueType = std::uint8_t;
/// Type used for the last_updated_parameter_set event (fixed-size, not semi-dynamic).
using ParameterSetNameEvent = std::array<ArrayValueType, kMaxParameterSetNameSize>;
/// Types used for the get_parameter_set method (semi-dynamic, allocated in shared memory).
using ParameterSetName =
    RuntimeSizedArray<ArrayValueType, score::memory::shared::PolymorphicOffsetPtrAllocator<ArrayValueType>>;
using ParameterSetContent =
    RuntimeSizedArray<ArrayValueType, score::memory::shared::PolymorphicOffsetPtrAllocator<ArrayValueType>>;

using GetParameterSet = ParameterSetContent(ParameterSetName, std::size_t);

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
    typename Trait::template Event<mw_com_icp_types::ParameterSetNameEvent> last_updated_parameter_set{
        *this,
        "last_updated_parameter_set"};

    typename Trait::template Field<mw_com_icp_types::InitialQualifierState> initial_qualifier_state{
        *this,
        "initial_qualifier_state"};

    typename Trait::template Method<mw_com_icp_types::GetParameterSet> get_parameter_set{*this, "get_parameter_set"};
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_LIB_MW_COM_TYPES_INTERNAL_CONFIG_PROVIDER_TYPE_H
