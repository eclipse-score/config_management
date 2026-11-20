// *******************************************************************************
// Copyright (c) 2026 Contributors to the Eclipse Foundation
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

#ifndef SCORE_CONFIG_MANAGEMENT_LIB_MW_COM_TYPES_CONFIG_CALIBRATION_TYPE_H
#define SCORE_CONFIG_MANAGEMENT_LIB_MW_COM_TYPES_CONFIG_CALIBRATION_TYPE_H

#include "score/config_management/lib/mw_com_types/runtime_sized_array.h"
#include "score/memory/shared/polymorphic_offset_ptr_allocator.h"
#include "score/mw/com/types.h"

#include <cstdint>

namespace score
{
namespace config_management
{
namespace mw_com_types
{

using ArrayValueType = std::uint8_t;

using ParameterSetName =
    RuntimeSizedArray<ArrayValueType, score::memory::shared::PolymorphicOffsetPtrAllocator<ArrayValueType>>;
using ParameterSetPayload =
    RuntimeSizedArray<ArrayValueType, score::memory::shared::PolymorphicOffsetPtrAllocator<ArrayValueType>>;

/// @brief Outcome of an update_parameter_set call.
enum class UpdateParameterSetResult : std::uint8_t
{
    kOk = 0U,
    kParsingError = 1U,
    kParameterSetNotFound = 2U,
    kParametersNotFound = 3U,
    kSendLastUpdatedParameterSetFailed = 4U,
    kParameterSetNotCalibratable = 5U,
    kUnknownError = 6U
};

/// @brief Signature of the update_parameter_set method: both arguments travel from the proxy to the skeleton, the
/// result travels back.
using UpdateParameterSet = UpdateParameterSetResult(ParameterSetName, ParameterSetPayload);

}  // namespace mw_com_types

/// @brief ConfigCalibration service interface.
///
/// @details The method name must match the methodName of the corresponding entry in mw_com_config.json, otherwise the
/// binding cannot be set up and service discovery never completes.
template <typename Trait>
class ConfigCalibrationInterface : public Trait::Base
{
  public:
    using Trait::Base::Base;

    typename Trait::template Method<mw_com_types::UpdateParameterSet> update_parameter_set{*this,
                                                                                           "update_parameter_set"};
};

}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_LIB_MW_COM_TYPES_CONFIG_CALIBRATION_TYPE_H
