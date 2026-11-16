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

#ifndef SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_ERROR_ERROR_H
#define SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_ERROR_ERROR_H

#include "score/result/error.h"
#include "score/result/error_code.h"

#include <string_view>

namespace score
{
namespace config_management
{

enum class ParameterSetJsonSerializerError : score::result::ErrorCode
{
    kNonFiniteNumber,
    kUnsupportedNumberType,
    kUnsupportedValueType,
    kQualifierOutOfRange,
};

score::result::Error MakeError(const ParameterSetJsonSerializerError code,
                               const std::string_view user_message = "") noexcept;

}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_ERROR_ERROR_H
