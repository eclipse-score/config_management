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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_ERROR_ERROR_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_ERROR_ERROR_H

#include "score/result/error.h"
#include "score/result/error_code.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

/// @brief Represents all errors that can be returned by Parameter Loader
enum class ParameterLoaderError : score::result::ErrorCode
{
    kFailedToFindCodingParamValuesKey,
    kInvalidCodingParamValuesKey,
    kCodingValueNotAvailable,
    kFailedToInsertValue,
    kFailedToFindCodingParamNameKey,
    kInvalidCodingParamNameKeyValue,
    kParameterSetMappingIsNullptr,
    kFailedToGetCodingParameterValue,
    kFailedToGetParameterSetForParameter,
};

/// @brief ADL overload to fulfill design requirements from lib/result
score::result::Error MakeError(const ParameterLoaderError code, const std::string_view user_message = "") noexcept;

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_ERROR_ERROR_H
