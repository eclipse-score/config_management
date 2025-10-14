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

#ifndef CODE_DATA_MODEL_ERROR_ERROR_H
#define CODE_DATA_MODEL_ERROR_ERROR_H

#include "score/result/error.h"
#include "score/result/error_code.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

/// @brief Represents all errors that can be returned by Data Model
enum class DataModelError : score::result::ErrorCode
{
    kParameterMissedError,
    kConvertingError,
    kParsingError,
    kParameterSetNotFound,
    kParametersNotFound,
    kParentParameterDataNotfound,
    kParameterSetNotCalibratable,
    kParameterAlreadyExists,
};

/// @brief ADL overload to fulfill design requirements from lib/result
score::result::Error MakeError(const DataModelError code, const std::string_view user_message = "") noexcept;

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_DATA_MODEL_ERROR_ERROR_H
