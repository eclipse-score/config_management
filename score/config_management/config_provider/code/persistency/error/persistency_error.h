// *******************************************************************************
// Copyright (c) 2025, 2026 Contributors to the Eclipse Foundation
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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_ERROR_PERSISTENCY_ERROR_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_ERROR_PERSISTENCY_ERROR_H

#include "score/result/error.h"
#include "score/result/error_code.h"

namespace score
{
namespace config_management
{
namespace config_provider
{

/// @brief Represents all errors that can be returned by our persistency library
enum class PersistencyError : score::result::ErrorCode
{
    kDataNotFound,
    kUnableToSaveToPersistency
};

/// @brief ADL overload to fulfill design requirements from lib/result
score::result::Error MakeError(const PersistencyError code, const std::string_view user_message = "") noexcept;

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_ERROR_PERSISTENCY_ERROR_H
