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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_INITIAL_QUALIFIER_STATE_TYPES_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_INITIAL_QUALIFIER_STATE_TYPES_H

#include <score/callback.hpp>

namespace score
{
namespace config_management
{
namespace config_provider
{

// According to AUTOSAR.ENUM.EXPLICIT_BASE_TYPE: Enumeration base type should be specified
enum class InitialQualifierState : std::uint8_t
{
    kUndefined,
    kInProgress,
    kDefault,
    kQualifying,
    kUnqualified,
    kQualified
};

using InitialQualifierStateNotifierCallbackType = score::cpp::callback<void(const InitialQualifierState&)>;

enum class InitialQualifierState : std::uint8_t
{
    kUndefined,
    kInProgress,
    kDefault,
    kQualifying,
    kUnqualified,
    kQualified
};

using InitialQualifierStateNotifierCallbackType = score::cpp::callback<void(const InitialQualifierState&)>;

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_CONFIG_PROVIDER_INITIAL_QUALIFIER_STATE_TYPES_H
