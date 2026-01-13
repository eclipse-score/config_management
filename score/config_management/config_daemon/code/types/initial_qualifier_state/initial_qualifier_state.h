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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_TYPES_INITIAL_QUALIFIER_STATE_INITIAL_QUALIFIER_STATE_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_TYPES_INITIAL_QUALIFIER_STATE_INITIAL_QUALIFIER_STATE_H

#include <cstdint>

namespace score
{
namespace config_management
{
namespace config_daemon
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

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_TYPES_INITIAL_QUALIFIER_STATE_INITIAL_QUALIFIER_STATE_H
