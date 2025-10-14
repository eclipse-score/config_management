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

#ifndef CODE_DATA_MODEL_PARAMETER_SET_QUALIFIER_H
#define CODE_DATA_MODEL_PARAMETER_SET_QUALIFIER_H

#include <cstdint>

namespace score
{
namespace config_management
{
namespace config_daemon
{
enum class ParameterSetQualifier : std::uint8_t
{
    kUnqualified,
    kQualified,
    kDefault,
    kModified
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_DATA_MODEL_PARAMETER_SET_QUALIFIER_H
