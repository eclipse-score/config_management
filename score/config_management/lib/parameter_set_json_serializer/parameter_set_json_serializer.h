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

#ifndef SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_PARAMETER_SET_JSON_SERIALIZER_H
#define SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_PARAMETER_SET_JSON_SERIALIZER_H

#include "score/json/internal/model/object.h"
#include "score/result/result.h"

#include <score/string.hpp>

#include <cstdint>

namespace score
{
namespace config_management
{

/// @brief Serializes the parameters of a parameter set into the IPC payloads specified by the Parameter Set JSON
/// Format Contract.
///
/// @details This is deliberately not a generic JSON writer. Its purpose is to emit exactly the byte layout pinned by
/// the contract, so that a payload never exceeds the buffer size computed at build time. The payload structure is
/// therefore fixed by the interface, and only the parameters are passed in:
///  - SerializeParameters():   {"<name>":<value>,...}                                (ConfigCalibration)
///  - SerializeParameterSet(): {"parameters":{"<name>":<value>,...},"qualifier":<n>} (InternalConfigProvider)
///
/// Each parameter value must be a boolean, a number or a (nested) list thereof. Any other value (e.g. an object or
/// null) is rejected with an error.
class ParameterSetJsonSerializer
{
  public:
    ParameterSetJsonSerializer() = default;
    virtual ~ParameterSetJsonSerializer() = default;

    ParameterSetJsonSerializer(ParameterSetJsonSerializer&&) = delete;
    ParameterSetJsonSerializer(const ParameterSetJsonSerializer&) = delete;
    ParameterSetJsonSerializer& operator=(ParameterSetJsonSerializer&&) = delete;
    ParameterSetJsonSerializer& operator=(const ParameterSetJsonSerializer&) = delete;

    /// @brief Serializes the parameters as one JSON object with one member per parameter (ConfigCalibration payload).
    /// @param parameters One member per parameter: member name = parameter name, member value = parameter value.
    /// @return The serialized payload, or an error if a parameter value cannot be serialized as per the contract.
    virtual score::Result<score::cpp::pmr::string> SerializeParameters(const score::json::Object& parameters) const = 0;

    /// @brief Serializes the parameters and qualifier as {"parameters":{...},"qualifier":<n>}
    /// (InternalConfigProvider payload).
    /// @param parameters One member per parameter: member name = parameter name, member value = parameter value.
    /// @param qualifier  The underlying value of the ParameterSetQualifier, a single decimal digit (0..9, BUD-02).
    /// @return The serialized payload, or an error if the qualifier is greater than 9 or a parameter value cannot be
    /// serialized as per the contract.
    virtual score::Result<score::cpp::pmr::string> SerializeParameterSet(const score::json::Object& parameters,
                                                                  std::uint8_t qualifier) const = 0;
};

}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_PARAMETER_SET_JSON_SERIALIZER_H
