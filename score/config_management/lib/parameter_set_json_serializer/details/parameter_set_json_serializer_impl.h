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

#ifndef SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_DETAILS_PARAMETER_SET_JSON_SERIALIZER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_DETAILS_PARAMETER_SET_JSON_SERIALIZER_IMPL_H

#include "score/config_management/lib/parameter_set_json_serializer/parameter_set_json_serializer.h"

namespace score
{
namespace config_management
{

/// @brief Emits the parameter set IPC payloads as specified by the Parameter Set JSON Format Contract, so that the
/// payload never exceeds the buffer size computed at build time by the buffer_size_calculator.
class ParameterSetJsonSerializerImpl final : public ParameterSetJsonSerializer
{
  public:
    ParameterSetJsonSerializerImpl() = default;

    score::Result<score::cpp::pmr::string> SerializeParameters(const score::json::Object& parameters) const override;
    score::Result<score::cpp::pmr::string> SerializeParameterSet(const score::json::Object& parameters,
                                                          std::uint8_t qualifier) const override;
};

}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_DETAILS_PARAMETER_SET_JSON_SERIALIZER_IMPL_H
