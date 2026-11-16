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

#ifndef SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_PARAMETER_SET_JSON_SERIALIZER_MOCK_H
#define SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_PARAMETER_SET_JSON_SERIALIZER_MOCK_H

#include "score/config_management/lib/parameter_set_json_serializer/parameter_set_json_serializer.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{

class ParameterSetJsonSerializerMock final : public ParameterSetJsonSerializer
{
  public:
    ~ParameterSetJsonSerializerMock() override = default;

    MOCK_METHOD(score::Result<score::cpp::pmr::string>, SerializeParameters, (const score::json::Object&), (const, override));
    MOCK_METHOD(score::Result<score::cpp::pmr::string>,
                SerializeParameterSet,
                (const score::json::Object&, std::uint8_t),
                (const, override));
};

}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_LIB_PARAMETER_SET_JSON_SERIALIZER_PARAMETER_SET_JSON_SERIALIZER_MOCK_H
