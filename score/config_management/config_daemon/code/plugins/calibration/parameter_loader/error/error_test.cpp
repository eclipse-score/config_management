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
#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/error/error.h"

#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

void TestMessage(ParameterLoaderError error, const char* message)
{
    EXPECT_EQ(MakeError(error).Message(), message);
}

TEST(ParameterLoaderError, CanConvertToString)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::MakeError");
    RecordProperty("Description", "Verifies that MakeError method will create error with correct code and message");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");

    TestMessage(ParameterLoaderError::kFailedToFindCodingParamValuesKey, "Failed to find 'codingParamValues' key");
    TestMessage(ParameterLoaderError::kInvalidCodingParamValuesKey, "Invalid 'codingParamValues' value");
    TestMessage(ParameterLoaderError::kCodingValueNotAvailable, "Coding value is not available for parameter");
    TestMessage(ParameterLoaderError::kFailedToInsertValue, "Failed to insert parameter data");
    TestMessage(ParameterLoaderError::kFailedToFindCodingParamNameKey, "Failed to find 'codingParamName' key");
    TestMessage(ParameterLoaderError::kInvalidCodingParamNameKeyValue, "Invalid 'codingParamName' value");
    TestMessage(ParameterLoaderError::kParameterSetMappingIsNullptr, "ParameterSetMapping is nullptr");
    TestMessage(ParameterLoaderError::kFailedToGetCodingParameterValue, "Failed to get coding parameter value");
    TestMessage(ParameterLoaderError::kFailedToGetParameterSetForParameter,
                "Failed to get parameter set for parameter");

    TestMessage(static_cast<ParameterLoaderError>(0xff), "Unknown Error!");
    TestMessage(static_cast<ParameterLoaderError>(-1), "Unknown Error!");
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
