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

#include "score/config_management/config_daemon/code/data_model/error/error.h"

#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

void TestMessage(DataModelError error, const char* message)
{
    EXPECT_EQ(MakeError(error).Message(), message);
}

TEST(DataModelErrorTest, CanConvertToString)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("Verifies", "::score::config_management::config_daemon::data_model::MakeError()");
    RecordProperty("Description", "This test verifies MakeError method with all possible values");

    TestMessage(DataModelError::kParameterMissedError, "Parameter Missed error");
    TestMessage(DataModelError::kConvertingError, "Converting error");
    TestMessage(DataModelError::kParsingError, "Parsing error");
    TestMessage(DataModelError::kParameterSetNotFound, "Parameter set not found");
    TestMessage(DataModelError::kParametersNotFound, "Parameters not found");
    TestMessage(DataModelError::kParentParameterDataNotfound, "Parent ParameterData not found");
    TestMessage(DataModelError::kParameterSetNotCalibratable, "Parameter Set is not calibratable");
    TestMessage(DataModelError::kParameterAlreadyExists, "Parameter with input name already exists");
    TestMessage(static_cast<DataModelError>(0xff), "Unknown Error!");
    TestMessage(static_cast<DataModelError>(-1), "Unknown Error!");
}

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
