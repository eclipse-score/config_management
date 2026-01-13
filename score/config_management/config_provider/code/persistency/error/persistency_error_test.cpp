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
#include "score/config_management/config_provider/code/persistency/error/persistency_error.h"

#include <score/utility.hpp>

#include <gtest/gtest.h>

#include <score/utility.hpp>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace coding
{
namespace
{

void TestMessage(PersistencyError error, const char* message)
{
    EXPECT_EQ(MakeError(error).Message(), message);
}

TEST(PersistencyErrorTest, CanConvertToString)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::coding::MakeError()");
    RecordProperty("Description", "This test verifies MakeError method with all possible values.");
    // Given all possible PersistencyError values
    // When MakeError is called
    // Then the correct message is returned
    TestMessage(PersistencyError::kDataNotFound, "Data not found");
    TestMessage(PersistencyError::kUnableToSaveToPersistency, "Unable to save data to persistency");
}

TEST(PersistencyErrorTest, ValueOutOfRangeResultsInAssertionFailure)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::coding::MakeError()");
    RecordProperty("Description", "This test verifies MakeError will terminate once an unknown error code is passed.");
    // Given an out of range PersistencyError value
    // When MakeError is called
    // Then an assertion failure occurs
    ASSERT_DEATH(
        {
            MakeError(
                static_cast<PersistencyError>(score::cpp::to_underlying(PersistencyError::kUnableToSaveToPersistency) + 1))
                .Message();
        },
        "");
    ASSERT_DEATH(
        {
            MakeError(
                static_cast<PersistencyError>(score::cpp::to_underlying(PersistencyError::kUnableToSaveToPersistency) + 42))
                .Message();
        },
        "");
    ASSERT_DEATH({ MakeError(static_cast<PersistencyError>(0xFF)).Message(); }, "");
}

}  // namespace
}  // namespace coding
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
