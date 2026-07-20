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
#include "score/config_management/config_daemon/code/plugins/calibration/error/error.h"

#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

void TestMessage(CalibrationError error, const char* message)
{
    EXPECT_EQ(MakeError(error).Message(), message);
}

TEST(CalibrationError, CanConvertToString)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::calibration::MakeError");
    RecordProperty("Description", "Verifies that MakeError method will create error with correct code and message");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");

    TestMessage(CalibrationError::kNullPtrFactoryError, "Factory is null ptr");
    TestMessage(CalibrationError::kParameterDataError, "Parameter data error");
    TestMessage(CalibrationError::kInitializationError, "Calibration initialization failed");
    TestMessage(static_cast<CalibrationError>(0xff), "Unknown Error!");
    TestMessage(static_cast<CalibrationError>(-1), "Unknown Error!");
}

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
