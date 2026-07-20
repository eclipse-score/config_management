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
#include "score/config_management/config_daemon/code/plugins/calibration/details/calibration_impl.h"
#include "score/config_management/config_daemon/code/plugins/calibration/plugin_creator/calibration_plugin_creator_impl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{
namespace test
{

class CalibrationPluginCreatorImplFixture : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        calibration_plugin_creator_ = std::make_unique<CalibrationPluginCreatorImpl>();
    }

    void TearDown() override {}

    std::unique_ptr<CalibrationPluginCreatorImpl> calibration_plugin_creator_;
};

TEST_F(CalibrationPluginCreatorImplFixture, CodingPluginCreatorCreatePlugin)
{
    RecordProperty("Priority", "3");
    RecordProperty("ASIL", "B");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::coding::CalibrationPluginCreator::CreatePlugin()");
    RecordProperty("Description", "This test ensures that CreatePlugin would return CalibrationPlugin");

    auto plugin = calibration_plugin_creator_->CreatePlugin();
    EXPECT_NE(plugin, nullptr);
    auto calibration = std::dynamic_pointer_cast<CalibrationImpl>(plugin);
    EXPECT_NE(calibration, nullptr);
}

}  // namespace test
}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
