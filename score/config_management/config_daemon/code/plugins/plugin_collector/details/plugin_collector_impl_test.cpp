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

#include "score/config_management/config_daemon/code/plugins/plugin_collector/details/plugin_collector_impl.h"
#include "score/config_management/config_daemon/code/plugins/plugin_creator_mock.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace test
{

namespace
{

using testing::_;
using testing::ByMove;
using testing::Exactly;
using testing::InSequence;
using testing::Invoke;
using testing::Matcher;
using testing::Return;
using testing::ReturnRef;
using testing::Sequence;
using testing::StrEq;

}  // namespace

class PluginCollectorFixture : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        plugin_collector_ = std::make_unique<PluginCollector>();
    }

    void TearDown() override {}

    std::unique_ptr<PluginCollector> plugin_collector_;
};

TEST_F(PluginCollectorFixture, PluginCollectorCreatePlugins)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::PluginCollector::CreatePlugins()");
    RecordProperty("Description", "This test ensures that CreatePlugins would return vector of Plugins");

    ASSERT_EQ((plugin_collector_->CreatePlugins()).size(), 0);
}

}  // namespace test
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
