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
#include "score/config_management/config_daemon/code/fault_event_reporter/details/fault_event_reporter_score_impl.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_score_types.h"
#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace fault_event_reporter
{
namespace test
{

class FaultEventReporterTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        reporter_ = std::make_shared<FaultEventReporter>();
    }
    std::shared_ptr<FaultEventReporter> reporter_;
};
TEST_F(FaultEventReporterTest, FaultEventReportPassedTest)
{
    RecordProperty("Description", "Verify return true if enum value is in range");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::fault_event_reporter::FaultEventReporter::Report()");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");

    reporter_->Initialize();
    EXPECT_EQ(reporter_->Report(static_cast<std::uint8_t>(FaultEventId::kUnkownError), true), true);
    EXPECT_EQ(reporter_->Report(2U, true), false);
}

TEST_F(FaultEventReporterTest, FaultEventReporterFailedTest)
{
    RecordProperty("Description", "Verify return false if enum value is out of range");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::fault_event_reporter::FaultEventReporter::ReportFaultId()");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");

    EXPECT_EQ(reporter_->Report(2U, true), false);
}

}  // namespace test
}  // namespace fault_event_reporter

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
