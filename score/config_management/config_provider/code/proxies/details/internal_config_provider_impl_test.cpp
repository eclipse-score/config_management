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

#include "score/config_management/config_provider/code/proxies/details/internal_config_provider_impl.h"

#include "score/config_management/config_provider/code/config_provider/error/error.h"
#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>

namespace score
{
namespace config_management
{
namespace config_provider
{

namespace
{

const std::chrono::milliseconds kZeroTimeout{0};
const AdditionalShmSizing kSizing{/*max_payload_size=*/64U, /*max_name_length=*/16U};
using MwComInitialQualifierStateType = score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState;

class InternalConfigProviderTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto proxy = std::make_unique<InternalConfigProvider::InternalMwComProxy>();
        state_ = proxy->GetState();
        unit_ = std::make_unique<InternalConfigProvider>(std::move(proxy));
    }

    std::shared_ptr<InternalConfigProviderProxyFakeState> state_;
    std::unique_ptr<InternalConfigProvider> unit_;
};

TEST_F(InternalConfigProviderTest, ConstructorSubscribesToInitialQualifierState)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::InternalConfigProvider::InternalConfigProvider()");
    RecordProperty("Description", "This test verifies a successful creation of InternalConfigProvider.");

    EXPECT_EQ(state_->initial_qualifier_state_subscriptions, 1U);
}

TEST_F(InternalConfigProviderTest, DestructorUnsubscribesFromLastUpdatedParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description", "This test verifies the destructor unsubscribes from the event.");

    unit_.reset();

    EXPECT_EQ(state_->last_updated_unsubscriptions, 1U);
}

class InternalConfigProviderGetInitialQualifierStatePassTest
    : public InternalConfigProviderTest,
      public ::testing::WithParamInterface<std::tuple<MwComInitialQualifierStateType, InitialQualifierState>>
{
};

TEST_P(InternalConfigProviderGetInitialQualifierStatePassTest, GetInitialQualifierState_Pass)
{
    RecordProperty("Priority", "3");
    RecordProperty("lobster-tracing", "ConfigProvider.GetInitialQualifierState");
    RecordProperty("Verifies", " 11397333");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("ASIL", "B");
    RecordProperty("Description",
                   "11397333: This test makes sure InternalConfigProvider can get InitialQualifierState through a "
                   "method GetInitialQualifierState.");

    state_->initial_qualifier_state_samples.push_back(std::get<0>(GetParam()));

    const auto result = unit_->GetInitialQualifierState(kZeroTimeout);

    EXPECT_EQ(result, std::get<1>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(
    GetInitialQualifierStatePass,
    InternalConfigProviderGetInitialQualifierStatePassTest,
    testing::Values(
        std::make_tuple(MwComInitialQualifierStateType::kDefault, InitialQualifierState::kDefault),
        std::make_tuple(MwComInitialQualifierStateType::kInProgress, InitialQualifierState::kInProgress),
        std::make_tuple(MwComInitialQualifierStateType::kQualified, InitialQualifierState::kQualified),
        std::make_tuple(MwComInitialQualifierStateType::kQualifying, InitialQualifierState::kQualifying),
        std::make_tuple(MwComInitialQualifierStateType::kUnqualified, InitialQualifierState::kUnqualified),
        std::make_tuple(MwComInitialQualifierStateType::kUndefined, InitialQualifierState::kUndefined),
        std::make_tuple(static_cast<MwComInitialQualifierStateType>(
                            std::numeric_limits<std::underlying_type_t<MwComInitialQualifierStateType>>::max()),
                        InitialQualifierState::kUndefined)));

TEST_F(InternalConfigProviderTest, GetInitialQualifierStateWithoutSampleReturnsUndefined)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Boundary test");
    RecordProperty("Description", "This test verifies kUndefined is returned while no sample was received.");

    EXPECT_EQ(unit_->GetInitialQualifierState(kZeroTimeout), InitialQualifierState::kUndefined);
}

TEST_F(InternalConfigProviderTest, GetParameterSetReturnsParsedJson)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description", "This test verifies the returned payload is parsed and the request is forwarded.");
    state_->response_content = R"({"a":1})";

    const auto result = unit_->GetParameterSet("MySet", kZeroTimeout, kSizing);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(state_->last_requested_name, "MySet");
    EXPECT_EQ(state_->last_requested_max_payload_size, kSizing.max_payload_size);
}

TEST_F(InternalConfigProviderTest, GetParameterSetFailsForTooLongName)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test verifies names exceeding max_name_length are rejected.");

    const auto result = unit_->GetParameterSet(std::string(kSizing.max_name_length + 1U, 'n'), kZeroTimeout, kSizing);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConfigProviderError::kParameterSetNameTooLong);
}

TEST_F(InternalConfigProviderTest, GetParameterSetFailsWhenAllocationFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test verifies an allocation failure of the method arguments is reported.");
    state_->fail_allocate = true;

    const auto result = unit_->GetParameterSet("MySet", kZeroTimeout, kSizing);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConfigProviderError::kMethodArgumentAllocationFailed);
}

TEST_F(InternalConfigProviderTest, GetParameterSetFailsWhenCallFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test verifies a failing method call is reported.");
    state_->fail_call = true;

    const auto result = unit_->GetParameterSet("MySet", kZeroTimeout, kSizing);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConfigProviderError::kGetParameterSetCallFailed);
}

TEST_F(InternalConfigProviderTest, GetParameterSetMapsNotFoundSentinel)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test verifies the not-found sentinel maps to kParameterSetNotFound.");
    state_->response_content = std::string{config_daemon::mw_com_icp_types::kParameterSetNotFoundContent};

    const auto result = unit_->GetParameterSet("MySet", kZeroTimeout, kSizing);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConfigProviderError::kParameterSetNotFound);
}

TEST_F(InternalConfigProviderTest, GetParameterSetMapsPayloadTooLargeSentinel)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test verifies the too-large sentinel maps to kParameterSetPayloadTooLarge.");
    state_->response_content = std::string{config_daemon::mw_com_icp_types::kParameterSetPayloadTooLargeContent};

    const auto result = unit_->GetParameterSet("MySet", kZeroTimeout, kSizing);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ConfigProviderError::kParameterSetPayloadTooLarge);
}

TEST_F(InternalConfigProviderTest, TrySubscribeSubscribesToLastUpdatedParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description", "This test verifies the event subscription.");

    EXPECT_TRUE(unit_->TrySubscribeToLastUpdatedParameterSetEvent(score::cpp::stop_token{}, [](const std::string_view) {}));
    EXPECT_EQ(state_->last_updated_subscriptions, 1U);
}

TEST_F(InternalConfigProviderTest, PollingRoutineReportsLastUpdatedParameterSets)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description", "This test verifies updated parameter set names reach the callback.");

    std::promise<std::string> reported;
    auto reported_future = reported.get_future();
    std::once_flag once;
    ASSERT_TRUE(unit_->TrySubscribeToLastUpdatedParameterSetEvent(score::cpp::stop_token{},
                                                                  [&reported, &once](const std::string_view name) {
                                                                      std::call_once(once, [&] {
                                                                          reported.set_value(std::string{name});
                                                                      });
                                                                  }));
    state_->last_updated_samples.push_back("UpdatedSet");

    unit_->StartParameterSetUpdatePollingRoutine(score::cpp::nullopt, std::chrono::milliseconds{10});

    ASSERT_EQ(reported_future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
    EXPECT_EQ(reported_future.get(), "UpdatedSet");
    unit_->StopParameterSetUpdatePollingRoutine();
}

TEST_F(InternalConfigProviderTest, CheckParameterSetUpdatesDoesNotReportWhenSampleRetrievalFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test verifies a failing sample retrieval produces no callback.");

    bool called{false};
    ASSERT_TRUE(unit_->TrySubscribeToLastUpdatedParameterSetEvent(score::cpp::stop_token{}, [&called](const std::string_view) {
        called = true;
    }));
    state_->last_updated_samples.push_back("UpdatedSet");
    state_->fail_last_updated_get_new_samples = true;

    unit_->CheckParameterSetUpdates();

    EXPECT_FALSE(called);
}

}  // namespace
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
