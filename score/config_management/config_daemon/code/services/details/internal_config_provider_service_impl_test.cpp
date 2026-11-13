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

#include "score/config_management/config_daemon/code/services/details/internal_config_provider_service_impl.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_reactor_mock.h"
#include "score/result/result.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <string>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace test
{

const auto kICPServiceInstanceSpecifierName =
    score::mw::com::InstanceSpecifier::Create(
        std::string("ConfigDaemon/ConfigDaemon_RootSwc/InternalConfigProviderAppPPort"))
        .value();

class InternalConfigProviderServiceMwComTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        reactor_mock_ = std::make_shared<InternalConfigProviderServiceReactorMock>();
    }
    void TearDown() override
    {
        InternalConfigProviderSkeleton::FailCreate() = false;
    }

    std::unique_ptr<InternalConfigProviderService> CreateService()
    {
        auto skeleton = InternalConfigProviderSkeleton::Create(kICPServiceInstanceSpecifierName).value();
        state_ = skeleton.GetState();
        return std::make_unique<InternalConfigProviderService>(reactor_mock_, std::move(skeleton));
    }

    static std::string ToString(const mw_com_icp_types::ParameterSetContent& content)
    {
        std::string result;
        for (std::size_t i = 0U; i < content.size(); ++i)
        {
            result.push_back(static_cast<char>(content.Data()[i]));
        }
        return result;
    }

    std::string InvokeHandler(const std::string& name, const std::size_t max_payload_size)
    {
        mw_com_icp_types::ParameterSetName name_array{
            score::memory::shared::PolymorphicOffsetPtrAllocator<mw_com_icp_types::ArrayValueType>{}};
        name_array.ReserveOnce(name.size());
        for (const auto c : name)
        {
            name_array.emplace_back(static_cast<mw_com_icp_types::ArrayValueType>(c));
        }
        mw_com_icp_types::ParameterSetContent content{
            score::memory::shared::PolymorphicOffsetPtrAllocator<mw_com_icp_types::ArrayValueType>{}};
        state_->get_parameter_set_handler(content, name_array, max_payload_size);
        return ToString(content);
    }

    std::shared_ptr<InternalConfigProviderServiceReactorMock> reactor_mock_;
    std::shared_ptr<InternalConfigProviderSkeletonFakeState> state_;
};

TEST_F(InternalConfigProviderServiceMwComTest, StartService)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::InternalConfigProviderService::Start()");
    RecordProperty("Description",
                   "This test ensures Start() method of InternalConfigProviderService would trigger OfferService "
                   "of InternalConfigProviderSkeleton");
    auto service = CreateService();
    ASSERT_TRUE(service->Start().has_value());
    EXPECT_TRUE(state_->offered);
    EXPECT_TRUE(static_cast<bool>(state_->get_parameter_set_handler));
}

TEST_F(InternalConfigProviderServiceMwComTest, StartServiceReturnsErrorWhenOfferFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test ensures Start() propagates a failing OfferService.");

    auto service = CreateService();
    state_->fail_offer_service = true;

    EXPECT_FALSE(service->Start().has_value());
    EXPECT_FALSE(state_->offered);
}

TEST_F(InternalConfigProviderServiceMwComTest, StopService)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::InternalConfigProviderService::Stop()");
    RecordProperty("Description",
                   "This test ensures Stop() method of InternalConfigProviderService would trigger "
                   "StopOfferService of InternalConfigProviderSkeleton");
    auto service = CreateService();
    ASSERT_TRUE(service->Start().has_value());
    ASSERT_TRUE(state_->offered);

    service->Stop();

    EXPECT_FALSE(state_->offered);
}

TEST_F(InternalConfigProviderServiceMwComTest, SetInitialQualifierState_AllEnumValues)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "39319032");
    RecordProperty("ASIL", "QM");
    RecordProperty("Description", "This test ensures that all possible InitialQualifierStates can be set.");
    auto service = CreateService();
    state_->initial_qualifier_states.clear();

    service->SetInitialQualifierState(InitialQualifierState::kDefault);
    service->SetInitialQualifierState(InitialQualifierState::kInProgress);
    service->SetInitialQualifierState(InitialQualifierState::kQualified);
    service->SetInitialQualifierState(InitialQualifierState::kQualifying);
    service->SetInitialQualifierState(InitialQualifierState::kUnqualified);
    service->SetInitialQualifierState(InitialQualifierState::kUndefined);

    using State = mw_com_icp_types::InitialQualifierState;
    EXPECT_THAT(state_->initial_qualifier_states,
                ::testing::ElementsAre(State::kDefault,
                                       State::kInProgress,
                                       State::kQualified,
                                       State::kQualifying,
                                       State::kUnqualified,
                                       State::kUndefined));
}

TEST_F(InternalConfigProviderServiceMwComTest, ConstructorPublishesUndefinedInitialQualifierState)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description", "This test ensures a new service starts with InitialQualifierState kUndefined.");

    auto skeleton = InternalConfigProviderSkeleton::Create(kICPServiceInstanceSpecifierName).value();
    const auto state = skeleton.GetState();
    const InternalConfigProviderService service{reactor_mock_, std::move(skeleton)};

    EXPECT_THAT(state->initial_qualifier_states,
                ::testing::ElementsAre(mw_com_icp_types::InitialQualifierState::kUndefined));
}

TEST_F(InternalConfigProviderServiceMwComTest, SendLastUpdatedParameterSetReturnsTrueOnSuccess)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty(
        "Verifies",
        "::score::config_management::config_daemon::InternalConfigProviderService::SendLastUpdatedParameterSet()");
    RecordProperty("Description",
                   "This test ensures SendLastUpdatedParameterSet returns true for a valid parameter set name.");

    auto service = CreateService();
    ASSERT_TRUE(service->Start().has_value());

    EXPECT_TRUE(service->SendLastUpdatedParameterSet("TestSet"));
    EXPECT_THAT(state_->sent_parameter_set_names, ::testing::ElementsAre("TestSet"));
}

TEST_F(InternalConfigProviderServiceMwComTest, SendLastUpdatedParameterSetReturnsFalseOnFailure)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty(
        "Verifies",
        "::score::config_management::config_daemon::InternalConfigProviderService::SendLastUpdatedParameterSet()");
    RecordProperty("Description", "This test ensures SendLastUpdatedParameterSet returns false when allocation fails.");

    auto service = CreateService();
    state_->fail_allocate = true;

    EXPECT_FALSE(service->SendLastUpdatedParameterSet("TestSet"));
    EXPECT_TRUE(state_->sent_parameter_set_names.empty());
}

TEST_F(InternalConfigProviderServiceMwComTest, SendLastUpdatedParameterSetReturnsFalseWhenSendFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test ensures SendLastUpdatedParameterSet returns false when Send fails.");

    auto service = CreateService();
    state_->fail_send = true;

    EXPECT_FALSE(service->SendLastUpdatedParameterSet("TestSet"));
}

TEST_F(InternalConfigProviderServiceMwComTest, HandlerReturnsContentOfKnownParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description", "This test ensures the registered handler returns the reactor's content.");

    auto service = CreateService();
    ASSERT_TRUE(service->Start().has_value());
    EXPECT_CALL(*reactor_mock_, GetParameterSet(std::string_view{"MySet"}))
        .WillOnce(::testing::Return(score::cpp::pmr::string{"{\"a\":1}"}));

    EXPECT_EQ(InvokeHandler("MySet", 100U), "{\"a\":1}");
}

TEST_F(InternalConfigProviderServiceMwComTest, HandlerReturnsNotFoundSentinelForUnknownParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test ensures the handler returns the not-found sentinel on reactor error.");

    auto service = CreateService();
    ASSERT_TRUE(service->Start().has_value());
    EXPECT_CALL(*reactor_mock_, GetParameterSet(::testing::_))
        .WillOnce(::testing::Return(score::MakeUnexpected<score::cpp::pmr::string>(
            score::mw::com::impl::MakeError(score::mw::com::impl::ComErrc::kBindingFailure))));

    EXPECT_EQ(InvokeHandler("Unknown", 100U), std::string{mw_com_icp_types::kParameterSetNotFoundContent});
}

TEST_F(InternalConfigProviderServiceMwComTest, HandlerReturnsPayloadTooLargeSentinelWhenContentExceedsBuffer)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Boundary test");
    RecordProperty("Description", "This test ensures the handler returns the too-large sentinel for big payloads.");

    auto service = CreateService();
    ASSERT_TRUE(service->Start().has_value());
    EXPECT_CALL(*reactor_mock_, GetParameterSet(::testing::_)).WillOnce(::testing::Return(score::cpp::pmr::string(64U, 'x')));

    EXPECT_EQ(InvokeHandler("Big", 32U), std::string{mw_com_icp_types::kParameterSetPayloadTooLargeContent});
}

TEST_F(InternalConfigProviderServiceMwComTest, CreateReturnsServiceWhenSkeletonCreationSucceeds)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Description", "This test ensures Create() returns a service for a creatable skeleton.");

    auto result = InternalConfigProviderService::Create(reactor_mock_, kICPServiceInstanceSpecifierName);

    EXPECT_TRUE(result.has_value());
}

TEST_F(InternalConfigProviderServiceMwComTest, CreateFailsWhenSkeletonCreationFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description", "This test ensures ICP service creation fails when the skeleton cannot be created.");

    InternalConfigProviderSkeleton::FailCreate() = true;

    auto result = InternalConfigProviderService::Create(reactor_mock_, kICPServiceInstanceSpecifierName);
    EXPECT_FALSE(result.has_value());
}

}  // namespace test
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
