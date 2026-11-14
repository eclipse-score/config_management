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
#include "score/config_management/config_provider/code/proxies/details/mw_com/internal_config_provider_impl.h"
#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"

#include "score/config_management/config_provider/code/config_provider/error/error.h"

#include "score/concurrency/notification.h"

#include "score/mw/com/runtime.h"
#include "score/mw/com/runtime_configuration.h"

#include "rules_cc/cc/runfiles/runfiles.h"

#include <gtest/gtest.h>

#include <future>

#include <iostream>
#include <stdexcept>

namespace score
{
namespace config_management
{
namespace config_provider
{

namespace
{

const std::chrono::milliseconds kZeroTimeout{0};

const std::string kICPSpecifier{"ConfigDaemonCustomer/ConfigDaemonCustomer_RootSwc/InternalConfigProviderAppRPort"};
using MwComSkeleton = score::mw::com::AsSkeleton<score::config_management::config_daemon::InternalConfigProviderInterface>;
using MwComInitialQualifierStateType = score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState;

class InternalConfigProviderTest : public ::testing::Test
{
  protected:
    using MWProxy = InternalConfigProvider::InternalMwComProxy;

    void SetUp() override
    {
        std::string error;
        // Resolves correctly whether config_management is the root module or an external bzlmod dependency.
        const std::unique_ptr<rules_cc::cc::runfiles::Runfiles> runfiles{
            rules_cc::cc::runfiles::Runfiles::CreateForTest(BAZEL_CURRENT_REPOSITORY, &error)};
        ASSERT_NE(runfiles, nullptr) << error;
        score::mw::com::runtime::RuntimeConfiguration runtime_configuration{
            runfiles->Rlocation("score_config_management/score/config_management/config_provider/code/proxies/details/mw_com/"
                               "test_mw_com_config.json")};
        score::mw::com::runtime::InitializeRuntime(runtime_configuration);

        skeleton_ = CreateService();

        std::ignore = skeleton_->initial_qualifier_state.Update(MwComInitialQualifierStateType::kUndefined);
        auto offer_result = skeleton_->OfferService();
        if (!offer_result.has_value())
        {
            throw std::runtime_error(std::string("OfferService() failed: ") +
                                     std::string(offer_result.error().Message()));
        }
        auto proxy = CreateProxy();
        // proxy_mock_ = proxy.get();
        unit_ = std::make_unique<InternalConfigProvider>(std::move(proxy));
    }

    void TearDown() override
    {
        // unit_->StopParameterSetUpdatePollingRoutine();
        // EXPECT_CALL(proxy_mock_->LastUpdatedParameterSet, Unsubscribe());
    }

    std::unique_ptr<MwComSkeleton> CreateService() const
    {
        // Prepare skeleton to offer the service
        auto instance_specifier_result = score::mw::com::InstanceSpecifier::Create(std::string(kICPSpecifier));
        // ASSERT_TRUE(instance_specifier_result.has_value());

        auto service_result = MwComSkeleton::Create(std::move(instance_specifier_result).value());
        // ASSERT_TRUE(service_result.has_value());
        auto& service = service_result.value();
        // The generated skeleton requires every declared method to have a registered handler before
        // OfferService() is called, otherwise SkeletonBase::VerifyAllMethodsRegistered() silently fails
        // with a generic kBindingFailure. This test does not exercise get_parameter_set() itself, so a
        // minimal handler that never resolves anything is sufficient to satisfy that precondition.
        auto handler = [](score::config_management::config_daemon::mw_com_icp_types::ParameterSetContent&,
                          const score::config_management::config_daemon::mw_com_icp_types::ParameterSetName&,
                          const std::size_t&) {};
        std::ignore = service.get_parameter_set.RegisterHandler(std::move(handler));
        return std::make_unique<MwComSkeleton>(std::move(service));
    }

    std::unique_ptr<MWProxy> CreateProxy() const
    {
        auto instance_specifier_result = score::mw::com::InstanceSpecifier::Create(std::string(kICPSpecifier));

        const auto proxy_handles_result = MWProxy::FindService(std::move(instance_specifier_result).value());
        const auto& proxy_handles = proxy_handles_result.value();
        if (proxy_handles.empty())
        {
            throw std::runtime_error("FindService() did not return any service handles for " + kICPSpecifier);
        }

        return std::make_unique<MWProxy>(MWProxy::Create(proxy_handles.front()).value());
    }

    std::unique_ptr<InternalConfigProvider> unit_;
    std::unique_ptr<MwComSkeleton> skeleton_;
};

TEST_F(InternalConfigProviderTest, CanConstructWithMWComProxy)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::InternalConfigProvider::InternalConfigProvider()");
    RecordProperty("Description", "This test verifies a successful creation of InternalConfigProvider.");
    // Given a constructed adaptive proxy of our InternalConfigProvider interface
    // When constructing our IInternalConfigProvider implementation with it
    // Then no issue occurs
    EXPECT_NO_THROW(InternalConfigProvider{CreateProxy()});
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

    // Given the InitialQualifierState is provided
    std::ignore = skeleton_->initial_qualifier_state.Update(std::get<0>(GetParam()));
    const auto result = unit_->GetInitialQualifierState(kZeroTimeout);
    // Then GetInitialQualifierState can get this value
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

}  // namespace
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
