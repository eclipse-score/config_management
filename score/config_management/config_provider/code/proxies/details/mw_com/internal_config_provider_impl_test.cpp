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
#include "config_management/ConfigDaemon/code/services/details/mw_com/generated_service/internal_config_provider_type.h"

#include "score/config_management/config_provider/code/config_provider/error/error.h"

#include "platform/aas/lib/concurrency/notification.h"

#include "score/mw/com/runtime.h"
#include "score/mw/com/runtime_configuration.h"

#include <gtest/gtest.h>

#include <future>

#include <iostream>

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
using MwComSkeleton = score::platform::config_daemon::InternalConfigProviderSkeleton;
using MwComNcdType = score::platform::config_daemon::mw_com_icp_types::InitialQualifierState;

class InternalConfigProviderTest : public ::testing::Test
{
  protected:
    using MWProxy = InternalConfigProvider::InternalMwComProxy;

    void SetUp() override
    {
        score::mw::com::runtime::RuntimeConfiguration runtime_configuration{
            "./score/config_management/ConfigProvider/code/proxies/details/mw_com/mw_com_config.json"};
        mw::com::runtime::InitializeRuntime(runtime_configuration);

        skeleton_ = CreateService();
        skeleton_->initial_qualifier_state.Update(MwComNcdType::kUndefined);
        score::cpp::ignore = skeleton_->OfferService();
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
        auto instance_specifier_result = score::mw::com::InstanceSpecifier::Create(kICPSpecifier);
        // ASSERT_TRUE(instance_specifier_result.has_value());

        auto service_result = MwComSkeleton::Create(std::move(instance_specifier_result).value());
        // ASSERT_TRUE(service_result.has_value());
        auto& service = service_result.value();
        return std::make_unique<MwComSkeleton>(std::move(service));
    }

    std::unique_ptr<MWProxy> CreateProxy() const
    {
        auto instance_specifier_result = score::mw::com::InstanceSpecifier::Create(kICPSpecifier);

        // EXPECT_TRUE(result.has_value());
        const auto proxy_handles_result = MWProxy::FindService(std::move(instance_specifier_result).value());
        const auto& proxy_handles = proxy_handles_result.value();

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
    RecordProperty("Verifies", "::score::platform::config_provider::InternalConfigProvider::InternalConfigProvider()");
    RecordProperty("ASIL", "QM");
    RecordProperty("Description", "This test verifies a successful creation of InternalConfigProvider.");
    // Given a constructed adaptive proxy of our InternalConfigProvider interface
    // When constructing our IInternalConfigProvider implementation with it
    // Then no issue occurs
    EXPECT_NO_THROW(InternalConfigProvider{CreateProxy()});
}

class InternalConfigProviderGetInitialQualifierStatePassTest
    : public InternalConfigProviderTest,
      public ::testing::WithParamInterface<std::tuple<MwComNcdType, InitialQualifierState>>
{
};

TEST_P(InternalConfigProviderGetInitialQualifierStatePassTest, GetInitialQualifierState_Pass)
{
    RecordProperty("Priority", "3");
    RecordProperty("Verifies", " 11397333");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("ASIL", "B");
    RecordProperty("Description", "This test check the GetInitialQualifierState would get expected parameter value successfully");

    skeleton_->initial_qualifier_state.Update(std::get<0>(GetParam()));
    const auto result = unit_->GetInitialQualifierState(kZeroTimeout);

    EXPECT_EQ(result, std::get<1>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(
    GetInitialQualifierStatePass,
    InternalConfigProviderGetInitialQualifierStatePassTest,
    testing::Values(
        std::make_tuple(MwComNcdType::kDefault, InitialQualifierState::kDefault),
        std::make_tuple(MwComNcdType::kInProgress, InitialQualifierState::kInProgress),
        std::make_tuple(MwComNcdType::kQualified, InitialQualifierState::kQualified),
        std::make_tuple(MwComNcdType::kQualifying, InitialQualifierState::kQualifying),
        std::make_tuple(MwComNcdType::kUnqualified, InitialQualifierState::kUnqualified),
        std::make_tuple(MwComNcdType::kUndefined, InitialQualifierState::kUndefined),
        std::make_tuple(static_cast<MwComNcdType>(std::numeric_limits<std::underlying_type_t<MwComNcdType>>::max()),
                        InitialQualifierState::kUndefined)));

}  // namespace
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
