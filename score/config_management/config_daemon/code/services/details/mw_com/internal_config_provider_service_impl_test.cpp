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

#include "score/config_management/config_daemon/code/services/details/mw_com/internal_config_provider_service_impl.h"
#include "platform/aas/mw/com/runtime.h"
#include "platform/aas/mw/com/runtime_configuration.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_reactor_mock.h"
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

const auto kICPServiceInstanceSpecifierName =
    score::mw::com::InstanceSpecifier::Create("ConfigDaemon/ConfigDaemon_RootSwc/InternalConfigProviderAppPPort").value();

class InternalConfigProviderServiceMwComTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        score::mw::com::runtime::RuntimeConfiguration runtime_configuration{
            "./score/config_management/config_daemon/code/services/details/mw_com/mw_com_config.json"};
        mw::com::runtime::InitializeRuntime(runtime_configuration);
    }
    void SetUp() override
    {
        reactor_mock_ = std::make_shared<InternalConfigProviderServiceReactorMock>();
    }
    std::shared_ptr<InternalConfigProviderServiceReactorMock> reactor_mock_;
};

TEST_F(InternalConfigProviderServiceMwComTest, StartService)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::InternalConfigProviderService::StartService()");
    RecordProperty("Description",
                   "This test ensures StartService method of InternalConfigProviderService would trigger OfferService "
                   "of InternalConfigProviderSkeleton");
    auto instance_specifier = kICPServiceInstanceSpecifierName;

    auto result = InternalConfigProviderService::Create(reactor_mock_, instance_specifier);
    ASSERT_TRUE(result.has_value());
    result.value().StartService();
}

TEST_F(InternalConfigProviderServiceMwComTest, StopService)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::InternalConfigProviderService::StopService()");
    RecordProperty("Description",
                   "This test ensures StopService method of InternalConfigProviderService would trigger "
                   "StopOfferService of InternalConfigProviderSkeleton");
    auto instance_specifier = kICPServiceInstanceSpecifierName;

    auto result = InternalConfigProviderService::Create(reactor_mock_, instance_specifier);
    ASSERT_TRUE(result.has_value());
    result.value().StopService();
}

TEST_F(InternalConfigProviderServiceMwComTest, SetInitialQualifierState_AllEnumValues)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "39319032");
    RecordProperty("ASIL", "QM");
    RecordProperty("Description", "This test ensures that all possible InitialQualifierStates can be set.");
    auto instance_specifier = kICPServiceInstanceSpecifierName;

    auto result = InternalConfigProviderService::Create(reactor_mock_, instance_specifier);
    ASSERT_TRUE(result.has_value());
    auto& service = result.value();

    service.SetInitialQualifierState(InitialQualifierState::kDefault);
    service.SetInitialQualifierState(InitialQualifierState::kInProgress);
    service.SetInitialQualifierState(InitialQualifierState::kQualified);
    service.SetInitialQualifierState(InitialQualifierState::kQualifying);
    service.SetInitialQualifierState(InitialQualifierState::kUnqualified);
    service.SetInitialQualifierState(InitialQualifierState::kUndefined);
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

    auto instance_specifier = kICPServiceInstanceSpecifierName;

    auto result = InternalConfigProviderService::Create(reactor_mock_, instance_specifier);
    ASSERT_TRUE(result.has_value());
    auto& service = result.value();

    service.StartService();

    EXPECT_TRUE(service.SendLastUpdatedParameterSet("TestSet"));
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

    auto instance_specifier = kICPServiceInstanceSpecifierName;

    auto result = InternalConfigProviderService::Create(reactor_mock_, instance_specifier);
    ASSERT_TRUE(result.has_value());
    auto& service = result.value();

    EXPECT_FALSE(service.SendLastUpdatedParameterSet("TestSet"));
}

TEST_F(InternalConfigProviderServiceMwComTest, CreateFailsWithInvalidInstanceSpecifier)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description",
                   "This test ensures ICP service creation aborts when provided with an invalid instance specifier.");

    auto invalid_specifier = score::mw::com::InstanceSpecifier::Create("Invalid/Service/Path");

    ASSERT_TRUE(invalid_specifier.has_value()) << "InstanceSpecifier::Create unexpectedly returned nullopt";

    auto invalid_instance_specifier = invalid_specifier.value();

    ASSERT_DEATH({ InternalConfigProviderService::Create(reactor_mock_, invalid_instance_specifier); }, "");
}

}  // namespace test
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
