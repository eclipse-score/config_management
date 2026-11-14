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
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_reactor_mock.h"
#include "score/mw/com/runtime.h"
#include "score/mw/com/runtime_configuration.h"

#include "rules_cc/cc/runfiles/runfiles.h"

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
    score::mw::com::InstanceSpecifier::Create(
        std::string("ConfigDaemon/ConfigDaemon_RootSwc/InternalConfigProviderAppPPort"))
        .value();

class InternalConfigProviderServiceMwComTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        std::string error;
        // Resolves correctly whether config_management is the root module or an external bzlmod dependency.
        const std::unique_ptr<rules_cc::cc::runfiles::Runfiles> runfiles{
            rules_cc::cc::runfiles::Runfiles::CreateForTest(BAZEL_CURRENT_REPOSITORY, &error)};
        ASSERT_NE(runfiles, nullptr) << error;
        score::mw::com::runtime::RuntimeConfiguration runtime_configuration{
            runfiles->Rlocation("score_config_management/score/config_management/config_daemon/config/mw_com_config.json")};
        score::mw::com::runtime::InitializeRuntime(runtime_configuration);
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
    RecordProperty("Verifies", "::score::config_management::config_daemon::InternalConfigProviderService::Start()");
    RecordProperty("Description",
                   "This test ensures Start() method of InternalConfigProviderService would trigger OfferService "
                   "of InternalConfigProviderSkeleton");
    auto instance_specifier = kICPServiceInstanceSpecifierName;

    auto result = InternalConfigProviderService::Create(reactor_mock_, instance_specifier);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result.value()->Start().has_value());
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
    auto instance_specifier = kICPServiceInstanceSpecifierName;

    auto result = InternalConfigProviderService::Create(reactor_mock_, instance_specifier);
    ASSERT_TRUE(result.has_value());
    result.value()->Stop();
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
    auto& service = *result.value();

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
    auto& service = *result.value();

    ASSERT_TRUE(service.Start().has_value());

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
    auto& service = *result.value();

    EXPECT_FALSE(service.SendLastUpdatedParameterSet("TestSet"));
}

TEST_F(InternalConfigProviderServiceMwComTest, CreateFailsWithInvalidInstanceSpecifier)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Negative test");
    RecordProperty("Description",
                   "This test ensures ICP service creation aborts when provided with an invalid instance specifier.");

    auto invalid_specifier = score::mw::com::InstanceSpecifier::Create(std::string("Invalid/Service/Path"));

    ASSERT_TRUE(invalid_specifier.has_value()) << "InstanceSpecifier::Create unexpectedly returned nullopt";

    auto invalid_instance_specifier = invalid_specifier.value();

    auto result = InternalConfigProviderService::Create(reactor_mock_, invalid_instance_specifier);
    EXPECT_FALSE(result.has_value());
}

}  // namespace test
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
