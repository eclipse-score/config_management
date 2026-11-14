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

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"
#include "score/config_management/config_daemon/code/factory/details/service_factory_impl.h"
#include "score/config_management/config_daemon/code/services/details/mw_com/internal_config_provider_service_impl.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_mock.h"

#include "score/mw/service/provided_services_container.h"

#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"
#include "score/mw/com/runtime.h"
#include "score/mw/com/runtime_configuration.h"

#include "rules_cc/cc/runfiles/runfiles.h"
#include "score/result/error.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <score/utility.hpp>
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

using ::testing::Exactly;

class TestServiceFactoryMwImpl : public ::testing::Test
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
        unit_ = std::make_unique<ServiceFactoryImpl>();
    }

    std::unique_ptr<ServiceFactoryImpl> unit_;
};

TEST_F(TestServiceFactoryMwImpl, Destruction)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ServiceFactoryImpl::~ServiceFactoryImpl");
    RecordProperty("Description", "Verify that ServiceFactoryImpl instances can be destroyed safely without throwing.");

    std::unique_ptr<ServiceFactory> factory_base = std::make_unique<ServiceFactoryImpl>();
    EXPECT_NO_THROW(factory_base.reset());

    auto factory_impl = std::make_unique<ServiceFactoryImpl>();
    EXPECT_NO_THROW(factory_impl.reset());

    EXPECT_NO_THROW([]() {
        ServiceFactoryImpl factory;
        score::cpp::ignore = factory;
    }());
}

TEST_F(TestServiceFactoryMwImpl, CreateInternalConfigProviderServiceSuccess)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::ServiceFactoryImpl::CreateInternalConfigProviderService()");
    RecordProperty("Description",
                   "This test verifies that the service factory creates an "
                   "InternalConfigProviderService.");

    const auto parameter_data = std::make_shared<data_model::ParameterSetCollection>();
    auto provided_services_container = unit_->CreateInternalConfigProviderService(parameter_data);

    ASSERT_EQ(provided_services_container.Size(), 1U);
    EXPECT_NE(provided_services_container.Get<InternalConfigProviderService>(), nullptr);

    RecordProperty("Result", "CreateInternalConfigProviderServiceSuccess Passed");
}

TEST_F(TestServiceFactoryMwImpl, CreateInternalConfigProviderService_InvalidParameterData)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::ServiceFactoryImpl::CreateInternalConfigProviderService()");
    RecordProperty("Description",
                   "Verify that service creation succeeds, but accessing an invalid parameter set fails as expected.");

    const auto parameter_data = std::make_shared<data_model::ParameterSetCollection>();
    auto result = parameter_data->UpdateParameterSet("InvalidSet", "not-a-json");
    EXPECT_FALSE(result.has_value());

    auto provided_services_container = unit_->CreateInternalConfigProviderService(parameter_data);

    ASSERT_EQ(provided_services_container.Size(), 1U);

    auto bad_param = parameter_data->GetParameterSet("InvalidSet");
    EXPECT_FALSE(bad_param.has_value());
}

TEST_F(TestServiceFactoryMwImpl, CreateLastUpdatedParameterSetSender)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::ServiceFactoryImpl::CreateLastUpdatedParameterSetSender()");
    RecordProperty("Description",
                   "This test ensures that CreateLastUpdatedParameterSetSender() returns a valid "
                   "LastUpdatedParameterSetSender callback");

    mw::service::ProvidedServicesContainer mock_service_container{};
    ASSERT_TRUE(mock_service_container.Emplace<::testing::NiceMock<InternalConfigProviderServiceMock>>().has_value());
    auto* mock_service_ptr = mock_service_container.Get<IInternalConfigProviderService>();

    auto last_updated_parameter_set_sender = unit_->CreateLastUpdatedParameterSetSender(mock_service_container);
    ASSERT_FALSE(last_updated_parameter_set_sender.empty());
    EXPECT_CALL(*dynamic_cast<InternalConfigProviderServiceMock*>(mock_service_ptr),
                SendLastUpdatedParameterSet("parameter_set_name"))
        .Times(Exactly(1));
    std::invoke(last_updated_parameter_set_sender, "parameter_set_name");
}

TEST_F(TestServiceFactoryMwImpl, CreateLastUpdatedParameterSetSenderFail)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::ServiceFactoryImpl::CreateLastUpdatedParameterSetSender()");
    RecordProperty("Description",
                   "This test ensures that CreateLastUpdatedParameterSetSender() returns a no-op (non-empty) "
                   "callback if ProvidedServicesContainer does not contain InternalConfigProviderService");

    mw::service::ProvidedServicesContainer mock_service_container{};
    auto last_updated_parameter_set_sender = unit_->CreateLastUpdatedParameterSetSender(mock_service_container);
    ASSERT_FALSE(last_updated_parameter_set_sender.empty());
    EXPECT_FALSE(std::invoke(last_updated_parameter_set_sender, "parameter_set_name"));
}

TEST_F(TestServiceFactoryMwImpl, CreateInitialQualifierStateSender)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::ServiceFactoryImpl::CreateInitialQualifierStateSender()");
    RecordProperty("Description",
                   "This test ensures that CreateInitialQualifierStateSender() returns a valid "
                   "InitialQualifierStateSender callback");

    mw::service::ProvidedServicesContainer mock_service_container{};
    ASSERT_TRUE(mock_service_container.Emplace<::testing::NiceMock<InternalConfigProviderServiceMock>>().has_value());
    auto* mock_service_ptr = mock_service_container.Get<IInternalConfigProviderService>();

    auto initial_qualifier_state_sender = unit_->CreateInitialQualifierStateSender(mock_service_container);
    ASSERT_FALSE(initial_qualifier_state_sender.empty());

    EXPECT_CALL(*dynamic_cast<InternalConfigProviderServiceMock*>(mock_service_ptr),
                SetInitialQualifierState(InitialQualifierState::kQualified))
        .Times(Exactly(1));
    std::invoke(initial_qualifier_state_sender, InitialQualifierState::kQualified);
}

TEST_F(TestServiceFactoryMwImpl, CreateInitialQualifierStateSenderFail)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::config_management::config_daemon::ServiceFactoryImpl::CreateInitialQualifierStateSender()");
    RecordProperty("Description",
                   "This test ensures that CreateInitialQualifierStateSender() returns a no-op (non-empty) callback if "
                   "ProvidedServicesContainer does not contain InternalConfigProviderService");

    mw::service::ProvidedServicesContainer mock_service_container{};
    auto initial_qualifier_state_sender = unit_->CreateInitialQualifierStateSender(mock_service_container);
    ASSERT_FALSE(initial_qualifier_state_sender.empty());
    std::invoke(initial_qualifier_state_sender, InitialQualifierState::kQualified);
}

}  // namespace
}  // namespace test
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
