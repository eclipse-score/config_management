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

#include "score/config_management/config_daemon/code/factory/details/factory_impl.h"
#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"
#include "score/config_management/config_daemon/code/services/details/internal_config_provider_service_impl.h"
#include "score/config_management/config_daemon/code/services/details/mw_com_config_json.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_mock.h"

#include "score/mw/service/provided_services_container.h"

#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"
#include "score/result/error.h"
#include "score/mw/com/runtime.h"
#include "score/mw/com/runtime_configuration.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <score/utility.hpp>
#include <fstream>
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

class TestFactoryImpl : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        unit_ = std::make_unique<FactoryImpl>();
    }

    std::unique_ptr<FactoryImpl> unit_;
};

TEST_F(TestFactoryImpl, CreatePluginCollector)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::FactoryImpl::CreatePluginCollector()");
    RecordProperty("Description",
                   "This test ensures that CreatePluginCollector() returns a valid PluginCollector object. Unlike "
                   "every other FactoryImpl method, this one is not delegated to InfrastructureFactory "
                   "and is therefore the only behavior genuinely owned by FactoryImpl itself.");

    // When calling CreatePluginCollector()
    const auto plugin_collector = unit_->CreatePluginCollector();

    // Then the returned plugin_collector instance must be valid
    ASSERT_NE(nullptr, plugin_collector) << "FactoryImpl did not return a valid PluginCollector object";
}

class TestFactoryImplServices : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        // Written to a temp file so no runfiles or working-directory-relative path is needed.
        const std::string config_path = testing::TempDir() + "mw_com_config.json";
        {
            std::ofstream config_file{config_path};
            config_file << kMwComConfigJson;
            ASSERT_TRUE(config_file.good()) << "Cannot write " << config_path;
        }
        score::mw::com::runtime::RuntimeConfiguration runtime_configuration{config_path};
        score::mw::com::runtime::InitializeRuntime(runtime_configuration);
    }
    void SetUp() override
    {
        unit_ = std::make_unique<FactoryImpl>();
    }

    std::unique_ptr<FactoryImpl> unit_;
};

TEST_F(TestFactoryImplServices, Destruction)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::FactoryImpl::~FactoryImpl");
    RecordProperty("Description", "Verify that FactoryImpl instances can be destroyed safely without throwing.");

    std::unique_ptr<Factory> factory_base = std::make_unique<FactoryImpl>();
    EXPECT_NO_THROW(factory_base.reset());

    auto factory_impl = std::make_unique<FactoryImpl>();
    EXPECT_NO_THROW(factory_impl.reset());

    EXPECT_NO_THROW([]() {
        FactoryImpl factory;
        score::cpp::ignore = factory;
    }());
}

TEST_F(TestFactoryImplServices, CreateInternalConfigProviderServiceSuccess)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::FactoryImpl::CreateInternalConfigProviderService()");
    RecordProperty("Description",
                   "This test verifies that the factory creates an "
                   "InternalConfigProviderService.");

    const auto parameter_data = std::make_shared<data_model::ParameterSetCollection>();
    auto provided_service_container = unit_->CreateInternalConfigProviderService(parameter_data);

    ASSERT_EQ(provided_service_container.Size(), 1U);
    EXPECT_NE(provided_service_container.Get<InternalConfigProviderService>(), nullptr);

    RecordProperty("Result", "CreateInternalConfigProviderServiceSuccess Passed");
}

TEST_F(TestFactoryImplServices, CreateInternalConfigProviderService_InvalidParameterData)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::FactoryImpl::CreateInternalConfigProviderService()");
    RecordProperty("Description",
                   "Verify that service creation succeeds, but accessing an invalid parameter set fails as expected.");

    const auto parameter_data = std::make_shared<data_model::ParameterSetCollection>();
    auto result = parameter_data->UpdateParameterSet("InvalidSet", "not-a-json");
    EXPECT_FALSE(result.has_value());

    auto provided_service_container = unit_->CreateInternalConfigProviderService(parameter_data);

    ASSERT_EQ(provided_service_container.Size(), 1U);

    auto bad_param = parameter_data->GetParameterSet("InvalidSet");
    EXPECT_FALSE(bad_param.has_value());
}

TEST_F(TestFactoryImplServices, CreateLastUpdatedParameterSetSender)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::FactoryImpl::CreateLastUpdatedParameterSetSender()");
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

TEST_F(TestFactoryImplServices, CreateLastUpdatedParameterSetSenderFail)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::FactoryImpl::CreateLastUpdatedParameterSetSender()");
    RecordProperty("Description",
                   "This test ensures that CreateLastUpdatedParameterSetSender() returns a no-op (non-empty) "
                   "callback if ProvidedServiceContainer does not contain InternalConfigProviderService");

    mw::service::ProvidedServicesContainer mock_service_container{};
    auto last_updated_parameter_set_sender = unit_->CreateLastUpdatedParameterSetSender(mock_service_container);
    ASSERT_FALSE(last_updated_parameter_set_sender.empty());
    EXPECT_FALSE(std::invoke(last_updated_parameter_set_sender, "parameter_set_name"));
}

TEST_F(TestFactoryImplServices, CreateInitialQualifierStateSender)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::FactoryImpl::CreateInitialQualifierStateSender()");
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

TEST_F(TestFactoryImplServices, CreateInitialQualifierStateSenderFail)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::FactoryImpl::CreateInitialQualifierStateSender()");
    RecordProperty("Description",
                   "This test ensures that CreateInitialQualifierStateSender() returns a no-op (non-empty) callback if "
                   "ProvidedServiceContainer does not contain InternalConfigProviderService");

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
