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
#include "score/config_management/config_provider/code/config_provider/factory/factory_mw_com.h"
#include "score/config_management/config_daemon/code/services/details/mw_com/generated_service/internal_config_provider_type.h"
#include "score/config_management/config_provider/code/persistency/persistency_mock.h"

#include "score/json/json_parser.h"

#include "score/mw/com/runtime.h"
#include "score/mw/com/runtime_configuration.h"

#include <gtest/gtest.h>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace test
{

struct DummyPort
{
    constexpr static auto Get()
    {
        return "ConfigDaemonCustomer/ConfigDaemonCustomer_RootSwc/InternalConfigProviderAppRPort";
    }
};

const std::string kICPSpecifier{"ConfigDaemonCustomer/ConfigDaemonCustomer_RootSwc/InternalConfigProviderAppRPort"};
using MwComSkeleton = score::config_management::config_daemon::InternalConfigProviderSkeleton;
using MwComInitialQualifierStateType = score::config_management::config_daemon::mw_com_icp_types::InitialQualifierState;

class ConfigProviderFactoryTest : public ::testing::Test
{
  public:
    void SetUp() override
    {
        score::mw::com::runtime::RuntimeConfiguration runtime_configuration{
            "./score/config_management/ConfigProvider/code/config_provider/factory/mw_com_config.json"};
        mw::com::runtime::InitializeRuntime(runtime_configuration);

        skeleton = CreateService();
        skeleton->initial_qualifier_state.Update(MwComInitialQualifierStateType::kUndefined);
        score::cpp::ignore = skeleton->OfferService();
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

    void TearDown() override
    {
        // AraProxy::DestroyFindProxy();
    }

    std::unique_ptr<MwComSkeleton> skeleton;
};

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_DefaultPolling_NoPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderFactory::Create()");
    RecordProperty(
        "Description",
        "This test verifies successful creation of default polling without persistency via config provider factory.");
    // Given that no persistency or polling related parameters are provided during creation
    score::platform::config_provider::ConfigProviderFactory config_provider_factory;
    auto config_provider =
        config_provider_factory.Create<DummyPort>({},                                // default stop_token
                                                  std::chrono::milliseconds(0U),     // zero timeout
                                                  score::cpp::pmr::get_default_resource(),  // default memory resource
                                                  []() noexcept {}                   // empty callback
        );
    // Expect that a valid ConfigProvider object still can be created.
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
}

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_CustomPolling_NoPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderFactory::Create()");
    RecordProperty(
        "Description",
        "This test verifies successful creation of custom polling without persistency via config provider factory.");
    // Given that polling related parameters is provided, but no persistency is provided during creation
    score::platform::config_provider::ConfigProviderFactory config_provider_factory;
    auto config_provider =
        config_provider_factory.Create<DummyPort>({},                             // default stop_token
                                                  std::chrono::milliseconds(0U),  // zero timeout
                                                  score::cpp::nullopt,                   // custom max_samples_limit provided
                                                  score::cpp::nullopt,  // custom polling_cycle_interval provided
                                                  score::cpp::pmr::get_default_resource(),  // default memory resource
                                                  []() noexcept {}                   // empty callback
        );
    // Expect that a valid ConfigProvider object still can be created.
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
}

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_DefaultPolling_Persistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderFactory::Create()");
    RecordProperty("Description",
                   "This test verifies successful creation of default polling with valid persistency via config "
                   "provider factory.");
    // Given that persistency is provided, but no polling related parameters is provided during creation
    score::platform::config_provider::ConfigProviderFactory config_provider_factory;
    auto persistency_mock = score::cpp::pmr::make_unique<PersistencyMock>(score::cpp::pmr::get_default_resource());
    auto config_provider =
        config_provider_factory.Create<DummyPort>({},                                // default stop_token
                                                  std::move(persistency_mock),       // persistency provided
                                                  score::cpp::pmr::get_default_resource(),  // default memory resource
                                                  []() noexcept {}                   // empty callback
        );
    // Expect that a valid ConfigProvider object still can be created.
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
}

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_CustomPolling_Persistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderFactory::Create()");
    RecordProperty(
        "Description",
        "This test verifies successful creation of custom polling with valid persistency via config provider factory.");
    // Given that both persistency and polling related parameters are provided during creation
    score::platform::config_provider::ConfigProviderFactory config_provider_factory;
    auto persistency_mock = score::cpp::pmr::make_unique<PersistencyMock>(score::cpp::pmr::get_default_resource());
    auto config_provider =
        config_provider_factory.Create<DummyPort>({},                           // default stop_token
                                                  std::move(persistency_mock),  // persistency provided
                                                  score::cpp::nullopt,                 // custom max_samples_limit provided
                                                  score::cpp::nullopt,  // custom polling_cycle_interval provided
                                                  score::cpp::pmr::get_default_resource(),  // default memory resource
                                                  []() noexcept {}                   // empty callback
        );
    // Expect that a valid ConfigProvider object still can be created.
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
}

TEST_F(ConfigProviderFactoryTest, FoundServiceDuringCreation)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "23162623");
    RecordProperty("ASIL", "QM");
    RecordProperty("Description",
                   "23162623: This test ensures that callback is triggered when service becomes available");

    // Given the service can be found during creation
    score::platform::config_provider::ConfigProviderFactory config_provider_factory;
    std::atomic<bool> callback_is_called_upon_found{false};
    std::condition_variable callback_cv;
    std::mutex callback_mutex;
    IsAvailableNotificationCallback callback{
        [&callback_is_called_upon_found, &callback_cv, &callback_mutex]() noexcept {
            std::unique_lock<std::mutex> ul{callback_mutex};
            callback_is_called_upon_found = true;
            ul.unlock();
            callback_cv.notify_all();
        }};
    auto config_provider = config_provider_factory.Create<DummyPort>(
        {}, std::chrono::milliseconds(0U), score::cpp::pmr::get_default_resource(), std::move(callback));
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
    std::unique_lock<std::mutex> ul{callback_mutex};
    callback_cv.wait_for(ul, std::chrono::milliseconds{1000});
    // Then the callback is triggered
    ASSERT_TRUE(callback_is_called_upon_found) << "Callback is triggered when the proxy finds service";
}

}  // namespace test
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
