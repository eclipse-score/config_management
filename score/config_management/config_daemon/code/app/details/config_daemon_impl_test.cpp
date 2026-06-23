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
#include "score/config_management/config_daemon/code/app/details/config_daemon_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_manager_mock.h"
#include "score/config_management/config_daemon/code/factory/factory.h"
#include "score/config_management/config_daemon/code/factory/factory_mock.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter_mock.h"
#include "score/config_management/config_daemon/code/plugins/plugin_collector/plugin_collector_mock.h"
#include "score/config_management/config_daemon/code/plugins/plugin_mock.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_mock.h"
#include "score/os/errno.h"
#include "score/result/result.h"

#include "score/os/mocklib/stat_mock.h"
#include "score/mw/service/provided_service.h"

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

namespace
{

using testing::_;
using testing::ByMove;
using testing::Invoke;
using testing::Return;

const char* gArgs[]{"ConfigDaemon"};

auto gDummyContext = score::mw::lifecycle::ApplicationContext(1, gArgs);

constexpr const std::int32_t kExitCodeSuccess{0};
constexpr const std::int32_t kExitCodeFailure{1};

}  // namespace

template <typename T>
class MockFactory
{
  public:
    std::unique_ptr<T> operator()()
    {
        return std::make_unique<T>();
    }
};

template <typename ServiceType>
class ServiceDecorator final : public score::mw::service::ProvidedService
{
  public:
    using ServiceHolder = std::unique_ptr<ServiceType>;

    template <typename ServiceImplType = ServiceType, typename... Args>
    static ServiceDecorator Create(Args&&... args)
    {
        ServiceDecorator instance{};
        instance.service_ = std::make_unique<ServiceImplType>(std::forward<Args>(args)...);
        return instance;
    }

    void StartService() noexcept override
    {
        service_->OfferService();
    }
    void StopService() noexcept override
    {
        service_->WithdrawService();
    }
    ServiceType* GetService() noexcept
    {
        return service_.get();
    }
    ServiceHolder ExtractService() noexcept
    {
        decltype(service_) service{};
        service_.swap(service);
        return service;
    }

  private:
    ServiceHolder service_;
};

class ConfigDaemonFixture : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        score::os::Stat::set_testing_instance(stat_mock_);

        factory_mock_ = std::make_unique<score::config_management::config_daemon::FactoryMock>();
        first_plugin_mock_ = std::make_shared<score::config_management::config_daemon::PluginMock>();
        second_plugin_mock_ = std::make_shared<score::config_management::config_daemon::PluginMock>();
        plugin_collector_mock_ = std::make_unique<PluginCollectorMock>();
    }

    void TearDown() override {}

    void FactoryDefaultSetup();
    void ComponentsDefaultSetup();
    void PluginCollectorSetup();
    mw::service::ProvidedServiceContainer CreateProvidedServiceContainer();

    score::os::StatMock stat_mock_;
    std::unique_ptr<score::config_management::config_daemon::FactoryMock> factory_mock_;
    std::shared_ptr<score::config_management::config_daemon::PluginMock> first_plugin_mock_;
    std::shared_ptr<score::config_management::config_daemon::PluginMock> second_plugin_mock_;
    std::unique_ptr<score::config_management::config_daemon::ConfigDaemon> config_daemon_app_;
    std::unique_ptr<PluginCollectorMock> plugin_collector_mock_;
};

mw::service::ProvidedServiceContainer ConfigDaemonFixture::CreateProvidedServiceContainer()
{
    score::mw::service::ProvidedServices<ServiceDecorator> services{};
    services.Add<InternalConfigProviderServiceMock>();
    return services;
}

void ConfigDaemonFixture::FactoryDefaultSetup()
{
    ON_CALL(*factory_mock_, CreateParameterSetCollectionManager(_)).WillByDefault(Invoke([](auto&&) {
        auto mock = std::make_shared<data_model::ParameterSetCollectionManagerMock>();
        ON_CALL(*mock, GetParameterSetCollection()).WillByDefault(Return(nullptr));
        ON_CALL(*mock, LoadParameterSetCollectionFromStorage())
            .WillByDefault(Return(Result<InitialQualifierState>{InitialQualifierState::kDefault}));
        return mock;
    }));
    ON_CALL(*factory_mock_, CreateFaultEventReporter()).WillByDefault(Invoke([] {
        return std::make_unique<fault_event_reporter::FaultEventReporterMock>();
    }));
    PluginCollectorSetup();
    ON_CALL(*factory_mock_, CreateLastUpdatedParameterSetSender(_)).WillByDefault(Invoke([](auto&&) {
        return [](const std::string_view) noexcept {
            return true;
        };
    }));
    ON_CALL(*factory_mock_, CreateInitialQualifierStateSender(_)).WillByDefault(Invoke([](auto&&) {
        return [](const InitialQualifierState) noexcept {};
    }));
    ON_CALL(*factory_mock_, CreateInternalConfigProviderService(_)).WillByDefault(Invoke([this](auto&&) {
        return CreateProvidedServiceContainer();
    }));
}

void ConfigDaemonFixture::ComponentsDefaultSetup()
{
    ON_CALL(*first_plugin_mock_, Initialize()).WillByDefault(Return(Result<void>{}));
}

void ConfigDaemonFixture::PluginCollectorSetup()
{
    std::vector<std::shared_ptr<IPlugin>> plugins;
    plugins.push_back(first_plugin_mock_);
    plugins.push_back(second_plugin_mock_);
    ON_CALL(*plugin_collector_mock_, CreatePlugins()).WillByDefault(Return(plugins));
    ON_CALL(*first_plugin_mock_, Initialize()).WillByDefault(Return(Result<void>{}));
    ON_CALL(*second_plugin_mock_, Initialize()).WillByDefault(Return(Result<void>{}));
    ON_CALL(*factory_mock_, CreatePluginCollector()).WillByDefault(Return(ByMove(std::move(plugin_collector_mock_))));
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppInitializeSuccess)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of equivalence classes and boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("lobster-tracing", "ConfigDaemon.StorageAccessibility");
    RecordProperty(
        "Description",
        "This test ensures that Initialize would return success, when factory can create all necessary "
        "components, and that umask is set to 0177, which should restrict the permission of files created to 0600");

    // Given the factory is able to create all necessary components
    FactoryDefaultSetup();
    EXPECT_CALL(stat_mock_, umask(score::os::IntegerToMode(0x7FU))).Times(testing::AtLeast(1));
    EXPECT_CALL(*factory_mock_, CreateFaultEventReporter()).WillOnce(Invoke([] {
        return std::make_unique<fault_event_reporter::FaultEventReporterMock>();
    }));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    // When the Initialize function is run
    // Then the Initialize function would succeed
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeSuccess);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToCreateFaultEventReporter)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty("Description",
                   "This test ensures that Initialize would fail, when FaultEventReporter cannot be created");

    // Given the factory fails to create FaultEventReporter
    FactoryDefaultSetup();
    EXPECT_CALL(*factory_mock_, CreateFaultEventReporter()).WillOnce(Return(ByMove(nullptr)));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    // When the Initialize function is run
    // Then the Initialize function would fail
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppSettingUmaskFailed)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::ConfigDaemon()");
    RecordProperty("Description", "This test ensures that constructor would not fail, when setting umask failed");

    // Given the factory is able to create all necessary components
    FactoryDefaultSetup();
    const auto enoent_expected_error = score::cpp::make_unexpected(score::os::Error::createFromErrno(ENOENT));
    EXPECT_CALL(stat_mock_, umask(score::os::IntegerToMode(0x7FU))).WillOnce(Return(enoent_expected_error));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    // When the Initialize function is run
    // Then the Initialize function would succeed
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeSuccess);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToCreateInternalConfigProviderService)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty(
        "Description",
        "This test ensures that Initialize would return fail, when InternalConfigProviderService cannot be created");

    // Given the factory failed to create RawDataStorage
    FactoryDefaultSetup();
    EXPECT_CALL(*factory_mock_, CreateInternalConfigProviderService(_)).Times(1).WillOnce(Invoke([](auto&&) {
        return mw::service::ProvidedServiceContainer{};
    }));
    ;
    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    // When the Initialize function is run
    // Then the Initialize function would fail
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppRunSucceed)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "6950665, 75561092");
    RecordProperty("ASIL", "B");
    RecordProperty("Description",
                   "This test ensures that Initialize and Run would succeed, when factory can create necessary "
                   "components as well as Initialize() and Run() was successfully executed for all plugins.");

    // Given the factory is able to create necessary components
    ComponentsDefaultSetup();
    FactoryDefaultSetup();
    EXPECT_CALL(*first_plugin_mock_, Initialize()).WillOnce(Return(Result<void>{}));
    EXPECT_CALL(*second_plugin_mock_, Initialize()).WillOnce(Return(Result<void>{}));
    EXPECT_CALL(*first_plugin_mock_, Run(_, _, _, _, _)).WillOnce(Return(kExitCodeSuccess));
    EXPECT_CALL(*second_plugin_mock_, Run(_, _, _, _, _)).WillOnce(Return(kExitCodeSuccess));
    EXPECT_CALL(*first_plugin_mock_, Deinitialize());
    EXPECT_CALL(*second_plugin_mock_, Deinitialize());
    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    score::cpp::stop_source source;
    source.request_stop();
    // When the Initialize and Run function are run
    // Then the both functions would fail
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeSuccess);
    ASSERT_EQ(config_daemon_app_->Run(source.get_token()), kExitCodeSuccess);
}

// ToDo: Update this within CleanUp task(Ticket-192926)
TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToCreatePluginCollector)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty("Description",
                   "This test ensures that Initialize would fail, when creation of PluginCollector failed");

    // Given the factory is able to create all necessary components
    FactoryDefaultSetup();
    EXPECT_CALL(*factory_mock_, CreatePluginCollector())
        .WillOnce(Return(ByMove(std::unique_ptr<PluginCollectorMock>{})));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToSetupPlugins)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("Verifies", "14351696");
    RecordProperty("ASIL", "B");
    RecordProperty("Description",
                   "This test ensures that Initialize would fail, when one of Plugin cannot be initialized");

    ComponentsDefaultSetup();
    FactoryDefaultSetup();

    Result<void> error_result{score::MakeUnexpected(score::json::Error::kParsingError, "")};
    EXPECT_CALL(*first_plugin_mock_, Initialize()).WillOnce(Return(error_result));
    EXPECT_CALL(*second_plugin_mock_, Initialize()).Times(0);

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));

    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToInitializeSecondPlugin)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty("Description",
                   "This test ensures that Initialize would fail, when one of Plugin cannot be initialized");

    ComponentsDefaultSetup();
    FactoryDefaultSetup();

    Result<void> error_result{score::MakeUnexpected(score::json::Error::kParsingError, "")};
    EXPECT_CALL(*first_plugin_mock_, Initialize()).WillOnce(Return(Result<void>{}));
    EXPECT_CALL(*second_plugin_mock_, Initialize()).WillOnce(Return(error_result));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));

    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToRunFirstPlugin)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Run()");
    RecordProperty("Description", "This test ensures that Run would fail, when Plugin->Run return error");

    FactoryDefaultSetup();

    EXPECT_CALL(*first_plugin_mock_, Run(_, _, _, _, _)).WillOnce(Return(kExitCodeFailure));
    EXPECT_CALL(*second_plugin_mock_, Run(_, _, _, _, _)).Times(0);
    EXPECT_CALL(*first_plugin_mock_, Deinitialize());
    EXPECT_CALL(*second_plugin_mock_, Deinitialize());

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    score::cpp::stop_source source;
    source.request_stop();

    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeSuccess);
    ASSERT_EQ(config_daemon_app_->Run(source.get_token()), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToRunSecondPlugin)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Run()");
    RecordProperty("Description", "This test ensures that Run would fail, when Plugin->Run return error");

    FactoryDefaultSetup();

    EXPECT_CALL(*first_plugin_mock_, Run(_, _, _, _, _)).WillOnce(Return(kExitCodeSuccess));
    EXPECT_CALL(*second_plugin_mock_, Run(_, _, _, _, _)).WillOnce(Return(kExitCodeFailure));
    EXPECT_CALL(*first_plugin_mock_, Deinitialize());
    EXPECT_CALL(*second_plugin_mock_, Deinitialize());

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    score::cpp::stop_source source;
    source.request_stop();

    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeSuccess);
    ASSERT_EQ(config_daemon_app_->Run(source.get_token()), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToInitializeAsPluginIsNull)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty("Description", "This test ensures that Initialize would fail, if Plugin is null");

    auto* const plugin_collector_mock_raw = plugin_collector_mock_.get();
    FactoryDefaultSetup();
    std::vector<std::shared_ptr<IPlugin>> plugins;
    std::shared_ptr<score::config_management::config_daemon::PluginMock> first_plugin_mock =
        std::make_shared<score::config_management::config_daemon::PluginMock>();
    std::shared_ptr<score::config_management::config_daemon::PluginMock> second_plugin_mock;
    plugins.push_back(first_plugin_mock);
    plugins.push_back(second_plugin_mock);
    EXPECT_CALL(*plugin_collector_mock_raw, CreatePlugins()).WillOnce(Return(plugins));
    ON_CALL(*first_plugin_mock, ParameterSetCollectionUpdateStart(_)).WillByDefault(Return(Result<void>{}));
    EXPECT_CALL(*first_plugin_mock, Initialize()).WillOnce(Return(Result<void>{}));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonRunFailDueToLastUpdatedParameterSetSenderCreationFailure)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Run()");
    RecordProperty(
        "Description",
        "This test ensures that Run would return fail, when LastUpdatedParamaterSetSender Callback cannot be created");

    // Given the factory failed to create LastUpdatedParameterSetSender
    ComponentsDefaultSetup();
    FactoryDefaultSetup();

    EXPECT_CALL(*factory_mock_, CreateLastUpdatedParameterSetSender(_))
        .WillOnce(Return(ByMove(LastUpdatedParameterSetSender{})));
    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    score::cpp::stop_source source;
    source.request_stop();
    config_daemon_app_->Initialize(gDummyContext);
    // When the Run function is triggered
    // Then the Run function would fail
    ASSERT_EQ(config_daemon_app_->Run(source.get_token()), 1);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToCreateParameterSetCollectionManager)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty("Description",
                   "This test ensures that Initialize would fail, when ParameterSetCollection cannot be created");

    FactoryDefaultSetup();
    EXPECT_CALL(*factory_mock_, CreateParameterSetCollectionManager(_)).WillOnce(Return(ByMove(nullptr)));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

}  // namespace test
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
