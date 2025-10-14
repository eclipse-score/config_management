#include "score/config_management/config_daemon/code/app/details/config_daemon_impl.h"
#include "score/os/errno.h"
#include "score/result/result.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_mock.h"
#include "score/config_management/config_daemon/code/factory/factory.h"
#include "score/config_management/config_daemon/code/factory/factory_mock.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter_mock.h"
#include "score/config_management/config_daemon/code/plugins/plugin_collector/plugin_collector_mock.h"
#include "score/config_management/config_daemon/code/plugins/plugin_mock.h"
#include "score/config_management/config_daemon/code/services/internal_config_provider_service_mock.h"

#include "score/os/mocklib/stat_mock.h"
#include "platform/aas/mw/service/mw/provided_service_builder.h"

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

        score::mw::service::ProvidedServices<mw::service::ProvidedServiceBuilder::DecoratorType> services{};
        services.Add<InternalConfigProviderServiceMock>();
        provided_services_container_mock_ = std::move(services);
    }

    void TearDown() override {}

    void FactoryDefaultSetup();
    void ComponentsDefaultSetup();
    void PluginCollectorSetup();

    score::os::StatMock stat_mock_;
    std::unique_ptr<score::config_management::config_daemon::FactoryMock> factory_mock_;
    std::shared_ptr<score::config_management::config_daemon::PluginMock> first_plugin_mock_;
    std::shared_ptr<score::config_management::config_daemon::PluginMock> second_plugin_mock_;
    std::unique_ptr<score::config_management::config_daemon::ConfigDaemon> config_daemon_app_;
    std::optional<mw::service::ProvidedServiceContainer> provided_services_container_mock_;
    std::unique_ptr<PluginCollectorMock> plugin_collector_mock_;
};

void ConfigDaemonFixture::FactoryDefaultSetup()
{
    auto parameterset_collection_mock = std::make_unique<data_model::ParameterSetCollectionMock>();
    auto fault_event_reporter_mock = std::make_unique<fault_event_reporter::FaultEventReporterMock>();

    ON_CALL(*factory_mock_, CreateParameterSetCollection())
        .WillByDefault(Return(ByMove(std::move(parameterset_collection_mock))));
    ON_CALL(*factory_mock_, CreateFaultEventReporter())
        .WillByDefault(Return(ByMove(std::move(fault_event_reporter_mock))));
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
        auto result = std::move(provided_services_container_mock_);
        provided_services_container_mock_ = std::nullopt;
        return std::move(result).value();
    }));
}

void ConfigDaemonFixture::ComponentsDefaultSetup()
{
    ON_CALL(*first_plugin_mock_, Initialize()).WillByDefault(Return(Result<Blank>{}));
}

void ConfigDaemonFixture::PluginCollectorSetup()
{
    std::vector<std::shared_ptr<IPlugin>> plugins;
    plugins.push_back(first_plugin_mock_);
    plugins.push_back(second_plugin_mock_);
    ON_CALL(*plugin_collector_mock_, CreatePlugins()).WillByDefault(Return(plugins));
    ON_CALL(*first_plugin_mock_, Initialize()).WillByDefault(Return(Result<Blank>{}));
    ON_CALL(*second_plugin_mock_, Initialize()).WillByDefault(Return(Result<Blank>{}));
    ON_CALL(*factory_mock_, CreatePluginCollector()).WillByDefault(Return(ByMove(std::move(plugin_collector_mock_))));
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppInitializeSuccess)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "12990991");
    RecordProperty("ASIL", "B");
    RecordProperty(
        "Description",
        "This test ensures that Initialize would return success, when factory can create all necessary "
        "components, and that umask is set to 0177, which should restrict the permission of files created to 0600");

    // Given the factory is able to create all necessary components
    FactoryDefaultSetup();
    EXPECT_CALL(stat_mock_, umask(score::os::IntegerToMode(0x7FU))).Times(testing::AtLeast(1));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    // When the Initialize function is run
    // Then the Initialize function would succeed
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeSuccess);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppSettingUmaskFailed)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
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
    RecordProperty("Verifies", "6950665");
    RecordProperty("ASIL", "B");
    RecordProperty("Description",
                   "This test ensures that Initialize and Run would succeed, when factory can create necessary "
                   "components as well as Initialize() and Run() was successfully executed for all plugins.");

    // Given the factory is able to create necessary components
    ComponentsDefaultSetup();
    FactoryDefaultSetup();
    EXPECT_CALL(*first_plugin_mock_, Initialize()).WillOnce(Return(Result<Blank>{}));
    EXPECT_CALL(*second_plugin_mock_, Initialize()).WillOnce(Return(Result<Blank>{}));
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

TEST_F(ConfigDaemonFixture, ConfigDaemonAppRunFailDueToInitialQualifierSenderCreationFailure)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Run()");
    RecordProperty(
        "Description",
        "This test ensures that Run would return fail, when InitialQualifierStateSender Callback cannot be created");

    // Given the factory failed to create InitialQualifierStateSender
    ComponentsDefaultSetup();
    FactoryDefaultSetup();
    EXPECT_CALL(*first_plugin_mock_, Deinitialize());

    EXPECT_CALL(*factory_mock_, CreateInitialQualifierStateSender(_))
        .WillOnce(Return(ByMove(InitialQualifierStateSender{})));
    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    score::cpp::stop_source source;
    source.request_stop();
    config_daemon_app_->Initialize(gDummyContext);
    // When the Run function is run
    // Then the Run function would fail
    ASSERT_EQ(config_daemon_app_->Run(source.get_token()), kExitCodeFailure);
}

// ToDo: Update this within CleanUp task(Ticket-192926)
TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToCreatePluginCollector)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty("Description",
                   "This test ensures that Initialize would fail, when creation of PluginCollector failed");

    // Given the factory is able to create all necessary components
    FactoryDefaultSetup();
    EXPECT_CALL(*factory_mock_, CreatePluginCollector()).WillOnce(Return(ByMove(std::move(nullptr))));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToSetupPlugins)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty("Description",
                   "This test ensures that Initialize would fail, when one of Plugin cannot be initialized");

    ComponentsDefaultSetup();
    FactoryDefaultSetup();

    ResultBlank error_result{score::MakeUnexpected(score::json::Error::kParsingError, "")};
    EXPECT_CALL(*first_plugin_mock_, Initialize()).WillOnce(Return(error_result));
    EXPECT_CALL(*second_plugin_mock_, Initialize()).Times(0);

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));

    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToInitializeSecondPlugin)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Initialize()");
    RecordProperty("Description",
                   "This test ensures that Initialize would fail, when one of Plugin cannot be initialized");

    ComponentsDefaultSetup();
    FactoryDefaultSetup();

    ResultBlank error_result{score::MakeUnexpected(score::json::Error::kParsingError, "")};
    EXPECT_CALL(*first_plugin_mock_, Initialize()).WillOnce(Return(Result<Blank>{}));
    EXPECT_CALL(*second_plugin_mock_, Initialize()).WillOnce(Return(error_result));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));

    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonAppFailedToRunFirstPlugin)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
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
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
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
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
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
    EXPECT_CALL(*first_plugin_mock, Initialize()).WillOnce(Return(Result<Blank>{}));

    config_daemon_app_ = std::make_unique<score::config_management::config_daemon::ConfigDaemon>(std::move(factory_mock_));
    ASSERT_EQ(config_daemon_app_->Initialize(gDummyContext), kExitCodeFailure);
}

TEST_F(ConfigDaemonFixture, ConfigDaemonRunFailDueToLastUpdatedParameterSetSenderCreationFailure)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing");
    RecordProperty("ASIL", "B");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_daemon::ConfigDaemon::Run()");
    RecordProperty(
        "Description",
        "This test ensures that Run would return fail, when LastUpdatedParamaterSetSender Callback cannot be created");

    // Given the factory failed to create LastUpdatedParameterSetSender
    ComponentsDefaultSetup();
    FactoryDefaultSetup();
    EXPECT_CALL(*first_plugin_mock_, Deinitialize());

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

}  // namespace test
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
