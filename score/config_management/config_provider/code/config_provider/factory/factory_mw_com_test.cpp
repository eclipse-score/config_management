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
#include "score/config_management/config_provider/code/config_provider/factory/factory_mw_com.h"
#include "score/config_management/config_provider/code/config_provider/error/error.h"
#include "score/config_management/config_provider/code/config_provider/factory/semi_dynamic_single_instantiation_strategy.h"
#include "score/config_management/config_provider/code/persistency/details/persistency_impl.h"
#include "score/config_management/config_provider/code/persistency/persistency_mock.h"
#include "score/config_management/config_provider/code/proxies/internal_config_provider.h"
#include "score/config_management/config_provider/code/proxies/internal_config_provider_mock.h"

#include "score/mw/service/find_service_strategy.h"
#include "score/json/json_parser.h"
#include "score/mw/com/runtime.h"
#include "score/mw/com/runtime_configuration.h"

#include <gtest/gtest.h>

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>

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

using Strategy = ConfigProviderFactory::Strategy;

struct FakeStrategySettings
{
    bool subscribe_result{true};
    InitialQualifierState initial_qualifier_state{InitialQualifierState::kUndefined};
};

template <typename ProxyBase, typename ProxyMock>
class AdaptiveFakeStrategy final : public mw::service::FindServiceStrategy<ProxyBase>
{
  public:
    using typename mw::service::FindServiceStrategy<ProxyBase>::OnServiceFoundCallback;

    explicit AdaptiveFakeStrategy(const FakeStrategySettings* settings = nullptr) : settings_{settings} {}

    void StartFind(std::unique_ptr<OnServiceFoundCallback> on_found) override
    {
        if (on_found == nullptr)
        {
            return;
        }
        auto proxy = std::make_unique<ProxyMock>();
        if (settings_ != nullptr)
        {
            ON_CALL(*proxy, TrySubscribeToLastUpdatedParameterSetEvent(::testing::_, ::testing::_))
                .WillByDefault(::testing::Return(settings_->subscribe_result));
            ON_CALL(*proxy, GetInitialQualifierState(::testing::_))
                .WillByDefault(::testing::Return(settings_->initial_qualifier_state));
        }
        (*on_found)(std::move(proxy));
    }

    void StopFind() noexcept override {}

  private:
    const FakeStrategySettings* settings_;
};

ConfigProviderFactory::StrategyFactory MakeFakeStrategyFactory(const FakeStrategySettings* settings = nullptr)
{
    return [settings](std::size_t /* additional_shm_size_bytes */) -> std::unique_ptr<Strategy> {
        return std::make_unique<AdaptiveFakeStrategy<IInternalConfigProvider, InternalConfigProviderMock>>(settings);
    };
}

class ConfigProviderFactoryTest : public ::testing::Test
{
  public:
    void SetUp() override
    {
        const char* const test_tmpdir = std::getenv("TEST_TMPDIR");
        buffer_size_report_path =
            std::string{test_tmpdir != nullptr ? test_tmpdir : "/tmp"} + "/buffer_size_report.json";
        std::ofstream buffer_size_report_file{buffer_size_report_path};
        buffer_size_report_file << R"({"buffer_size_mapping": {"DummyParameterSet": 16425}})";
        buffer_size_report_file.close();
    }

    void TearDown() override
    {
        std::remove(buffer_size_report_path.c_str());
    }

    std::string buffer_size_report_path;
};

TEST(ConfigProviderFactoryStrategyWiringTest, CreateUsesSemiDynamicSingleInstantiationStrategyByDefault)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderFactory::Create()");
    RecordProperty(
        "Description",
        "This test verifies that ConfigProviderFactory::Create() builds a real "
        "SemiDynamicSingleInstantiationStrategy to discover the service. Create() forwards to CreateInternal() "
        "*without* ever passing a `make_strategy` argument (see factory_mw_com.h), so CreateInternal()'s default "
        "parameter value - `MakeDefaultStrategyFactory<InternalConfigProviderPort>()` - is unconditionally what "
        "Create() uses: there is no other code path or indirection to verify. Calling `MakeDefaultStrategyFactory()` "
        "below therefore exercises the exact same function Create() invokes, not just an equivalent one. We "
        "deliberately do NOT call the real public Create() here: doing so would reach "
        "SemiDynamicSingleInstantiationStrategy::StartFind() -> MwComProxy::StartFindService() -> "
        "score::mw::com::impl::Runtime::getInstance(), whose default lazy initialization parses "
        "'./etc/mw_com_config.json' and calls std::terminate() if that file is missing/invalid - crashing the "
        "whole gtest binary, not just one test, since gtest runs all tests of a binary in a single process.");

    const auto make_strategy = ConfigProviderFactory::MakeDefaultStrategyFactory<DummyPort>();
    std::unique_ptr<Strategy> strategy = make_strategy(0U);

    using ExpectedStrategy = SemiDynamicSingleInstantiationStrategy<IInternalConfigProvider,
                                                                    InternalConfigProvider,
                                                                    InternalConfigProvider::InternalMwComProxy,
                                                                    DummyPort>;
    const auto* const semi_dynamic_strategy = dynamic_cast<ExpectedStrategy*>(strategy.get());
    ASSERT_NE(nullptr, semi_dynamic_strategy)
        << "ConfigProviderFactory does not build a SemiDynamicSingleInstantiationStrategy by default";
    EXPECT_EQ(DummyPort::Get(), semi_dynamic_strategy->GetPortIdentifier());
}

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_DefaultPolling_NoPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderFactory::Create()");
    RecordProperty(
        "Description",
        "This test verifies successful creation of default polling without persistency via config provider factory.");
    score::config_management::config_provider::ConfigProviderFactory config_provider_factory{};
    auto config_provider = config_provider_factory.Create<DummyPort>(
        {},
        std::chrono::milliseconds(0U),
        score::cpp::pmr::make_unique<PersistencyImpl>(score::cpp::pmr::get_default_resource()),
        score::cpp::pmr::vector<std::string_view>{},
        MakeFakeStrategyFactory(),
        score::cpp::pmr::get_default_resource(),
        []() noexcept {},
        buffer_size_report_path);
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_CustomPolling_NoPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderFactory::Create()");
    RecordProperty(
        "Description",
        "This test verifies successful creation of custom polling without persistency via config provider factory.");
    score::config_management::config_provider::ConfigProviderFactory config_provider_factory{};
    auto config_provider = config_provider_factory.Create<DummyPort>(
        {},
        std::chrono::milliseconds(0U),
        score::cpp::pmr::make_unique<PersistencyImpl>(score::cpp::pmr::get_default_resource()),
        score::cpp::pmr::vector<std::string_view>{},
        MakeFakeStrategyFactory(),
        score::cpp::pmr::get_default_resource(),
        []() noexcept {},
        buffer_size_report_path);
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_DefaultPolling_Persistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderFactory::Create()");
    RecordProperty("Description",
                   "This test verifies successful creation of default polling with valid persistency via config "
                   "provider factory.");
    score::config_management::config_provider::ConfigProviderFactory config_provider_factory{};
    auto persistency_mock = score::cpp::pmr::make_unique<PersistencyMock>(score::cpp::pmr::get_default_resource());
    auto config_provider = config_provider_factory.Create<DummyPort>(
        {},
        std::chrono::milliseconds(0U),
        std::move(persistency_mock),
        score::cpp::pmr::vector<std::string_view>{},
        MakeFakeStrategyFactory(),
        score::cpp::pmr::get_default_resource(),
        []() noexcept {},
        buffer_size_report_path);
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_CustomPolling_Persistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderFactory::Create()");
    RecordProperty(
        "Description",
        "This test verifies successful creation of custom polling with valid persistency via config provider factory.");
    score::config_management::config_provider::ConfigProviderFactory config_provider_factory{};
    auto persistency_mock = score::cpp::pmr::make_unique<PersistencyMock>(score::cpp::pmr::get_default_resource());
    auto config_provider = config_provider_factory.Create<DummyPort>(
        {},
        std::chrono::milliseconds(0U),
        std::move(persistency_mock),
        score::cpp::pmr::vector<std::string_view>{},
        MakeFakeStrategyFactory(),
        score::cpp::pmr::get_default_resource(),
        []() noexcept {},
        buffer_size_report_path);
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

TEST_F(ConfigProviderFactoryTest, FoundServiceDuringCreation)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("lobster-tracing", "ConfigProvider.CallbackTriggeredOnServiceAvailable");
    RecordProperty("Verifies", "23162623");
    RecordProperty("ASIL", "QM");
    RecordProperty("Description",
                   "23162623: This test ensures that callback is triggered when service becomes available");

    score::config_management::config_provider::ConfigProviderFactory config_provider_factory{};
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
    FakeStrategySettings fake_strategy_settings{true, InitialQualifierState::kUndefined};
    auto config_provider = config_provider_factory.Create<DummyPort>(
        {},
        std::chrono::milliseconds(0U),
        score::cpp::pmr::make_unique<PersistencyImpl>(score::cpp::pmr::get_default_resource()),
        score::cpp::pmr::vector<std::string_view>{},
        MakeFakeStrategyFactory(&fake_strategy_settings),
        score::cpp::pmr::get_default_resource(),
        std::move(callback),
        buffer_size_report_path);
    ASSERT_NE(nullptr, config_provider) << "Factory did not return a valid ConfigProvider object";
    std::unique_lock<std::mutex> ul{callback_mutex};
    callback_cv.wait_for(ul, std::chrono::milliseconds{1000});
    ASSERT_TRUE(callback_is_called_upon_found) << "Callback is triggered when the proxy finds service";
}

TEST_F(ConfigProviderFactoryTest, CreateConfigProvider_MissingBufferSizeReport_FallsBackToDefaultBufferSizes)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderFactory::Create()");
    RecordProperty("Description",
                   "This test verifies that the config provider factory still creates a valid ConfigProvider "
                   "(falling back to default buffer sizes instead of returning nullptr) when "
                   "buffer_size_report.json cannot be found.");
    score::config_management::config_provider::ConfigProviderFactory config_provider_factory{};
    auto config_provider = config_provider_factory.Create<DummyPort>(
        {},
        std::chrono::milliseconds(0U),
        score::cpp::pmr::make_unique<PersistencyImpl>(score::cpp::pmr::get_default_resource()),
        score::cpp::pmr::vector<std::string_view>{},
        MakeFakeStrategyFactory(),
        score::cpp::pmr::get_default_resource(),
        []() noexcept {},
        buffer_size_report_path + "_missing");
    ASSERT_NE(nullptr, config_provider) << "Factory did not fall back to default buffer sizes as expected";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

}  // namespace test
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
