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
#include "score/config_management/config_provider/code/config_provider/builder/details/config_provider_builder_impl.h"
#include "score/config_management/config_provider/code/config_provider/builder/config_provider_builder_mock.h"
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
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <future>

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

using Strategy = ConfigProviderBuilder::Strategy;
using DummyBuilder = ConfigProviderBuilderImpl<DummyPort>;

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

ConfigProviderBuilder::StrategyFactory MakeFakeStrategyFactory(const FakeStrategySettings* settings = nullptr)
{
    return [settings](std::size_t /* additional_shm_size_bytes */) -> std::unique_ptr<Strategy> {
        return std::make_unique<AdaptiveFakeStrategy<IInternalConfigProvider, InternalConfigProviderMock>>(settings);
    };
}

class ConfigProviderBuilderTest : public ::testing::Test
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

TEST(ConfigProviderBuilderStrategyWiringTest, MakeDefaultStrategyFactory_CreatesSemiDynamicSingleInstantiationStrategy)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderBuilder::MakeDefaultStrategyFactory()");
    RecordProperty(
        "Description",
        "This test verifies that MakeDefaultStrategyFactory() creates a real "
        "SemiDynamicSingleInstantiationStrategy to discover the service. The default `make_strategy_` "
        "is `MakeDefaultStrategyFactory<InternalConfigProviderPort>()` unless `WithStrategyFactory()` replaces it, "
        "so calling `MakeDefaultStrategyFactory()` below exercises the exact same function Build() invokes. We "
        "deliberately do NOT call the real Build() here: doing so would reach "
        "SemiDynamicSingleInstantiationStrategy::StartFind() -> MwComProxy::StartFindService() -> "
        "score::mw::com::impl::Runtime::getInstance(), whose default lazy initialization parses "
        "'./etc/mw_com_config.json' and calls std::terminate() if that file is missing/invalid - crashing the "
        "whole gtest binary, not just one test, since gtest runs all tests of a binary in a single process.");

    const auto make_strategy = DummyBuilder::MakeDefaultStrategyFactory();
    std::unique_ptr<Strategy> strategy = make_strategy(0U);

    using ExpectedStrategy = SemiDynamicSingleInstantiationStrategy<IInternalConfigProvider,
                                                                    InternalConfigProvider,
                                                                    InternalConfigProvider::InternalMwComProxy,
                                                                    DummyPort>;
    const auto* const semi_dynamic_strategy = dynamic_cast<ExpectedStrategy*>(strategy.get());
    ASSERT_NE(nullptr, semi_dynamic_strategy)
        << "ConfigProviderBuilder does not build a SemiDynamicSingleInstantiationStrategy by default";
    EXPECT_EQ(DummyPort::Get(), semi_dynamic_strategy->GetPortIdentifier());
}

TEST_F(ConfigProviderBuilderTest, Build_CalledTwice_Terminates)
{
    RecordProperty("ASIL", "B");
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderBuilder::Build()");
    RecordProperty("Description", "This test verifies that a builder cannot be used to build twice.");
    DummyBuilder config_provider_builder{};
    config_provider_builder.WithStrategyFactory(MakeFakeStrategyFactory())
        .WithBufferSizeReportPath(buffer_size_report_path)
        .WithRequiredParameterSets(score::cpp::pmr::vector<std::string_view>{});
    ASSERT_NE(nullptr, config_provider_builder.Build({}));
    ASSERT_EQ(nullptr, config_provider_builder.Build({}));
}

TEST_F(ConfigProviderBuilderTest, CreateConfigProvider_DefaultPolling_NoPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderBuilder::Build()");
    RecordProperty("Description",
                   "This test verifies successful creation of default polling without persistency via config "
                   "provider builder.");
    DummyBuilder config_provider_builder{};
    auto config_provider =
        config_provider_builder.WithStrategyFactory(MakeFakeStrategyFactory())
            .WithBufferSizeReportPath(buffer_size_report_path)
            .WithRequiredParameterSets(score::cpp::pmr::vector<std::string_view>{})
            .WithPersistency(score::cpp::pmr::make_unique<PersistencyImpl>(score::cpp::pmr::get_default_resource()))
            .Build({});
    ASSERT_NE(nullptr, config_provider) << "Builder did not return a valid ConfigProvider object";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

TEST_F(ConfigProviderBuilderTest, CreateConfigProvider_DefaultPolling_Persistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderBuilder::Build()");
    RecordProperty("Description",
                   "This test verifies successful creation of default polling with valid persistency via config "
                   "provider builder.");
    DummyBuilder config_provider_builder{};
    auto persistency_mock = score::cpp::pmr::make_unique<PersistencyMock>(score::cpp::pmr::get_default_resource());
    auto config_provider = config_provider_builder.WithStrategyFactory(MakeFakeStrategyFactory())
                               .WithBufferSizeReportPath(buffer_size_report_path)
                               .WithRequiredParameterSets(score::cpp::pmr::vector<std::string_view>{})
                               .WithPersistency(std::move(persistency_mock))
                               .Build({});
    ASSERT_NE(nullptr, config_provider) << "Builder did not return a valid ConfigProvider object";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

TEST_F(ConfigProviderBuilderTest, FoundServiceDuringCreation)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("lobster-tracing", "ConfigProvider.CallbackTriggeredOnServiceAvailable");
    RecordProperty("Verifies", "23162623");
    RecordProperty("ASIL", "QM");
    RecordProperty("Description", "This test ensures that callback is triggered when service becomes available");

    DummyBuilder config_provider_builder{};
    std::promise<void> callback_called;
    std::atomic<bool> callback_signaled{false};
    AvailabilityNotificationCallback callback{[&callback_called, &callback_signaled]() noexcept {
        if (!callback_signaled.exchange(true))
        {
            callback_called.set_value();
        }
    }};
    FakeStrategySettings fake_strategy_settings{true, InitialQualifierState::kUndefined};
    auto config_provider =
        config_provider_builder.WithStrategyFactory(MakeFakeStrategyFactory(&fake_strategy_settings))
            .WithBufferSizeReportPath(buffer_size_report_path)
            .WithAvailabilityNotificationCallback(std::move(callback))
            .WithRequiredParameterSets(score::cpp::pmr::vector<std::string_view>{})
            .WithPersistency(score::cpp::pmr::make_unique<PersistencyImpl>(score::cpp::pmr::get_default_resource()))
            .Build({});
    ASSERT_NE(nullptr, config_provider) << "Builder did not return a valid ConfigProvider object";
    callback_called.get_future().wait();
    EXPECT_TRUE(callback_signaled) << "Callback is triggered when the proxy finds service";
}

TEST_F(ConfigProviderBuilderTest, CreateConfigProvider_MissingBufferSizeReport_FallsBackToDefaultBufferSizes)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderBuilder::Build()");
    RecordProperty("Description",
                   "This test verifies that the config provider builder still creates a valid ConfigProvider "
                   "(falling back to default buffer sizes instead of returning nullptr) when "
                   "buffer_size_report.json cannot be found.");
    DummyBuilder config_provider_builder{};
    const std::string missing_report_path = buffer_size_report_path + "_missing";
    auto config_provider = config_provider_builder.WithStrategyFactory(MakeFakeStrategyFactory())
                               .WithBufferSizeReportPath(missing_report_path)
                               .WithRequiredParameterSets(score::cpp::pmr::vector<std::string_view>{})
                               .Build({});
    ASSERT_NE(nullptr, config_provider) << "Builder did not fall back to default buffer sizes as expected";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

TEST_F(ConfigProviderBuilderTest, BuildCreatesConfigProviderWithDefaults)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderBuilder::Build()");
    RecordProperty("Description",
                   "This test verifies that Build() creates a ConfigProviderImpl when only the settings needed to "
                   "avoid a real mw::com runtime are given.");
    DummyBuilder config_provider_builder{};
    auto config_provider = config_provider_builder.WithStrategyFactory(MakeFakeStrategyFactory())
                               .WithBufferSizeReportPath(buffer_size_report_path)
                               .Build({});
    ASSERT_NE(nullptr, config_provider) << "Build() did not return a valid ConfigProvider object";
    EXPECT_NE(nullptr, dynamic_cast<ConfigProviderImpl*>(config_provider.get()))
        << "ConfigProvider object is not a ConfigProviderImpl instance";
}

TEST_F(ConfigProviderBuilderTest, BuildForwardsAllSettings)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Generation and analysis of equivalence classes");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::config_management::config_provider::ConfigProviderBuilder::Build()");
    RecordProperty("Description",
                   "This test verifies that Build() forwards notification callback so that the callback is triggered "
                   "when the service is found.");
    DummyBuilder config_provider_builder{};
    std::promise<void> callback_called;
    std::atomic<bool> callback_signaled{false};
    FakeStrategySettings fake_strategy_settings{true, InitialQualifierState::kUndefined};
    const score::cpp::pmr::vector<std::string_view> parameter_set_names{};
    auto config_provider =
        config_provider_builder.WithStrategyFactory(MakeFakeStrategyFactory(&fake_strategy_settings))
            .WithBufferSizeReportPath(buffer_size_report_path)
            .WithRequiredParameterSets(parameter_set_names)
            .WithConnectionTimeout(std::chrono::milliseconds(0U))
            .WithPersistency(score::cpp::pmr::make_unique<PersistencyImpl>(score::cpp::pmr::get_default_resource()))
            .WithMemoryResource(score::cpp::pmr::get_default_resource())
            .WithAvailabilityNotificationCallback(
                AvailabilityNotificationCallback{[&callback_called, &callback_signaled]() noexcept {
                    if (!callback_signaled.exchange(true))
                    {
                        callback_called.set_value();
                    }
                }})
            .Build({});
    ASSERT_NE(nullptr, config_provider) << "Build() did not return a valid ConfigProvider object";
    callback_called.get_future().wait();
    EXPECT_TRUE(callback_signaled) << "Callback is triggered when the proxy finds service";
}
}  // namespace test
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
