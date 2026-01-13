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
#include "score/config_management/config_provider/code/config_provider/details/config_provider_impl.h"
#include "score/config_management/config_provider/code/config_provider/error/error.h"
#include "score/config_management/config_provider/code/config_provider/initial_qualifier_state_types.h"
#include "score/config_management/config_provider/code/parameter_set/parameter_set.h"
#include "score/config_management/config_provider/code/persistency/persistency_mock.h"
#include "score/config_management/config_provider/code/proxies/internal_config_provider_mock.h"

#include "score/config_management/config_provider/code/persistency/error/persistency_error.h"

#include "score/concurrency/future/interruptible_promise.h"
#include "score/concurrency/interruptible_wait.h"
#include "score/concurrency/notification.h"

#include "score/json/json_parser.h"
#include "score/mw/log/detail/common/recorder_factory.h"
#include "score/mw/log/runtime.h"

#include <gtest/gtest.h>

#include <future>
#include <memory>
#include <type_traits>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace test
{

using namespace std::chrono_literals;

using ::testing::_;
using ::testing::ByMove;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;

MATCHER_P(StringViewCompare, str, "")
{
    auto str_arg = std::string(arg.begin(), arg.end());
    *result_listener << ::testing::PrintToString(str) << " shall equal " << ::testing::PrintToString(str_arg);
    return str == str_arg;
}

class ConfigProviderTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        persistency_ = score::cpp::pmr::make_unique<PersistencyMock>(score::cpp::pmr::get_default_resource());
        correct_parameter_set_from_proxy_ = json::JsonParser{}.FromBuffer(R"(
        {
            "parameters": {
                "parameter_name": 55
            },
            "qualifier": 1
        }
        )");
        updated_parameter_set_from_proxy_ = json::JsonParser{}.FromBuffer(R"(
        {
            "parameters": {
                "parameter_name": 56
            },
            "qualifier": 3
        }
        )");
    };
    void UnblockMakeProxyAvailable()
    {
        std::unique_lock<std::mutex> ul{is_available_mutex_};
        is_available_ = true;
        ul.unlock();
        is_available_cv_.notify_all();
    }
    void BlockUntilProxyIsReady(score::cpp::stop_token token)
    {
        std::unique_lock<std::mutex> ul{is_available_mutex_};
        is_available_cv_.wait(ul, token, [this]() {
            return is_available_ == true;
        });
    }
    void TearDown() override
    {
        stop_source_.request_stop();
        registered_on_changed_parameter_set_callback_ = nullptr;
    }
    void SetUpPersistency()
    {
        EXPECT_CALL(*persistency_, ReadCachedParameterSets(_, _, _))
            .WillOnce(Invoke([&](ParameterMap& cached_parameter_sets,
                                 score::cpp::pmr::memory_resource*,
                                 const score::filesystem::Filesystem&) -> void {
                const score::cpp::pmr::string param_set_key{parameter_set_name_};
                const std::string param_set_json = R"(
                    {
                        "parameters": {
                            "parameter_name": 54
                        },
                        "qualifier": 0
                    })";
                json::JsonParser json_parser{};
                auto persisted_parameter_set =
                    std::make_shared<const ParameterSet>(json_parser.FromBuffer(param_set_json).value());

                cached_parameter_sets.emplace(param_set_key, persisted_parameter_set);
                return;
            }));
    }
    void FailProxySearch()
    {
        promise_.SetError(static_cast<score::result::Error>(ConfigProviderError::kProxyNotReady));
    }

    void SetUpProxyButProxyCouldNotProvideInitialQualifierStateOnFirstRequest()
    {
        std::unique_ptr<InternalConfigProviderMock> internal_config_provider =
            std::make_unique<InternalConfigProviderMock>();
        icp_mock_ = internal_config_provider.get();
        EXPECT_CALL(*icp_mock_, TrySubscribeToLastUpdatedParameterSetEvent(_, _)).WillOnce(Return(true));

        EXPECT_CALL(*icp_mock_, GetInitialQualifierState(ConfigProviderImpl::kDefaultResponseTimeout))
            .Times(2)
            .WillOnce(Return(InitialQualifierState::kUndefined))
            .WillOnce(Return(InitialQualifierState::kQualified));
        promise_.SetValue(std::move(internal_config_provider));
    }

    void SetUpProxy(std::string set_name,
                    const score::Result<score::json::Any>& content,
                    InitialQualifierState final_initial_qualifier_state = InitialQualifierState::kDefault)
    {
        std::unique_ptr<InternalConfigProviderMock> internal_config_provider =
            std::make_unique<InternalConfigProviderMock>();
        icp_mock_ = internal_config_provider.get();
        EXPECT_CALL(*icp_mock_, TrySubscribeToLastUpdatedParameterSetEvent(_, _))
            .WillOnce(Invoke(
                [this](const score::cpp::stop_token&, IInternalConfigProvider::OnChangedParameterSetCallback&& callback) {
                    registered_on_changed_parameter_set_callback_ = std::move(callback);
                    return true;
                }));
        EXPECT_CALL(*icp_mock_,
                    GetParameterSet(StringViewCompare(set_name), ConfigProviderImpl::kDefaultResponseTimeout))
            .WillRepeatedly(
                Invoke([&content](const score::cpp::string_view, const std::chrono::milliseconds) -> Result<json::Any> {
                    if (content.has_value())
                    {
                        auto temp = content.value().CloneByValue();
                        return Result<json::Any>{std::move(temp)};
                    }
                    return Unexpected{content.error()};
                }));

        EXPECT_CALL(*icp_mock_,
                    GetParameterSet(StringViewCompare("wrong_set_name"), ConfigProviderImpl::kDefaultResponseTimeout))
            .WillRepeatedly(Return(ByMove(MakeUnexpected(ConfigProviderError::kProxyReturnedNoResult))));
        EXPECT_CALL(
            *icp_mock_,
            GetParameterSet(StringViewCompare("invalid_parameter_set"), ConfigProviderImpl::kDefaultResponseTimeout))
            .WillRepeatedly(Return(ByMove(Result<json::Any>{json::Any{}})));

        EXPECT_CALL(*icp_mock_, GetInitialQualifierState(ConfigProviderImpl::kDefaultResponseTimeout))
            .WillRepeatedly(Return(final_initial_qualifier_state));

        EXPECT_CALL(*icp_mock_, StopParameterSetUpdatePollingRoutine()).Times(1);
        promise_.SetValue(std::move(internal_config_provider));
    }
    auto CreateConfigProviderWithAvailableCallback(IsAvailableNotificationCallback callback)
    {
        return std::make_unique<ConfigProviderImpl>(promise_.GetInterruptibleFuture().value(),
                                                    stop_source_.get_token(),
                                                    score::cpp::pmr::get_default_resource(),
                                                    score::cpp::nullopt,  // default max_samples_limit
                                                    score::cpp::nullopt,  // default polling_cycle_interval
                                                    std::move(callback),
                                                    std::move(persistency_));
    }

    score::Result<score::json::Any> correct_parameter_set_from_proxy_;
    score::Result<score::json::Any> updated_parameter_set_from_proxy_;
    const std::string parameter_set_name_ = "set_name";
    const std::string parameter_name_ = "parameter_name";
    const int updated_content_from_proxy_ = 56;
    const int parameter_content_from_proxy_ = 55;
    const int parameter_content_from_persistency_ = 54;
    const score::config_management::config_daemon::ParameterSetQualifier updated_qualifier_from_proxy_ =
        score::config_management::config_daemon::ParameterSetQualifier::kModified;
    const score::config_management::config_daemon::ParameterSetQualifier parameter_qualifier_from_proxy_ =
        score::config_management::config_daemon::ParameterSetQualifier::kQualified;
    const score::config_management::config_daemon::ParameterSetQualifier parameter_qualifier_from_persistency_ =
        score::config_management::config_daemon::ParameterSetQualifier::kUnqualified;
    concurrency::InterruptiblePromise<std::unique_ptr<IInternalConfigProvider>> promise_;
    std::shared_ptr<const ParameterSet> persisted_cache_set_;
    std::atomic<bool> is_available_{false};
    concurrency::InterruptibleConditionalVariable is_available_cv_;
    std::mutex is_available_mutex_;
    InternalConfigProviderMock* icp_mock_{nullptr};
    score::cpp::stop_source stop_source_;
    PersistencyMock* persistency_mock_{nullptr};
    score::cpp::pmr::unique_ptr<PersistencyMock> persistency_;
    IInternalConfigProvider::OnChangedParameterSetCallback registered_on_changed_parameter_set_callback_{nullptr};
};

TEST_F(ConfigProviderTest, ProxySearchingBlocked_ClientDoNotWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "32232080, 14351548, 32231893");
    RecordProperty("ASIL", "B");
    RecordProperty(
        "Description",
        "32232080: This test checks if qualification of the Parameter Sets has not finished and persistent-caching is "
        "disabled, no Parameter Set will be provided to the user application."
        "14351548: This test checks that ConfigProvider get Undefined InitialQualifierState when there is no update from "
        "ConfigDaemon application."
        "32231893: This test checks that ConfigProvider cannot fetch data from persistent-caching if no persistency "
        "object for the cache is provided during creation of the ConfigProvider.");
    // Given a ConfigProvider instance which is blocked waiting for its proxy to become available
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});

    // Then GetInitialQualifierState() would return Undefined InitialQualifierState
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUndefined);
    // Then GetParameterSet() would return ProxyNotReady error and cannot fetch from persistency
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    EXPECT_TRUE(
        config_provider->OnChangedParameterSet(parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {})
            .has_value());
    EXPECT_EQ(config_provider->CheckParameterSetUpdates().error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    stop_source_.request_stop();
}

TEST_F(ConfigProviderTest, ProxySearchingFailed_ClientDoNotWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "32232080, 14351548, 32231893");
    RecordProperty("ASIL", "B");
    RecordProperty(
        "Description",
        "32232080: This test checks if qualification of the Parameter Sets has not finished and persistent-caching is "
        "disabled, no Parameter Set will be provided to the user application."
        "14351548: This test checks that ConfigProvider get Undefined InitialQualifierState when there is no update from "
        "ConfigDaemon application."
        "32231893: This test checks that ConfigProvider cannot fetch data from persistent-caching if no persistency "
        "object for the cache is provided during creation of the ConfigProvider.");

    // Given a ConfigProvider instance which failed to find its proxy
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});
    FailProxySearch();

    // Then GetInitialQualifierState() would return Undefined InitialQualifierState
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUndefined);
    // Then GetParameterSet() would return ProxyNotReady error and cannot fetch from persistency
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    EXPECT_TRUE(
        config_provider->OnChangedParameterSet(parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {})
            .has_value());
    EXPECT_EQ(config_provider->CheckParameterSetUpdates().error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
}

TEST_F(ConfigProviderTest, ProxySearchingBlocked_DestroyRightAway_NoPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl(), "
                   "::score::platform::config_provider::ConfigProviderImpl::~ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test verifies that a ConfigProviderImpl instance can get destroyed directly after its "
                   "creation even though it might internally still be waiting for the proxy to become available.");

    // Given a ConfigProvider instance
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});

    // Check that ConfigProvider instance is valid
    EXPECT_NE(config_provider, nullptr);

    // And destroying it right away
    EXPECT_NO_THROW(config_provider.reset());

    // Then such destruction must succeed and not block in any way
}

TEST_F(ConfigProviderTest, ProxySearchingBlocked_DestroyAfterWait_NoPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies",
                   "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl(), "
                   "::score::platform::config_provider::ConfigProviderImpl::~ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test verifies that a ConfigProviderImpl instance can get destroyed after waiting a certain "
                   "amount of time even though it is internally still waiting for the proxy to become available.");

    // Given a ConfigProvider instance
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});

    // Check that ConfigProvider instance is valid
    EXPECT_NE(config_provider, nullptr);

    // When waiting for its proxy to be become available after 100ms in vain
    EXPECT_FALSE(config_provider->WaitUntilConnected(100ms, {}));

    // And destroying it afterwards
    EXPECT_NO_THROW(config_provider.reset());

    // Then such destruction must succeed and not block in any way
}

TEST_F(ConfigProviderTest, ProxySearchingBlocked_RequestStop_NoPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test verifies that a user can cancel ConfigProviderImpl's internal logic which waits "
                   "until its proxy became available.");

    // Given a ConfigProvider instance which received a stop_token instance upon construction
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});

    // When waiting for it to be in the state of awaiting its proxy to connect
    auto is_awaiting_proxy_connection_future = std::async(std::launch::async, [&config_provider] {
        while (not(config_provider->IsAwaitingProxyConnection()))
        {
            std::this_thread::sleep_for(1ms);
        }
    });
    ASSERT_EQ(is_awaiting_proxy_connection_future.wait_for(1s), std::future_status::ready);

    // And requesting stop at our `stop_source_` after a few milliseconds
    std::this_thread::sleep_for(10ms);
    stop_source_.request_stop();

    // Then the ConfigProvider instance must be no longer awaiting its proxy to connect at latest after 1s
    auto is_no_longer_awaiting_proxy_connection_future = std::async(std::launch::async, [&config_provider] {
        while (config_provider->IsAwaitingProxyConnection())
        {
            std::this_thread::sleep_for(1ms);
        }
    });
    EXPECT_EQ(is_no_longer_awaiting_proxy_connection_future.wait_for(1s), std::future_status::ready);
}

TEST_F(ConfigProviderTest, ProxySearchingBlocked_ClientWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test checks the scenario when the client waits for the proxy to be available and the "
                   "searching thread is blocked, the client thread would be blocked as well.");
    std::atomic<bool> shall_not_enter = true;
    // Given a ConfigProvider instance which is blocked waiting for its proxy to become available
    score::cpp::jthread client_thread{[this, &shall_not_enter]() {
        auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});
        BlockUntilProxyIsReady(stop_source_.get_token());
        // Then the client thread would be blocked as well
        EXPECT_FALSE(shall_not_enter);
    }};
    shall_not_enter = false;
    stop_source_.request_stop();
    client_thread.join();
}

TEST_F(ConfigProviderTest, ProxySearchingFailed_ClientWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test checks the scenario when the client waits for the proxy to be available and the "
                   "searching thread failed to find a thread, the client thread would be blocked.");
    std::atomic<bool> shall_not_enter = true;
    // Given a ConfigProvider instance which is blocked waiting for its proxy to become available, but fails
    score::cpp::jthread client_thread{[this, &shall_not_enter]() {
        auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});
        FailProxySearch();
        BlockUntilProxyIsReady(stop_source_.get_token());
        // Then the client thread would be blocked as well
        EXPECT_FALSE(shall_not_enter);
    }};
    shall_not_enter = false;
    stop_source_.request_stop();
    client_thread.join();
}

TEST_F(ConfigProviderTest, ProxySearchingSuccess_ClientWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("Verifies", " 11397333, 32232137");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("ASIL", "B");
    RecordProperty(
        "Description",
        "This test checks the scenario when the client waits for the proxy to be available and the persistency is "
        "empty. The client would get error kProxyNotReady when trying to use config_provider, when the proxy searching "
        "thread is still blocked. The client would get updated ParameterSet when trying to use config_provider, when "
        "the proxy searching thread finds the proxy."
        "11397333: The Qualifier state can be retrieved to indicate the integrity of the Parameter Set data."
        "32232137: After the qualification has finished and the service is found, ConfigProvider can find the updated "
        "ParameterSet.");

    // Given a ConfigProvider instance which is blocked waiting for its proxy to become available
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    // Then GetInitialQualifierState() would return Undefined InitialQualifierState
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUndefined);
    // Then GetParameterSet() would return ProxyNotReady error
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    EXPECT_TRUE(
        config_provider->OnChangedParameterSet(parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {})
            .has_value());
    // Then CheckParameterSetUpdates() would return ProxyNotReady error
    EXPECT_EQ(config_provider->CheckParameterSetUpdates().error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, InitialQualifierState::kQualified);
    // Given the proxy searching thread found the proxy
    BlockUntilProxyIsReady(stop_source_.get_token());

    // Then GetInitialQualifierState() would return Qualified InitialQualifierState
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kQualified);
    // Then GetParameterSet() would return correct ParameterSet from proxy
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_)
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_proxy_);
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).value()->GetQualifier().value(),
              parameter_qualifier_from_proxy_);

    EXPECT_EQ(config_provider->OnChangedParameterSet(parameter_set_name_, nullptr).error(),
              MakeUnexpected(ConfigProviderError::kEmptyCallbackProvided).error());
    EXPECT_TRUE(config_provider->CheckParameterSetUpdates().has_value());
}

TEST_F(ConfigProviderTest, InitialQualifierStateWasInitiallyNotAvailableFromProxy_ClientWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::GetInitialQualifierState()");
    RecordProperty("Description",
                   "This test checks the scenario when NCD state was initially not available in proxy, but could be "
                   "received later by a request");
    // Given a ConfigProvider instance which is blocked waiting for its proxy to become available
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    // Then GetInitialQualifierState() would return Undefined InitialQualifierState before proxy is available
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUndefined);
    SetUpProxyButProxyCouldNotProvideInitialQualifierStateOnFirstRequest();
    // Given the proxy searching thread found the proxy
    BlockUntilProxyIsReady(stop_source_.get_token());
    // Then GetInitialQualifierState() would return updated InitialQualifierState after proxy is available
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kQualified);
}

TEST_F(ConfigProviderTest, ProxySearchingSuccessButNcdIsUnqualified_ClientWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::GetInitialQualifierState()");
    RecordProperty(
        "Description",
        "This test checks the scenario when the client waits for the proxy to be available and the persistency is "
        "empty. If proxy returned an unqualified NCD state it will be cached and returned on a get request.");

    // Given a ConfigProvider instance waiting for proxy with unqualified NCD state
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUndefined);
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    EXPECT_TRUE(
        config_provider->OnChangedParameterSet(parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {})
            .has_value());
    EXPECT_EQ(config_provider->CheckParameterSetUpdates().error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, InitialQualifierState::kUnqualified);
    BlockUntilProxyIsReady(stop_source_.get_token());

    // Then GetInitialQualifierState returns unqualified state from proxy
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUnqualified);
    // Then GetParameterSet returns unqualified parameter set
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_)
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_proxy_);
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).value()->GetQualifier().value(),
              parameter_qualifier_from_proxy_);

    EXPECT_EQ(config_provider->OnChangedParameterSet(parameter_set_name_, nullptr).error(),
              MakeUnexpected(ConfigProviderError::kEmptyCallbackProvided).error());
    EXPECT_TRUE(config_provider->CheckParameterSetUpdates().has_value());
}

TEST_F(ConfigProviderTest, InitialQualifierStateWasInitiallyNotAvailableFromProxy_ClientWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::GetInitialQualifierState()");
    RecordProperty(
        "Description",
        "This test checks the scenario when initialQualifierState was initially not available in proxy, but could be "
        "received later by a request");
    // Given a ConfigProvider instance waiting for proxy that cannot provide NCD state initially
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    // Then GetInitialQualifierState returns undefined before proxy is available
    EXPECT_EQ(config_provider->GetInitialQualifierState(std::nullopt), InitialQualifierState::kUndefined);
    // When proxy becomes available and can provide NCD state on second try
    SetUpProxyButProxyCouldNotProvideInitialQualifierStateOnFirstRequest();
    BlockUntilProxyIsReady(stop_source_.get_token());
    // Then GetInitialQualifierState returns qualified state from proxy
    EXPECT_EQ(config_provider->GetInitialQualifierState(std::nullopt), InitialQualifierState::kQualified);
}

TEST_F(ConfigProviderTest, ProxySearchingSuccessButInitialQualifierStateIsUnqualified_ClientWait_EmptyPersistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::GetInitialQualifierState()");
    RecordProperty(
        "Description",
        "This test checks the scenario when the client waits for the proxy to be available and the persistency is "
        "empty. If proxy returned an unqualified InitialQualifierState it will be cached and returned on a get "
        "request.");

    // Given a ConfigProvider instance waiting for proxy with unqualified InitialQualifierState
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    // Then GetInitialQualifierState returns undefined before proxy is available
    EXPECT_EQ(config_provider->GetInitialQualifierState(std::nullopt), InitialQualifierState::kUndefined);
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    EXPECT_TRUE(
        config_provider->OnChangedParameterSet(parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {})
            .has_value());
    EXPECT_EQ(config_provider->CheckParameterSetUpdates().error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    // When proxy becomes available with unqualified InitialQualifierState
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, InitialQualifierState::kUnqualified);
    BlockUntilProxyIsReady(stop_source_.get_token());

    // Then GetInitialQualifierState returns unqualified state from proxy
    EXPECT_EQ(config_provider->GetInitialQualifierState(std::nullopt), InitialQualifierState::kUnqualified);
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_)
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_proxy_);
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).value()->GetQualifier().value(),
              parameter_qualifier_from_proxy_);

    EXPECT_EQ(config_provider->OnChangedParameterSet(parameter_set_name_, nullptr).error(),
              MakeUnexpected(ConfigProviderError::kEmptyCallbackProvided).error());
    EXPECT_TRUE(config_provider->CheckParameterSetUpdates().has_value());
}

TEST_F(ConfigProviderTest, ProxySearchingBlocked_ClientDoNotWait_Persistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "32231893");
    RecordProperty("ASIL", "QM");
    RecordProperty(
        "Description",
        "32231893: This test checks the scenario when the client waits for the proxy to be available and the "
        "persistency is "
        "not empty. The client would get persisted ParameterSet when trying to use config_provider, when the proxy "
        "searching thread is still blocked.");
    // Given persistency with cached parameter sets
    SetUpPersistency();
    // When ConfigProvider is created with proxy search blocked
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});

    // Then GetInitialQualifierState returns undefined (proxy not available)
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUndefined);
    // Then GetParameterSet returns cached parameter set from persistency
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_)
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_persistency_);
    EXPECT_TRUE(
        config_provider->OnChangedParameterSet(parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {})
            .has_value());
    EXPECT_EQ(config_provider->CheckParameterSetUpdates().error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
    stop_source_.request_stop();
}

TEST_F(ConfigProviderTest, ProxySearchingFailed_ClientDoNotWait_Persistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "32231893");
    RecordProperty("ASIL", "QM");
    RecordProperty(
        "Description",
        "32231893: This test checks the scenario when the client waits for the proxy to be available and the "
        "persistency is "
        "not empty. The client would get persisted ParameterSet when trying to use config_provider, when the proxy "
        "searching thread failed to find the proxy.");
    // Given persistency with cached parameter sets
    SetUpPersistency();
    // When ConfigProvider is created and proxy search fails
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});
    FailProxySearch();

    // Then GetInitialQualifierState returns undefined (proxy not available)
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUndefined);
    // Then GetParameterSet returns cached parameter set from persistency
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_)
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_persistency_);
    EXPECT_TRUE(
        config_provider->OnChangedParameterSet(parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {})
            .has_value());
    EXPECT_EQ(config_provider->CheckParameterSetUpdates().error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());
}

TEST_F(ConfigProviderTest, SubscribeBeforeGettingDataFromProxy)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test ensures that during construction stage, the ConfigProvider would subscribe to the "
                   "LastUpdatedParameterSetEvent "
                   "before fetching any ParameterSet name from it");

    // Given persistency and a mock proxy setup
    SetUpPersistency();
    std::unique_ptr<InternalConfigProviderMock> internal_config_provider =
        std::make_unique<InternalConfigProviderMock>();
    icp_mock_ = internal_config_provider.get();
    promise_.SetValue(std::move(internal_config_provider));
    {
        InSequence s;
        // Then subscribe is called before GetParameterSet
        EXPECT_CALL(*icp_mock_, TrySubscribeToLastUpdatedParameterSetEvent(_, _)).WillOnce(Return(true));
        EXPECT_CALL(
            *icp_mock_,
            GetParameterSet(StringViewCompare(parameter_set_name_), ConfigProviderImpl::kDefaultResponseTimeout))
            .Times(1);
    }

    // When ConfigProvider is created and proxy becomes available
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    BlockUntilProxyIsReady(stop_source_.get_token());
}

TEST_F(ConfigProviderTest, FailedToSubscribe)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty(
        "Description",
        "This test verifies that during construction stage, when the ConfigProvider failed to subscribe to the "
        "LastUpdatedParameterSetEvent, the setup thread would not try to fetch data from proxy and the "
        "client would be blocked when waiting for the proxy to be available.");

    // Given persistency and a mock proxy that fails subscription
    SetUpPersistency();
    std::unique_ptr<InternalConfigProviderMock> internal_config_provider =
        std::make_unique<InternalConfigProviderMock>();
    icp_mock_ = internal_config_provider.get();  // Before the proxy is available
    promise_.SetValue(std::move(internal_config_provider));
    EXPECT_CALL(*icp_mock_, TrySubscribeToLastUpdatedParameterSetEvent(_, _)).WillOnce(Return(false));

    // Then GetParameterSet should not be called since subscription failed
    EXPECT_CALL(*icp_mock_, GetParameterSet(_, _)).Times(0);

    score::cpp::stop_source test_stop_source{};
    concurrency::Notification thread_running, thread_finished;
    // When client thread tries to wait for proxy
    score::cpp::jthread client_thread{[&]() {
        thread_running.notify();
        auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});
        BlockUntilProxyIsReady(test_stop_source.get_token());
        thread_finished.notify();
    }};
    thread_running.waitWithAbort(test_stop_source.get_token());
    // Then client thread should remain blocked
    EXPECT_FALSE(thread_finished.waitForWithAbort(std::chrono::milliseconds(10), test_stop_source.get_token()));
    test_stop_source.request_stop();
    thread_finished.waitWithAbort(test_stop_source.get_token());
    client_thread.join();
}

TEST_F(ConfigProviderTest, SubscribeWithEmptyCallback)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test checks the branch when the subscription is success but no callback is provided for "
                   "notification purpose during construction stage.");

    // Given persistency and a mock proxy that succeeds subscription
    SetUpPersistency();
    std::unique_ptr<InternalConfigProviderMock> internal_config_provider =
        std::make_unique<InternalConfigProviderMock>();
    icp_mock_ = internal_config_provider.get();
    promise_.SetValue(std::move(internal_config_provider));
    EXPECT_CALL(*icp_mock_, TrySubscribeToLastUpdatedParameterSetEvent(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*icp_mock_,
                GetParameterSet(StringViewCompare(parameter_set_name_), ConfigProviderImpl::kDefaultResponseTimeout))
        .Times(1);

    score::cpp::stop_source test_stop_source{};
    concurrency::Notification thread_running, thread_finished;
    // When client thread creates ConfigProvider with empty callback
    score::cpp::jthread client_thread{[&]() {
        thread_running.notify();
        auto config_provider = CreateConfigProviderWithAvailableCallback({});
        BlockUntilProxyIsReady(test_stop_source.get_token());
        thread_finished.notify();
    }};
    thread_running.waitWithAbort(test_stop_source.get_token());
    // Then client thread should remain blocked (no callback means no unblock trigger)
    EXPECT_FALSE(thread_finished.waitForWithAbort(std::chrono::milliseconds(10), test_stop_source.get_token()));
    test_stop_source.request_stop();
    thread_finished.waitWithAbort(test_stop_source.get_token());
    client_thread.join();
}

TEST_F(ConfigProviderTest, ProxySearchingSuccess_ClientWait_Persistency)
{
    RecordProperty("Priority", "3");
    RecordProperty("Verifies", " 11397333, 32232137, 32233375");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("ASIL", "B");
    RecordProperty(
        "Description",
        "This test checks the scenario when the client waits for the proxy to be available and the persistency is not"
        "empty. The client would get persisted ParameterSet when trying to use config_provider, when the proxy "
        "searching thread is still blocked. The client would get updated ParameterSet when trying to use "
        "config_provider, when "
        "the proxy searching thread finds the proxy."
        "11397333: The Qualifier state can be retrieved to indicate the integrity of the Parameter Set data."
        "32232137: After the qualification has finished and the service is found, ConfigProvider can find the updated "
        "ParameterSet."
        "32233375: The Qualifier state of cached ParameterSet is always UNQUALIFIED.");

    // Given persistency with cached parameter sets
    SetUpPersistency();
    // When ConfigProvider is created and waits for proxy
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    // Then GetInitialQualifierState returns undefined initially
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kUndefined);
    // Then GetParameterSet returns cached parameter set from persistency before proxy
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_)
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_persistency_);
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).value()->GetQualifier().value(),
              parameter_qualifier_from_persistency_);
    EXPECT_TRUE(
        config_provider->OnChangedParameterSet(parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {})
            .has_value());
    EXPECT_EQ(config_provider->CheckParameterSetUpdates().error(),
              MakeUnexpected(ConfigProviderError::kProxyNotReady).error());

    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, InitialQualifierState::kQualified);
    BlockUntilProxyIsReady(stop_source_.get_token());

    // When proxy becomes available
    // Then GetInitialQualifierState returns qualified
    EXPECT_EQ(config_provider->GetInitialQualifierState(), InitialQualifierState::kQualified);
    // Then GetParameterSet returns updated parameter set from proxy
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_)
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_proxy_);
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_).value()->GetQualifier().value(),
              parameter_qualifier_from_proxy_);
    EXPECT_EQ(config_provider->OnChangedParameterSet(parameter_set_name_, nullptr).error(),
              MakeUnexpected(ConfigProviderError::kEmptyCallbackProvided).error());
    EXPECT_TRUE(config_provider->CheckParameterSetUpdates().has_value());
    EXPECT_EQ(config_provider->GetCachedParameterSetsCount(), 1U);
}

TEST_F(ConfigProviderTest, Success_LastUpdatedParameterSetReceiveHandler)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test verifies receive callback is triggered when"
                   "'set_name' parameter set is updated during the construction stage of ConfigProviderImpl");
    // Given a ConfigProvider instance with proxy ready
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());
    // When a callback is registered and parameter set is updated
    bool check_flag{false};
    const auto parameter_set_result = config_provider->OnChangedParameterSet(
        parameter_set_name_, [&](std::shared_ptr<const ParameterSet> parameter_set) noexcept {
            check_flag = true;
            auto parameter_set_value = parameter_set->GetParameterAs<std::uint32_t>(parameter_name_);
            EXPECT_TRUE(parameter_set_value.has_value());
            EXPECT_EQ(parameter_set_value.value(), parameter_content_from_proxy_);
        });

    // Then callback registration succeeds
    EXPECT_TRUE(parameter_set_result.has_value());
    // And callback is triggered with correct parameter set
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    registered_on_changed_parameter_set_callback_(parameter_set_name_);
    EXPECT_TRUE(check_flag);
}

TEST_F(ConfigProviderTest, Success_UserCallbackOverridesEmptyCallback)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Verification of the control flow and data flow");
    RecordProperty("Verifies",
                   "::score::platform::config_provider::ConfigProviderImpl::RegisterUpdateHandlerForParameterSetName()");
    RecordProperty("Description",
                   "This test verifies that the user provided callback is overriding the empty internal callback and "
                   "is called when an update is received.");
    // Given a ConfigProvider instance with proxy ready
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());
    bool check_flag{false};

    // When GetParameterSet is called first (sets empty internal callback)
    auto result = config_provider->GetParameterSet(parameter_set_name_);
    ASSERT_TRUE(result.has_value());

    // And OnChangedParameterSet is called with user callback (overrides empty callback)
    const auto parameter_set_result =
        config_provider->OnChangedParameterSet(parameter_set_name_, [&](std::shared_ptr<const ParameterSet>) noexcept {
            check_flag = true;
        });
    EXPECT_TRUE(parameter_set_result.has_value());

    // Then user callback is triggered when parameter set updates
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    registered_on_changed_parameter_set_callback_(parameter_set_name_);

    // Then check_flag should be set to true indicating user callback was called
    EXPECT_TRUE(check_flag);
}

TEST_F(ConfigProviderTest, Success_LastUpdatedParameterSetReceiveHandlerCalledForParameterSetWithNoCallback)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test verifies that the receive callback is triggered"
                   "successfully in case a proper update callback for a ParameterSet is not yet registered");

    // Given a ConfigProvider instance with proxy and persistency
    EXPECT_CALL(*persistency_, CacheParameterSet(_, _, _, _)).Times(2);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto json_result_1 = json::JsonParser{}.FromBuffer(R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 3
    }
    )");
    auto json_result_2 = json::JsonParser{}.FromBuffer(R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 3
    }
    )");
    // When proxy returns parameter set updates
    EXPECT_CALL(*icp_mock_,
                GetParameterSet(StringViewCompare(parameter_set_name_), ConfigProviderImpl::kDefaultResponseTimeout))
        .Times(2)
        .WillOnce(Return(ByMove(std::move(json_result_1))))
        .WillOnce(Return(ByMove(std::move(json_result_2))));

    BlockUntilProxyIsReady(stop_source_.get_token());

    // Then GetParameterSet returns correct value
    EXPECT_EQ(config_provider->GetParameterSet(parameter_set_name_)
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_proxy_);
    // Then callback is triggered even without registered callback
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    registered_on_changed_parameter_set_callback_(parameter_set_name_);
}

TEST_F(ConfigProviderTest, Success_LastUpdatedParameterSetReceiveHandlerCalledTwiceWithSameParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "32233418");
    RecordProperty("ASIL", "QM");
    RecordProperty(
        "Description",
        "32233418: This test verifies success of calling LastUpdatedParameterSetReceiveHandler() twice if one "
        "parameter_set is updated twice due to change in ParameterSetQualifier");

    // Given a ConfigProvider instance with proxy and parameter set updates
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto json_result_1 = json::JsonParser{}.FromBuffer(R"(
    {
        "parameters": {
            "parameter_name": 1
        },
        "qualifier": 3
    }
    )");

    auto json_result_2 = json::JsonParser{}.FromBuffer(R"(
    {
        "parameters": {
            "parameter_name": 2
        },
        "qualifier": 4
    }
    )");

    const std::string set_name = parameter_set_name_;

    // When proxy returns two different parameter set values
    EXPECT_CALL(*icp_mock_, GetParameterSet(StringViewCompare(set_name), ConfigProviderImpl::kDefaultResponseTimeout))
        .Times(2)
        .WillOnce(Return(ByMove(std::move(json_result_1))))
        .WillOnce(Return(ByMove(std::move(json_result_2))));
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    std::uint8_t callback_number{0};
    BlockUntilProxyIsReady(stop_source_.get_token());
    // Then callback is registered
    EXPECT_TRUE(config_provider
                    ->OnChangedParameterSet(parameter_set_name_,
                                            [&](std::shared_ptr<const ParameterSet> parameter_set) noexcept {
                                                auto parameter_set_value =
                                                    parameter_set->GetParameterAs<std::uint32_t>(parameter_name_);
                                                EXPECT_TRUE(parameter_set_value.has_value());
                                                EXPECT_EQ(parameter_set_value.value(), ++callback_number);
                                            })
                    .has_value());
    // When callback is triggered twice with same parameter set name but different values
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    registered_on_changed_parameter_set_callback_(parameter_set_name_);
    EXPECT_EQ(callback_number, 1);
    // Then second update is also processed
    registered_on_changed_parameter_set_callback_(parameter_set_name_);
    EXPECT_EQ(callback_number, 2);
}

TEST_F(ConfigProviderTest, Success_LastUpdatedParameterSetReceiveHandlerCalledTwice)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test verifies success of calling receive callback twice if two "
                   "parameter_sets are updated during construction stage of ConfigProviderImpl");

    // Given a ConfigProvider instance with proxy ready
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto json_result_1 = json::JsonParser{}.FromBuffer(R"(
    {
        "parameters": {
            "parameter_name": 55
        },
        "qualifier": 3
    }
    )");
    auto json_result_2 = json::JsonParser{}.FromBuffer(R"(
    {
        "parameters": {
            "parameter_name": 66
        },
        "qualifier": 3
    }
    )");
    const std::string set_name_1 = "set_name_1";
    const std::string set_name_2 = "set_name_2";

    // When proxy returns two different parameter sets
    EXPECT_CALL(*icp_mock_, GetParameterSet(StringViewCompare(set_name_1), ConfigProviderImpl::kDefaultResponseTimeout))
        .WillOnce(Return(ByMove(std::move(json_result_1))));
    EXPECT_CALL(*icp_mock_, GetParameterSet(StringViewCompare(set_name_2), ConfigProviderImpl::kDefaultResponseTimeout))
        .WillOnce(Return(ByMove(std::move(json_result_2))));
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    BlockUntilProxyIsReady(stop_source_.get_token());

    std::uint8_t callback_number{0};

    // Then first callback is registered and triggered
    const auto parameter_set_result_1 = config_provider->OnChangedParameterSet(
        set_name_1, [&](std::shared_ptr<const ParameterSet> parameter_set) noexcept {
            callback_number = 1;
            auto parameter_set_value = parameter_set->GetParameterAs<std::uint32_t>(parameter_name_);
            EXPECT_TRUE(parameter_set_value.has_value());
            EXPECT_EQ(parameter_set_value.value(), 55);
        });
    EXPECT_TRUE(parameter_set_result_1.has_value());
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    registered_on_changed_parameter_set_callback_(set_name_1);
    EXPECT_EQ(callback_number, 1);

    // Then second callback is registered and triggered
    const auto parameter_set_result_2 = config_provider->OnChangedParameterSet(
        set_name_2, [&](std::shared_ptr<const ParameterSet> parameter_set) noexcept {
            callback_number = 2;
            auto parameter_set_value = parameter_set->GetParameterAs<std::uint32_t>(parameter_name_);
            EXPECT_TRUE(parameter_set_value.has_value());
            EXPECT_EQ(parameter_set_value.value(), 66);
        });
    EXPECT_TRUE(parameter_set_result_2.has_value());
    registered_on_changed_parameter_set_callback_(set_name_2);
    EXPECT_EQ(callback_number, 2);
}

TEST_F(ConfigProviderTest, LastUpdatedParameterSetReceiveHandlerFailedToGetParameters)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test verifies failure of calling user received if returned "
                   "parameter_set is not valid json");

    // Given a ConfigProvider instance with proxy ready
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);

    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    bool check_flag{false};
    BlockUntilProxyIsReady(stop_source_.get_token());

    // When a callback is registered for the parameter set
    const auto parameter_set_result = config_provider->OnChangedParameterSet(
        parameter_set_name_, [&](std::shared_ptr<const ParameterSet> parameter_set) noexcept {
            check_flag = true;
            auto parameter_set_value = parameter_set->GetParameterAs<std::uint32_t>(parameter_name_);
            EXPECT_TRUE(parameter_set_value.has_value());
            EXPECT_EQ(parameter_set_value.value(), 55);
        });

    EXPECT_TRUE(parameter_set_result.has_value());
    // Then callback is triggered with wrong parameter set name
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    registered_on_changed_parameter_set_callback_("wrong_set_name");
    // Then check_flag should remain false (callback not called for wrong name)
    EXPECT_FALSE(check_flag);
}

TEST_F(ConfigProviderTest, DuplicateSetParameterSetCallbackFails)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::OnChangedParameterSet()");
    RecordProperty(
        "Description",
        "This test verifies failure of calling OnChangedParameterSet() twice with the same parameter_set_name");

    // Given a ConfigProvider instance with proxy ready
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());

    // When first OnChangedParameterSet call succeeds
    const auto parameter_set_result = config_provider->OnChangedParameterSet(
        parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {});
    EXPECT_TRUE(parameter_set_result.has_value());

    // Then second OnChangedParameterSet call with same name fails
    const auto parameter_set_result2 = config_provider->OnChangedParameterSet(
        parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {});
    EXPECT_FALSE(parameter_set_result2.has_value());
    EXPECT_EQ(parameter_set_result2.error(), MakeUnexpected(ConfigProviderError::kCallbackAlreadySet).error());
}

TEST_F(ConfigProviderTest, DuplicateSetParameterSetCallbackFailsOnChangedParameterSetCbk)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::OnChangedParameterSetCbk()");
    RecordProperty("Description",
                   "This test verifies failure of calling OnChangedParameterSetCbk() with an empty callback");

    // Given a ConfigProvider instance with proxy ready
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());

    // When first OnChangedParameterSetCbk call succeeds
    const auto parameter_set_result = config_provider->OnChangedParameterSetCbk(
        parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {});
    EXPECT_TRUE(parameter_set_result.has_value());

    // Then second OnChangedParameterSetCbk call with same name fails
    const auto parameter_set_result2 = config_provider->OnChangedParameterSetCbk(
        parameter_set_name_, [](std::shared_ptr<const ParameterSet>) noexcept {});
    EXPECT_FALSE(parameter_set_result2.has_value());
    EXPECT_EQ(parameter_set_result2.error(), MakeUnexpected(ConfigProviderError::kCallbackAlreadySet).error());
}

TEST_F(ConfigProviderTest, CallOnChangedParameterSetCbkWithEmptyCallback)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::OnChangedParameterSetCbk()");
    RecordProperty(
        "Description",
        "This test verifies failure of calling OnChangedParameterSetCbk() twice with the same parameter_set_name");

    // Given a ConfigProvider instance
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    // When OnChangedParameterSetCbk is called with null callback
    // Then it returns error for empty callback provided
    EXPECT_EQ(config_provider->OnChangedParameterSetCbk(parameter_set_name_, nullptr).error(),
              MakeUnexpected(ConfigProviderError::kEmptyCallbackProvided).error());
}

TEST_F(ConfigProviderTest, ProxySearchingSuccess_ClientWait_EmptyPersistency_WrongPsName)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::GetParameterSet()");
    RecordProperty("ASIL", "QM");
    RecordProperty(
        "Description",
        "This test checks the scenario when the client waits for the proxy to be available and the persistency is "
        "empty. The client would get error kProxyReturnedNoResult when trying to use config_provider to get a not "
        "existing ParameterSet from available proxy.");

    // Given a ConfigProvider instance with proxy ready and empty persistency
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());

    // When trying to get a non-existing ParameterSet
    // Then expect kProxyReturnedNoResult error
    EXPECT_EQ(config_provider->GetParameterSet("wrong_set_name", std::nullopt).error(),
              MakeUnexpected(ConfigProviderError::kProxyReturnedNoResult).error());

    // below needed only for debug logging coverage
    EXPECT_TRUE(config_provider->GetParameterSet("invalid_parameter_set", std::nullopt).has_value());
}

TEST_F(ConfigProviderTest, SuccessLastUpdatedParameterSetPersistedInCache)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of requirements");
    RecordProperty("TestType", "Requirements-based test");
    RecordProperty("Verifies", "32233530");
    RecordProperty("ASIL", "QM");
    RecordProperty(
        "Description",
        "32233530: This test ensures that upon reception of an updated Parameter Set, its cached value shall be "
        "updated with the new values and such new values shall be written to the persistent cache.");

    // Given ConfigProvider with persistency and proxy ready
    EXPECT_CALL(*persistency_, CacheParameterSet(_, _, _, _)).Times(2);
    SetUpPersistency();
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    BlockUntilProxyIsReady(stop_source_.get_token());
    // When an updated parameter set is received from proxy
    EXPECT_CALL(*icp_mock_,
                GetParameterSet(StringViewCompare(parameter_set_name_), ConfigProviderImpl::kDefaultResponseTimeout))
        .WillOnce(Return(ByMove(std::move(updated_parameter_set_from_proxy_))));

    // Then callback is invoked and parameter set is cached with new values
    const auto parameter_set_result = config_provider->OnChangedParameterSet(
        parameter_set_name_, [&](std::shared_ptr<const ParameterSet> parameter_set) noexcept {
            EXPECT_EQ(parameter_set->GetParameterAs<std::uint32_t>(parameter_name_).value(),
                      updated_content_from_proxy_);
            EXPECT_EQ(parameter_set->GetQualifier().value(), updated_qualifier_from_proxy_);
        });

    EXPECT_TRUE(parameter_set_result.has_value());
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    registered_on_changed_parameter_set_callback_(parameter_set_name_);

    const auto provider_parameter_set_result = config_provider->GetParameterSet(parameter_set_name_);
    EXPECT_EQ(provider_parameter_set_result.value()->GetParameterAs<std::uint32_t>(parameter_name_).value(),
              updated_content_from_proxy_);
    EXPECT_EQ(provider_parameter_set_result.value()->GetQualifier().value(), updated_qualifier_from_proxy_);

    score::mw::log::detail::Configuration config{};
    config.SetLogMode({score::mw::LogMode::kConsole});
    config.SetDefaultConsoleLogLevel(score::mw::log::LogLevel::kInfo);
    auto recorder =
        score::mw::log::detail::RecorderFactory().CreateRecorderFromLogMode(score::mw::LogMode::kConsole, config);

    // below needed to cover non-debug branch in GetParameterSet method
    score::mw::log::detail::Runtime::SetRecorder(recorder.get());
    const auto provider_parameter_set_result2 = config_provider->GetParameterSet(parameter_set_name_);
    EXPECT_EQ(provider_parameter_set_result2.value()->GetParameterAs<std::uint32_t>(parameter_name_).value(),
              updated_content_from_proxy_);
    EXPECT_EQ(provider_parameter_set_result2.value()->GetQualifier().value(), updated_qualifier_from_proxy_);

    score::mw::log::detail::Runtime::SetRecorder(nullptr);
}

TEST_F(ConfigProviderTest, WaitUntilConnected_success)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::WaitUntilConnected()");
    RecordProperty("Description",
                   "This test checks the scenario when InternalConfigProvider proxy is found, WaitUntilConnected would"
                   "not be blocked and return true.");
    // Given proxy search would succeed
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    // When create ConfigProvider
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    BlockUntilProxyIsReady(stop_source_.get_token());
    // Then expecet WaitUntilConnected would return true
    EXPECT_TRUE(config_provider->WaitUntilConnected(std::chrono::milliseconds(0U), stop_source_.get_token()));
}

TEST_F(ConfigProviderTest, WaitUntilConnected_timeout)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::WaitUntilConnected()");
    RecordProperty(
        "Description",
        "This test checks the scenario when InternalConfigProvider proxy is not found, WaitUntilConnected would"
        "unblock itself after timeout and return false.");
    // Given proxy search would fail
    FailProxySearch();
    // When create ConfigProvider
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});
    // Then expecet WaitUntilConnected would return false after timeout
    EXPECT_FALSE(config_provider->WaitUntilConnected(std::chrono::milliseconds(0U), stop_source_.get_token()));
}

TEST_F(ConfigProviderTest, WaitUntilConnected_StopRequested)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::WaitUntilConnected()");
    RecordProperty("Description",
                   "This test checks the scenario when proxy is not found and stop token is triggered before timeout,"
                   "WaitUntilConnected would not block.");

    std::atomic<bool> shall_not_enter = true;
    auto client_thread = score::cpp::jthread([this, &shall_not_enter]() {
        // Given proxy search would fail
        FailProxySearch();
        // When create ConfigProvider and call WaitUntilConnected with stop token requested before timeout
        auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});
        // Then expecet WaitUntilConnected would return false without blocking when stop is requested before timeout
        EXPECT_FALSE(config_provider->WaitUntilConnected(std::chrono::hours(1), stop_source_.get_token()));
        EXPECT_FALSE(shall_not_enter);
    });
    shall_not_enter = false;
    stop_source_.request_stop();
    client_thread.join();
}

TEST_F(ConfigProviderTest, Test_OnChangedInitialQualifierState)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Analysis of boundary values");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::OnChangedInitialQualifierState()");
    RecordProperty("Description", "This test verifies checks the call to OnChangedInitialQualifierState() does nothing.");

    // Given a ConfigProvider instance with proxy not ready
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});

    // Expect calling OnChangedInitialQualifierState does nothing
    config_provider->OnChangedInitialQualifierState(nullptr);
}

TEST_F(ConfigProviderTest, Test_FailedFetchInitialParameterSetValuesFrom)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test checks the case when internal config provider fails to get parameter sets during "
                   "execution of FetchInitialParameterSetValuesFrom at the construction stage of ConfigProviderImpl.");
    SetUpPersistency();
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    score::Result<score::json::Any> value_not_found_result{MakeUnexpected(ConfigProviderError::kValueNotFound)};
    SetUpProxy(parameter_set_name_, value_not_found_result);
    BlockUntilProxyIsReady(stop_source_.get_token());
    // Given a ConfigProvider instance which finds a proxy, which would return error when GetParameterSet is called
    // Then certain branch would get executed during construction stage when FetchInitialParameterSetValuesFrom is
    // called
}

TEST_F(ConfigProviderTest, Test_FailLastUpdatedParameterSetReceiveHandler)
{
    RecordProperty("Priority", "3");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("TestType", "Interface test");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description", "This test checks the case when unregistered parameter set gets updated.");
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());
    // Given ConfigProvider with proxy ready
    // Given that OnChangedParameterSet register callback for "wrong_set_name" (unregistered parameter set)
    const auto register_callback_result =
        config_provider->OnChangedParameterSet("wrong_set_name", [&](std::shared_ptr<const ParameterSet>) noexcept {
            ASSERT_TRUE(false);
        });
    EXPECT_TRUE(register_callback_result.has_value());
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    // When the registered_on_changed_parameter_set_callback_ is called with not registered name
    // Then GetParameterSet function would not triggered
    EXPECT_CALL(*icp_mock_, GetParameterSet(score::cpp::string_view(parameter_set_name_), _)).Times(0);
    registered_on_changed_parameter_set_callback_(parameter_set_name_);
}

TEST_F(ConfigProviderTest, LastUpdatedParameterSetFailedGetParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::ConfigProviderImpl()");
    RecordProperty("Description",
                   "This test verifies failure of calling receive callback twice if "
                   "parameter set is failed to fetch from internal config provider during the construction stage of "
                   "ConfigProviderImpl");
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());
    // Given ConfigProvider with proxy ready
    // Given that GetParameterSet would get error for "parameter_set_name_" from proxy
    // When OnChangedParameterSet register callback for "parameter_set_name_"
    const auto register_callback_result = config_provider->OnChangedParameterSet(
        parameter_set_name_, [&](std::shared_ptr<const ParameterSet>) noexcept {});
    EXPECT_TRUE(register_callback_result.has_value());
    ASSERT_NE(registered_on_changed_parameter_set_callback_, nullptr);
    // When the registered_on_changed_parameter_set_callback_ is called with registered name
    // Then GetParameterSet function would be triggered with this name
    EXPECT_CALL(*icp_mock_, GetParameterSet(score::cpp::string_view(parameter_set_name_), _))
        .WillOnce(Return(ByMove(MakeUnexpected(ConfigProviderError::kProxyReturnedNoResult))));
    registered_on_changed_parameter_set_callback_(parameter_set_name_);
}

TEST_F(ConfigProviderTest, GetParameterSetsByNameList_ProxyNotReady)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::GetParameterSetsByNameList()");
    RecordProperty("Description",
                   "This test verifies that the GetParameterSetsByNameList gets errors when proxy is not ready.");
    // Given a ConfigProvider instance with proxy not ready
    auto config_provider = CreateConfigProviderWithAvailableCallback([]() noexcept {});
    score::cpp::pmr::vector<score::cpp::string_view> set_names{"set1", "set2"};
    // When GetParameterSetsByNameList is called
    auto result = config_provider->GetParameterSetsByNameList(set_names, std::nullopt);
    // Then each result should be an error indicating proxy is not ready
    ASSERT_EQ(result.size(), 2);
    for (const auto& [name, value] : result)
    {
        EXPECT_FALSE(value.has_value());
        EXPECT_EQ(value.error(), MakeUnexpected(ConfigProviderError::kProxyNotReady, "Proxy is not ready").error());
    }
}

TEST_F(ConfigProviderTest, GetParameterSetsByNameList_WithProxy)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::GetParameterSetsByNameList()");
    RecordProperty(
        "Description",
        "This test verifies that GetParameterSetsByNameList would gets cached value if cached value is available. "
        "This test verifies that GetParameterSetsByNameList would gets error if cached value cannot be retrieved from "
        "proxy. "
        "This test verifies that GetParameterSetsByNameList would gets value if value can be retrieved from proxy. ");
    SetUpPersistency();
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    // Given ConfigProvider with proxy ready, and persistency having cached value for "parameter_set_name_"
    BlockUntilProxyIsReady(stop_source_.get_token());

    // Then GetParameterSetsByNameList would get cached value for "parameter_set_name_"
    auto json_result = json::JsonParser{}.FromBuffer(R"({"parameters":{"parameter_name":123},"qualifier":1})");
    EXPECT_CALL(*icp_mock_, GetParameterSet(StringViewCompare("new_set"), _))
        .WillOnce(Return(ByMove(std::move(json_result))));

    // Then GetParameterSet would get error for "missing_set" which is a key not existing in persistency nor
    // retrievable from proxy
    EXPECT_CALL(*icp_mock_, GetParameterSet(StringViewCompare("missing_set"), _))
        .WillOnce(
            Return(ByMove(MakeUnexpected(ConfigProviderError::kParameterSetNotFound, "Parameter set not found"))));

    score::cpp::pmr::vector<score::cpp::string_view> set_names{score::cpp::string_view(parameter_set_name_), "missing_set", "new_set"};
    // When GetParameterSetsByNameList is called
    auto result = config_provider->GetParameterSetsByNameList(set_names, std::nullopt);
    // Then it would get cached value for "parameter_set_name_"
    // Then it would get error for "missing_set" which is a key not existing in persistency nor retrievable from
    // proxy
    // Then it would get value for "new_set" retrievable from proxy
    ASSERT_EQ(result.size(), 3);

    EXPECT_TRUE(result.at(score::cpp::pmr::string(parameter_set_name_)).has_value());
    EXPECT_EQ(result.at(score::cpp::pmr::string(parameter_set_name_))
                  .value()
                  ->GetParameterAs<std::uint32_t>(parameter_name_)
                  .value(),
              parameter_content_from_proxy_);
    EXPECT_EQ(result.at(score::cpp::pmr::string(parameter_set_name_)).value()->GetQualifier().value(),
              parameter_qualifier_from_proxy_);

    EXPECT_FALSE(result.at("missing_set").has_value());
    EXPECT_EQ(result.at("missing_set").error(),
              MakeUnexpected(ConfigProviderError::kParameterSetNotFound, "Parameter set not found").error());

    EXPECT_TRUE(result.at("new_set").has_value());
    EXPECT_EQ(result.at("new_set").value()->GetParameterAs<std::uint32_t>("parameter_name").value(), 123);
}

class RepeatableConfigProviderTest : public ConfigProviderTest, public ::testing::WithParamInterface<int>
{
};

TEST_P(RepeatableConfigProviderTest, TestSharedInternalConfigProvider1)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies",
                   "::score::platform::config_provider::ConfigProviderImpl::CheckParameterSetUpdates(), "
                   "::score::platform::config_provider::ConfigProviderImpl::GetInitialQualifierState(), "
                   "::score::platform::config_provider::ConfigProviderImpl::GetParameterSet(), "
                   "::score::platform::config_provider::ConfigProviderImpl::IsAwaitingProxyConnection(), "
                   "::score::platform::config_provider::ConfigProviderImpl::WaitUntilConnected()");
    RecordProperty(
        "Description",
        "This test verifies that there would be no race condition while accessing `internal_config_provider_`");
    // Given a ConfigProvider instance with proxy ready
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, InitialQualifierState::kQualified);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });
    BlockUntilProxyIsReady(stop_source_.get_token());

    std::promise<void> go, get_parameter_set_ready, get_initial_qualifier_state_ready, check_ps_update_ready,
        wait_until_connected_ready, is_awaiting_proxy_ready;
    std::shared_future<void> ready{go.get_future()};

    auto check_ps_update_done = std::async(std::launch::async, [&]() {
        check_ps_update_ready.set_value();
        ready.wait();
        return config_provider->CheckParameterSetUpdates();
    });

    auto wait_until_connected_done = std::async(std::launch::async, [&]() {
        wait_until_connected_ready.set_value();
        ready.wait();
        return config_provider->WaitUntilConnected(std::chrono::milliseconds::zero(), stop_source_.get_token());
    });

    auto is_awaiting_proxy_done = std::async(std::launch::async, [&]() {
        is_awaiting_proxy_ready.set_value();
        ready.wait();
        return config_provider->IsAwaitingProxyConnection();
    });

    auto get_initial_qualifier_state_done = std::async(std::launch::async, [&]() {
        get_initial_qualifier_state_ready.set_value();
        ready.wait();
        return config_provider->GetInitialQualifierState(std::nullopt);
    });

    auto get_parameter_set_done = std::async(std::launch::async, [&]() {
        get_parameter_set_ready.set_value();
        ready.wait();
        return config_provider->GetParameterSet(parameter_set_name_, std::nullopt);
    });

    get_initial_qualifier_state_ready.get_future().wait();
    get_parameter_set_ready.get_future().wait();
    check_ps_update_ready.get_future().wait();
    is_awaiting_proxy_ready.get_future().wait();
    wait_until_connected_ready.get_future().wait();

    // When GetInitialQualifierState, GetParameterSet, CheckParameterSetUpdates, IsAwaitingProxyConnection and WaitUntilConnected
    // are called concurrently
    go.set_value();
    auto initial_qualifier_state = get_initial_qualifier_state_done.get();
    auto parameter_set = get_parameter_set_done.get();
    auto check_ps_update_result = check_ps_update_done.get();
    auto is_awaiting_proxy_result = is_awaiting_proxy_done.get();
    auto wait_until_connected_result = wait_until_connected_done.get();

    // Then expect their behaviors are correct and deterministic
    EXPECT_TRUE(check_ps_update_result.has_value());
    EXPECT_FALSE(is_awaiting_proxy_result);
    EXPECT_TRUE(wait_until_connected_result);
    EXPECT_EQ(initial_qualifier_state, InitialQualifierState::kQualified);
    EXPECT_EQ(parameter_set.value()->GetParameterAs<std::uint32_t>(parameter_name_).value(),
              parameter_content_from_proxy_);
}

TEST_P(RepeatableConfigProviderTest, TestSharedInternalConfigProvider2)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies",
                   "::score::platform::config_provider::ConfigProviderImpl::GetInitialQualifierState(), "
                   "::score::platform::config_provider::ConfigProviderImpl::GetParameterSet(), ");
    RecordProperty(
        "Description",
        "This test verifies that there would be no race condition while accessing `internal_config_provider_`");
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, InitialQualifierState::kQualified);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());
    std::promise<void> go, get_parameter_set_ready, get_initial_qualifier_state_ready, callback_ready;
    std::shared_future<void> ready{go.get_future()};

    auto get_initial_qualifier_state_done = std::async(std::launch::async, [&]() {
        get_initial_qualifier_state_ready.set_value();
        ready.wait();
        return config_provider->GetInitialQualifierState(std::nullopt);
    });

    auto callback_done = std::async(std::launch::async, [&]() {
        callback_ready.set_value();
        ready.wait();
        registered_on_changed_parameter_set_callback_(parameter_set_name_);
    });

    auto get_parameter_set_done = std::async(std::launch::async, [&]() {
        get_parameter_set_ready.set_value();
        ready.wait();
        return config_provider->GetParameterSet(parameter_set_name_, std::nullopt);
    });

    get_initial_qualifier_state_ready.get_future().wait();
    get_parameter_set_ready.get_future().wait();
    callback_ready.get_future().wait();

    // Given GetInitialQualifierState, GetParameterSet and client callback are called concurrently
    go.set_value();
    auto initial_qualifier_state = get_initial_qualifier_state_done.get();
    auto parameter_set = get_parameter_set_done.get();
    callback_done.get();
    // Expect their behaviors are correct and deterministic
    EXPECT_EQ(initial_qualifier_state, InitialQualifierState::kQualified);
    EXPECT_EQ(parameter_set.value()->GetParameterAs<std::uint32_t>(parameter_name_).value(),
              parameter_content_from_proxy_);
}

TEST_P(RepeatableConfigProviderTest, TestSharedParameterSet)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies",
                   "::score::platform::config_provider::ConfigProviderImpl::GetCachedParameterSetsCount(), "
                   "::score::platform::config_provider::ConfigProviderImpl::GetParameterSet()");
    RecordProperty("Description",
                   "This test verifies that there would be no race condition while accessing `parameter_sets_`");
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, InitialQualifierState::kQualified);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());
    std::promise<void> go, get_parameter_set_ready, get_cached_ps_ready, callback_ready;
    std::atomic<bool> get_parameter_set_finished{false};
    std::atomic<bool> callback_finished{false};
    std::shared_future<void> ready{go.get_future()};

    auto get_cached_ps_done = std::async(std::launch::async, [&]() {
        get_cached_ps_ready.set_value();
        ready.wait();
        while (!get_parameter_set_finished && !callback_finished)
        {
            // wait until either function put something into the parameter set
        }
        return config_provider->GetCachedParameterSetsCount();
    });

    auto callback_done = std::async(std::launch::async, [&]() {
        config_provider->OnChangedParameterSet(parameter_set_name_,
                                               [](std::shared_ptr<const ParameterSet>) noexcept {});
        callback_ready.set_value();
        ready.wait();
        registered_on_changed_parameter_set_callback_(parameter_set_name_);
        callback_finished = true;
    });

    auto get_parameter_set_done = std::async(std::launch::async, [&]() {
        get_parameter_set_ready.set_value();
        ready.wait();
        auto ret{config_provider->GetParameterSet(parameter_set_name_, std::nullopt)};
        get_parameter_set_finished = true;
        return ret;
    });

    get_cached_ps_ready.get_future().wait();
    get_parameter_set_ready.get_future().wait();
    callback_ready.get_future().wait();
    // Given GetParameterSet, GetCachedParameterSetsCount and client callback are called concurrently
    go.set_value();
    auto parameter_set = get_parameter_set_done.get();
    callback_done.get();
    auto ps_count = get_cached_ps_done.get();

    // Expect their behaviors are correct and deterministic
    EXPECT_EQ(ps_count, 1);
    EXPECT_EQ(parameter_set.value()->GetParameterAs<std::uint32_t>(parameter_name_).value(),
              parameter_content_from_proxy_);
}

TEST_P(RepeatableConfigProviderTest, TestSharedClientHandlers)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies",
                   "::score::platform::config_provider::ConfigProviderImpl::OnChangedParameterSet(), "
                   "::score::platform::config_provider::ConfigProviderImpl::GetParameterSet()");
    RecordProperty("Description",
                   "This test verifies that there would be no race condition with shared data client_handlers_");
    // Given a ConfigProvider instance with proxy ready
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, InitialQualifierState::kQualified);
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    BlockUntilProxyIsReady(stop_source_.get_token());
    std::promise<void> go, get_parameter_set_ready, on_changed_ps_ready, callback_ready;
    std::atomic<bool> get_parameter_set_finished{false};
    std::atomic<bool> callback_finished{false};
    std::shared_future<void> ready{go.get_future()};

    auto on_changed_ps_done = std::async(std::launch::async, [&]() {
        on_changed_ps_ready.set_value();
        ready.wait();
        while (!get_parameter_set_finished && !callback_finished)
        {
            // wait until either function put something into the parameter set
        }
        return config_provider->OnChangedParameterSet(parameter_set_name_,
                                                      [](std::shared_ptr<const ParameterSet>) noexcept {});
    });

    auto callback_done = std::async(std::launch::async, [&]() {
        config_provider->OnChangedParameterSet(parameter_set_name_,
                                               [](std::shared_ptr<const ParameterSet>) noexcept {});
        callback_ready.set_value();
        ready.wait();
        registered_on_changed_parameter_set_callback_(parameter_set_name_);
        callback_finished = true;
    });

    auto get_parameter_set_done = std::async(std::launch::async, [&]() {
        get_parameter_set_ready.set_value();
        ready.wait();
        auto ret{config_provider->GetParameterSet(parameter_set_name_, std::nullopt)};
        get_parameter_set_finished = true;
        return ret;
    });

    on_changed_ps_ready.get_future().wait();
    get_parameter_set_ready.get_future().wait();
    callback_ready.get_future().wait();
    // When OnChangedParameterSet, GetParameterSet and client callback are called concurrently
    go.set_value();
    auto parameter_set = get_parameter_set_done.get();
    callback_done.get();
    auto on_changed_ps_result = on_changed_ps_done.get();

    // Then expect their behaviors are correct and deterministic
    EXPECT_EQ(on_changed_ps_result.error(), ConfigProviderError::kCallbackAlreadySet);
    EXPECT_EQ(parameter_set.value()->GetParameterAs<std::uint32_t>(parameter_name_).value(),
              parameter_content_from_proxy_);
}

INSTANTIATE_TEST_SUITE_P(RepeatTenTimes, RepeatableConfigProviderTest, ::testing::Range(0, 10));

class ConfigProviderConvertInitialQualifierStateToInitialQualifierStatePassTest
    : public ConfigProviderTest,
      public ::testing::WithParamInterface<std::tuple<InitialQualifierState, InitialQualifierState>>
{
};
TEST_P(ConfigProviderConvertInitialQualifierStateToInitialQualifierStatePassTest, ConvertInitialQualifierStateToInitialQualifierStatePassTest)
{
    RecordProperty("Priority", "3");
    RecordProperty("TestType", "Interface test");
    RecordProperty("DerivationTechnique", "Error guessing based on knowledge or experience");
    RecordProperty("Verifies", "::score::platform::config_provider::ConfigProviderImpl::GetInitialQualifierState()");
    RecordProperty("Description", "This test check that GetInitialQualifierState() would get expected value successfully");
    // Given the CfgP is created and proxy is created and ready as well
    auto config_provider = CreateConfigProviderWithAvailableCallback([this]() noexcept {
        UnblockMakeProxyAvailable();
    });

    // icp_mock calls GetInitialQualifierState
    SetUpProxy(parameter_set_name_, correct_parameter_set_from_proxy_, std::get<1>(GetParam()));
    BlockUntilProxyIsReady(stop_source_.get_token());

    // When CfgP calls GetInitialQualifierState
    const auto initial_qualifier_state = config_provider->GetInitialQualifierState();

    // Then for each respsone from icp_mock->GetInitialQualifierState,
    // it should match with the corresponding InitialQualifierState value
    EXPECT_EQ(initial_qualifier_state, std::get<0>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(ConvertInitialQualifierStateToInitialQualifierStatePassTest,
                         ConfigProviderConvertInitialQualifierStateToInitialQualifierStatePassTest,
                         testing::Values(std::make_tuple(InitialQualifierState::kDefault, InitialQualifierState::kDefault),
                                         std::make_tuple(InitialQualifierState::kInProgress, InitialQualifierState::kInProgress),
                                         std::make_tuple(InitialQualifierState::kQualified, InitialQualifierState::kQualified),
                                         std::make_tuple(InitialQualifierState::kQualifying, InitialQualifierState::kQualifying),
                                         std::make_tuple(InitialQualifierState::kUnqualified, InitialQualifierState::kUnqualified),
                                         std::make_tuple(InitialQualifierState::kUndefined, InitialQualifierState::kUndefined),
                                         std::make_tuple(InitialQualifierState::kUndefined, static_cast<InitialQualifierState>(7))));
// -------------------------------------------------------------
// Compile-time public API regression coverage (config_provider.h)
// * Unused helper referencing every public ConfigProvider API.
// * Includes related headers: config_provider.h.
// * Build fails if a public signature is removed or changed (compile error acts as guard).
// * Update: add one trivial usage per newly added public symbol.
// * Migration (add → deprecate → remove): add new symbol; add usage here; run
//   spp_promote_test; deprecate old; wait release window; remove old + usage;
//   update docs if semantics changed. Keep changes incremental.
// * Reviewer non‑breaking steps when an existing API changes:
//     1. Run spp_promote_test to see if any downstream repos still use the old method.
//     2. Introduce the new version beside the old; add BOTH usages here.
//     3. After all users migrate (verified again via spp_promote_test):
//        - Remove old usage from this function.
//        - Remove / modify the old API symbol.
//     4. If any users remain, do NOT alter/remove the old symbol or its usage.
// -------------------------------------------------------------
namespace
{
[[maybe_unused]] void CoverConfigProviderAPI()
{
    using namespace score::platform::config_provider;
    ConfigProvider* provider = nullptr;
    score::cpp::string_view set_name{"regression_set"};
    std::optional<std::chrono::milliseconds> timeout{50};
    score::cpp::pmr::vector<score::cpp::string_view> set_names;
    OnChangedParameterSetCallback cb;
    InitialQualifierStateNotifierCallbackType ncd_cb;
    std::string set_name_str{"regression_set"};
    std::string_view set_name_std_view{set_name_str};
    score::cpp::stop_token stop_token;

    using OnChangedPSFn = decltype(&ConfigProvider::OnChangedParameterSet);
    using OnChangedPSCbkFn = decltype(&ConfigProvider::OnChangedParameterSetCbk);

    static_assert(std::is_invocable_v<OnChangedPSFn, ConfigProvider*, std::string&, OnChangedParameterSetCallback>,
                  "OnChangedParameterSet must accept std::string& (downstream owning string pattern).");
    static_assert(std::is_invocable_v<OnChangedPSCbkFn, ConfigProvider*, std::string&, OnChangedParameterSetCallback>,
                  "OnChangedParameterSetCbk must accept std::string& (downstream owning string pattern).");

    if (provider)
    {
        provider->GetParameterSet(set_name, timeout);
        provider->GetParameterSetsByNameList(set_names, timeout);
        provider->OnChangedInitialQualifierState(std::move(ncd_cb));
        provider->OnChangedParameterSet(set_name_str, std::move(cb));
        provider->OnChangedParameterSetCbk(set_name_std_view, std::move(cb));
        provider->OnChangedParameterSetCbk(set_name_str, std::move(cb));
        provider->GetInitialQualifierState(timeout);
        provider->WaitUntilConnected(std::chrono::milliseconds{10}, stop_token);
        (void)provider->CheckParameterSetUpdates();
        provider->GetCachedParameterSetsCount();
    }
}

}  // namespace
}  // namespace test
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
