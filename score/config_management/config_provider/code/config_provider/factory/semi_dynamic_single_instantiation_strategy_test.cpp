/*********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

#include "score/config_management/config_provider/code/config_provider/factory/semi_dynamic_single_instantiation_strategy.h"

#include "score/result/result.h"
#include "score/mw/service/proxy_builder_base.h"
#include "score/mw/service/single_instance_holder.h"
#include "score/concurrency/future/interruptible_promise.h"
#include "score/mw/com/com_error_domain.h"
#include "score/mw/com/types.h"

#include <score/assert.hpp>
#include <score/callback.hpp>
#include <score/utility.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace score
{
namespace config_management
{
namespace config_provider
{
namespace test
{
namespace
{

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

constexpr auto kPortIdentifierString =
    "ConfigDaemonCustomer/ConfigDaemonCustomer_RootSwc/InternalConfigProviderAppRPort";
constexpr std::size_t kAdditionalShmSizeBytes{1024U};
const auto kInstanceSpecifier = score::mw::com::InstanceSpecifier::Create(kPortIdentifierString).value();

/// @brief Own, minimal fake for the `MwComProxy` template parameter of `SemiDynamicSingleInstantiationStrategy`.
///
/// @details `SemiDynamicSingleInstantiationStrategy::StartFind()` routes proxy creation through
///          `score::mw::com::impl::ProxyWithSemiDynamicMethodFactory<MwComProxy>::Create`, which is hard-coded to
///          take a `score::mw::com::impl::HandleType` (the real, vendored library type) rather than
///          `MwComProxy::HandleType`. Consequently, `HandleType` must alias the real library type for this fake to
///          even compile - but since none of the tests below make `StartFindService`'s callback report a found
///          handle, `Create()` is compiled but never actually invoked at runtime, so no real `HandleType` instance
///          ever needs to be constructed. This avoids exercising `score::mw::com`'s real lola runtime entirely,
///          side-stepping a TSAN lock-order-inversion bug in the vendored library's `ServiceDiscoveryClient` that's
///          triggered merely by calling `StartFindService`/`StopFindService` for real.
class FakeMwComProxy
{
  public:
    using HandleType = score::mw::com::impl::HandleType;

    class Mock
    {
      public:
        Mock() {}

        MOCK_METHOD(score::mw::com::FindServiceHandle,
                    StartFindService,
                    (score::mw::com::FindServiceHandler<HandleType>, score::mw::com::InstanceSpecifier),
                    ());
        MOCK_METHOD(score::Result<void>, StopFindService, (score::mw::com::FindServiceHandle), ());
    };

    static score::Result<FakeMwComProxy> Create(const HandleType, std::size_t) noexcept
    {
        return FakeMwComProxy{};
    }

    static score::Result<score::mw::com::FindServiceHandle> StartFindService(
        score::mw::com::FindServiceHandler<HandleType> handler,
        score::mw::com::InstanceSpecifier instance_specifier)
    {
        return GetMockInstance().StartFindService(std::move(handler), std::move(instance_specifier));
    }

    static score::Result<void> StopFindService(score::mw::com::FindServiceHandle handle)
    {
        return GetMockInstance().StopFindService(handle);
    }

    ~FakeMwComProxy() noexcept = default;
    FakeMwComProxy(FakeMwComProxy&&) noexcept = default;
    FakeMwComProxy& operator=(FakeMwComProxy&&) noexcept = default;
    FakeMwComProxy(const FakeMwComProxy&) = delete;
    FakeMwComProxy& operator=(const FakeMwComProxy&) = delete;

    static Mock& GetMockInstance()
    {
        SCORE_LANGUAGE_FUTURECPP_PRECONDITION_PRD(gMockInstance != nullptr);
        return *gMockInstance;
    }

    static void SetUpMockInstance()
    {
        SCORE_LANGUAGE_FUTURECPP_PRECONDITION_PRD(gMockInstance == nullptr);
        gMockInstance = std::make_unique<Mock>();
    }

    static void DestroyMockInstance()
    {
        gMockInstance.reset();
    }

  private:
    FakeMwComProxy() = default;
    static std::unique_ptr<Mock> gMockInstance;
};

std::unique_ptr<FakeMwComProxy::Mock> FakeMwComProxy::gMockInstance{};

using MwComProxy = FakeMwComProxy;

class FakeMwComProxyMockGuard
{
  public:
    FakeMwComProxyMockGuard()
    {
        MwComProxy::SetUpMockInstance();
    }

    ~FakeMwComProxyMockGuard()
    {
        MwComProxy::DestroyMockInstance();
    }
};

/// @brief Dummy public interface, standing in for `IInternalConfigProvider`.
class Proxy
{
  public:
    virtual ~Proxy() = default;
};

/// @brief Dummy implementation, standing in for `InternalConfigProvider`. Only needs to be constructible from a
///        `std::unique_ptr<MwComProxy>`, as required by `SemiDynamicSingleInstantiationStrategy`.
class ProxyImpl : public Proxy
{
  public:
    explicit ProxyImpl(std::unique_ptr<MwComProxy>) {}
};

struct DummyPort
{
    constexpr static auto Get()
    {
        return kPortIdentifierString;
    }
};

using Strategy = SemiDynamicSingleInstantiationStrategy<Proxy, ProxyImpl, MwComProxy, DummyPort>;
using StrategyWithCtorPortIdentifier = SemiDynamicSingleInstantiationStrategy<Proxy, ProxyImpl, MwComProxy>;

class SemiDynamicSingleInstantiationStrategyFixture : public ::testing::Test
{
  public:
    void SetUp() override
    {
        ON_CALL(proxy_mock, StartFindService(_, _)).WillByDefault(Return(dummy_find_service_handle));

        ON_CALL(proxy_mock, StopFindService(_)).WillByDefault(Invoke([this] {
            stop_find_service_invocations++;
            return score::Result<void>{};
        }));
    }

    std::unique_ptr<typename mw::service::ProxyBuilderBase<Proxy>::BuilderCallback> CreateBuilderCallback()
    {
        score::concurrency::InterruptiblePromise<mw::service::SingleInstanceHolder<Proxy>> promise{};
        score::cpp::callback<void(Proxy&)> user_callback = [this](Proxy&) {
            found_invocations++;
        };
        return std::make_unique<typename mw::service::ProxyBuilderBase<Proxy>::BuilderCallback>(
            std::move(promise), std::move(user_callback));
    }

    FakeMwComProxyMockGuard fake_proxy_mock_guard{};
    MwComProxy::Mock& proxy_mock{MwComProxy::GetMockInstance()};

    score::mw::com::FindServiceHandle dummy_find_service_handle{score::mw::com::impl::make_FindServiceHandle(10U)};
    std::size_t found_invocations{0U};
    std::uint32_t stop_find_service_invocations{0U};
};

TEST_F(SemiDynamicSingleInstantiationStrategyFixture,
       CanGetPortIdentifierWhenConstructingWithPortIdentifierTemplateArgument)
{
    // Given a Strategy instance whereby a `PortIdentifier` type got provided as template argument
    Strategy strategy{kAdditionalShmSizeBytes};

    // When getting the PortIdentifier
    const auto& port_identifier = strategy.GetPortIdentifier();

    // Then its port identifier must have gotten determined via the `PortIdentifier` type defined above
    EXPECT_EQ(port_identifier, DummyPort::Get());
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture,
       CanGetPortIdentifierWhenConstructingWithPortIdentifierConstructorArgument)
{
    // Given a Strategy instance where no `PortIdentifier` type got provided as template argument but was provided to
    // the constructor
    StrategyWithCtorPortIdentifier strategy{std::string{kPortIdentifierString}, kAdditionalShmSizeBytes};

    // When getting the PortIdentifier
    const auto& port_identifier = strategy.GetPortIdentifier();

    // Then its port identifier must be equal to the one provided as constructor argument
    EXPECT_EQ(port_identifier, kPortIdentifierString);
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture, StartAndStopFindServiceAreNotCalledOnConstruction)
{
    // Expecting that Start/StopFindService will never be called
    EXPECT_CALL(proxy_mock, StartFindService(_, _)).Times(0);
    EXPECT_CALL(proxy_mock, StopFindService(_)).Times(0);

    // When creating a Strategy without calling StartFind()
    Strategy strategy{kAdditionalShmSizeBytes};
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture, StopFindDoesNotCrashWhenFindWasNeverCalled)
{
    // Given a Strategy instance for which StartFind() was never called
    Strategy strategy{kAdditionalShmSizeBytes};

    // When calling StopFind()
    strategy.StopFind();

    // Then StopFindService is never called, since StartFind() was never started
    EXPECT_EQ(stop_find_service_invocations, 0U);
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture, DestructionDoesNotCrashWhenFindWasNeverCalled)
{
    // Given a Strategy instance for which StartFind() was never called
    // When it goes out of scope
    {
        Strategy strategy{kAdditionalShmSizeBytes};
    }

    // Then no crash occurs and StopFindService is never called
    EXPECT_EQ(stop_find_service_invocations, 0U);
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture, CallingFindWillCallStartFindService)
{
    // Expecting that StartFindService will be called with the strategy's instance specifier
    EXPECT_CALL(proxy_mock, StartFindService(_, kInstanceSpecifier)).Times(1);

    // Given a Strategy instance
    Strategy strategy{kAdditionalShmSizeBytes};

    // When calling StartFind()
    strategy.StartFind(CreateBuilderCallback());
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture, UserCallbackNotInvokedWhenServiceIsSearchedButNotFound)
{
    // Given a Strategy instance
    Strategy strategy{kAdditionalShmSizeBytes};

    // When calling StartFind() but no service is found
    strategy.StartFind(CreateBuilderCallback());

    // Then the user callback is never invoked
    EXPECT_EQ(found_invocations, 0U);
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture, CallingStopFindWillCallStopFindService)
{
    // Expecting that StopFindService will be called
    EXPECT_CALL(proxy_mock, StopFindService(_)).Times(1);

    // Given a Strategy instance which has started StartFind()
    Strategy strategy{kAdditionalShmSizeBytes};
    strategy.StartFind(CreateBuilderCallback());

    // When calling StopFind()
    EXPECT_EQ(stop_find_service_invocations, 0U);
    strategy.StopFind();
    EXPECT_EQ(stop_find_service_invocations, 1U);
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture, StopFindCanBeCalledMultipleTimesWithoutCrashing)
{
    // Given a Strategy instance which has started StartFind()
    Strategy strategy{kAdditionalShmSizeBytes};
    strategy.StartFind(CreateBuilderCallback());

    // When calling StopFind() repeatedly
    // Then StopFindService is only invoked once, since the second call finds no active find-service handle anymore
    strategy.StopFind();
    strategy.StopFind();
    EXPECT_EQ(stop_find_service_invocations, 1U);
}

TEST_F(SemiDynamicSingleInstantiationStrategyFixture, StopFindWillBeCalledOnDestruction)
{
    // Expecting that StopFindService will be called
    EXPECT_CALL(proxy_mock, StopFindService(_)).Times(1);

    // Given a Strategy instance which has started StartFind()
    auto strategy = std::make_unique<Strategy>(kAdditionalShmSizeBytes);
    strategy->StartFind(CreateBuilderCallback());

    // When destroying the Strategy
    EXPECT_EQ(stop_find_service_invocations, 0U);
    strategy.reset();
    EXPECT_EQ(stop_find_service_invocations, 1U);
}

}  // namespace
}  // namespace test
}  // namespace config_provider
}  // namespace config_management
}  // namespace score
