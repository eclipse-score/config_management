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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PROXIES_DETAILS_FAKE_INTERNAL_CONFIG_PROVIDER_PROXY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PROXIES_DETAILS_FAKE_INTERNAL_CONFIG_PROVIDER_PROXY_H

// Fake variant of `internal_config_provider_proxy.h`, exposed under the same include path by the
// `internal_config_provider_proxy_fake_for_unit_test` target. It instantiates the real
// `InternalConfigProviderInterface` with a trait that keeps everything in process memory. The real
// `InternalConfigProvider` logic can thus be unit tested without an mw::com runtime, a skeleton and an
// mw_com_config.json. Inputs and recorded calls are exchanged via `InternalConfigProviderProxyFakeState`, which tests
// obtain via `GetState()`.

#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"

#include "score/memory/shared/polymorphic_offset_ptr_allocator.h"
#include "score/mw/com/impl/com_error.h"
#include "score/result/result.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

namespace score
{
namespace config_management
{
namespace config_provider
{

struct InternalConfigProviderProxyFakeState
{
    std::size_t initial_qualifier_state_subscriptions{0U};
    std::deque<config_daemon::mw_com_icp_types::InitialQualifierState> initial_qualifier_state_samples{};

    std::size_t last_updated_subscriptions{0U};
    std::size_t last_updated_unsubscriptions{0U};
    std::deque<std::string> last_updated_samples{};
    bool fail_last_updated_get_new_samples{false};

    bool fail_allocate{false};
    bool fail_call{false};
    std::string response_content{};
    std::string last_requested_name{};
    std::size_t last_requested_max_payload_size{0U};
};

namespace fake_proxy_detail
{

using State = InternalConfigProviderProxyFakeState;
using Allocator = score::memory::shared::PolymorphicOffsetPtrAllocator<config_daemon::mw_com_icp_types::ArrayValueType>;

inline score::result::Error BindingFailure()
{
    return score::mw::com::impl::MakeError(score::mw::com::impl::ComErrc::kBindingFailure);
}

class Base
{
  public:
    Base() : state_{std::make_shared<State>()} {}
    Base(const Base&) = delete;
    Base& operator=(const Base&) = delete;
    ~Base() = default;

    std::shared_ptr<State> GetState() const
    {
        return state_;
    }

  private:
    std::shared_ptr<State> state_;
};

template <typename T>
class Event
{
  public:
    Event(Base& base, const char*) : state_{base.GetState()} {}

    score::Result<void> Subscribe(const std::size_t)
    {
        ++state_->last_updated_subscriptions;
        return {};
    }

    void Unsubscribe()
    {
        ++state_->last_updated_unsubscriptions;
    }

    template <typename Callback>
    score::Result<std::size_t> GetNewSamples(Callback&& callback, const std::size_t max_samples)
    {
        if (state_->fail_last_updated_get_new_samples)
        {
            return score::MakeUnexpected<std::size_t>(BindingFailure());
        }
        std::size_t delivered{0U};
        while ((delivered < max_samples) && !state_->last_updated_samples.empty())
        {
            auto sample = std::make_unique<T>();
            sample->fill(0U);
            const auto& name = state_->last_updated_samples.front();
            std::copy(name.begin(), name.end(), sample->begin());
            state_->last_updated_samples.pop_front();
            callback(std::move(sample));
            ++delivered;
        }
        return delivered;
    }

  private:
    std::shared_ptr<State> state_;
};

template <typename T>
class Field
{
  public:
    Field(Base& base, const char*) : state_{base.GetState()} {}

    score::Result<void> Subscribe(const std::size_t)
    {
        ++state_->initial_qualifier_state_subscriptions;
        return {};
    }

    score::Result<std::size_t> GetNumNewSamplesAvailable() const
    {
        return state_->initial_qualifier_state_samples.size();
    }

    template <typename Callback>
    score::Result<std::size_t> GetNewSamples(Callback&& callback, const std::size_t max_samples)
    {
        std::size_t delivered{0U};
        while ((delivered < max_samples) && !state_->initial_qualifier_state_samples.empty())
        {
            const auto sample = std::make_unique<T>(state_->initial_qualifier_state_samples.front());
            state_->initial_qualifier_state_samples.pop_front();
            callback(sample);
            ++delivered;
        }
        return delivered;
    }

  private:
    std::shared_ptr<State> state_;
};

template <typename Signature>
class Method;

template <>
class Method<config_daemon::mw_com_icp_types::GetParameterSet>
{
  public:
    using Name = config_daemon::mw_com_icp_types::ParameterSetName;
    using Content = config_daemon::mw_com_icp_types::ParameterSetContent;
    using Arguments = std::tuple<std::unique_ptr<Name>, std::unique_ptr<std::size_t>>;

    Method(Base& base, const char*) : state_{base.GetState()} {}

    score::Result<Arguments> Allocate()
    {
        if (state_->fail_allocate)
        {
            return score::MakeUnexpected<Arguments>(BindingFailure());
        }
        return Arguments{std::make_unique<Name>(Allocator{}), std::make_unique<std::size_t>(0U)};
    }

    score::Result<std::unique_ptr<Content>> operator()(std::unique_ptr<Name> name,
                                                       std::unique_ptr<std::size_t> max_payload_size)
    {
        if (state_->fail_call)
        {
            return score::MakeUnexpected<std::unique_ptr<Content>>(BindingFailure());
        }
        state_->last_requested_name.assign(reinterpret_cast<const char*>(name->Data()), name->size());
        state_->last_requested_max_payload_size = *max_payload_size;

        auto content = std::make_unique<Content>(Allocator{});
        content->ReserveOnce(state_->response_content.size());
        for (const auto c : state_->response_content)
        {
            content->emplace_back(static_cast<config_daemon::mw_com_icp_types::ArrayValueType>(c));
        }
        return content;
    }

  private:
    std::shared_ptr<State> state_;
};

struct Trait
{
    using Base = fake_proxy_detail::Base;
    template <typename T>
    using Event = fake_proxy_detail::Event<T>;
    template <typename T>
    using Field = fake_proxy_detail::Field<T>;
    template <typename Signature>
    using Method = fake_proxy_detail::Method<Signature>;
};

}  // namespace fake_proxy_detail

class InternalConfigProviderProxy : public config_daemon::InternalConfigProviderInterface<fake_proxy_detail::Trait>
{
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PROXIES_DETAILS_FAKE_INTERNAL_CONFIG_PROVIDER_PROXY_H
