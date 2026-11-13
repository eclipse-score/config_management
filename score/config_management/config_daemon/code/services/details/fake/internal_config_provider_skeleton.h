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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_SERVICES_DETAILS_FAKE_INTERNAL_CONFIG_PROVIDER_SKELETON_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_SERVICES_DETAILS_FAKE_INTERNAL_CONFIG_PROVIDER_SKELETON_H

// Fake variant of `internal_config_provider_skeleton.h`, exposed under the same include path by the
// `internal_config_provider_skeleton_fake_for_unit_test` target. It instantiates the real
// `InternalConfigProviderInterface` with a trait that keeps everything in process memory. The real service logic can
// thus be unit tested without an mw::com runtime and without an mw_com_config.json. All observable behavior is
// recorded in `InternalConfigProviderSkeletonFakeState`, which tests obtain via `GetState()`.

#include "score/config_management/lib/mw_com_types/internal_config_provider_type.h"

#include "score/mw/com/impl/com_error.h"
#include "score/result/result.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace score
{
namespace config_management
{
namespace config_daemon
{

struct InternalConfigProviderSkeletonFakeState
{
    using Handler = std::function<
        void(mw_com_icp_types::ParameterSetContent&, const mw_com_icp_types::ParameterSetName&, const std::size_t&)>;

    Handler get_parameter_set_handler{};
    bool offered{false};
    std::vector<mw_com_icp_types::InitialQualifierState> initial_qualifier_states{};
    std::vector<std::string> sent_parameter_set_names{};

    bool fail_offer_service{false};
    bool fail_update{false};
    bool fail_allocate{false};
    bool fail_send{false};
};

namespace fake_skeleton_detail
{

using State = InternalConfigProviderSkeletonFakeState;

class Base
{
  public:
    Base() : state_{std::make_shared<State>()} {}
    Base(Base&&) noexcept = default;
    Base& operator=(Base&&) noexcept = default;
    Base(const Base&) = delete;
    Base& operator=(const Base&) = delete;
    ~Base() = default;

    score::Result<void> OfferService()
    {
        if (state_->fail_offer_service)
        {
            return score::MakeUnexpected(score::mw::com::impl::ComErrc::kBindingFailure);
        }
        state_->offered = true;
        return {};
    }

    void StopOfferService()
    {
        state_->offered = false;
    }

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

    score::Result<std::unique_ptr<T>> Allocate()
    {
        if (state_->fail_allocate)
        {
            return score::MakeUnexpected<std::unique_ptr<T>>(
                score::mw::com::impl::MakeError(score::mw::com::impl::ComErrc::kSampleAllocationFailure));
        }
        return std::make_unique<T>();
    }

    score::Result<void> Send(std::unique_ptr<T> sample)
    {
        if (state_->fail_send)
        {
            return score::MakeUnexpected(score::mw::com::impl::ComErrc::kBindingFailure);
        }
        const auto* const begin = sample->data();
        state_->sent_parameter_set_names.emplace_back(reinterpret_cast<const char*>(begin));
        return {};
    }

  private:
    std::shared_ptr<State> state_;
};

template <typename T>
class Field
{
  public:
    Field(Base& base, const char*) : state_{base.GetState()} {}

    score::Result<void> Update(const T& value)
    {
        if (state_->fail_update)
        {
            return score::MakeUnexpected(score::mw::com::impl::ComErrc::kBindingFailure);
        }
        state_->initial_qualifier_states.push_back(value);
        return {};
    }

  private:
    std::shared_ptr<State> state_;
};

template <typename Signature>
class Method
{
  public:
    Method(Base& base, const char*) : state_{base.GetState()} {}

    template <typename Handler>
    score::Result<void> RegisterHandler(Handler&& handler)
    {
        state_->get_parameter_set_handler = std::forward<Handler>(handler);
        return {};
    }

  private:
    std::shared_ptr<State> state_;
};

struct Trait
{
    using Base = fake_skeleton_detail::Base;
    template <typename T>
    using Event = fake_skeleton_detail::Event<T>;
    template <typename T>
    using Field = fake_skeleton_detail::Field<T>;
    template <typename Signature>
    using Method = fake_skeleton_detail::Method<Signature>;
};

}  // namespace fake_skeleton_detail

class InternalConfigProviderSkeleton : public InternalConfigProviderInterface<fake_skeleton_detail::Trait>
{
  public:
    static bool& FailCreate()
    {
        static bool fail_create{false};
        return fail_create;
    }

    static score::Result<InternalConfigProviderSkeleton> Create(const score::mw::com::InstanceSpecifier&)
    {
        if (FailCreate())
        {
            return score::MakeUnexpected<InternalConfigProviderSkeleton>(
                score::mw::com::impl::MakeError(score::mw::com::impl::ComErrc::kBindingFailure));
        }
        return InternalConfigProviderSkeleton{};
    }
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_SERVICES_DETAILS_FAKE_INTERNAL_CONFIG_PROVIDER_SKELETON_H
