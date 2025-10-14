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

#include "score/config_management/config_daemon/code/services/details/mw_com/internal_config_provider_service_impl.h"

#include "score/mw/log/logging.h"

#include "score/result/result.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{

namespace
{
mw_com_icp_types::InitialQualifierState Convert(const InitialQualifierState& value)
{
    mw_com_icp_types::InitialQualifierState result = mw_com_icp_types::InitialQualifierState::kUndefined;

    switch (value)
    {
        case InitialQualifierState::kDefault:
        {
            result = mw_com_icp_types::InitialQualifierState::kDefault;
        }
        break;

        case InitialQualifierState::kInProgress:
        {
            result = mw_com_icp_types::InitialQualifierState::kInProgress;
        }
        break;

        case InitialQualifierState::kQualified:
        {
            result = mw_com_icp_types::InitialQualifierState::kQualified;
        }
        break;

        case InitialQualifierState::kQualifying:
        {
            result = mw_com_icp_types::InitialQualifierState::kQualifying;
        }
        break;

        case InitialQualifierState::kUnqualified:
        {
            result = mw_com_icp_types::InitialQualifierState::kUnqualified;
        }
        break;

        case InitialQualifierState::kUndefined:
        {
            result = mw_com_icp_types::InitialQualifierState::kUndefined;
        }
        break;

        default:
        {
            result = mw_com_icp_types::InitialQualifierState::kUndefined;
        }
        break;
    }

    return result;
}
}  // namespace

InternalConfigProviderService::InternalConfigProviderService(
    std::shared_ptr<InternalConfigProviderServiceReactor> internal_config_provider_service_reactor,
    InternalConfigProviderSkeleton icp_skeleton)
    : internal_config_provider_service_reactor_{std::move(internal_config_provider_service_reactor)},
      icp_skeleton_{std::move(icp_skeleton)},
      initial_qualifier_state_{config_daemon::InitialQualifierState::kUndefined},
      logger_{mw::log::CreateLogger(std::string_view{"Serv"})}
{
    InternalConfigProviderService::SetInitialQualifierState(initial_qualifier_state_);
}

score::Result<InternalConfigProviderService> InternalConfigProviderService::Create(
    std::shared_ptr<InternalConfigProviderServiceReactor> internal_config_provider_service_reactor,
    const mw::com::InstanceSpecifier& instance_specifier)
{
    auto icp_skeleton_result{InternalConfigProviderSkeleton::Create(instance_specifier)};
    if (!icp_skeleton_result.has_value())
    {
        mw::log::LogError()
            << "InternalConfigProviderService::Create() - Failed to create InternalConfigProviderSkeleton: "
            << icp_skeleton_result.error();
        return MakeUnexpected<InternalConfigProviderService>(icp_skeleton_result.error());
    }
    return InternalConfigProviderService{internal_config_provider_service_reactor,
                                         std::move(icp_skeleton_result).value()};
}

void InternalConfigProviderService::StartService()
{
    const auto offer_service_result = icp_skeleton_.OfferService();
    if (!offer_service_result.has_value())
    {
        mw::log::LogError() << "Failed to Offer InvocationCount service due to error:" << offer_service_result.error();
    }
}

void InternalConfigProviderService::StopService()
{

    icp_skeleton_.StopOfferService();
}

void InternalConfigProviderService::SetInitialQualifierState(
    const config_daemon::InitialQualifierState initial_qualifier_state) noexcept
{
    initial_qualifier_state_ = initial_qualifier_state;
    const auto state = Convert(initial_qualifier_state_);
    logger_.LogInfo() << "InternalConfigProviderService::" << __func__ << "Setting InitialQualifierState: "
                      << static_cast<std::underlying_type_t<mw_com_icp_types::InitialQualifierState>>(state);
    const auto update_result = icp_skeleton_.initial_qualifier_state.Update(state);
    if (!update_result.has_value())
    {
        logger_.LogError() << "InternalConfigProviderService::" << __func__ << "Failed to set InitialQualifierSate";
    }
}

bool InternalConfigProviderService::SendLastUpdatedParameterSet(const std::string_view parameter_set_name) noexcept
{
    logger_.LogDebug() << "InternalConfigProviderService::" << __func__;

    auto event_sample_result = icp_skeleton_.last_updated_parameterset.Allocate();
    if (!event_sample_result.has_value())
    {
        mw::log::LogError() << "Allocation of event sample failed!";
        return false;
    }
    auto& event_sample = event_sample_result.value();

    std::fill(event_sample->begin(), event_sample->end(), 0);
    score::cpp::ignore = std::copy(std::begin(parameter_set_name), std::end(parameter_set_name), event_sample->begin());

    mw::log::LogDebug() << "InternalConfigProviderService::" << __func__
                        << "Sending LastUpdatedParameterSet: " << parameter_set_name;
    // TODO: Ticket-153602 fix 'forming reference to void' in unit test for Send() method
    auto send_result = icp_skeleton_.last_updated_parameterset.Send(std::move(event_sample));
    if (!send_result.has_value())
    {
        logger_.LogError() << "InternalConfigProviderService::" << __func__
                           << "Failed to send last updated parameter set";
        return false;
    }
    return true;
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
