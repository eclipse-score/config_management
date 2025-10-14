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

#include "score/config_management/config_daemon/code/services/details/internal_config_provider_service_reactor_impl.h"
#include "score/mw/log/logging.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{

InternalConfigProviderServiceReactorImpl::InternalConfigProviderServiceReactorImpl(
    std::shared_ptr<data_model::IReadOnlyParameterSetCollection> read_only_parameter_data_interface)
    : InternalConfigProviderServiceReactor(),
      read_only_parameter_data_interface_{std::move(read_only_parameter_data_interface)}
{
}

score::Result<score::cpp::pmr::string> InternalConfigProviderServiceReactorImpl::GetParameterSet(
    const std::string_view parameter_set_name)
{
    auto param_set_result =
        read_only_parameter_data_interface_->GetParameterSet({parameter_set_name.data(), parameter_set_name.size()});

    if (!param_set_result.has_value())
    {
        mw::log::LogError() << __func__ << ": Key not found";
        return MakeUnexpected<score::cpp::pmr::string>(param_set_result.error());
    }

    return param_set_result;
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
