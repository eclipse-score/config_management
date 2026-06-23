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
#include "score/config_management/config_provider/code/persistency/details/persistency_impl.h"

namespace score
{
namespace config_management
{
namespace config_provider
{

PersistencyImpl::PersistencyImpl() : Persistency{}, logger_{mw::log::CreateLogger(std::string_view("CfgP"))} {}

void PersistencyImpl::ReadParameterSetsByNameListFromFile(ParameterMap&,
                                                           const score::cpp::pmr::vector<std::string_view>&,
                                                           score::cpp::pmr::memory_resource*) noexcept
{
    logger_.LogDebug() << "Empty persistency is used, no parameter sets would be loaded from file";
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
