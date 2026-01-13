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
#include "score/config_management/config_provider/code/persistency/details/persistency_empty.h"

namespace score
{
namespace config_management
{
namespace config_provider
{

PersistencyImpl::PersistencyImpl() : Persistency{}, logger_{mw::log::CreateLogger(std::string_view("CfgP"))} {}

void PersistencyImpl::CacheParameterSet(const ParameterMap&,
                                         const score::cpp::pmr::string,
                                         const std::shared_ptr<const ParameterSet>,
                                         bool) noexcept
{
    logger_.LogDebug() << "Empty persistency is used, no caching is done";
}

void PersistencyImpl::ReadCachedParameterSets(ParameterMap&,
                                               score::cpp::pmr::memory_resource*,
                                               const score::filesystem::Filesystem&) noexcept
{
    logger_.LogDebug() << "Empty persistency is used, no caching would be read";
}

void PersistencyImpl::SyncToStorage() noexcept
{
    logger_.LogDebug() << "Empty persistency is used, no syncing is done";
}

}  // namespace config_provider
}  // namespace config_management
}  // namespace score
