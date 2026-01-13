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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_PERSISTENCY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_PERSISTENCY_H

#include "score/filesystem/filesystem.h"
#include "score/result/result.h"
#include "score/config_management/config_provider/code/parameter_set/parameter_set.h"

#include <score/memory.hpp>
#include <score/unordered_map.hpp>
#include <string>

namespace score
{
namespace config_management
{
namespace config_provider
{

///
/// @brief Persistency interface
///
/// Public interface of a optional persistency module of ConfigProvider
///

using ParameterMap = score::cpp::pmr::unordered_map<score::cpp::pmr::string, std::shared_ptr<const ParameterSet>>;

class Persistency
{
  public:
    Persistency() noexcept = default;
    Persistency(Persistency&&) = delete;
    Persistency(const Persistency&) = delete;
    Persistency& operator=(Persistency&&) = delete;
    Persistency& operator=(const Persistency&) = delete;
    virtual ~Persistency() = default;

    /// @brief Reads all parameter set value from persistency cluster into local cache
    ///
    /// @param cached_parameter_sets local cached parameter set
    /// @param memory_resource memory resource used for memory allocation
    /// @param filesystem filesystem used for flash_counter file access
    ///
    virtual void ReadCachedParameterSets(ParameterMap& cached_parameter_sets,
                                         score::cpp::pmr::memory_resource* memory_resource,
                                         const score::filesystem::Filesystem& filesystem) noexcept = 0;

    /// @brief Cache a parameter set into the persistency cluster
    ///
    /// @param cached_parameter_sets local cached parameter set
    /// @param param_set_key parameter set name
    /// @param parameter_set parameter set value
    /// @param sync_to_storage flag indicating whether to sync to storage
    ///
    virtual void CacheParameterSet(const ParameterMap& cached_parameter_sets,
                                   const score::cpp::pmr::string param_set_key,
                                   const std::shared_ptr<const ParameterSet> parameter_set,
                                   bool sync_to_storage) noexcept = 0;

    /// @brief Sync all cached parameter sets to the storage
    ///
    virtual void SyncToStorage() noexcept = 0;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_PERSISTENCY_H
