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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PERSISTENCY_PERSISTENCY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PERSISTENCY_PERSISTENCY_H

#include "score/config_management/config_provider/code/parameter_set/parameter_set.h"
#include "score/result/result.h"

#include <score/memory.hpp>
#include <score/string.hpp>
#include <score/unordered_map.hpp>
#include <score/vector.hpp>
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

    /// @brief Reads only the selected parameter sets from ConfigDaemon JSON files into local cache.
    ///
    /// Uses flash-counter based file selection:
    /// - If flash counter has not changed, tries parameter_set_collection.json first.
    /// - Otherwise, or if actual file is unavailable, loads from default_parameter_set_collection.json.
    ///
    /// @param cached_parameter_sets local cached parameter set map to be updated
    /// @param set_names parameter set names that should be loaded
    /// @param memory_resource memory resource used for memory allocation
    /// @param filesystem filesystem used for file access
    ///
    virtual void ReadParameterSetsByNameListFromFile(ParameterMap& cached_parameter_sets,
                                                     const score::cpp::pmr::vector<std::string_view>& set_names,
                                                     score::cpp::pmr::memory_resource* memory_resource) noexcept = 0;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PERSISTENCY_PERSISTENCY_H
