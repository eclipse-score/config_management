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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_DETAILS_PERSISTENCY_EMPTY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_DETAILS_PERSISTENCY_EMPTY_H

#include "score/config_management/config_provider/code/persistency/persistency.h"

#include "score/mw/log/logger.h"

namespace score
{
namespace config_management
{
namespace config_provider
{

///
/// @brief Implementation of Persistency interface
///

class PersistencyImpl final : public Persistency
{
  public:
    explicit PersistencyImpl();
    void ReadCachedParameterSets(ParameterMap& cached_parameter_sets,
                                 score::cpp::pmr::memory_resource* memory_resource,
                                 const score::filesystem::Filesystem& filesystem) noexcept override;
    void CacheParameterSet(const ParameterMap& cached_parameter_sets,
                           const score::cpp::pmr::string param_set_key,
                           const std::shared_ptr<const ParameterSet> parameter_set,
                           bool sync_to_storage) noexcept override;
    void SyncToStorage() noexcept override;

  private:
    mw::log::Logger& logger_;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGPROVIDER_CODE_PERSISTENCY_DETAILS_PERSISTENCY_EMPTY_H
