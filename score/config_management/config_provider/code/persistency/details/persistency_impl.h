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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PERSISTENCY_DETAILS_PERSISTENCY_EMPTY_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PERSISTENCY_DETAILS_PERSISTENCY_EMPTY_H

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
    void ReadParameterSetsByNameListFromFile(ParameterMap& cached_parameter_sets,
                                             const score::cpp::pmr::vector<std::string_view>& set_names,
                                             score::cpp::pmr::memory_resource* memory_resource) noexcept override;

  private:
    mw::log::Logger& logger_;
};

}  // namespace config_provider
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_PROVIDER_CODE_PERSISTENCY_DETAILS_PERSISTENCY_EMPTY_H
