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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETERSET_COLLECTION_MANAGER_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETERSET_COLLECTION_MANAGER_H

#include "score/result/result.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

/// @brief Interface for ParameterSetCollectionManager.
///
/// Owns a primary ParameterSetCollection and coordinates update requests by
/// notifying plugins directly. Exposes the underlying collection for read/write
/// access. Components needing the full collection interface should call
/// GetParameterSetCollection().
class IParameterSetCollectionManager
{
  public:
    IParameterSetCollectionManager() noexcept;
    IParameterSetCollectionManager(IParameterSetCollectionManager&&) noexcept = delete;
    IParameterSetCollectionManager(const IParameterSetCollectionManager&) noexcept = delete;
    IParameterSetCollectionManager& operator=(IParameterSetCollectionManager&&) & noexcept = delete;
    IParameterSetCollectionManager& operator=(const IParameterSetCollectionManager&) & noexcept = delete;
    virtual ~IParameterSetCollectionManager() noexcept;

    /// @brief Returns the primary ParameterSetCollection owned by this manager.
    virtual std::shared_ptr<IParameterSetCollection> GetParameterSetCollection() = 0;

    /// @brief Triggers a ParameterSetCollection update by notifying all registered plugins.
    virtual ResultBlank ParameterSetCollectionUpdateRequest() = 0;
};

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETERSET_COLLECTION_MANAGER_H
