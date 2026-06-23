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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_DATA_MODEL_PARAMETER_SET_STORAGE_PARAMETER_SET_STORAGE_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_DATA_MODEL_PARAMETER_SET_STORAGE_PARAMETER_SET_STORAGE_H

#include "score/result/result.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{
class IParameterSetCollection;

/// @brief Interface for persisting the parameter set collection.
///        Implementations own the full persistence strategy: JSON serialization,
///        hash calculation, KVS write, and (where applicable) flash counter copy.
class IParameterSetStorage
{
  public:
    virtual ~IParameterSetStorage() = default;
    IParameterSetStorage() = default;
    IParameterSetStorage(IParameterSetStorage&&) = delete;
    IParameterSetStorage(const IParameterSetStorage&) = delete;
    IParameterSetStorage& operator=(IParameterSetStorage&&) = delete;
    IParameterSetStorage& operator=(const IParameterSetStorage&) = delete;

    /// @brief Persist the complete parameter set collection to durable storage.
    ///
    /// Implementations are responsible for serializing the collection, computing
    /// the integrity hash, writing all artifacts to persistent storage, and
    /// (where applicable) storing the flash counter copy.
    ///
    /// @param collection  The collection to persist.
    /// @return Result<void> on success, error on failure.
    virtual Result<void> StoreParameterSetCollection(IParameterSetCollection& collection) noexcept = 0;

    /// @brief Load the parameter set collection from persistent storage on startup.
    ///
    /// Checks the flash counter against its KVS copy to detect a flash event.
    /// If a flash is detected, updates the KVS copy, removes ParameterSetCollection.json
    /// and loads DefaultParameterSetCollection.json.
    /// Otherwise, verifies the SHA-256 hash of ParameterSetCollection.json against
    /// the KVS copy and loads ParameterSetCollection.json on success, or falls back
    /// to DefaultParameterSetCollection.json on any integrity failure.
    ///
    /// @param collection  The in-memory collection to populate.
    /// @return Result<bool>: true if ParameterSetCollection.json was loaded (kQualifying),
    ///         false if DefaultParameterSetCollection.json was loaded (kDefault),
    ///         or an error on unrecoverable failure (e.g. flash counter unreadable).
    virtual Result<bool> LoadParameterSetCollection(IParameterSetCollection& collection) noexcept = 0;
};
}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_DATA_MODEL_PARAMETER_SET_STORAGE_PARAMETER_SET_STORAGE_H
