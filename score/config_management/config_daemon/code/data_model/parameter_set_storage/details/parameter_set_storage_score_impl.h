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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETER_SET_STORAGE_DETAILS_PARAMETER_SET_STORAGE_SCORE_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETER_SET_STORAGE_DETAILS_PARAMETER_SET_STORAGE_SCORE_IMPL_H

#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/parameter_set_storage.h"

#include "kvs.hpp"

#include <memory>
#include <string>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

/// @brief Implementation of IParameterSetStorage for the score build.
///        Serializes the collection to JSON, stores the SHA-256 hash via score KVS.
///        Flash counter is not applicable on score and is a no-op.
class ParameterSetStorageScoreImpl final : public IParameterSetStorage
{
  public:
    /// @brief Construct the storage impl, taking ownership of an opened Kvs instance.
    explicit ParameterSetStorageScoreImpl(std::unique_ptr<score::mw::per::kvs::Kvs> kvs) noexcept;

    ResultBlank StoreParameterSetCollection(data_model::IParameterSetCollection& collection) noexcept override;

  private:
    Result<std::string> ReadParameterSetCollectionHash() const noexcept;
    ResultBlank PersistParameterSetCollectionHash(const std::string& hash) noexcept;
    std::unique_ptr<score::mw::per::kvs::Kvs> kvs_;
};

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETER_SET_STORAGE_DETAILS_PARAMETER_SET_STORAGE_SCORE_IMPL_H
