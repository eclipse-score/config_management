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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_DATA_MODEL_DETAILS_PARAMETERSET_COLLECTION_MANAGER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_DATA_MODEL_DETAILS_PARAMETERSET_COLLECTION_MANAGER_IMPL_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection_manager.h"

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/parameter_set_storage.h"
#include "score/config_management/config_daemon/code/plugins/plugin.h"
#include "score/result/result.h"
#include "score/mw/log/logger.h"

#include <memory>
#include <vector>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

/// @brief Concrete implementation of IParameterSetCollectionManager.
///
/// Wraps the primary ParameterSetCollection and owns a temporary ParameterSetCollection
/// used during update procedures. Delegates all IParameterSetCollection operations to the
/// primary collection. ParameterSetCollectionUpdateRequest() triggers plugins directly
/// using a fresh temporary collection as target.
///
/// This class owns the plugins so it can orchestrate the update without circular
/// ownership between ParameterSetCollection and plugins.
class ParameterSetCollectionManager final : public IParameterSetCollectionManager
{
  public:
    ParameterSetCollectionManager(std::shared_ptr<IParameterSetCollection> primary_collection,
                                  const std::vector<std::shared_ptr<IPlugin>>& plugins,
                                  std::unique_ptr<IParameterSetStorage> storage) noexcept;
    ~ParameterSetCollectionManager() noexcept override = default;

    ParameterSetCollectionManager(ParameterSetCollectionManager&&) = delete;
    ParameterSetCollectionManager(const ParameterSetCollectionManager&) = delete;
    ParameterSetCollectionManager& operator=(ParameterSetCollectionManager&&) = delete;
    ParameterSetCollectionManager& operator=(const ParameterSetCollectionManager&) = delete;

    Result<InitialQualifierState> LoadParameterSetCollectionFromStorage() noexcept override;

    std::shared_ptr<IParameterSetCollection> GetParameterSetCollection() override;

    /// @brief Triggers plugins to populate a temporary ParameterSetCollection.
    Result<void> ParameterSetCollectionUpdateRequest() override;

  private:
    Result<void> NotifyPluginsToUpdate(ParameterSetCollection& temporary_collection);

    std::shared_ptr<IParameterSetCollection> primary_collection_;
    std::vector<std::weak_ptr<IPlugin>> plugins_;
    std::unique_ptr<IParameterSetStorage> storage_;
    mw::log::Logger& logger_;
};

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_DATA_MODEL_DETAILS_PARAMETERSET_COLLECTION_MANAGER_IMPL_H
