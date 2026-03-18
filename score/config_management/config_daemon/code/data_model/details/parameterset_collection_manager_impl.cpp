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

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_manager_impl.h"

#include "score/mw/log/logging.h"
#include "score/config_management/config_daemon/code/data_model/error/error.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

ParameterSetCollectionManager::ParameterSetCollectionManager(
    std::shared_ptr<IParameterSetCollection> primary_collection,
    const std::vector<std::shared_ptr<IPlugin>>& plugins,
    std::unique_ptr<IParameterSetStorage> storage) noexcept
    : IParameterSetCollectionManager{},
      primary_collection_{std::move(primary_collection)},
      plugins_{plugins.begin(), plugins.end()},
      storage_{std::move(storage)},
      logger_{mw::log::CreateLogger(std::string_view{"CmMg"})}
{
}

std::shared_ptr<IParameterSetCollection> ParameterSetCollectionManager::GetParameterSetCollection()
{
    return primary_collection_;
}

ResultBlank ParameterSetCollectionManager::ParameterSetCollectionUpdateRequest()
{
    logger_.LogInfo() << "ParameterSetCollectionManager::" << __func__ << ": Starting update procedure";

    auto temporary_collection = std::make_unique<ParameterSetCollection>();
    auto result = NotifyPluginsToUpdate(*temporary_collection);

    if (result.has_value() == false)
    {
        logger_.LogError() << "ParameterSetCollectionManager::" << __func__
                           << ": Failed to update ParameterSetCollection with error: " << result.error();
        return score::MakeUnexpected(DataModelError::kFailedToUpdateParameterSetCollectionJson,
                                   "Failed to update ParameterSetCollection");
    }

    if (storage_ != nullptr)
    {
        auto store_result = storage_->StoreParameterSetCollection(*temporary_collection);
        if (store_result.has_value() == false)
        {
            logger_.LogError() << "ParameterSetCollectionManager::" << __func__
                               << ": Failed to persist ParameterSetCollection with error: " << store_result.error();
            return score::MakeUnexpected(DataModelError::kFailedToUpdateParameterSetCollectionJson,
                                       "Failed to persist ParameterSetCollection");
        }
    }

    logger_.LogInfo() << "ParameterSetCollectionManager::" << __func__ << ": Update completed successfully";
    return {};
}

ResultBlank ParameterSetCollectionManager::NotifyPluginsToUpdate(ParameterSetCollection& temporary_collection)
{
    if (plugins_.empty())
    {
        logger_.LogError() << "ParameterSetCollectionManager::" << __func__
                           << ": No plugins available to update ParameterSetCollection";
        return score::MakeUnexpected(DataModelError::kFailedToUpdateParameterSetCollectionJson,
                                   "No plugins available to update ParameterSetCollection");
    }

    // Plugins are in dependency order: primary plugin always before dependent plugin.
    for (auto& weak_plugin : plugins_)
    {
        auto plugin = weak_plugin.lock();
        if (plugin == nullptr)
        {
            logger_.LogError() << "ParameterSetCollectionManager::" << __func__ << ": Plugin expired";
            return score::MakeUnexpected(DataModelError::kFailedToUpdateParameterSetCollectionJson,
                                       "Plugin expired during ParameterSetCollection update");
        }
        auto update_result = plugin->ParameterSetCollectionUpdateStart(temporary_collection);
        if (update_result.has_value() == false)
        {
            logger_.LogError() << "ParameterSetCollectionManager::" << __func__
                               << ": Failed to update ParameterSetCollection with error: " << update_result.error();
            return score::MakeUnexpected(DataModelError::kFailedToUpdateParameterSetCollectionJson,
                                       "Failed to update ParameterSetCollection");
        }
    }

    logger_.LogInfo() << "ParameterSetCollectionManager::" << __func__
                      << ": ParameterSetCollection update completed successfully";
    return {};
}

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
