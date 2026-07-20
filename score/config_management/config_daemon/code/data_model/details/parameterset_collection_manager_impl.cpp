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

#include "score/config_management/config_daemon/code/data_model/error/error.h"
#include "score/mw/log/logging.h"

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

Result<InitialQualifierState> ParameterSetCollectionManager::LoadParameterSetCollectionFromStorage() noexcept
{
    if (storage_ == nullptr)
    {
        logger_.LogError() << "ParameterSetCollectionManager::" << __func__ << ": No storage configured";
        return score::MakeUnexpected(DataModelError::kFailedToLoadParameterSetCollectionJson, "No storage configured");
    }

    const auto load_result = storage_->LoadParameterSetCollection(*primary_collection_);
    if (!load_result.has_value())
    {
        logger_.LogError() << "ParameterSetCollectionManager::" << __func__
                           << ": Failed to load ParameterSetCollection: " << load_result.error()
                           << "; falling back to default data";
        return score::MakeUnexpected(DataModelError::kFailedToLoadParameterSetCollectionJson,
                                   "Failed to load ParameterSetCollection");
    }

    const bool actual_data_loaded = load_result.value();
    logger_.LogInfo() << "ParameterSetCollectionManager::" << __func__
                      << ": ParameterSetCollection loaded; actual_data_loaded=" << actual_data_loaded;

    const auto initial_qualifier =
        actual_data_loaded ? ParameterSetQualifier::kQualifying : ParameterSetQualifier::kDefault;
    const auto collection_json_result = primary_collection_->GetParameterSetCollectionAsJson();
    if (collection_json_result.has_value())
    {
        for (const auto& entry : collection_json_result.value())
        {
            const auto set_result =
                primary_collection_->SetParameterSetQualifier(entry.first.GetAsStringView(), initial_qualifier);
            if (!set_result.has_value())
            {
                logger_.LogError() << "ParameterSetCollectionManager::" << __func__
                                   << ": Failed to set initial qualifier for: " << entry.first.GetAsStringView();
            }
        }
    }

    return actual_data_loaded ? InitialQualifierState::kQualifying : InitialQualifierState::kDefault;
}

std::shared_ptr<IParameterSetCollection> ParameterSetCollectionManager::GetParameterSetCollection()
{
    return primary_collection_;
}

Result<void> ParameterSetCollectionManager::ParameterSetCollectionUpdateRequest()
{
    logger_.LogInfo() << "ParameterSetCollectionManager::" << __func__ << ": Starting update procedure";

    ParameterSetCollection temporary_collection{};
    auto result = NotifyPluginsToUpdate(temporary_collection);

    if (result.has_value() == false)
    {
        logger_.LogError() << "ParameterSetCollectionManager::" << __func__
                           << ": Failed to update ParameterSetCollection with error: " << result.error();
        return score::MakeUnexpected(DataModelError::kFailedToUpdateParameterSetCollectionJson,
                                   "Failed to update ParameterSetCollection");
    }

    if (storage_ != nullptr)
    {
        auto store_result = storage_->StoreParameterSetCollection(temporary_collection);
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

Result<void> ParameterSetCollectionManager::NotifyPluginsToUpdate(ParameterSetCollection& temporary_collection)
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
        // Suppress AUTOSAR C++14 A18-5-8 rule finding.
        // The object is a locked weak_ptr which is allocated in the heap.
        // coverity[autosar_cpp14_a18_5_8_violation]
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
