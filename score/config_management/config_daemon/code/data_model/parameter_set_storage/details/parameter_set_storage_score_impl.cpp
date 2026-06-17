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

#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/details/parameter_set_storage_score_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameter_set_qualifier.h"
#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/error/parameter_set_storage_error.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"

#include "kvsvalue.hpp"
#include "score/hash/code/common/algorithms.h"
#include "score/hash/code/core/factory/impl/safe_hash_calculator_factory.h"
#include "score/json/json_writer.h"

#include <memory>
#include <variant>
#include <vector>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

namespace
{
constexpr std::string_view kParameterSetHashKvsKey{"ActualParameterHashKey"};
}  // namespace

ParameterSetStorageScoreImpl::ParameterSetStorageScoreImpl(std::unique_ptr<score::mw::per::kvs::Kvs> kvs) noexcept
    : IParameterSetStorage{}, kvs_{std::move(kvs)}
{
}

Result<void> ParameterSetStorageScoreImpl::StoreParameterSetCollection(
    data_model::IParameterSetCollection& collection) noexcept
{
    // Collect all parameter sets into a JSON object, overriding qualifier to kQualifying.
    json::JsonWriter json_writer{};
    auto collection_json_result = collection.GetParameterSetCollectionAsJson();
    if (!collection_json_result.has_value())
    {
        return MakeUnexpected(ParameterSetStorageError::kUnableToSaveToPersistency,
                              "Failed to get parameter set collection as JSON");
    }
    auto collection_json = std::move(collection_json_result).value();
    for (auto& entry : collection_json)
    {
        const auto set_object = entry.second.As<json::Object>();
        if (set_object.has_value())
        {
            set_object.value().get()["qualifier"] = json::Any{score::cpp::to_underlying(ParameterSetQualifier::kQualifying)};
        }
    }

    // Serialize, hash, and store.
    const auto buffer_result = json_writer.ToBuffer(collection_json);
    if (!buffer_result.has_value())
    {
        return MakeUnexpected(ParameterSetStorageError::kUnableToSaveToPersistency,
                              "Failed to serialize collection to buffer");
    }
    const auto& json_string = buffer_result.value();
    std::vector<std::uint8_t> serialized_bytes(json_string.size(), 0U);
    score::cpp::ignore = std::copy(json_string.cbegin(), json_string.cend(), serialized_bytes.begin());

    hash::SafeHashCalculatorFactory hash_factory{};
    const auto hash_result = hash_factory.CalculateHash(hash::HashAlgorithm::kSha256, serialized_bytes);
    if (!hash_result.has_value())
    {
        return MakeUnexpected(ParameterSetStorageError::kUnableToSaveToPersistency, "Failed to calculate SHA-256 hash");
    }

    const score::cpp::pmr::string hash_pmr = hash_result.value().ToString();
    return PersistParameterSetCollectionHash(std::string{hash_pmr.begin(), hash_pmr.end()});
}

Result<void> ParameterSetStorageScoreImpl::PersistParameterSetCollectionHash(const std::string& hash) noexcept
{
    const auto set_result = kvs_->set_value(kParameterSetHashKvsKey, score::mw::per::kvs::KvsValue{hash});
    if (!set_result.has_value())
    {
        return MakeUnexpected(ParameterSetStorageError::kUnableToSaveToPersistency, "Failed to set hash in score KVS");
    }
    const auto flush_result = kvs_->flush();
    if (!flush_result.has_value())
    {
        return MakeUnexpected(ParameterSetStorageError::kUnableToSaveToPersistency,
                              "Failed to flush hash to score KVS storage");
    }
    return {};
}

Result<std::string> ParameterSetStorageScoreImpl::ReadParameterSetCollectionHash() const noexcept
{
    const auto get_result = kvs_->get_value(kParameterSetHashKvsKey);
    if (!get_result.has_value())
    {
        return MakeUnexpected(ParameterSetStorageError::kDataNotFound, "Hash not found in score KVS");
    }
    const auto& kvsvalue = get_result.value();
    if (kvsvalue.getType() != score::mw::per::kvs::KvsValue::Type::String)
    {
        return MakeUnexpected(ParameterSetStorageError::kDataNotFound, "Hash value in score KVS has unexpected type");
    }
    return std::get<std::string>(kvsvalue.getValue());
}

Result<bool> ParameterSetStorageScoreImpl::LoadParameterSetCollection(
    data_model::IParameterSetCollection& /*collection*/) noexcept
{
    // Filesystem-based PSC loading is not applicable on the SCORE platform.
    // Always indicate that the default parameter set collection is in use.
    return false;
}

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
