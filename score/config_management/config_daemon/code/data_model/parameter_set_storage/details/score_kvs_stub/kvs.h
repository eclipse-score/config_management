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

#ifndef SCORE_LIB_KVS_KVS_HPP
#define SCORE_LIB_KVS_KVS_HPP

#include "score/kvs/kvs_value.h"

#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/error/parameter_set_storage_error.h"

#include <cstdint>
#include <memory>
#include <string_view>

namespace score::kvs
{

struct InstanceId
{
    explicit InstanceId(std::size_t id) : id{id} {}
    std::size_t id{0U};
};

enum class KvsDefaults : std::uint8_t
{
    kRequired = 0,
    kOptional = 1,
    kIgnored = 2,
};

enum class KvsLoad : std::uint8_t
{
    kRequired = 0,
    kOptional = 1,
    kIgnored = 2,
};

// Stub for score-persistency's Kvs. Concrete so make_unique<Kvs>(unique_ptr<Kvs>) in
// factory_mw_com_impl.cpp compiles. MockKvs subclasses and overrides the virtual methods for tests.
class Kvs
{
  public:
    Kvs() = default;
    // Accepts a unique_ptr<Kvs> to match the real score-persistency API used in factory_mw_com_impl.cpp.
    explicit Kvs(std::unique_ptr<Kvs> /*inner*/) noexcept {}
    virtual ~Kvs() = default;
    Kvs(const Kvs&) = delete;
    Kvs& operator=(const Kvs&) = delete;
    Kvs(Kvs&&) noexcept = delete;
    Kvs& operator=(Kvs&&) noexcept = delete;

    virtual score::Result<KvsValue> GetValue(std::string_view /*key*/) const noexcept
    {
        return score::MakeUnexpected<KvsValue>(
            score::MakeUnexpected(::score::config_management::config_daemon::data_model::ParameterSetStorageError::kDataNotFound)
                .error());
    }
    virtual score::Result<void> SetValue(std::string_view /*key*/, const KvsValue& /*value*/) noexcept
    {
        return score::MakeUnexpected(
            ::score::config_management::config_daemon::data_model::ParameterSetStorageError::kUnableToSaveToPersistency);
    }
    virtual score::Result<void> Flush() noexcept
    {
        return score::MakeUnexpected(
            ::score::config_management::config_daemon::data_model::ParameterSetStorageError::kUnableToSaveToPersistency);
    }
};

}  // namespace score::kvs

#endif  // SCORE_LIB_KVS_KVS_HPP
