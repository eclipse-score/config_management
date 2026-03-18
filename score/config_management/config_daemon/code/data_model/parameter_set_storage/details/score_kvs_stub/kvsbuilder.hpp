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

// Stub replacing score-persistency's kvsbuilder.hpp for SPP compilation.
// Only the subset of the API used by factory_mw_impl.cpp is provided.

#ifndef SCORE_LIB_KVS_KVSBUILDER_HPP
#define SCORE_LIB_KVS_KVSBUILDER_HPP

#include "kvs.hpp"

#include <memory>
#include <string>

namespace score::mw::per::kvs
{

/// @brief Stub KvsBuilder — build() always returns an empty (failure) Result.
class KvsBuilder final
{
  public:
    explicit KvsBuilder(const InstanceId& /*instance_id*/) {}

    KvsBuilder& need_defaults_flag(bool /*flag*/) noexcept
    {
        return *this;
    }
    KvsBuilder& need_kvs_flag(bool /*flag*/) noexcept
    {
        return *this;
    }
    KvsBuilder& dir(std::string&& /*dir_path*/) noexcept
    {
        return *this;
    }

    score::Result<std::unique_ptr<Kvs>> build() noexcept
    {
        return score::Result<std::unique_ptr<Kvs>>{std::make_unique<Kvs>()};
    }
};

}  // namespace score::mw::per::kvs

#endif  // SCORE_LIB_KVS_KVSBUILDER_HPP
