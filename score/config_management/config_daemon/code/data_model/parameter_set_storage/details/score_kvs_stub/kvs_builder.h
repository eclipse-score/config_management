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

// Stub replacing score-persistency's kvs_builder.h for builds without the real library.

#ifndef SCORE_LIB_KVS_KVS_BUILDER_H
#define SCORE_LIB_KVS_KVS_BUILDER_H

#include "score/kvs/kvs.h"

#include <memory>
#include <string>

namespace score::kvs
{

/// @brief Stub KvsBuilder — Build() always returns an empty (failure) Result.
class KvsBuilder final
{
  public:
    explicit KvsBuilder(const InstanceId& /*instance_id*/) {}

    KvsBuilder& Defaults(KvsDefaults /*mode*/) noexcept
    {
        return *this;
    }
    KvsBuilder& KvsLoad(score::kvs::KvsLoad /*mode*/) noexcept
    {
        return *this;
    }
    KvsBuilder& WorkingDir(const std::string& /*working_dir*/) noexcept
    {
        return *this;
    }

    score::Result<std::unique_ptr<Kvs>> Build() noexcept
    {
        return score::Result<std::unique_ptr<Kvs>>{std::make_unique<Kvs>()};
    }
};

}  // namespace score::kvs

#endif  // SCORE_LIB_KVS_KVS_BUILDER_H
