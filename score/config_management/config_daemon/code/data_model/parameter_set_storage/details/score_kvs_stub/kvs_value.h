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

#ifndef SCORE_LIB_KVS_KVSVALUE_HPP
#define SCORE_LIB_KVS_KVSVALUE_HPP

#include "score/result/result.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace score::kvs
{

class KvsValue final
{
  public:
    using Array = std::vector<std::shared_ptr<KvsValue>>;
    using Object = std::unordered_map<std::string, std::shared_ptr<KvsValue>>;

    enum class Type
    {
        kI32,
        kU32,
        kI64,
        kU64,
        kF64,
        kBoolean,
        kString,
        kNull,
        kArray,
        kObject
    };

    explicit KvsValue(const std::string& str) : value_{str}, type_{Type::kString} {}
    explicit KvsValue(std::string&& str) : value_{std::move(str)}, type_{Type::kString} {}
    explicit KvsValue(Type type) : value_{std::string{}}, type_{type} {}

    KvsValue(const KvsValue&) = default;
    KvsValue& operator=(const KvsValue&) = default;
    KvsValue(KvsValue&&) noexcept = default;
    KvsValue& operator=(KvsValue&&) noexcept = default;

    Type GetType() const noexcept
    {
        return type_;
    }

    const std::variant<std::string>& GetValue() const noexcept
    {
        return value_;
    }

  private:
    std::variant<std::string> value_;
    Type type_{Type::kNull};
};

}  // namespace score::kvs

#endif  // SCORE_LIB_KVS_KVSVALUE_HPP
