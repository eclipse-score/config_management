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

namespace score::mw::per::kvs
{

class KvsValue final
{
  public:
    using Array = std::vector<std::shared_ptr<KvsValue>>;
    using Object = std::unordered_map<std::string, std::shared_ptr<KvsValue>>;

    // NOLINTBEGIN(readability-identifier-naming) — enum constants mirror real score-persistency KvsValue::Type
    enum class Type
    {
        i32,
        u32,
        i64,
        u64,
        f64,
        Boolean,
        String,
        Null,
        Array,
        Object
    };
    // NOLINTEND(readability-identifier-naming)

    explicit KvsValue(const std::string& str) : value_{str}, type_{Type::String} {}
    explicit KvsValue(std::string&& str) : value_{std::move(str)}, type_{Type::String} {}
    explicit KvsValue(Type type) : value_{std::string{}}, type_{type} {}

    KvsValue(const KvsValue&) = default;
    KvsValue& operator=(const KvsValue&) = default;
    KvsValue(KvsValue&&) noexcept = default;
    KvsValue& operator=(KvsValue&&) noexcept = default;

    // NOLINTBEGIN(readability-identifier-naming) — method names mirror real score-persistency KvsValue API
    Type getType() const noexcept
    {
        return type_;
    }

    const std::variant<std::string>& getValue() const noexcept
    {
        return value_;
    }
    // NOLINTEND(readability-identifier-naming)

  private:
    std::variant<std::string> value_;
    Type type_{Type::Null};
};

}  // namespace score::mw::per::kvs

#endif  // SCORE_LIB_KVS_KVSVALUE_HPP
