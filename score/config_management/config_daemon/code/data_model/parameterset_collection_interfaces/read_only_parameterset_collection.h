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

#ifndef CODE_DATA_MODEL_PARAMETERSET_COLLECTION_INTERFACES_READ_ONLY_PARAMETERSET_COLLECTION_H
#define CODE_DATA_MODEL_PARAMETERSET_COLLECTION_INTERFACES_READ_ONLY_PARAMETERSET_COLLECTION_H

#include "score/json/internal/model/any.h"
#include "score/result/result.h"

#include <score/string.hpp>
#include <string>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

class IReadOnlyParameterSetCollection
{
  public:
    IReadOnlyParameterSetCollection() noexcept;
    IReadOnlyParameterSetCollection(IReadOnlyParameterSetCollection&&) noexcept = delete;
    IReadOnlyParameterSetCollection(const IReadOnlyParameterSetCollection&) noexcept = delete;
    IReadOnlyParameterSetCollection& operator=(IReadOnlyParameterSetCollection&&) noexcept = delete;
    IReadOnlyParameterSetCollection& operator=(const IReadOnlyParameterSetCollection&) noexcept = delete;
    virtual ~IReadOnlyParameterSetCollection() noexcept;

    virtual Result<score::cpp::pmr::string> GetParameterSet(const std::string set_name) const = 0;
    virtual Result<json::Any> GetParameterFromSet(const score::cpp::string_view set_name,
                                                  const score::cpp::string_view parameter_name) const = 0;
};

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_DATA_MODEL_PARAMETERSET_COLLECTION_INTERFACES_READ_ONLY_PARAMETERSET_COLLECTION_H
