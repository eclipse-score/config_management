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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETER_IMPL_H

#include "score/json/internal/model/any.h"

#include <score/optional.hpp>
#include <score/string.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{
class Parameter
{
  public:
    const json::Any& GetValue() const
    {
        return value_;
    }
    void SetValue(json::Any&& value)
    {
        value_ = std::move(value);
    }

  private:
    json::Any value_;
};
}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETER_IMPL_H
