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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETERSET_COLLECTION_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETERSET_COLLECTION_H

#include "score/json/internal/model/any.h"
#include "score/result/result.h"
#include "score/config_management/config_daemon/code/data_model/parameter_set_qualifier.h"
#include "score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces/read_only_parameterset_collection.h"

#include <score/string_view.hpp>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

class IParameterSetCollection : public IReadOnlyParameterSetCollection
{
  public:
    IParameterSetCollection() noexcept;
    IParameterSetCollection(IParameterSetCollection&&) noexcept = delete;
    IParameterSetCollection(const IParameterSetCollection&) noexcept = delete;
    IParameterSetCollection& operator=(IParameterSetCollection&&) & noexcept = delete;
    IParameterSetCollection& operator=(const IParameterSetCollection&) & noexcept = delete;
    ~IParameterSetCollection() noexcept override;

    virtual ResultBlank Insert(const score::cpp::string_view set_name,
                               const score::cpp::string_view parameter_name,
                               json::Any&& parameter_value) noexcept = 0;
    virtual ResultBlank UpdateParameterSet(const score::cpp::string_view set_name, const score::cpp::string_view set) = 0;
    virtual bool SetCalibratable(const score::cpp::string_view set_name, const bool is_calibratable) const noexcept = 0;

    virtual score::Result<score::config_management::config_daemon::ParameterSetQualifier> GetParameterSetQualifier(
        const score::cpp::string_view set_name) const = 0;
    virtual ResultBlank SetParameterSetQualifier(
        const score::cpp::string_view set_name,
        const score::config_management::config_daemon::ParameterSetQualifier qualifier) = 0;
};

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_PARAMETERSET_COLLECTION_H
