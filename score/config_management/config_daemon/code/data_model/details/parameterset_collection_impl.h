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

#ifndef SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETERSET_COLLECTION_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETERSET_COLLECTION_IMPL_H

#include "score/config_management/config_daemon/code/data_model/parameterset_collection.h"

#include "score/result/result.h"
#include "score/mw/log/logger.h"

#include <score/optional.hpp>
#include <score/string.hpp>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace data_model
{

class ParameterSet;
class ParameterSetCollection final : public IParameterSetCollection
{
  public:
    ParameterSetCollection();
    ~ParameterSetCollection() noexcept override = default;
    ParameterSetCollection(ParameterSetCollection&&) = delete;
    ParameterSetCollection(const ParameterSetCollection&) = delete;

    ParameterSetCollection& operator=(ParameterSetCollection&&) = delete;
    ParameterSetCollection& operator=(const ParameterSetCollection&) = delete;

    ResultBlank Insert(const score::cpp::string_view set_name,
                       const score::cpp::string_view parameter_name,
                       json::Any&& parameter_value) noexcept override;
    Result<json::Any> GetParameterFromSet(const score::cpp::string_view set_name,
                                          const score::cpp::string_view parameter_name) const override;
    Result<score::cpp::pmr::string> GetParameterSet(const std::string set_name) const override;
    ResultBlank UpdateParameterSet(const score::cpp::string_view set_name, const score::cpp::string_view set) override;
    bool SetCalibratable(const score::cpp::string_view set_name, const bool is_calibratable) const noexcept override;

    score::Result<score::config_management::config_daemon::ParameterSetQualifier> GetParameterSetQualifier(
        const score::cpp::string_view set_name) const override;
    ResultBlank SetParameterSetQualifier(const score::cpp::string_view set_name,
                                         const score::config_management::config_daemon::ParameterSetQualifier qualifier) override;

  private:
    Result<std::shared_ptr<ParameterSet>> Find(const score::cpp::string_view set_name) const noexcept;

    mw::log::Logger& logger_;
    mutable std::mutex mutex_;
    std::unordered_map<score::cpp::pmr::string, std::shared_ptr<ParameterSet>> parameter_sets_;
};

}  // namespace data_model
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIGDAEMON_CODE_DATA_MODEL_DETAILS_PARAMETERSET_COLLECTION_IMPL_H
