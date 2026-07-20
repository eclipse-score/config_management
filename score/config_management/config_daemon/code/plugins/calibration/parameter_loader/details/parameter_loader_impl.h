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
#ifndef SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_DETAILS_PARAMETER_LOADER_IMPL_H
#define SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_DETAILS_PARAMETER_LOADER_IMPL_H

#include "score/config_management/config_daemon/code/fault_event_reporter/fault_event_reporter.h"
#include "score/config_management/config_daemon/code/plugins/calibration/parameter_loader/parameter_loader.h"
#include "score/config_management/config_daemon/code/plugins/coding/param_set_mapping/param_set_mapping.hpp"
#include "score/result/result.h"
#include "score/mw/log/logger.h"

#include <cstdint>

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

class ParameterLoaderImpl final : public ParameterLoader
{
  public:
    ParameterLoaderImpl(
        std::unique_ptr<score::Result<json::Any>> calibration_data,
        const std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping,
        std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter = nullptr,
        std::unique_ptr<score::mw::diag::DTC> dtc_integrity_error = nullptr,
        std::unique_ptr<score::mw::diag::DTC> dtc_default_values_in_use = nullptr);

    ~ParameterLoaderImpl() override = default;

    ParameterLoaderImpl(ParameterLoaderImpl&&) = delete;
    ParameterLoaderImpl(const ParameterLoaderImpl&) = delete;

    ParameterLoaderImpl& operator=(ParameterLoaderImpl&&) = delete;
    ParameterLoaderImpl& operator=(const ParameterLoaderImpl&) = delete;

    bool LoadParameterData(const std::shared_ptr<data_model::IParameterSetCollection> parameter_data) override;

  private:
    void SetIntegrityErrorDtcsToFailed() noexcept;
    void LoadParameterSets(json::Object& param_sets);
    bool GetObjectElement(std::pair<const score::memory::StringComparisonAdaptor, score::json::Any>& obj,
                          std::string& obj_name,
                          score::json::Object& obj_value) const;
    bool HandleContainsDefaultValues(const json::Object& param_set_obj, const std::string& param_set_name);
    void LoadParameterSetParameters(json::Object& parameter_set_parameters_object,
                                    const std::string& param_set_name,
                                    ParameterSetQualifier& set_qualifier);
    void LoadParameter(json::Object& param_obj,
                       const std::string& param_name,
                       const std::string& param_set_name,
                       ParameterSetQualifier& set_qualifier);
    Result<void> LoadCodingDependentParameterFromJson(
        const std::string& param_set_name,
        const std::string& param_name,
        std::map<score::memory::StringComparisonAdaptor, score::json::Any>& param_coding_dependency,
        ParameterSetQualifier& set_qualifier);
    bool GetCodingParamValue(const std::string& coding_param_set_name,
                             const std::string& coding_param_name,
                             std::string& coding_param_value) const;
    Result<void> LoadCodingDependentParameterValue(
        const std::string& param_set_name,
        const std::string& param_name,
        std::map<score::memory::StringComparisonAdaptor, score::json::Any>& param_coding_dependency,
        const std::string& coding_param_name);
    bool LoadParameterFromJson(const std::string& param_set_name,
                               const std::string& param_name,
                               std::map<memory::StringComparisonAdaptor, json::Any>& parameter_obj) noexcept;
    void SetDtcs() noexcept;

    std::unique_ptr<score::Result<json::Any>> calibration_data_;
    std::shared_ptr<data_model::IParameterSetCollection> parameter_data_;
    std::shared_ptr<score::config_management::config_daemon::coding::IParamSetMapping> parameter_set_mapping_;
    std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter_;
    std::unique_ptr<score::mw::diag::DTC> dtc_integrity_error_;
    std::unique_ptr<score::mw::diag::DTC> dtc_default_values_in_use_;
    bool parameter_sets_default_in_use_error_;
    bool parameter_sets_integrity_error_;
    mw::log::Logger& logger_;
};

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // SCORE_CONFIG_MANAGEMENT_CONFIG_DAEMON_CODE_PLUGINS_CALIBRATION_PARAMETER_LOADER_DETAILS_PARAMETER_LOADER_IMPL_H
