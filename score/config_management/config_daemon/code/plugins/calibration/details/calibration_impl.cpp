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
#include "score/config_management/config_daemon/code/plugins/calibration/details/calibration_impl.h"

#include "score/config_management/config_daemon/code/plugins/calibration/error/error.h"

#include "score/language/safecpp/scoped_function/move_only_scoped_function.h"
#include "score/json/json_parser.h"
#include "score/mw/log/logging.h"
#include <memory>
namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{
namespace
{
constexpr std::string_view kCalibrationParametersPath = "etc/calibration_parameters.json";
}  // namespace

CalibrationImpl::CalibrationImpl(std::unique_ptr<calibration::Factory> factory) noexcept
    : IPlugin{},
      fault_event_reporter_{nullptr},
      factory_{std::move(factory)},
      logger_{mw::log::CreateLogger(std::string_view{"CalP"})},
      scope_{}
{
    logger_.LogInfo() << "Calibration::" << __func__ << " - Created";
}

Result<void> CalibrationImpl::Initialize()
{
    if (factory_ == nullptr)
    {
        logger_.LogError() << "Calibration::" << __func__ << " - factory_ is null ptr";
        return Unexpected{MakeError(CalibrationError::kNullPtrFactoryError, "factory_ is null ptr")};
    }

    calibration_proxies_ = factory_->CreateCalibrationProxies();

    parameter_set_mapping_ = factory_->CreateParamSetMapping();
    if (auto param_set_config_result = parameter_set_mapping_->LoadParameterSetConfig();
        !param_set_config_result.has_value())
    {
        logger_.LogError() << "Calibration::" << __func__
                           << "Unable to load param set configuration: " << param_set_config_result.error();
        return Unexpected{MakeError(CalibrationError::kInitializationError,
                                    "configDaemon:calibration::Calibration Failed to load parameter set config.")};
    }

    return {};
}

void CalibrationImpl::Deinitialize() noexcept {}

CalibrationImpl::ServiceTogglerHandler::ServiceTogglerHandler(
    const std::shared_ptr<ServiceToggler> calibration_service_toggler)
    : calibration_service_toggler_(calibration_service_toggler)
{
}

void CalibrationImpl::ServiceTogglerHandler::operator()(score::Result<std::unique_ptr<ISecureDebug>>& secure_debug)
{
    if (secure_debug.has_value() == true)  // LCOV_EXCL_BR_LINE (else branch can't be hit, see below.)
    {
        secure_debug.value()->SetCalibrationEnabledCallback(CalibrationEnabledHandler(calibration_service_toggler_));
        const score::Result<bool> calibration_enabled = secure_debug.value()->GetCalibrationEnabled();
        if (calibration_enabled.has_value())
        {
            calibration_service_toggler_->ToggleInterface(calibration_enabled.value());
        }
        // else - Error is logged in SecureDebug
    }
    else
    {
        // This line should never be hit because mw::service is guaranteed to return a
        // concurrency::InterruptibleFuture<std::unique_ptr<ProxySpec>> on a Get call.
        // Therefore, the score::Result will always have a value.
        mw::log::LogError() << "Continuation callback called with wrong argument"; /* LCOV_EXCL_LINE */
    }
}

CalibrationImpl::CalibrationEnabledHandler::CalibrationEnabledHandler(
    const std::shared_ptr<ServiceToggler> calibration_service_toggler)
    : calibration_service_toggler_(calibration_service_toggler)
{
}

void CalibrationImpl::CalibrationEnabledHandler::operator()(const bool enabled)
{
    calibration_service_toggler_->ToggleInterface(enabled);
}

std::int32_t CalibrationImpl::Run(
    std::shared_ptr<data_model::IParameterSetCollectionManager> parameterset_collection_manager,
    LastUpdatedParameterSetSender cbk_send_last_updated_parameter_set,
    [[maybe_unused]] InitialQualifierStateSender,
    score::cpp::stop_token stop_token,
    std::shared_ptr<fault_event_reporter::IFaultEventReporter> fault_event_reporter)
{
    if (factory_ == nullptr)
    {
        return EXIT_FAILURE;
    }

    fault_event_reporter_ = std::move(fault_event_reporter);
    parameterset_collection_ = parameterset_collection_manager->GetParameterSetCollection();
    last_updated_parameter_set_sender_ = std::move(cbk_send_last_updated_parameter_set);

    calibration_update_observer_ = factory_->CreateCalibrationUpdateObserver();
    if (calibration_update_observer_ == nullptr)
    {
        logger_.LogError() << "Calibration::" << __func__ << " - Failed to create calibration update observer.";
        return EXIT_FAILURE;
    }
    auto container = calibration_proxies_.WaitForMandatoryProxies(stop_token);

    secure_debug_proxy_data_ = factory_->CreateSecureDebugFuture(container);

    // Temporary workaround: Call LoadParameterData to determine qualifiers and set DTCs.
    // The daemon already loaded parameters via LoadParameterSetCollectionFromStorage() before
    // plugin Run() is called, so Insert calls will return kParameterAlreadyExists which is
    // handled gracefully. This ensures qualifiers and DTCs are properly set until a final
    // architecture decision is made.
    logger_.LogInfo() << "Calibration::" << __func__ << " - Start to load parameter data";
    // NOLINTBEGIN(score-banned-function): file_path for this method is "etc/calibration_parameters.json" and this file
    // is saved under '/opt/ConfigDaemon/' folder.
    // '/opt' folder is protected by qtsafefs guarantees.
    // Therefore FromFile API is safe to use in this scenario.
    // Suppress AUTOSAR C++14 A18-5-8 rule finding.
    // calibration_data is a heap-allocated unique_ptr required by the CreateParameterLoader interface.
    // coverity[autosar_cpp14_a18_5_8_violation]
    auto calibration_data =
        std::make_unique<score::Result<json::Any>>(score::json::JsonParser().FromFile(kCalibrationParametersPath));
    // NOLINTEND(score-banned-function)

    auto dtc_integrity_error = factory_->CreateClearableDtcIntegrityError();
    auto dtc_default_values_in_use = factory_->CreateClearableDtcDefaultValuesInUse();

    auto parameter_loader = factory_->CreateParameterLoader(std::move(calibration_data),
                                                            parameter_set_mapping_,
                                                            fault_event_reporter_,
                                                            std::move(dtc_integrity_error),
                                                            std::move(dtc_default_values_in_use));
    if (parameter_loader != nullptr)
    {
        if (!parameter_loader->LoadParameterData(parameterset_collection_))
        {
            logger_.LogError() << "Calibration::" << __func__ << " - Failed to load parameter data.";
        }
    }
    else
    {
        logger_.LogError() << "Calibration::" << __func__ << " - Failed to create ParameterLoader.";
    }

    decltype(last_updated_parameter_set_sender_) last_updated_parameter_set_sender{};
    std::swap(last_updated_parameter_set_sender_, last_updated_parameter_set_sender);
    auto calibration_service = factory_->CreateCalibrationService(
        parameterset_collection_, std::move(last_updated_parameter_set_sender), calibration_update_observer_);
    auto calibration_service_toggler = factory_->CreateServiceToggler(std::move(calibration_service));
    const ServiceTogglerHandler calibration_service_toggler_handler{std::move(calibration_service_toggler)};
    // LCOV_EXCL_START (tool issue)
    const auto result = secure_debug_proxy_data_.GetProxyFuture().Then(
        score::safecpp::MoveOnlyScopedFunction<void(score::Result<std::unique_ptr<ISecureDebug>>&)>{
            this->scope_, calibration_service_toggler_handler});
    // LCOV_EXCL_STOP
    if (result.has_value() == false)
    {
        const result::Error error = result.error();
        logger_.LogError() << "Calibration::" << __func__
                           << " - secure_debug_future::Then returns error: " << error.Message();
    }
    logger_.LogInfo() << "Calibration::" << __func__ << " - End";

    return EXIT_SUCCESS;
}

Result<void> CalibrationImpl::ParameterSetCollectionUpdateStart(
    data_model::IParameterSetCollection& parameter_set_collection)
{
    logger_.LogInfo() << "Calibration::" << __func__;

    if (factory_ == nullptr)
    {
        logger_.LogError() << "Calibration::" << __func__ << " - factory_ is null ptr";
        return Unexpected{MakeError(CalibrationError::kNullPtrFactoryError, "factory_ is null ptr")};
    }

    // NOLINTBEGIN(score-banned-function): file_path for this method is "etc/calibration_parameters.json" and this file
    // is saved under '/opt/ConfigDaemon/' folder.
    // '/opt' folder is protected by qtsafefs guarantees.
    // Therefore FromFile API is safe to use in this scenario.
    // Suppress AUTOSAR C++14 A18-5-8 rule finding.
    // calibration_data is a heap-allocated unique_ptr required by the CreateParameterLoader interface.
    // coverity[autosar_cpp14_a18_5_8_violation]
    auto calibration_data =
        std::make_unique<score::Result<json::Any>>(score::json::JsonParser().FromFile(kCalibrationParametersPath));
    // NOLINTEND(score-banned-function)

    auto dtc_integrity_error = factory_->CreateClearableDtcIntegrityError();
    auto dtc_default_values_in_use = factory_->CreateClearableDtcDefaultValuesInUse();

    auto parameter_loader = factory_->CreateParameterLoader(std::move(calibration_data),
                                                            parameter_set_mapping_,
                                                            fault_event_reporter_,
                                                            std::move(dtc_integrity_error),
                                                            std::move(dtc_default_values_in_use));
    if (parameter_loader == nullptr)
    {
        logger_.LogError() << "Calibration::" << __func__ << " - Failed to create ParameterLoader.";
        return Unexpected{MakeError(CalibrationError::kInitializationError,
                                    "Failed to create ParameterLoader for collection update")};
    }

    auto collection_ptr = std::shared_ptr<data_model::IParameterSetCollection>(
        &parameter_set_collection, [](data_model::IParameterSetCollection*) {});

    if (!parameter_loader->LoadParameterData(collection_ptr))
    {
        logger_.LogError() << "Calibration::" << __func__ << " - Failed to load parameter data.";
        return Unexpected{MakeError(CalibrationError::kInitializationError,
                                    "Failed to load calibration parameter data during collection update")};
    }

    return {};
}
}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
