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

#ifndef CODE_FACTORY_DETAILS_FACTORY_IMPL_H
#define CODE_FACTORY_DETAILS_FACTORY_IMPL_H

#include "score/config_management/config_daemon/code/factory/factory.h"
#include "score/config_management/config_daemon/code/json_helper/json_helper.h"

#include "score/hash/code/core/factory/i_hash_calculator_factory.h"

#include <score/memory.hpp>
#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class Factory final : public IFactory
{
  public:
    Factory();
    ~Factory() override = default;
    Factory(Factory&&) = delete;
    Factory(const Factory&) = delete;

    Factory& operator=(Factory&&) = delete;
    Factory& operator=(const Factory&) = delete;

    mw::service::ProvidedServiceContainer CreateInternalConfigProviderService(
        const std::shared_ptr<data_model::IParameterSetCollection> read_only_parameter_data_interface) const override;
    LastUpdatedParameterSetSender CreateLastUpdatedParameterSetSender(
        mw::service::ProvidedServiceContainer& services) override;
    InitialQualifierStateSender CreateInitialQualifierStateSender(
        mw::service::ProvidedServiceContainer& services) override;

    std::shared_ptr<data_model::IParameterSetCollection> CreateParameterSetCollection() const override;
    std::shared_ptr<fault_event_reporter::IFaultEventReporter> CreateFaultEventReporter() const override;

    std::unique_ptr<IPluginCollector> CreatePluginCollector() const override;

  private:
    std::shared_ptr<common::IJsonHelper> json_helper_;
    std::shared_ptr<score::hash::IHashCalculatorFactory> hash_calculator_factory_;
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_FACTORY_DETAILS_FACTORY_IMPL_H
