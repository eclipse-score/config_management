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

#ifndef CODE_FACTORY_FACTORY_MOCK_H
#define CODE_FACTORY_FACTORY_MOCK_H

#include "score/config_management/config_daemon/code/factory/factory.h"

#include <gmock/gmock.h>

namespace score
{
namespace config_management
{
namespace config_daemon
{

class FactoryMock final : public IFactory
{
  public:
    FactoryMock();
    ~FactoryMock();
    FactoryMock(FactoryMock&&) = delete;
    FactoryMock(const FactoryMock&) = delete;
    FactoryMock& operator=(FactoryMock&&) = delete;
    FactoryMock& operator=(const FactoryMock&) = delete;

    MOCK_METHOD(mw::service::ProvidedServiceContainer,
                CreateInternalConfigProviderService,
                (const std::shared_ptr<data_model::IParameterSetCollection>),
                (const, override));
    MOCK_METHOD(LastUpdatedParameterSetSender,
                CreateLastUpdatedParameterSetSender,
                (mw::service::ProvidedServiceContainer & services),
                (override));
    MOCK_METHOD(InitialQualifierStateSender,
                CreateInitialQualifierStateSender,
                (mw::service::ProvidedServiceContainer & services),
                (override));

    MOCK_METHOD(std::shared_ptr<data_model::IParameterSetCollection>,
                CreateParameterSetCollection,
                (),
                (const, override));

    MOCK_METHOD(std::unique_ptr<IPluginCollector>, CreatePluginCollector, (), (const, override));

    MOCK_METHOD(std::shared_ptr<fault_event_reporter::IFaultEventReporter>,
                CreateFaultEventReporter,
                (),
                (const, override));
};

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score

#endif  // CODE_FACTORY_FACTORY_MOCK_H
