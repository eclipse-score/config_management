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

#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_impl.h"
#include "score/config_management/config_daemon/code/data_model/details/parameterset_collection_manager_impl.h"
#include "score/config_management/config_daemon/code/data_model/parameter_set_storage/details/parameter_set_storage_score_impl.h"
#include "score/config_management/config_daemon/code/factory/details/infrastructure_factory_impl.h"
#include "score/config_management/config_daemon/code/fault_event_reporter/details/fault_event_reporter_score_impl.h"
#include "score/config_management/config_daemon/code/json_helper/details/json_helper_impl.h"

#include "score/kvs/kvs_builder.h"
#include "score/mw/log/logging.h"

#include <memory>

namespace score
{
namespace config_management
{
namespace config_daemon
{

InfrastructureFactoryImpl::InfrastructureFactoryImpl()
    : InfrastructureFactory{}, json_helper_{std::make_shared<common::JsonHelper>()}
{
}

std::shared_ptr<data_model::IParameterSetCollectionManager>
InfrastructureFactoryImpl::CreateParameterSetCollectionManager(std::vector<std::shared_ptr<IPlugin>>& plugins) const
{
    auto kvs_result = score::kvs::KvsBuilder(score::kvs::InstanceId{0U})
                          .Defaults(score::kvs::KvsDefaults::kOptional)
                          .KvsLoad(score::kvs::KvsLoad::kOptional)
                          .WorkingDir("/persistent/trusted/ConfigDaemon")
                          .Build();
    if (!kvs_result.has_value())
    {
        mw::log::LogError() << "InfrastructureFactoryImpl::" << __func__
                            << ": Failed to open score KVS for parameter set storage";
        return nullptr;
    }
    auto storage = std::make_unique<data_model::ParameterSetStorageScoreImpl>(
        std::make_unique<score::kvs::Kvs>(std::move(kvs_result).value()));

    auto primary_collection = std::make_shared<data_model::ParameterSetCollection>();
    return std::make_shared<data_model::ParameterSetCollectionManager>(
        std::move(primary_collection), plugins, std::move(storage));
}

std::shared_ptr<fault_event_reporter::IFaultEventReporter> InfrastructureFactoryImpl::CreateFaultEventReporter() const
{
    return std::make_shared<fault_event_reporter::FaultEventReporter>();
}

}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
