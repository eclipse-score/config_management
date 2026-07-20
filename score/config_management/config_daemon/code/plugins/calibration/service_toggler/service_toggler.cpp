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
#include "score/config_management/config_daemon/code/plugins/calibration/service_toggler/service_toggler.h"

namespace score
{
namespace config_management
{
namespace config_daemon
{
namespace calibration
{

ServiceToggler::ServiceToggler() noexcept = default;
/* KW_SUPPRESS_START:AUTOSAR.STYLE.SINGLE_STMT_PER_LINE: It is a single statement, false positive. */
/* KW_SUPPRESS_START:MISRA.OBJ.TYPE.IDENT: False positive due to outside class definition of destructor */
ServiceToggler::~ServiceToggler() noexcept = default;
/* KW_SUPPRESS_END:MISRA.OBJ.TYPE.IDENT */
/* KW_SUPRRESS_END:AUTOSAR.STYLE.SINGLE_STMT_PER_LINE */

}  // namespace calibration
}  // namespace config_daemon
}  // namespace config_management
}  // namespace score
