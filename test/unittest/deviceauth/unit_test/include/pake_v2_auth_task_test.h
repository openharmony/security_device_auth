/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PAKE_V2_AUTH_TASK_TEST_H
#define PAKE_V2_AUTH_TASK_TEST_H
#ifdef __cpluscplus
extern "C"
{
#endif

#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info_mock.h"
#include "json_utils.h"
#include "protocol_task_main_mock.h"
#include "securec.h"
#include "json_utils.h"
#include "string_util.h"
#include "account_task_main.h"
#include "pake_v2_auth_client_task.h"
#include "pake_v2_auth_server_task.h"
#include "pake_v2_auth_task_common.h"
#include "account_version_util.h"
#include "asy_token_manager.h"
#include "pake_defs.h"

#ifdef __cpluscplus
}
#endif
#endif // PAKE_V2_AUTH_TASK_TEST_H