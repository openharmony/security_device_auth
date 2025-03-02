/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "cred_session_util.h"

#include "hc_log.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_types.h"
#include "json_utils.h"
#include "identity_service_defines.h"

int32_t BuildClientCredContext(int32_t osAccountId, int64_t requestId, CJson *context, const char **returnAppId)
{
    (void)osAccountId;
    (void)requestId;
    (void)context;
    (void)returnAppId;
    return IS_ERR_NOT_SUPPORT;
}

int32_t BuildServerCredContext(int64_t requestId, CJson *context, char **returnPeerUdid, const char **returnAppId)
{
    (void)requestId;
    (void)context;
    (void)returnPeerUdid;
    (void)returnAppId;
    return IS_ERR_NOT_SUPPORT;
}
