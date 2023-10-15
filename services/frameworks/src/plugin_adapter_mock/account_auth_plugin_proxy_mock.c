/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "account_auth_plugin_proxy.h"

#include "device_auth_defines.h"

int32_t SetAccountAuthPlugin(const CJson *inputParams, AccountAuthExtPlug *accountAuthPlugin)
{
    (void)inputParams;
    (void)accountAuthPlugin;
    return HC_ERR_NOT_SUPPORT;
}

int32_t ExcuteCredMgrCmd(int32_t osAccountId, int32_t cmdId, const CJson *in, CJson *out)
{
    (void)osAccountId;
    (void)cmdId;
    (void)in;
    (void)out;
    return HC_ERR_NOT_SUPPORT;
}

int32_t CreateAuthSession(int32_t *sessionId, const CJson *in, CJson *out)
{
    (void)sessionId;
    (void)in;
    (void)out;
    return HC_ERR_NOT_SUPPORT;
}

int32_t ProcessAuthSession(int32_t *sessionId, const CJson *in, CJson *out, int32_t *status)
{
    (void)sessionId;
    (void)in;
    (void)out;
    (void)status;
    return HC_ERR_NOT_SUPPORT;
}

int32_t DestroyAuthSession(int32_t sessionId)
{
    (void)sessionId;
    return HC_ERR_NOT_SUPPORT;
}

void DestoryAccountAuthPlugin(void)
{
}

int32_t HasAccountAuthPlugin(void)
{
    return HC_ERR_NOT_SUPPORT;
}