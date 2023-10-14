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
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_types.h"

static AccountAuthExtPlug *g_accountAuthPlugin = NULL;
static AccountAuthExtPlugCtx *g_accountAuthPlugCtx = NULL;

static int32_t InitAccountAuthPluginCtx(void)
{
    g_accountAuthPlugCtx = (AccountAuthExtPlugCtx *)HcMalloc(sizeof(AccountAuthExtPlugCtx), 0);
    if (g_accountAuthPlugCtx == NULL) {
        LOGE("[ACCOUNT_AUTH_PLUGIN]: Malloc memory failed.");
        return HC_ERR_INVALID_PARAMS;
    }
    g_accountAuthPlugCtx->getStoragePath = GetAccountStoragePath;
    return HC_SUCCESS;
}

int32_t SetAccountAuthPlugin(const CJson *inputParams, AccountAuthExtPlug *accountAuthPlugin)
{
    g_accountAuthPlugin = accountAuthPlugin;
    if (g_accountAuthPlugin == NULL || g_accountAuthPlugin->createSession == NULL ||
        g_accountAuthPlugin->excuteCredMgrCmd == NULL || g_accountAuthPlugin->processSession == NULL ||
        g_accountAuthPlugin->destroySession == NULL) {
        LOGE("[ACCOUNT_AUTH_PLUGIN]: SetAccountAuthPlugin:Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = InitAccountAuthPluginCtx();
    if (res != HC_SUCCESS) {
        LOGE("[ACCOUNT_AUTH_PLUGIN]: Init account auth ctx failed.");
        return res;
    }
    return g_accountAuthPlugin->base.init(&g_accountAuthPlugin->base,
        inputParams, (const ExtPluginCtx *)g_accountAuthPlugCtx);
}

int32_t ExcuteCredMgrCmd(int32_t osAccountId, int32_t cmdId, const CJson *in, CJson *out)
{
    if (g_accountAuthPlugin == NULL || g_accountAuthPlugin->excuteCredMgrCmd == NULL) {
        LOGE("[ACCOUNT_AUTH_PLUGIN]: excuteCredMgrCmd: Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    return g_accountAuthPlugin->excuteCredMgrCmd(osAccountId, cmdId, in, out);
}

int32_t CreateAuthSession(int32_t *sessionId, const CJson *in, CJson *out)
{
    if (g_accountAuthPlugin == NULL || g_accountAuthPlugin->createSession == NULL) {
        LOGE("[ACCOUNT_AUTH_PLUGIN]: createSession: Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    return g_accountAuthPlugin->createSession(sessionId, in, out);
}

int32_t ProcessAuthSession(int32_t *sessionId, const CJson *in, CJson *out, int32_t *status)
{
    if (g_accountAuthPlugin == NULL || g_accountAuthPlugin->processSession == NULL) {
        LOGE("[ACCOUNT_AUTH_PLUGIN]: processSession: Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    return g_accountAuthPlugin->processSession(sessionId, in, out, status);
}

int32_t DestroyAuthSession(int32_t sessionId)
{
    if (g_accountAuthPlugin == NULL || g_accountAuthPlugin->destroySession == NULL) {
        LOGE("[ACCOUNT_AUTH_PLUGIN]: destroySession: Input params is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    return g_accountAuthPlugin->destroySession(sessionId);
}

void DestoryAccountAuthPlugin(void)
{
    if (g_accountAuthPlugin != NULL && g_accountAuthPlugin->base.destroy != NULL) {
        g_accountAuthPlugin->base.destroy(&g_accountAuthPlugin->base);
        g_accountAuthPlugin = NULL;
    }
    if (g_accountAuthPlugCtx != NULL) {
        HcFree(g_accountAuthPlugCtx);
        g_accountAuthPlugCtx = NULL;
    }
}

int32_t HasAccountAuthPlugin(void)
{
    if (g_accountAuthPlugin == NULL || g_accountAuthPlugin->excuteCredMgrCmd == NULL) {
        LOGI("[ACCOUNT_AUTH_PLUGIN]: processSession: plugin is invalid.");
        return HC_ERR_NOT_SUPPORT;
    }
    return HC_SUCCESS;
}