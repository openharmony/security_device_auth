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

#include "account_lifecycle_plugin_proxy.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"

static AccountLifecyleExtPlug *g_accountLifeCyclePlugin = NULL;
static AccountLifecyleExtPlugCtx *g_accountPluginCtx = NULL;

static int32_t InitAccountLifecyclePluginCtx(void)
{
    g_accountPluginCtx = (AccountLifecyleExtPlugCtx *)HcMalloc(sizeof(AccountLifecyleExtPlugCtx), 0);
    if (g_accountPluginCtx == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Malloc memory failed.");
        return HC_ERROR;
    }
    const DeviceGroupManager *gmInstace = GetGmInstance();
    if(gmInstace == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Gm instance is null.");
        HcFree(g_accountPluginCtx);
        g_accountPluginCtx = NULL;
        return HC_ERR_INVALID_PARAMS;
    }
    g_accountPluginCtx->createGroup = gmInstace->createGroup;
    g_accountPluginCtx->deleteGroup = gmInstace->deleteGroup;
    g_accountPluginCtx->getGroupInfo = gmInstace->getGroupInfo;
    g_accountPluginCtx->getRegisterInfo = gmInstace->getRegisterInfo;
    g_accountPluginCtx->regCallback = gmInstace->regCallback;
    g_accountPluginCtx->unRegCallback = gmInstace->unRegCallback;
    return HC_SUCCESS;
}

int32_t SetAccountLifecyclePlugin(const CJson *inputParams, AccountLifecyleExtPlug *accountLifeCyclePlugin)
{
    g_accountLifeCyclePlugin = accountLifeCyclePlugin;
    if (g_accountLifeCyclePlugin == NULL || g_accountLifeCyclePlugin->base.init == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Input params are invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = InitAccountLifecyclePluginCtx();
    if (res != HC_SUCCESS) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Get account life ctx failed.");
        return HC_ERROR;
    }
    return g_accountLifeCyclePlugin->base.init(&g_accountLifeCyclePlugin->base,
        inputParams, (const ExtPluginCtx *)g_accountPluginCtx);
}

void DestoryAccountLifecyclePlugin(void)
{
    if (g_accountLifeCyclePlugin != NULL && g_accountLifeCyclePlugin->base.destroy != NULL) {
        g_accountLifeCyclePlugin->base.destroy(&g_accountLifeCyclePlugin->base);
        g_accountLifeCyclePlugin = NULL;
    }
    if (g_accountPluginCtx != NULL) {
        HcFree(g_accountPluginCtx);
        g_accountPluginCtx = NULL;
    }
}