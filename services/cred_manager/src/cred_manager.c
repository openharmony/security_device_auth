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

#include "cred_manager.h"

#include "account_related_cred_plugin.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_vector.h"
#include "hitrace_adapter.h"

DECLARE_HC_VECTOR(CredPluginVec, CredPlugin *);
IMPLEMENT_HC_VECTOR(CredPluginVec, CredPlugin *, 2)

static CredPluginVec g_credPluginVec;

int32_t ProcCred(int32_t pluginName, int32_t osAccountId, int32_t cmdId, CJson *in, CJson *out)
{
    uint32_t index;
    CredPlugin **pluginPtr;
    FOR_EACH_HC_VECTOR(g_credPluginVec, index, pluginPtr) {
        if ((*pluginPtr)->pluginName == pluginName) {
            return (*pluginPtr)->procCred(osAccountId, cmdId, in, out);
        }
    }
    LOGE("[CredMgr]: There is no matched cred plugin. [Name]: %d", pluginName);
    return HC_ERR_NOT_SUPPORT;
}

int32_t InitCredMgr(void)
{
    g_credPluginVec = CREATE_HC_VECTOR(CredPluginVec);
    CredPlugin *plugin = GetAccountRelatedCredPlugin();
    if (plugin != NULL) {
        int32_t res = plugin->init();
        if (res == HC_SUCCESS) {
            (void)g_credPluginVec.pushBackT(&g_credPluginVec, plugin);
        } else {
            LOGW("[CredMgr]: Init account related cred plugin fail. [Res]: %d", res);
        }
    }
    LOGI("[CredMgr]: Init success!");
    return HC_SUCCESS;
}

void DestroyCredMgr(void)
{
    uint32_t index;
    CredPlugin **pluginPtr;
    FOR_EACH_HC_VECTOR(g_credPluginVec, index, pluginPtr) {
        (*pluginPtr)->destroy();
    }
    DESTROY_HC_VECTOR(CredPluginVec, &g_credPluginVec);
}

int32_t AddCredPlugin(const CredPlugin *plugin)
{
    if (plugin == NULL || plugin->init == NULL ||
        plugin->destroy == NULL || plugin->procCred == NULL) {
        LOGE("The plugin is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = plugin->init();
    if (res != HC_SUCCESS) {
        LOGE("[CredMgr]: Init cred plugin fail. [Res]: %d", res);
        return HC_ERR_INIT_FAILED;
    }
    bool isNeedReplace = false;
    uint32_t index;
    CredPlugin **pluginPtr;
    FOR_EACH_HC_VECTOR(g_credPluginVec, index, pluginPtr) {
        if ((*pluginPtr)->pluginName == plugin->pluginName) {
            isNeedReplace = true;
            break;
        }
    }
    if (g_credPluginVec.pushBack(&g_credPluginVec, &plugin) == NULL) {
        LOGE("[CredMgr]: Push cred plugin to vector fail.");
        plugin->destroy();
        return HC_ERR_ALLOC_MEMORY;
    }
    if (isNeedReplace) {
        LOGI("[CredMgr]: Replace cred plugin. [Name]: %d", plugin->pluginName);
        HC_VECTOR_POPELEMENT(&g_credPluginVec, pluginPtr, index);
    } else {
        LOGI("[CredMgr]: Add new cred plugin. [Name]: %d", plugin->pluginName);
    }
    return HC_SUCCESS;
}

void DelCredPlugin(int32_t pluginName)
{
    uint32_t index;
    CredPlugin **pluginPtr;
    FOR_EACH_HC_VECTOR(g_credPluginVec, index, pluginPtr) {
        if ((*pluginPtr)->pluginName == pluginName) {
            LOGI("[CredMgr]: Delete cred plugin success. [Name]: %d", pluginName);
            (*pluginPtr)->destroy();
            HC_VECTOR_POPELEMENT(&g_credPluginVec, pluginPtr, index);
            break;
        }
    }
}
