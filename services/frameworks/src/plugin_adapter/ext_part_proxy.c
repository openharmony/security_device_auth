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

#include "ext_part_proxy.h"

#include <stddef.h>
#include "account_auth_plugin_proxy.h"
#include "account_lifecycle_plugin_proxy.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"

static ExtPart *g_extPart = NULL;

static int32_t ParsePlugins(const ExtPartProxy *pluginProxy)
{
    ExtPluginList pluginList = pluginProxy->getPluginListFunc(g_extPart);
    ExtPluginNode *current =  pluginList;
    while (current != NULL) {
        if (current->plugin == NULL) {
            current = current->next;
            continue;
        }
        switch (current->plugin->pluginType) {
            case EXT_PLUGIN_ACCT_LIFECYCLE:
                SetAccountLifecyclePlugin(NULL, (AccountLifecyleExtPlug *)(current->plugin));
                break;
            case EXT_PLUGIN_ACCT_AUTH:
                SetAccountAuthPlugin(NULL, (AccountAuthExtPlug *)(current->plugin));
                break;
            default:
                LOGW("Invalid plugin type %d", current->plugin->pluginType);
                break;
        }
        current = current->next;
    }
    return HC_SUCCESS;
}

int32_t AddExtPlugin(const ExtPartProxy *pluginProxy)
{
    if (pluginProxy == NULL || pluginProxy->initExtPartFunc == NULL || pluginProxy->getPluginListFunc == NULL ||
        pluginProxy->destroyExtPartFunc == NULL) {
        LOGE("[EXT_PLUGIN]: The plugin is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    g_extPart = (ExtPart *)HcMalloc(sizeof(ExtPart), 0);
    if (g_extPart == NULL) {
        LOGE("[EXT_PLUGIN]: Malloc memory failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HC_ERROR;
    do {
        res = pluginProxy->initExtPartFunc(NULL, g_extPart);
        if (res != HC_SUCCESS) {
            LOGE("[EXT_PLUGIN]: Init ext failed.");
            break;
        }
        res = ParsePlugins(pluginProxy);
        if (res != HC_SUCCESS) {
            LOGE("[EXT_PLUGIN]: Parse ext plugin failed.");
            break;
        }
        return HC_SUCCESS;
    } while (0);
    HcFree(g_extPart);
    g_extPart = NULL;
    return res;
}

void DestroyExt(ExtPartProxy *pluginProxy)
{
    if (pluginProxy != NULL) {
        pluginProxy->destroyExtPartFunc(g_extPart);
    }
    if (g_extPart != NULL) {
        HcFree(g_extPart);
        g_extPart = NULL;
    }
}