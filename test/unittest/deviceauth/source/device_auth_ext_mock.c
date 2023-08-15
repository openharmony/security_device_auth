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

#include "device_auth_ext.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "json_utils.h"

static ExtPluginList g_list = NULL;

int32_t InitPlugin(struct ExtPlugin *extPlugin, const cJSON *params, const struct ExtPluginCtx *context)
{
    (void)extPlugin;
    (void)params;
    (void)context;
    return HC_SUCCESS;
}

void DestroyPlugin(struct ExtPlugin *extPlugin)
{
    (void)extPlugin;
    LOGI("DestroyPlugin");
}

ExtPluginNode *CreateNode(int32_t plugType)
{
    LOGI("CreateNode");
    ExtPluginNode *node = (ExtPluginNode *)HcMalloc(sizeof(ExtPluginNode), 0);
    if (node == NULL) {
        LOGE("Failed to malloc plugin node!");
        return NULL;
    }
    node->plugin = (ExtPlugin *)HcMalloc(sizeof(ExtPlugin), 0);
    if (node->plugin == NULL) {
        LOGE("Failed to malloc plugin!");
        HcFree(node);
        return NULL;
    }
    node->plugin->pluginType = plugType;
    node->plugin->init = InitPlugin;
    node->plugin->destroy = DestroyPlugin;
    node->next = NULL;
    return node;
}

void AddPlugin(ExtPluginList *list, ExtPluginNode *node)
{
    if (*list == NULL) {
        *list = node;
    } else {
        ExtPluginNode *p = *list;
        while (p->next != NULL) {
            p = p->next;
        }
        p->next = node;
    }
}

void DestroyList(ExtPluginList list)
{
    while (list != NULL) {
        ExtPluginNode *node = list;
        list = list->next;
        HcFree(node->plugin);
        node->plugin = NULL;
        HcFree(node);
        node = NULL;
    }
}

int32_t InitExtPart(const cJSON *params, ExtPart *extPart)
{
    LOGI("InitExtPart.");
    (void)params;
    if (extPart == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    extPart->instance = (ExtPart *)HcMalloc(sizeof(ExtPart), 0);
    if (extPart->instance == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

ExtPluginList GetExtPlugins(ExtPart *extPart)
{
    LOGI("GetExtPlugins.");
    (void)extPart;
    AddPlugin(&g_list, CreateNode(EXT_PLUGIN_ACCT_AUTH));
    return g_list;
}

void DestroyExtPart(ExtPart *extPart)
{
    LOGI("DestroyExtPart.");
    if (extPart != NULL) {
        HcFree(extPart->instance);
        extPart->instance = NULL;
    }
    DestroyList(g_list);
}