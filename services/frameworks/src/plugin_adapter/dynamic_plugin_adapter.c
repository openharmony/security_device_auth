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


#include "plugin_adapter.h"

#include <stddef.h>
#include "cred_plugin_def.h"
#include "cred_manager.h"
#include "dev_auth_dynamic_load.h"
#include "dev_auth_module_manager.h"
#include "device_auth_defines.h"
#include "hc_log.h"

typedef const CredPlugin *(*GetCredPluginFunc)(void);
typedef const AuthModuleBase *(*GetAuthModulePluginFunc)(void);

#define CRED_PLUGIN_FUNC "GetExtendCredPlugin"
#define AUTH_MODULE_PLUGIN_FUNC "GetExtendAuthModulePlugin"

static void *g_handle = NULL;

static const CredPlugin *GetCredPluginFromLib(void *handle)
{
    GetCredPluginFunc getCredPluginFunc = (GetCredPluginFunc)DevAuthDlsym(handle, CRED_PLUGIN_FUNC);
    if (getCredPluginFunc == NULL) {
        LOGE("[Plugin]: get func from dynamic plugin fail.");
        return NULL;
    }
    return getCredPluginFunc();
}

static const AuthModuleBase *GetAuthModulePluginFromLib(void *handle)
{
    GetAuthModulePluginFunc getAuthModulePluginFunc =
        (GetAuthModulePluginFunc)DevAuthDlsym(handle, AUTH_MODULE_PLUGIN_FUNC);
    if (getAuthModulePluginFunc == NULL) {
        LOGE("[Plugin]: get func from dynamic plugin fail.");
        return NULL;
    }
    return getAuthModulePluginFunc();
}

static int32_t LoadDynamicPlugin(void *handle)
{
    const CredPlugin *credPlugin = GetCredPluginFromLib(handle);
    const AuthModuleBase *authModulePlugin = GetAuthModulePluginFromLib(handle);
    if (credPlugin == NULL || authModulePlugin == NULL) {
        LOGE("[Plugin]: no need to load plugins.");
        return HC_ERROR;
    }
    int32_t res = AddCredPlugin(credPlugin);
    if (res != HC_SUCCESS) {
        LOGE("[Plugin]: init cred plugin fail. [Res]: %d", res);
        return res;
    }
    res = AddAuthModulePlugin(authModulePlugin);
    if (res != HC_SUCCESS) {
        LOGE("[Plugin]: init auth module plugin fail. [Res]: %d", res);
        DelCredPlugin(credPlugin->pluginName);
        return res;
    }
    return HC_SUCCESS;
}

static void UnloadDynamicPlugin(void *handle)
{
    const CredPlugin *credPlugin = GetCredPluginFromLib(handle);
    const AuthModuleBase *authModulePlugin = GetAuthModulePluginFromLib(handle);
    if (credPlugin == NULL || authModulePlugin == NULL) {
        LOGE("[Plugin]: no need to unload plugins.");
        return;
    }
    DelAuthModulePlugin(authModulePlugin->moduleType);
    DelCredPlugin(credPlugin->pluginName);
}

void LoadExtendPlugin(void)
{
    if (g_handle != NULL) {
        LOGE("[Plugin]: The plugin has been loaded.");
        return;
    }
    g_handle = DevAuthDlopen("/system/lib/libdev_auth_extend_plugin.z.so");
    if (g_handle == NULL) {
        LOGW("[Plugin]: open dynamic plugin fail.");
        return;
    }
    if (LoadDynamicPlugin(g_handle) != HC_SUCCESS) {
        DevAuthDlclose(g_handle);
        g_handle = NULL;
        return;
    }
    LOGI("[Plugin]: load extend plugin success.");
}

void UnloadExtendPlugin(void)
{
    if (g_handle == NULL) {
        LOGE("[Plugin]: The plugin has not been loaded.");
        return;
    }
    UnloadDynamicPlugin(g_handle);
    DevAuthDlclose(g_handle);
    g_handle = NULL;
    LOGI("[Plugin]: unload extend plugin success.");
}