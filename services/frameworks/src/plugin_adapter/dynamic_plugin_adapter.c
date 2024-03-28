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
#include "device_auth_ext.h"
#include "ext_part_proxy.h"
#include "hc_log.h"

typedef const CredPlugin *(*GetCredPluginFunc)(void);
typedef const AuthModuleBase *(*GetAuthModulePluginFunc)(void);

#define CRED_PLUGIN_FUNC "GetExtendCredPlugin"
#define AUTH_MODULE_PLUGIN_FUNC "GetExtendAuthModulePlugin"

#define FUNC_NAME_INIT_EXT_PART "InitExtPart"
#define FUNC_NAME_EXT_PLUGIN_LIST "GetExtPlugins"
#define FUNC_NAME_DESTROY_EXT_PART "DestroyExtPart"

static void *g_handle = NULL;
static ExtPartProxy g_pluginFunc;

static const ExtPartProxy *GetPluginFuncFromLib(void *handle)
{
    do {
        g_pluginFunc.initExtPartFunc = DevAuthDlsym(handle, FUNC_NAME_INIT_EXT_PART);
        if (g_pluginFunc.initExtPartFunc == NULL) {
            LOGE("[Plugin]: Get init func from dynamic plugin fail.");
            break;
        }
        g_pluginFunc.getPluginListFunc = DevAuthDlsym(handle, FUNC_NAME_EXT_PLUGIN_LIST);
        if (g_pluginFunc.getPluginListFunc == NULL) {
            LOGE("[Plugin]: Get plug list func from dynamic plugin fail.");
            break;
        }
        g_pluginFunc.destroyExtPartFunc = DevAuthDlsym(handle, FUNC_NAME_DESTROY_EXT_PART);
        if (g_pluginFunc.destroyExtPartFunc == NULL) {
            LOGE("[Plugin]: Get destroy func from dynamic plugin fail.");
            break;
        }
        return &g_pluginFunc;
    } while (0);
    return NULL;
}

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
    int32_t res = HC_SUCCESS;
    if (credPlugin != NULL) {
        res = AddCredPlugin(credPlugin);
        if (res != HC_SUCCESS) {
            LOGE("[Plugin]: init cred plugin fail. [Res]: %d", res);
            return res;
        }
    }
    const AuthModuleBase *authModulePlugin = GetAuthModulePluginFromLib(handle);
    if (authModulePlugin != NULL) {
        res = AddAuthModulePlugin(authModulePlugin);
        if (res != HC_SUCCESS) {
            LOGE("[Plugin]: init auth module plugin fail. [Res]: %d", res);
            return res;
        }
    }
    const ExtPartProxy *pluginFunc = GetPluginFuncFromLib(handle);
    if (pluginFunc != NULL) {
        res = AddExtPlugin(pluginFunc);
        if (res != HC_SUCCESS) {
            LOGE("[Plugin]: init ext plugin fail. [Res]: %d", res);
            return res;
        }
    }
    return HC_SUCCESS;
}

static void UnloadDynamicPlugin(void *handle)
{
    const CredPlugin *credPlugin = GetCredPluginFromLib(handle);
    const AuthModuleBase *authModulePlugin = GetAuthModulePluginFromLib(handle);
    if (credPlugin != NULL) {
        DelCredPlugin(credPlugin->pluginName);
    }
    if (authModulePlugin != NULL) {
        DelAuthModulePlugin(authModulePlugin->moduleType);
    }
}

void LoadExtendPlugin(void)
{
    if (g_handle != NULL) {
        LOGE("[Plugin]: The plugin has been loaded.");
        return;
    }
    do {
        g_handle = DevAuthDlopen("/system/lib64/libdevice_auth_ext.z.so");
        if (g_handle != NULL) {
            LOGI("[Plugin]: Open lib64 dynamic plugin success.");
            break;
        }
        g_handle = DevAuthDlopen("/system/lib/libdevice_auth_ext.z.so");
    } while (0);
    if (g_handle == NULL) {
        LOGI("[Plugin]: There are no plugin that need to be loaded.");
        return;
    }
    LOGI("[Plugin]: Open lib32 dynamic plugin success.");
    if (LoadDynamicPlugin(g_handle) != HC_SUCCESS) {
        DevAuthDlclose(g_handle);
        g_handle = NULL;
    }
}

void UnloadExtendPlugin(void)
{
    if (g_handle == NULL) {
        LOGE("[Plugin]: The plugin has not been loaded.");
        return;
    }
    DestroyExt(&g_pluginFunc);
    UnloadDynamicPlugin(g_handle);
    DevAuthDlclose(g_handle);
    g_handle = NULL;
    LOGI("[Plugin]: unload extend plugin success.");
}