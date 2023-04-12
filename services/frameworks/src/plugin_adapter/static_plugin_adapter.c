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

#include "cred_manager.h"
#include "dev_auth_module_manager.h"
#include "device_auth_defines.h"
#include "hc_log.h"

#ifdef __CC_ARM                         /* ARM Compiler */
    #define DEV_AUTH_WEAK               __weak
#elif defined (__IAR_SYSTEMS_ICC__)     /* for IAR Compiler */
    #define DEV_AUTH_WEAK               __weak
#elif defined (__GNUC__)                /* GNU GCC Compiler */
    #define DEV_AUTH_WEAK               __attribute__((weak))
#else
    #define DEV_AUTH_WEAK
#endif

DEV_AUTH_WEAK const CredPlugin *GetExtendCredPlugin(void)
{
    return NULL;
}

DEV_AUTH_WEAK const AuthModuleBase *GetExtendAuthModulePlugin(void)
{
    return NULL;
}

void LoadExtendPlugin(void)
{
    const CredPlugin *credPlugin = GetExtendCredPlugin();
    const AuthModuleBase *authModulePlugin = GetExtendAuthModulePlugin();
    if (credPlugin == NULL || authModulePlugin == NULL) {
        LOGI("[Plugin]: no need to load plugins.");
        return;
    }
    int32_t res = AddCredPlugin(credPlugin);
    if (res != HC_SUCCESS) {
        LOGE("[Plugin]: init cred plugin fail. [Res]: %d", res);
        return;
    }
    res = AddAuthModulePlugin(authModulePlugin);
    if (res != HC_SUCCESS) {
        LOGE("[Plugin]: init auth module plugin fail. [Res]: %d", res);
        DelCredPlugin(credPlugin->pluginName);
        return;
    }
    LOGI("[Plugin]: load extend plugin success.");
}

void UnloadExtendPlugin(void)
{
    const CredPlugin *credPlugin = GetExtendCredPlugin();
    const AuthModuleBase *authModulePlugin = GetExtendAuthModulePlugin();
    if (credPlugin == NULL || authModulePlugin == NULL) {
        LOGI("[Plugin]: no need to unload plugins.");
        return;
    }
    DelAuthModulePlugin(authModulePlugin->moduleType);
    DelCredPlugin(credPlugin->pluginName);
    LOGI("[Plugin]: unload extend plugin success.");
}