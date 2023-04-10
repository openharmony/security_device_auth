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

static const CredPlugin *GetExtendCredPlugin(void)
{
    return NULL;
}

static const AuthModuleBase *GetExtendAuthModulePlugin(void)
{
    return NULL;
}

void LoadExtendPlugin(void)
{
    int32_t res = AddCredPlugin(GetExtendCredPlugin());
    if (res != HC_SUCCESS) {
        LOGE("[Plugin]: init plugin fail. [Res]: %d", res);
        return;
    }
    res = AddAuthModulePlugin(GetExtendAuthModulePlugin());
    if (res != HC_SUCCESS) {
        LOGE("[Plugin]: init plugin fail. [Res]: %d", res);
        DelCredPlugin(GetExtendCredPlugin()->pluginName);
        return;
    }
    LOGI("[Plugin]: load extend plugin success.");
}

void UnloadExtendPlugin(void)
{
    DelAuthModulePlugin(authModulePlugin()->moduleType);
    DelCredPlugin(credPlugin()->pluginName);
    LOGI("[Plugin]: unload extend plugin success.");
}