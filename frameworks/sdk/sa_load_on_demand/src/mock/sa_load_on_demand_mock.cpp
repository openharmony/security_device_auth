/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sa_load_on_demand.h"
#include "common_defs.h"

int32_t AddCallbackInfoToList(const char *appId, const DeviceAuthCallback *callback,
    const DataChangeListener *dataChangeListener, CredChangeListener *credChangeListener, int32_t callbackType)
{
    (void)appId;
    (void)callback;
    (void)dataChangeListener;
    (void)credChangeListener;
    (void)callbackType;
    return HC_ERR_NOT_SUPPORT;
}

int32_t RemoveCallbackInfoFromList(const char *appId, int32_t callbackType)
{
    (void)appId;
    (void)callbackType;
    return HC_ERR_NOT_SUPPORT;
}

void SetRegCallbackFunc(RegCallbackFunc regCallbackFunc)
{
    (void)regCallbackFunc;
}

void SetRegDataChangeListenerFunc(RegDataChangeListenerFunc regDataChangeListenerFunc)
{
    (void)regDataChangeListenerFunc;
}

void SetRegCredChangeListenerFunc(RegCredChangeListenerFunc regCredChangeListenerFunc)
{
    (void)regCredChangeListenerFunc;
}

void RegisterDevAuthCallbackIfNeed(void) {}

int32_t LoadDeviceAuthSaIfNotLoad(void)
{
    return HC_ERR_NOT_SUPPORT;
}

void SubscribeDeviceAuthSa(void) {}

void UnSubscribeDeviceAuthSa(void) {}

int32_t InitLoadOnDemand(void)
{
    return HC_ERR_NOT_SUPPORT;
}

void DeInitLoadOnDemand(void) {}
