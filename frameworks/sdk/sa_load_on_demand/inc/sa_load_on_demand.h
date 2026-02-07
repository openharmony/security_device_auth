/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef SA_LOAD_ON_DEMAND_H
#define SA_LOAD_ON_DEMAND_H

#include <stdint.h>
#include "device_auth.h"
#include "ipc_sdk_defines.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*RegCallbackFunc)(const char *appId, const DeviceAuthCallback *callback, bool needCache);
typedef int32_t (*RegDataChangeListenerFunc)(const char *appId, const DataChangeListener *listener, bool needCache);
typedef int32_t (*RegCredChangeListenerFunc)(const char *appId, CredChangeListener *listener, bool needCache);

int32_t AddCallbackInfoToList(const char *appId, const DeviceAuthCallback *callback,
    const DataChangeListener *dataChangeListener, CredChangeListener *listener, int32_t callbackType);
int32_t RemoveCallbackInfoFromList(const char *appId, int32_t callbackType);

void SetRegCallbackFunc(RegCallbackFunc regCallbackFunc);
void SetRegDataChangeListenerFunc(RegDataChangeListenerFunc regDataChangeListenerFunc);
void SetRegCredChangeListenerFunc(RegCredChangeListenerFunc regCredChangeListenerFunc);
void RegisterDevAuthCallbackIfNeed(void);

void SubscribeDeviceAuthSa(void);
void UnSubscribeDeviceAuthSa(void);

int32_t InitLoadOnDemand(void);
void DeInitLoadOnDemand(void);

#ifdef __cplusplus
}
#endif
#endif
