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

#include "saloadondemand_fuzzer.h"
#include "device_auth.h"
#include "ipc_sdk_defines.h"
#include "device_auth_defines.h"
#include "securec.h"
#include <cstddef>
#include <cstdint>
#include <string>

#include "base/security/device_auth/frameworks/sdk/sa_load_on_demand/src/sa_load_on_demand.cpp"

namespace OHOS {

static int32_t regCallbackMock(const char *appId, const DeviceAuthCallback *callback, bool needCache)
{
    (void)appId;
    (void)callback;
    (void)needCache;
    return HC_SUCCESS;
}

static int32_t regDataChangeListenerMock(const char *appId, const DataChangeListener *callback, bool needCache)
{
    (void)appId;
    (void)callback;
    (void)needCache;
    return HC_SUCCESS;
}

static int32_t regCredChangeListenerMock(const char *appId, CredChangeListener *callback, bool needCache)
{
    (void)appId;
    (void)callback;
    (void)needCache;
    return HC_SUCCESS;
}

static void SaLoadOnDemandFuzz001(void)
{
    SetRegCallbackFunc(regCallbackMock);
    SetRegDataChangeListenerFunc(regDataChangeListenerMock);
    SetRegCredChangeListenerFunc(regCredChangeListenerMock);
    RegisterDevAuthCallbackIfNeed();
}

bool FuzzDoSaLoadOnDemandFuzz(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)InitLoadOnDemand();
    (void)InitSdkIpcCallBackList();
    SubscribeDeviceAuthSa();
    SaLoadOnDemandFuzz001();
    UnSubscribeDeviceAuthSa();
    DeInitLoadOnDemand();
    DeInitSdkIpcCallBackList();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoSaLoadOnDemandFuzz(data, size);
    return 0;
}
