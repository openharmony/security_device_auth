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

#include <mutex>
#include "sa_load_on_demand.h"
#include "common_defs.h"
#include "hc_log.h"
#include "hc_types.h"
#include "iservice_registry.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "parameter.h"
#include "sa_listener.h"
#include "string_util.h"
#include "ipc_adapt.h"

static OHOS::sptr<OHOS::DevAuth::SaListener> g_saListener = nullptr;
static std::recursive_mutex g_devAuthCallbackMutex;

static bool g_devAuthSaIsActive = false;
static bool volatile g_devAuthInitStatus = false;

static RegCallbackFunc g_regCallback;
static RegDataChangeListenerFunc g_regDataChangeListener;
static RegCredChangeListenerFunc g_regCredChangeListener;

static void RegisterDevAuthCallback()
{
    RegisterSdkCallBack(g_regCallback, g_regDataChangeListener, g_regCredChangeListener);
}

static void OnReceivedDevAuthAdded()
{
    LOGI("SA load, need to register cache callback.");
    RegisterDevAuthCallback();
    std::lock_guard<std::recursive_mutex> autoLock(g_devAuthCallbackMutex);
    g_devAuthSaIsActive = true;
}

static void OnReceivedDevAuthRemoved()
{
    LOGI("SA unload.");
    std::lock_guard<std::recursive_mutex> autoLock(g_devAuthCallbackMutex);
    g_devAuthSaIsActive = false;
}

void SetRegCallbackFunc(RegCallbackFunc regCallbackFunc)
{
    g_regCallback = regCallbackFunc;
}

void SetRegDataChangeListenerFunc(RegDataChangeListenerFunc regDataChangeListenerFunc)
{
    g_regDataChangeListener = regDataChangeListenerFunc;
}

void SetRegCredChangeListenerFunc(RegCredChangeListenerFunc regCredChangeListenerFunc)
{
    g_regCredChangeListener = regCredChangeListenerFunc;
}

void RegisterDevAuthCallbackIfNeed(void)
{
    if (g_devAuthInitStatus == false) {
        LOGE("device auth not init.");
        return;
    }
    std::lock_guard<std::recursive_mutex> autoLock(g_devAuthCallbackMutex);
    if (!g_devAuthSaIsActive) {
        LOGE("[SDK]: need to register callback.");
        RegisterDevAuthCallback();
    }
}

void SubscribeDeviceAuthSa(void)
{
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        LOGE("[SDK]: Get systemabilitymanager instance failed.");
        return;
    }

    SaStatusChangeCallback statusChangeCallback;
    statusChangeCallback.onReceivedSaAdd = OnReceivedDevAuthAdded;
    statusChangeCallback.onReceivedSaRemoved = OnReceivedDevAuthRemoved;
    if (g_saListener == nullptr) {
        g_saListener = new(std::nothrow) OHOS::DevAuth::SaListener(statusChangeCallback);
        if (g_saListener == nullptr) {
            LOGE("[SDK]: alloc saListener failed.");
            return;
        }
    }
    if (saMgr->SubscribeSystemAbility(OHOS::DEVICE_AUTH_SERVICE_ID, g_saListener) == OHOS::ERR_OK) {
        LOGI("[SDK]: Subscribe device auth sa successfully.");
    } else {
        LOGE("[SDK]: Subscribe device auth sa failed.");
    }
}

void UnSubscribeDeviceAuthSa(void)
{
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        LOGE("[SDK]: Get systemabilitymanager instance failed.");
        return;
    }
    if (g_saListener == nullptr) {
        LOGE("[SDK]: g_saListener is nullptr.");
        return;
    }
    if (saMgr->UnSubscribeSystemAbility(OHOS::DEVICE_AUTH_SERVICE_ID, g_saListener) == OHOS::ERR_OK) {
        LOGI("[SDK]: UnSubscribe device auth sa successfully.");
    } else {
        LOGE("[SDK]: UnSubscribe device auth sa failed.");
    }
}

int32_t InitLoadOnDemand(void)
{
    g_devAuthInitStatus = true;
    return HC_SUCCESS;
}

void DeInitLoadOnDemand(void)
{
    g_devAuthInitStatus = false;
}