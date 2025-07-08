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

#include "sa_load_on_demand.h"
#include "common_defs.h"
#include "hc_log.h"
#include "hc_types.h"
#include "iservice_registry.h"
#include "hc_vector.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "parameter.h"
#include "sa_listener.h"
#include "hc_mutex.h"

using namespace std;
using namespace OHOS;

static sptr<DevAuth::SaListener> g_saListener = nullptr;
static HcMutex g_devAuthCallbackMutex;

DECLARE_HC_VECTOR(DevAuthCallbackInfoVec, DevAuthCallbackInfo)
IMPLEMENT_HC_VECTOR(DevAuthCallbackInfoVec, DevAuthCallbackInfo, 1)
static DevAuthCallbackInfoVec g_devAuthCallbackList;
static bool g_devAuthSaIsActive = false;
static bool volatile g_devAuthInitStatus = false;

static RegCallbackFunc g_regCallback;
static RegDataChangeListenerFunc g_regDataChangeListener;
static RegCredChangeListenerFunc g_regCredChangeListener;

static int32_t DoBuildDevAuthCallback(DevAuthCallbackInfo *callbackInfo, const DeviceAuthCallback *callback)
{
    DeviceAuthCallback *copyCallback = (DeviceAuthCallback *)HcMalloc(sizeof(DeviceAuthCallback), 0);
    if (copyCallback == nullptr) {
        LOGE("[SDK]: Failed to malloc callback memory.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(copyCallback, sizeof(DeviceAuthCallback), callback, sizeof(DeviceAuthCallback)) != HC_SUCCESS) {
        LOGE("[SDK]: Failed to copy callback.");
        HcFree(copyCallback);
        return HC_ERR_MEMORY_COPY;
    }
    callbackInfo->callback.deviceAuthCallback = copyCallback;
    return HC_SUCCESS;
}

static int32_t DoBuildGroupChangeListener(DevAuthCallbackInfo *callbackInfo,
    const DataChangeListener *dataChangeListener)
{
    DataChangeListener *copyListener = (DataChangeListener *)HcMalloc(sizeof(DataChangeListener), 0);
    if (copyListener == nullptr) {
        LOGE("[SDK]: Failed to malloc copyListener memory.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(copyListener, sizeof(DataChangeListener), dataChangeListener, sizeof(DataChangeListener))
        != HC_SUCCESS) {
        LOGE("[SDK]: Failed to copy dataChangeListener.");
        HcFree(copyListener);
        return HC_ERR_MEMORY_COPY;
    }
    callbackInfo->callback.dataChangeListener = copyListener;
    return HC_SUCCESS;
}

static int32_t DoBuildCredChangeListener(DevAuthCallbackInfo *callbackInfo,
    const CredChangeListener *credChangeListener)
{
    CredChangeListener *copyListener = (CredChangeListener *)HcMalloc(sizeof(CredChangeListener), 0);
    if (copyListener == nullptr) {
        LOGE("[SDK]: Failed to malloc credChangeListener memory.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(copyListener, sizeof(CredChangeListener), credChangeListener, sizeof(CredChangeListener))
        != HC_SUCCESS) {
        LOGE("[SDK]: Failed to copy copyListener.");
        HcFree(copyListener);
        return HC_ERR_MEMORY_COPY;
    }
    callbackInfo->callback.credChangeListener = copyListener;
    return HC_SUCCESS;
}

static void FreeCallbackByType(DevAuthCallbackInfo *entry)
{
    switch (entry->callbackType) {
        case DEVAUTH_CALLBACK:
            HcFree(entry->callback.deviceAuthCallback);
            entry->callback.deviceAuthCallback = nullptr;
            break;
        case GROUP_CHANGE_LISTENER:
            HcFree(entry->callback.dataChangeListener);
            entry->callback.dataChangeListener = nullptr;
            break;
        case CRED_CHANGE_LISTENER:
            HcFree(entry->callback.credChangeListener);
            entry->callback.credChangeListener = nullptr;
            break;
        default:
            LOGE("invalid callback type.");
            break;
    }
}

static int32_t CreateCallbackByType(DevAuthCallbackInfo *entry, const DeviceAuthCallback *callback,
    const DataChangeListener *dataChangeListener, CredChangeListener *listener)
{
    int32_t ret = HC_ERR_IPC_CALLBACK_TYPE;
    switch (entry->callbackType) {
        case DEVAUTH_CALLBACK:
            ret = DoBuildDevAuthCallback(entry, callback);
            break;
        case GROUP_CHANGE_LISTENER:
            ret = DoBuildGroupChangeListener(entry, dataChangeListener);
            break;
        case CRED_CHANGE_LISTENER:
            ret = DoBuildCredChangeListener(entry, listener);
            break;
        default:
            LOGE("invalid callback type.");
            break;
    }
    return ret;
}

static int32_t BuildCallbackInfo(DevAuthCallbackInfo *callbackInfo, const char *appId,
    const DeviceAuthCallback *callback, const DataChangeListener *dataChangeListener, CredChangeListener *listener)
{
    uint32_t appIdLen = HcStrlen(appId) + 1;
    char *copyAppId = (char *)HcMalloc(appIdLen, 0);
    if (copyAppId == nullptr) {
        LOGE("[SDK]: Failed to malloc appId.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (strcpy_s(copyAppId, appIdLen, appId) != HC_SUCCESS) {
        LOGE("[SDK]: Failed to copy appId.");
        HcFree(copyAppId);
        return HC_ERR_ALLOC_MEMORY;
    }
    callbackInfo->appId = copyAppId;
    int32_t ret = CreateCallbackByType(callbackInfo, callback, dataChangeListener, listener);
    if (ret != HC_SUCCESS) {
        LOGE("[SDK]: Do build callback failed.");
        HcFree(copyAppId);
    }
    return ret;
}

static void ClearCallbackInfo(DevAuthCallbackInfo *callbackInfo)
{
    HcFree(callbackInfo->appId);
    FreeCallbackByType(callbackInfo);
}

static bool UpdateCallback(DevAuthCallbackInfo *callbackInfo, const DeviceAuthCallback *callback,
    const DataChangeListener *dataChangeListener, CredChangeListener *listener, uint32_t index)
{
    DevAuthCallbackInfo tmpCallbackInfo;
    tmpCallbackInfo.callbackType = callbackInfo->callbackType;
    tmpCallbackInfo.callback = callbackInfo->callback;
    if (CreateCallbackByType(callbackInfo, callback, dataChangeListener, listener) != HC_SUCCESS) {
        LOGE("[SDK]: Update callback failed.");
        return false;
    }
    FreeCallbackByType(&tmpCallbackInfo);
    return true;
}

static bool UpdateCallbackInfoIfExist(const char *appId, const DeviceAuthCallback *callback,
    const DataChangeListener *dataChangeListener, CredChangeListener *listener, int32_t callbackType)
{
    uint32_t index;
    DevAuthCallbackInfo *entry = nullptr;
    (void)LockHcMutex(&g_devAuthCallbackMutex);
    FOR_EACH_HC_VECTOR(g_devAuthCallbackList, index, entry) {
        if (entry == nullptr || entry->appId == nullptr) {
            continue;
        }
        if (strcmp(entry->appId, appId) == 0 && entry->callbackType == callbackType) {
            LOGI("[SDK]:start to update callback, appId: %" LOG_PUB "s, callbackType: %" LOG_PUB "d",
                appId, callbackType);
            bool ret = UpdateCallback(entry, callback, dataChangeListener, listener, index);
            UnlockHcMutex(&g_devAuthCallbackMutex);
            return ret;
        }
    }
    UnlockHcMutex(&g_devAuthCallbackMutex);
    return false;
}

static void RegisterDevAuthCallback()
{
    uint32_t index;
    DevAuthCallbackInfo *callbackInfo = nullptr;
    int32_t ret = HC_SUCCESS;
    (void)LockHcMutex(&g_devAuthCallbackMutex);
    LOGI("[SDK]: cache list size: %" LOG_PUB "d", g_devAuthCallbackList.size(&g_devAuthCallbackList));
    FOR_EACH_HC_VECTOR(g_devAuthCallbackList, index, callbackInfo) {
        if (callbackInfo == nullptr || callbackInfo->appId == nullptr) {
            continue;
        }
        switch (callbackInfo->callbackType) {
            case DEVAUTH_CALLBACK:
                LOGI("regCallback.");
                ret = g_regCallback(callbackInfo->appId, callbackInfo->callback.deviceAuthCallback, false);
                break;
            case GROUP_CHANGE_LISTENER:
                LOGI("regDataChangeListener.");
                ret = g_regDataChangeListener(callbackInfo->appId, callbackInfo->callback.dataChangeListener, false);
                break;
            case CRED_CHANGE_LISTENER:
                LOGI("regCredChangeListener.");
                ret = g_regCredChangeListener(callbackInfo->appId, callbackInfo->callback.credChangeListener, false);
                break;
            default:
                LOGE("invalid callback type: %" LOG_PUB "d.", callbackInfo->callbackType);
                break;
        }
        LOGI("register result: %" LOG_PUB "d.", ret);
    }
    UnlockHcMutex(&g_devAuthCallbackMutex);
}

static void OnReceivedDevAuthAdded()
{
    LOGI("SA load, need to register cache callback.");
    RegisterDevAuthCallback();
    (void)LockHcMutex(&g_devAuthCallbackMutex);
    g_devAuthSaIsActive = true;
    UnlockHcMutex(&g_devAuthCallbackMutex);
}

static void OnReceivedDevAuthRemoved()
{
    LOGI("SA unload.");
    (void)LockHcMutex(&g_devAuthCallbackMutex);
    g_devAuthSaIsActive = false;
    UnlockHcMutex(&g_devAuthCallbackMutex);
}

int32_t AddCallbackInfoToList(const char *appId, const DeviceAuthCallback *callback,
    const DataChangeListener *dataChangeListener, CredChangeListener *listener, int32_t callbackType)
{
    if (UpdateCallbackInfoIfExist(appId, callback, dataChangeListener, listener, callbackType)) {
        LOGI("[SDK]:Callback info exist, update successfully.");
        return HC_SUCCESS;
    }
    DevAuthCallbackInfo callbackInfo;
    callbackInfo.callbackType = callbackType;
    int32_t ret = BuildCallbackInfo(&callbackInfo, appId, callback, dataChangeListener, listener);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    (void)LockHcMutex(&g_devAuthCallbackMutex);
    if (g_devAuthCallbackList.pushBack(&g_devAuthCallbackList, &callbackInfo) == nullptr) {
        LOGE("[SDK]: Failed to add callbackInfo.");
        ClearCallbackInfo(&callbackInfo);
        UnlockHcMutex(&g_devAuthCallbackMutex);
        return HC_ERR_ALLOC_MEMORY;
    }
    LOGI("[SDK]: Add callback info successfully, cache list size: %" LOG_PUB "d.",
        g_devAuthCallbackList.size(&g_devAuthCallbackList));
    UnlockHcMutex(&g_devAuthCallbackMutex);
    return HC_SUCCESS;
}

int32_t RemoveCallbackInfoFromList(const char *appId, int32_t callbackType)
{
    uint32_t index;
    DevAuthCallbackInfo *entry = nullptr;
    int32_t ret = HC_SUCCESS;
    (void)LockHcMutex(&g_devAuthCallbackMutex);
    FOR_EACH_HC_VECTOR(g_devAuthCallbackList, index, entry) {
        if (entry == nullptr || entry->appId == nullptr) {
            continue;
        }
        if (strcmp(entry->appId, appId) == 0 && entry->callbackType == callbackType) {
            LOGW("[SDK]: start to remove callbackInfo.");
            DevAuthCallbackInfo deleteCallbackInfo;
            HC_VECTOR_POPELEMENT(&g_devAuthCallbackList, &deleteCallbackInfo, index);
            ClearCallbackInfo(&deleteCallbackInfo);
            UnlockHcMutex(&g_devAuthCallbackMutex);
            return ret;
        }
    }
    UnlockHcMutex(&g_devAuthCallbackMutex);
    return ret;
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
    (void)LockHcMutex(&g_devAuthCallbackMutex);
    if (!g_devAuthSaIsActive) {
        LOGE("[SDK]: need to register callback.");
        RegisterDevAuthCallback();
    }
    UnlockHcMutex(&g_devAuthCallbackMutex);
}

int32_t LoadDeviceAuthSaIfNotLoad(void)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        LOGE("[SDK]: Get systemabilitymanager instance failed.");
        return HC_ERR_IPC_GET_SAMGR_FAILED;
    }
    auto deviceAuthSa = saMgr->CheckSystemAbility(DEVICE_AUTH_SERVICE_ID);
    if (deviceAuthSa != nullptr) {
        return HC_SUCCESS;
    }
    deviceAuthSa = saMgr->LoadSystemAbility(DEVICE_AUTH_SERVICE_ID, DEVICE_AUTH_SA_LOAD_TIME);
    if (deviceAuthSa == nullptr) {
        LOGE("[SDK]: SaMgr load device auth sa failed, reason is loading timeout probably.");
        return HC_ERR_IPC_LOAD_SA_FAILED;
    }
    return HC_SUCCESS;
}

void SubscribeDeviceAuthSa(void)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        LOGE("[SDK]: Get systemabilitymanager instance failed.");
        return;
    }

    SaStatusChangeCallback statusChangeCallback;
    statusChangeCallback.onReceivedSaAdd = OnReceivedDevAuthAdded;
    statusChangeCallback.onReceivedSaRemoved = OnReceivedDevAuthRemoved;
    if (g_saListener == nullptr) {
        g_saListener = new DevAuth::SaListener(statusChangeCallback);
    }
    if (saMgr->SubscribeSystemAbility(DEVICE_AUTH_SERVICE_ID, g_saListener) == OHOS::ERR_OK) {
        LOGI("[SDK]: Subscribe device auth sa successfully.");
    } else {
        LOGE("[SDK]: Subscribe device auth sa failed.");
    }
}

void UnSubscribeDeviceAuthSa(void)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        LOGE("[SDK]: Get systemabilitymanager instance failed.");
        return;
    }
    if (saMgr->UnSubscribeSystemAbility(DEVICE_AUTH_SERVICE_ID, g_saListener) == OHOS::ERR_OK) {
        LOGI("[SDK]: UnSubscribe device auth sa successfully.");
    } else {
        LOGE("[SDK]: UnSubscribe device auth sa failed.");
    }
}

int32_t InitLoadOnDemand(void)
{
    int32_t ret = InitHcMutex(&g_devAuthCallbackMutex, true);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    g_devAuthCallbackList = CREATE_HC_VECTOR(DevAuthCallbackInfoVec);
    g_devAuthInitStatus = true;
    return HC_SUCCESS;
}

void DeInitLoadOnDemand(void)
{
    g_devAuthInitStatus = false;
    DESTROY_HC_VECTOR(DevAuthCallbackInfoVec, &g_devAuthCallbackList);
    DestroyHcMutex(&g_devAuthCallbackMutex);
}