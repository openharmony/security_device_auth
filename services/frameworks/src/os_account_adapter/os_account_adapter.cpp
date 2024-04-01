/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "os_account_adapter.h"

#include <vector>
#include "account_subscriber.h"
#include "common_defs.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "device_auth.h"
#include "hc_log.h"
#include "iservice_registry.h"
#include "matching_skills.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "sa_subscriber.h"
#include "system_ability_definition.h"

typedef struct {
    EventCallbackId callbackId;
    OsAccountCallbackFunc onOsAccountUnlocked;
    OsAccountCallbackFunc onOsAccountRemoved;
} OsAccountEventCallback;
DECLARE_HC_VECTOR(EventCallbackVec, OsAccountEventCallback)
IMPLEMENT_HC_VECTOR(EventCallbackVec, OsAccountEventCallback, 1)

static std::shared_ptr<OHOS::DevAuth::AccountSubscriber> g_accountSubscriber = nullptr;
static OHOS::sptr<OHOS::DevAuth::SaSubscriber> g_saSubscriber = nullptr;
static EventCallbackVec g_callbackVec;
static bool g_isInitialized = false;
static bool g_isCommonEventSubscribed = false;
static bool g_isSaSubscribed = false;
static const int32_t SYSTEM_DEFAULT_USER = 100;
static OHOS::DevAuth::OsAccountEventNotifier g_accountEventNotifier;
static OHOS::DevAuth::SaEventNotifier g_saEventNotifier;

static void NotifyOsAccountUnlocked(int32_t osAccountId)
{
    if (!g_isInitialized) {
        return;
    }
    uint32_t index;
    OsAccountEventCallback *callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        callback->onOsAccountUnlocked(osAccountId);
    }
}

static void NotifyOsAccountRemoved(int32_t osAccountId)
{
    if (!g_isInitialized) {
        return;
    }
    uint32_t index;
    OsAccountEventCallback *callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        callback->onOsAccountRemoved(osAccountId);
    }
}

static void SubscribeCommonEvent(void)
{
    if (g_isCommonEventSubscribed) {
        return;
    }
    if (g_accountSubscriber == nullptr) {
        g_accountEventNotifier.notifyOsAccountUnlocked = NotifyOsAccountUnlocked;
        g_accountEventNotifier.notifyOsAccountRemoved = NotifyOsAccountRemoved;
        OHOS::EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
        OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        g_accountSubscriber = std::make_shared<OHOS::DevAuth::AccountSubscriber>(subscribeInfo, g_accountEventNotifier);
    }
    if (OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(g_accountSubscriber)) {
        LOGI("[OsAccountAdapter]: subscribe common event succeed!");
        g_isCommonEventSubscribed = true;
    } else {
        LOGE("[OsAccountAdapter]: subscribe common event failed!");
    }
}

static void UnSubscribeCommonEvent(void)
{
    if (!g_isCommonEventSubscribed) {
        return;
    }
    if (OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(g_accountSubscriber)) {
        g_isCommonEventSubscribed = false;
        LOGI("[OsAccountAdapter]: unsubscribe common event succeed!");
    } else {
        LOGE("[OsAccountAdapter]: unsubscribe common event failed!");
    }
}

static void UnSubscribeSystemAbility(void)
{
    if (!g_isSaSubscribed) {
        return;
    }
    OHOS::sptr<OHOS::ISystemAbilityManager> sysMgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysMgr == nullptr) {
        LOGE("[OsAccountAdapter]: system ability manager is null!");
        return;
    }
    if (sysMgr->UnSubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, g_saSubscriber) == OHOS::ERR_OK) {
        LOGI("[OsAccountAdapter]: unsubscribe common event sa succeed!");
        g_isSaSubscribed = false;
    } else {
        LOGE("[OsAccountAdapter]: unsubscribe common event sa failed!");
    }
}

static void NotifySystemAbilityAdded(int32_t systemAbilityId)
{
    if (systemAbilityId == OHOS::COMMON_EVENT_SERVICE_ID) {
        LOGI("[OsAccountAdapter]: common event sa added, try to subscribe common event.");
        SubscribeCommonEvent();
        if (g_isCommonEventSubscribed) {
            UnSubscribeSystemAbility();
        }
    } else {
        LOGE("[OsAccountAdapter]: invalid system ability!");
    }
}

static void SubscribeSystemAbility(void)
{
    if (g_isSaSubscribed) {
        return;
    }
    OHOS::sptr<OHOS::ISystemAbilityManager> sysMgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysMgr == nullptr) {
        LOGE("[OsAccountAdapter]: system ability manager is null!");
        return;
    }
    if (g_saSubscriber == nullptr) {
        g_saEventNotifier.notifySystemAbilityAdded = NotifySystemAbilityAdded;
        g_saSubscriber = new OHOS::DevAuth::SaSubscriber(g_saEventNotifier);
    }
    if (sysMgr->SubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, g_saSubscriber) == OHOS::ERR_OK) {
        LOGI("[OsAccountAdapter]: subscribe common event sa succeed!");
        g_isSaSubscribed = true;
    } else {
        LOGE("[OsAccountAdapter]: subscribe common event sa failed!");
    }
}

static bool IsCallbackExist(EventCallbackId callbackId)
{
    uint32_t index;
    OsAccountEventCallback *callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        if (callback->callbackId == callbackId) {
            return true;
        }
    }
    return false;
}

static int32_t GetCurrentActiveOsAccountId(void)
{
    std::vector<int> activatedOsAccountIds;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activatedOsAccountIds);
    if ((res != OHOS::ERR_OK) || (activatedOsAccountIds.size() <= 0)) {
        LOGE("[OsAccountAdapter]: QueryActiveOsAccountIds fail. [Res]: %d", res);
        return INVALID_OS_ACCOUNT;
    }
    int osAccountId = activatedOsAccountIds[0];
    if (osAccountId != SYSTEM_DEFAULT_USER) {
        LOGI("[OsAccountAdapter]: Current active os accountId: %d", osAccountId);
    }
    return osAccountId;
}

void InitOsAccountAdapter(void)
{
    if (g_isInitialized) {
        return;
    }
    g_callbackVec = CREATE_HC_VECTOR(EventCallbackVec);
    SubscribeSystemAbility();
    g_isInitialized = true;
}

void DestroyOsAccountAdapter(void)
{
    if (!g_isInitialized) {
        return;
    }
    g_isInitialized = false;
    UnSubscribeSystemAbility();
    UnSubscribeCommonEvent();
    DESTROY_HC_VECTOR(EventCallbackVec, &g_callbackVec);
}

bool IsOsAccountUnlocked(int32_t osAccountId)
{
    bool isUnlocked = false;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(osAccountId, isUnlocked);
    if (res != OHOS::ERR_OK) {
        LOGE("[OsAccountAdapter]: Check account verify status failed, res: %d, accountId: %d", res, osAccountId);
        return false;
    }
    return isUnlocked;
}

int32_t GetAllOsAccountIds(int32_t **osAccountIds, uint32_t *size)
{
    if (osAccountIds == nullptr || size == nullptr) {
        LOGE("[OsAccountAdapter]: invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    std::vector<OHOS::AccountSA::OsAccountInfo> osAccountInfos;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos);
    uint32_t accountSize = osAccountInfos.size();
    if ((res != OHOS::ERR_OK) || (accountSize <= 0)) {
        LOGE("[OsAccountAdapter]: QueryAllCreatedOsAccounts failed. [Res]: %d", res);
        return HC_ERROR;
    }
    *osAccountIds = (int32_t *)HcMalloc(accountSize * sizeof(int32_t), 0);
    if (*osAccountIds == nullptr) {
        LOGE("[OsAccountAdapter]: Failed to alloc memory for osAccountIds!");
        return HC_ERR_ALLOC_MEMORY;
    }
    for (uint32_t index = 0; index < accountSize; index++) {
        (*osAccountIds)[index] = osAccountInfos[index].GetLocalId();
    }
    *size = accountSize;
    return HC_SUCCESS;
}

int32_t DevAuthGetRealOsAccountLocalId(int32_t inputId)
{
    if (inputId == ANY_OS_ACCOUNT) {
        return GetCurrentActiveOsAccountId();
    } else if (inputId >= 0) {
        if (inputId != SYSTEM_DEFAULT_USER) {
            LOGI("[OsAccountAdapter]: Use input os account! [Id]: %d", inputId);
        }
        return inputId;
    } else {
        LOGE("[OsAccountAdapter]: The input os account is invalid! [Id]: %d", inputId);
        return INVALID_OS_ACCOUNT;
    }
}

void AddOsAccountEventCallback(EventCallbackId callbackId, OsAccountCallbackFunc unlockFunc,
    OsAccountCallbackFunc removeFunc)
{
    if (!g_isInitialized) {
        LOGE("[OsAccountAdapter]: Not initialized!");
        return;
    }
    if (unlockFunc == nullptr || removeFunc == nullptr) {
        LOGE("[OsAccountAdapter]: Invalid input param!");
        return;
    }
    if (IsCallbackExist(callbackId)) {
        LOGE("[OsAccountAdapter]: Callback already exist!");
        return;
    }
    OsAccountEventCallback eventCallback;
    eventCallback.callbackId = callbackId;
    eventCallback.onOsAccountUnlocked = unlockFunc;
    eventCallback.onOsAccountRemoved = removeFunc;
    if (g_callbackVec.pushBackT(&g_callbackVec, eventCallback) == nullptr) {
        LOGE("[OsAccountAdapter]: Failed to add event callback!");
    }
}

void RemoveOsAccountEventCallback(EventCallbackId callbackId)
{
    if (!g_isInitialized) {
        return;
    }
    uint32_t index;
    OsAccountEventCallback *callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        if (callback->callbackId == callbackId) {
            OsAccountEventCallback deleteCallback;
            HC_VECTOR_POPELEMENT(&g_callbackVec, &deleteCallback, index);
            return;
        }
    }
}

bool IsOsAccountSupported(void)
{
    return true;
}