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

IMPLEMENT_HC_VECTOR(EventCallbackVec, OsAccountEventCallback*, 1)

static std::shared_ptr<OHOS::DevAuth::AccountSubscriber> g_accountSubscriber = nullptr;
static OHOS::sptr<OHOS::DevAuth::SaSubscriber> g_saSubscriber = nullptr;
static EventCallbackVec g_callbackVec;
static bool g_isInitialized = false;
static bool g_isCommonEventSubscribed = false;
static OHOS::DevAuth::OsAccountEventNotifier g_accountEventNotifier;
static OHOS::DevAuth::SaEventNotifier g_saEventNotifier;

bool IsOsAccountUnlocked(int32_t osAccountId)
{
    bool isUnlocked = false;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(osAccountId, isUnlocked);
    if (res != OHOS::ERR_OK) {
        LOGE("[OsAccountAdapter]: Check account verify status failed, res: %d, accountId: %d", res, osAccountId);
        return false;
    }
    LOGI("[OsAccountAdapter]: account verified status: %d, accountId: %d", isUnlocked, osAccountId);
    return isUnlocked;
}

bool CheckOsAccountStatus(int32_t osAccountId)
{
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("[OsAccountAdapter]: Os account is not unlocked, account id: %d", osAccountId);
        return false;
    }
    if (g_isInitialized) {
        uint32_t index;
        OsAccountEventCallback **callback;
        FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
            (*callback)->loadDataIfNotLoaded(osAccountId);
        }
    }
    return true;
}

int32_t GetCurrentActiveOsAccountId(void)
{
    std::vector<int> activatedOsAccountIds;
    LOGI("[OsAccountAdapter]: QueryActiveOsAccountIds enter.");
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activatedOsAccountIds);
    LOGI("[OsAccountAdapter]: QueryActiveOsAccountIds quit. [Res]: %d", res);
    if ((res != OHOS::ERR_OK) || (activatedOsAccountIds.size() <= 0)) {
        LOGE("[OsAccountAdapter]: QueryActiveOsAccountIds fail. [Res]: %d", res);
        return INVALID_OS_ACCOUNT;
    }
    int osAccountId = activatedOsAccountIds[0];
    LOGI("[OsAccountAdapter]: Current active os accountId: %d", osAccountId);
    return osAccountId;
}

void LoadAllAccountsData(void)
{
    if (!g_isInitialized) {
        return;
    }
    std::vector<OHOS::AccountSA::OsAccountInfo> osAccountInfos;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos);
    if ((res != OHOS::ERR_OK) || (osAccountInfos.size() <= 0)) {
        LOGE("[OsAccountAdapter]: QueryAllCreatedOsAccounts failed. [Res]: %d", res);
        return;
    }
    for (OHOS::AccountSA::OsAccountInfo osAccountInfo : osAccountInfos) {
        (void)CheckOsAccountStatus(osAccountInfo.GetLocalId());
    }
}

int32_t DevAuthGetRealOsAccountLocalId(int32_t inputId)
{
    if (inputId == ANY_OS_ACCOUNT) {
        return GetCurrentActiveOsAccountId();
    } else if (inputId >= 0) {
        LOGI("[OsAccountAdapter]: Use input os account! [Id]: %d", inputId);
        return inputId;
    } else {
        LOGE("[OsAccountAdapter]: The input os account is invalid! [Id]: %d", inputId);
        return INVALID_OS_ACCOUNT;
    }
}

static void NotifyOsAccountUnlocked(int32_t osAccountId)
{
    uint32_t index;
    OsAccountEventCallback **callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        (*callback)->onOsAccountUnlocked(osAccountId);
    }
}

static void NotifyOsAccountRemoved(int32_t osAccountId)
{
    uint32_t index;
    OsAccountEventCallback **callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        (*callback)->onOsAccountRemoved(osAccountId);
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

static void NotifySystemAbilityAdded(int32_t systemAbilityId)
{
    if (systemAbilityId == OHOS::COMMON_EVENT_SERVICE_ID) {
        LOGI("[OsAccountAdapter]: common event sa added, try to subscribe common event.");
        SubscribeCommonEvent();
    } else {
        LOGE("[OsAccountAdapter]: invalid system ability!");
    }
}

static void SubscribeSystemAbility(void)
{
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
    } else {
        LOGE("[OsAccountAdapter]: subscribe common event sa failed!");
    }
}

static void UnSubscribeSystemAbility(void)
{
    OHOS::sptr<OHOS::ISystemAbilityManager> sysMgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysMgr == nullptr) {
        LOGE("[OsAccountAdapter]: system ability manager is null!");
        return;
    }
    if (sysMgr->UnSubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, g_saSubscriber) == OHOS::ERR_OK) {
        LOGI("[OsAccountAdapter]: unsubscribe common event sa succeed!");
    } else {
        LOGE("[OsAccountAdapter]: unsubscribe common event sa failed!");
    }
}

static bool IsCallbackExist(EventCallbackId callbackId)
{
    uint32_t index;
    OsAccountEventCallback **callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        if ((*callback)->callbackId == callbackId) {
            return true;
        }
    }
    return false;
}

void InitOsAccountAdapter(void)
{
    if (g_isInitialized) {
        return;
    }
    SubscribeCommonEvent();
    SubscribeSystemAbility();
    g_callbackVec = CREATE_HC_VECTOR(EventCallbackVec);
    g_isInitialized = true;
}

void DestroyOsAccountAdapter(void)
{
    if (!g_isInitialized) {
        return;
    }
    g_isInitialized = false;
    DESTROY_HC_VECTOR(EventCallbackVec, &g_callbackVec);
    UnSubscribeSystemAbility();
    UnSubscribeCommonEvent();
}

int32_t AddOsAccountEventCallback(OsAccountEventCallback *callback)
{
    if (!g_isInitialized) {
        LOGE("[OsAccountAdapter]: Not initialized!");
        return HC_ERR_INIT_FAILED;
    }
    if (callback == nullptr) {
        LOGE("[OsAccountAdapter]: Invalid input param!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (IsCallbackExist(callback->callbackId)) {
        LOGE("[OsAccountAdapter]: Callback already exist!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (g_callbackVec.pushBackT(&g_callbackVec, callback) == nullptr) {
        LOGE("[OsAccountAdapter]: Failed to add os account callback!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

OsAccountEventCallback *RemoveOsAccountEventCallback(EventCallbackId callbackId)
{
    if (!g_isInitialized) {
        return nullptr;
    }
    uint32_t index;
    OsAccountEventCallback **callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        if ((*callback)->callbackId == callbackId) {
            OsAccountEventCallback *deleteCallback;
            HC_VECTOR_POPELEMENT(&g_callbackVec, &deleteCallback, index);
            return deleteCallback;
        }
    }
    return nullptr;
}