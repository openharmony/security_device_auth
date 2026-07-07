/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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
#include "net_observer.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "sa_subscriber.h"
#include "system_ability_definition.h"
#include "hc_mutex.h"

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
#include "os_account_subprofile_client.h"
#include "device_auth_ext.h"
#include "account_task_manager.h"
#endif

typedef struct {
    EventCallbackId callbackId;
    OsAccountCallbackFunc onOsAccountUnlocked;
    OsAccountCallbackFunc onOsAccountRemoved;
} OsAccountEventCallback;
DECLARE_HC_VECTOR(EventCallbackVec, OsAccountEventCallback)
IMPLEMENT_HC_VECTOR(EventCallbackVec, OsAccountEventCallback, 1)

static std::shared_ptr<OHOS::DevAuth::AccountSubscriber> g_accountSubscriber = nullptr;
static OHOS::sptr<OHOS::DevAuth::SaSubscriber> g_eventSaSubscriber = nullptr;
static OHOS::sptr<OHOS::DevAuth::SaSubscriber> g_netSaSubscriber = nullptr;
static EventCallbackVec g_callbackVec;
static bool g_isInitialized = false;
static bool g_isCommonEventSubscribed = false;
static bool g_isNetObserverSubscribed = false;
static bool g_isEventSaSubscribed = false;
static bool g_isNetSaSubscribed = false;
static const int32_t SYSTEM_DEFAULT_USER = 100;
static OHOS::DevAuth::OsAccountEventNotifier g_accountEventNotifier;
static OHOS::DevAuth::SaEventNotifier g_saEventNotifier;
static OHOS::sptr<NetObserver> g_observer = nullptr;
static HcMutex g_osAccountMutex = { 0 };
#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
static GroupRelationChangeCallback g_groupCallback = nullptr;
static CredRelationChangeCallback g_credCallback = nullptr;
static ProfileDeleteCallback g_deleteGroupCallback = nullptr;
static ProfileDeleteCallback g_deleteCredCallback = nullptr;
static ProfileSwitchStartCallback g_groupSwitchStartCallback = nullptr;
static ProfileSwitchedCallback g_groupSwitchedCallback = nullptr;
#endif

void NotifyOsAccountUnlocked(int32_t osAccountId)
{
    (void)LockHcMutex(&g_osAccountMutex);
    if (!g_isInitialized) {
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    uint32_t index;
    OsAccountEventCallback *callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        callback->onOsAccountUnlocked(osAccountId);
    }
    UnlockHcMutex(&g_osAccountMutex);
}

void NotifyOsAccountRemoved(int32_t osAccountId)
{
    (void)LockHcMutex(&g_osAccountMutex);
    if (!g_isInitialized) {
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    uint32_t index;
    OsAccountEventCallback *callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        callback->onOsAccountRemoved(osAccountId);
    }
    UnlockHcMutex(&g_osAccountMutex);
}

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
void NotifyGroupRelationChange(AccountSwitchBroadcastType type, int32_t osAccountId, const char *subProfileIdStr,
    const char *groupId, const char *udid)
{
    (void)LockHcMutex(&g_osAccountMutex);
    if (g_groupCallback == nullptr) {
        LOGE("[OsAccountAdapter]: callback is null!");
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    switch (type) {
        case ACCOUNT_SWITCH_BROADCAST_DEVICE_INACTIVE:
            g_groupCallback(DEVICE_RELATION_INACTIVE, osAccountId, subProfileIdStr, groupId, udid);
            break;
        case ACCOUNT_SWITCH_BROADCAST_DEVICE_ACTIVE:
            g_groupCallback(DEVICE_RELATION_ACTIVE, osAccountId, subProfileIdStr, groupId, udid);
            break;
        case ACCOUNT_SWITCH_BROADCAST_GROUP_INACTIVE:
            g_groupCallback(GROUP_RELATION_INACTIVE, osAccountId, subProfileIdStr, groupId, udid);
            break;
        case ACCOUNT_SWITCH_BROADCAST_GROUP_ACTIVE:
            g_groupCallback(GROUP_RELATION_ACTIVE, osAccountId, subProfileIdStr, groupId, udid);
            break;
        default:
            LOGE("[OsAccountAdapter]: invalid type!");
            break;
    }
    UnlockHcMutex(&g_osAccountMutex);
}

void NotifyCredRelationChange(AccountSwitchBroadcastType type, int32_t osAccountId, const char *subProfileIdStr,
    const char *credId)
{
    (void)LockHcMutex(&g_osAccountMutex);
    if (g_credCallback == nullptr) {
        LOGE("[OsAccountAdapter]: callback is null!");
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    switch (type) {
        case ACCOUNT_SWITCH_BROADCAST_CREDENTIAL_INACTIVE:
            g_credCallback(CRED_RELATION_INACTIVE, osAccountId, subProfileIdStr, credId);
            break;
        case ACCOUNT_SWITCH_BROADCAST_CREDENTIAL_ACTIVE:
            g_credCallback(CRED_RELATION_ACTIVE, osAccountId, subProfileIdStr, credId);
            break;
        default:
            LOGE("[OsAccountAdapter]: invalid type!");
            break;
    }
    UnlockHcMutex(&g_osAccountMutex);
}

static int32_t GetSubProfileIdStr(int32_t subProfileId, char *subProfileIdStr, uint32_t subProfileIdStrLen)
{
    int len = snprintf_s(subProfileIdStr, subProfileIdStrLen, subProfileIdStrLen, "%d", subProfileId);
    if (len <= 0) {
        LOGE("[OsAccountAdapter]: convert subProfileId to string failed!");
        return HC_ERROR;
    }
    return HC_SUCCESS;
}

void NotifySubProfileSwitched(int32_t osAccountId, int32_t fromSubProfileId, int32_t toSubProfileId)
{
    char fromSubProfileIdStr[SUB_PROFILE_ID_CHAR_MAX_LEN + 1];
    int32_t res = GetSubProfileIdStr(fromSubProfileId, fromSubProfileIdStr, SUB_PROFILE_ID_CHAR_MAX_LEN);
    if (res != HC_SUCCESS) {
        LOGE("[OsAccountAdapter]: failed to get fromSubProfileIdStr!");
        return;
    }
    char toSubProfileIdStr[SUB_PROFILE_ID_CHAR_MAX_LEN + 1];
    res = GetSubProfileIdStr(toSubProfileId, toSubProfileIdStr, SUB_PROFILE_ID_CHAR_MAX_LEN);
    if (res != HC_SUCCESS) {
        LOGE("[OsAccountAdapter]: failed to get toSubProfileIdStr!");
        return;
    }
    (void)LockHcMutex(&g_osAccountMutex);
    if (g_groupSwitchStartCallback != nullptr) {
        g_groupSwitchStartCallback();
    }
    UnlockHcMutex(&g_osAccountMutex);
    NotifyAccountSwitch(osAccountId, fromSubProfileIdStr, toSubProfileIdStr,
        NotifyGroupRelationChange, NotifyCredRelationChange);
    (void)LockHcMutex(&g_osAccountMutex);
    if (g_groupSwitchedCallback != nullptr) {
        g_groupSwitchedCallback(osAccountId, toSubProfileIdStr);
    }
    UnlockHcMutex(&g_osAccountMutex);
}

void NotifySubProfileDeleted(int32_t osAccountId, int32_t subProfileId)
{
    char subProfileIdStr[SUB_PROFILE_ID_CHAR_MAX_LEN + 1];
    int32_t res = GetSubProfileIdStr(subProfileId, subProfileIdStr, SUB_PROFILE_ID_CHAR_MAX_LEN);
    if (res != HC_SUCCESS) {
        LOGE("[OsAccountAdapter]: failed to get subProfileIdStr!");
        return;
    }
    (void)LockHcMutex(&g_osAccountMutex);
    if (g_deleteGroupCallback != nullptr) {
        g_deleteGroupCallback(osAccountId, subProfileIdStr);
    }
    if (g_deleteCredCallback != nullptr) {
        g_deleteCredCallback(osAccountId, subProfileIdStr);
    }
    UnlockHcMutex(&g_osAccountMutex);
}
#endif

static void SubscribeCommonEvent(void)
{
    if (g_isCommonEventSubscribed) {
        return;
    }
    if (g_accountSubscriber == nullptr) {
        g_accountEventNotifier.notifyOsAccountUnlocked = NotifyOsAccountUnlocked;
        g_accountEventNotifier.notifyOsAccountRemoved = NotifyOsAccountRemoved;
    #ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
        g_accountEventNotifier.notifySubProfileSwitched = NotifySubProfileSwitched;
        g_accountEventNotifier.notifySubProfileDeleted = NotifySubProfileDeleted;
    #endif
        OHOS::EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BLUETOOTH_HOST_STATE_UPDATE);
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    #ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_OS_ACCOUNT_SUB_PROFILE_SWITCHED);
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_OS_ACCOUNT_SUB_PROFILE_DELETED);
    #endif
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
    OHOS::sptr<OHOS::ISystemAbilityManager> sysMgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysMgr == nullptr) {
        LOGE("[OsAccountAdapter]: system ability manager is null!");
        return;
    }
    if (g_isEventSaSubscribed) {
        if (sysMgr->UnSubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, g_eventSaSubscriber) == OHOS::ERR_OK) {
            LOGI("[OsAccountAdapter]: unsubscribe common event sa succeed!");
            g_isEventSaSubscribed = false;
        } else {
            LOGE("[OsAccountAdapter]: unsubscribe common event sa failed!");
        }
    }
    if (g_isNetSaSubscribed) {
        if (sysMgr->UnSubscribeSystemAbility(OHOS::COMM_NET_CONN_MANAGER_SYS_ABILITY_ID, g_netSaSubscriber) ==
            OHOS::ERR_OK) {
            LOGI("[OsAccountAdapter]: unsubscribe net connection manager sa succeed!");
            g_isNetSaSubscribed = false;
        } else {
            LOGE("[OsAccountAdapter]: unsubscribe net connection manager sa failed!");
        }
    }
}

static void StartNetObserver(void)
{
    if (g_isNetObserverSubscribed) {
        return;
    }
    g_observer = new(std::nothrow) NetObserver();
    if (g_observer == nullptr) {
        LOGE("[OsAccountAdapter]: failed to create net observer!");
        return;
    }
    g_observer->StartObserver();
    g_isNetObserverSubscribed = true;
}

static void StopNetObserver(void)
{
    if (!g_isNetObserverSubscribed) {
        return;
    }
    g_observer->StopObserver();
    g_observer = nullptr;
    g_isNetObserverSubscribed = false;
}

static void NotifySystemAbilityAdded(int32_t systemAbilityId)
{
    if (systemAbilityId == OHOS::COMMON_EVENT_SERVICE_ID) {
        LOGI("[OsAccountAdapter]: common event sa added, try to subscribe common event.");
        SubscribeCommonEvent();
    } else if (systemAbilityId == OHOS::COMM_NET_CONN_MANAGER_SYS_ABILITY_ID) {
        LOGI("[OsAccountAdapter]: net connection manager sa added, try to subscribe net observer.");
        StartNetObserver();
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
    g_saEventNotifier.notifySystemAbilityAdded = NotifySystemAbilityAdded;
    if (!g_isEventSaSubscribed) {
        if (g_eventSaSubscriber == nullptr) {
            g_eventSaSubscriber = new OHOS::DevAuth::SaSubscriber(g_saEventNotifier);
        }
        if (sysMgr->SubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, g_eventSaSubscriber) == OHOS::ERR_OK) {
            LOGI("[OsAccountAdapter]: subscribe common event sa succeed!");
            g_isEventSaSubscribed = true;
        } else {
            LOGE("[OsAccountAdapter]: subscribe common event sa failed!");
        }
    }
    if (!g_isNetSaSubscribed) {
        if (g_netSaSubscriber == nullptr) {
            g_netSaSubscriber = new OHOS::DevAuth::SaSubscriber(g_saEventNotifier);
        }
        if (sysMgr->SubscribeSystemAbility(OHOS::COMM_NET_CONN_MANAGER_SYS_ABILITY_ID, g_netSaSubscriber) ==
            OHOS::ERR_OK) {
            LOGI("[OsAccountAdapter]: subscribe net connection manager sa succeed!");
            g_isNetSaSubscribed = true;
        } else {
            LOGE("[OsAccountAdapter]: subscribe net connection manager sa failed!");
        }
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

int32_t GetCurrentActiveOsAccountId(void)
{
    std::vector<int> activatedOsAccountIds;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activatedOsAccountIds);
    if ((res != OHOS::ERR_OK) || (activatedOsAccountIds.size() <= 0)) {
        LOGE("[OsAccountNativeFwk][QueryActiveOsAccountIds]: fail. [Res]: %" LOG_PUB "d", res);
        return INVALID_OS_ACCOUNT;
    }
    int osAccountId = activatedOsAccountIds[0];
    if (osAccountId != SYSTEM_DEFAULT_USER) {
        LOGI("[OsAccountNativeFwk][QueryActiveOsAccountIds]: Current active os accountId: %" LOG_PUB "d", osAccountId);
    }
    return osAccountId;
}

void InitOsAccountAdapter(void)
{
    if (!g_osAccountMutex.isInitialized) {
        int32_t res = InitHcMutex(&g_osAccountMutex, true);
        if (res != HC_SUCCESS) {
            LOGE("[OsAccountAdapter]: init os account mutex failed, res: %" LOG_PUB "d", res);
            return;
        }
    }
    (void)LockHcMutex(&g_osAccountMutex);
    if (g_isInitialized) {
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    g_callbackVec = CREATE_HC_VECTOR(EventCallbackVec);
    g_isInitialized = true;
    UnlockHcMutex(&g_osAccountMutex);
    SubscribeSystemAbility();
}

void DestroyOsAccountAdapter(void)
{
    (void)LockHcMutex(&g_osAccountMutex);
    if (!g_isInitialized) {
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    g_isInitialized = false;
    DESTROY_HC_VECTOR(EventCallbackVec, &g_callbackVec);
    UnlockHcMutex(&g_osAccountMutex);
    UnSubscribeSystemAbility();
    UnSubscribeCommonEvent();
    StopNetObserver();
    DestroyHcMutex(&g_osAccountMutex);
}

bool IsOsAccountUnlocked(int32_t osAccountId)
{
    bool isUnlocked = false;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(osAccountId, isUnlocked);
    if (res != OHOS::ERR_OK) {
        LOGE("[OsAccountNativeFwk][IsOsAccountVerified]: Check account verify status failed, res: %" LOG_PUB
            "d, accountId: %" LOG_PUB "d", res, osAccountId);
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
        LOGE("[OsAccountNativeFwk][QueryAllCreatedOsAccounts]: failed. [Res]: %" LOG_PUB "d", res);
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
    } else if (inputId >= SYSTEM_DEFAULT_USER) {
        if (inputId != SYSTEM_DEFAULT_USER) {
            LOGI("[OsAccountAdapter]: Use input os account! [Id]: %" LOG_PUB "d", inputId);
        }
        return inputId;
    } else {
        LOGE("[OsAccountAdapter]: The input os account is invalid! [Id]: %" LOG_PUB "d", inputId);
        return INVALID_OS_ACCOUNT;
    }
}

bool CheckIsForegroundOsAccountId(int32_t osAccountId)
{
    bool isForeground = false;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::IsOsAccountForeground(osAccountId, isForeground);
    if (res != OHOS::ERR_OK) {
        LOGE("[OsAccountAdapter]: Check whether account is foreground failed, res: \
            %" LOG_PUB "d, accountId: %" LOG_PUB "d", res, osAccountId);
        return false;
    }
    return isForeground;
}

void AddOsAccountEventCallback(EventCallbackId callbackId, OsAccountCallbackFunc unlockFunc,
    OsAccountCallbackFunc removeFunc)
{
    (void)LockHcMutex(&g_osAccountMutex);
    if (!g_isInitialized) {
        LOGE("[OsAccountAdapter]: Not initialized!");
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    if (unlockFunc == nullptr || removeFunc == nullptr) {
        LOGE("[OsAccountAdapter]: Invalid input param!");
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    if (IsCallbackExist(callbackId)) {
        LOGE("[OsAccountAdapter]: Callback already exist!");
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    OsAccountEventCallback eventCallback;
    eventCallback.callbackId = callbackId;
    eventCallback.onOsAccountUnlocked = unlockFunc;
    eventCallback.onOsAccountRemoved = removeFunc;
    if (g_callbackVec.pushBackT(&g_callbackVec, eventCallback) == nullptr) {
        LOGE("[OsAccountAdapter]: Failed to add event callback!");
    }
    UnlockHcMutex(&g_osAccountMutex);
}

void RemoveOsAccountEventCallback(EventCallbackId callbackId)
{
    (void)LockHcMutex(&g_osAccountMutex);
    if (!g_isInitialized) {
        UnlockHcMutex(&g_osAccountMutex);
        return;
    }
    uint32_t index;
    OsAccountEventCallback *callback;
    FOR_EACH_HC_VECTOR(g_callbackVec, index, callback) {
        if (callback->callbackId == callbackId) {
            OsAccountEventCallback deleteCallback;
            HC_VECTOR_POPELEMENT(&g_callbackVec, &deleteCallback, index);
            UnlockHcMutex(&g_osAccountMutex);
            return;
        }
    }
    UnlockHcMutex(&g_osAccountMutex);
}

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
int32_t GetForegroundSubProfileIdStr(int32_t osAccountId, char *subProfileIdStr, uint32_t subProfileIdStrLen)
{
    int32_t subProfileId = DEFAULT_SUB_PROFILE_ID;
    OHOS::AccountSA::OsAccountSubProfileClient &instance = OHOS::AccountSA::OsAccountSubProfileClient::GetInstance();
    OHOS::ErrCode res = instance.GetOsAccountForegroundSubProfileId(osAccountId, subProfileId);
    if (res != OHOS::ERR_OK) {
        LOGE("[OsAccountNativeFwk][GetOsAccountForegroundSubProfileId]: fail. [Res]: %" LOG_PUB "d", res);
        return HC_ERROR;
    }
    return GetSubProfileIdStr(subProfileId, subProfileIdStr, subProfileIdStrLen);
}

void SetGroupRelationChangeCallback(GroupRelationChangeCallback callback)
{
    (void)LockHcMutex(&g_osAccountMutex);
    g_groupCallback = callback;
    UnlockHcMutex(&g_osAccountMutex);
}

void SetCredRelationChangeCallback(CredRelationChangeCallback callback)
{
    (void)LockHcMutex(&g_osAccountMutex);
    g_credCallback = callback;
    UnlockHcMutex(&g_osAccountMutex);
}

void SetProfileDeleteCallbackForGroup(ProfileDeleteCallback callback)
{
    (void)LockHcMutex(&g_osAccountMutex);
    g_deleteGroupCallback = callback;
    UnlockHcMutex(&g_osAccountMutex);
}

void SetProfileDeleteCallbackForCred(ProfileDeleteCallback callback)
{
    (void)LockHcMutex(&g_osAccountMutex);
    g_deleteCredCallback = callback;
    UnlockHcMutex(&g_osAccountMutex);
}

void SetProfileSwitchStartCallbackForGroup(ProfileSwitchStartCallback callback)
{
    (void)LockHcMutex(&g_osAccountMutex);
    g_groupSwitchStartCallback = callback;
    UnlockHcMutex(&g_osAccountMutex);
}

void SetProfileSwitchedCallbackForGroup(ProfileSwitchedCallback callback)
{
    (void)LockHcMutex(&g_osAccountMutex);
    g_groupSwitchedCallback = callback;
    UnlockHcMutex(&g_osAccountMutex);
}
#endif

bool IsOsAccountSupported(void)
{
    return true;
}