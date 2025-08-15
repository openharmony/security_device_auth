/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#include "broadcast_manager.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "securec.h"
#include "string_util.h"

typedef struct {
    char *appId;
    DataChangeListener *listener;
} ListenerEntry;

DECLARE_HC_VECTOR(ListenerEntryVec, ListenerEntry);
IMPLEMENT_HC_VECTOR(ListenerEntryVec, ListenerEntry, 1);
static ListenerEntryVec g_listenerEntryVec;
static HcMutex *g_broadcastMutex = NULL;

static void PostOnGroupCreated(const char *messageStr)
{
    if (messageStr == NULL) {
        LOGE("The messageStr is NULL!");
        return;
    }
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (entry->listener->onGroupCreated != NULL) {
            LOGI("[Broadcaster]: PostOnGroupCreated! [AppId]: %" LOG_PUB "s", entry->appId);
            entry->listener->onGroupCreated(messageStr);
        }
    }
    UnlockHcMutex(g_broadcastMutex);
}

static void PostOnGroupDeleted(const char *messageStr)
{
    if (messageStr == NULL) {
        LOGE("The messageStr is NULL!");
        return;
    }
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (entry->listener->onGroupDeleted != NULL) {
            LOGI("[Broadcaster]: PostOnGroupDeleted! [AppId]: %" LOG_PUB "s", entry->appId);
            entry->listener->onGroupDeleted(messageStr);
        }
    }
    UnlockHcMutex(g_broadcastMutex);
}

static void PostOnDeviceBound(const char *peerUdid, const char *messageStr)
{
    if ((peerUdid == NULL) || (messageStr == NULL)) {
        LOGE("The peerUdid or messageStr is NULL!");
        return;
    }
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (entry->listener->onDeviceBound != NULL) {
            LOGI("[Broadcaster]: PostOnDeviceBound! [AppId]: %" LOG_PUB "s", entry->appId);
            entry->listener->onDeviceBound(peerUdid, messageStr);
        }
    }
    UnlockHcMutex(g_broadcastMutex);
}

static void PostOnDeviceUnBound(const char *peerUdid, const char *messageStr)
{
    if ((peerUdid == NULL) || (messageStr == NULL)) {
        LOGE("The peerUdid or messageStr is NULL!");
        return;
    }
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (entry->listener->onDeviceUnBound != NULL) {
            LOGI("[Broadcaster]: PostOnDeviceUnBound! [AppId]: %" LOG_PUB "s", entry->appId);
            entry->listener->onDeviceUnBound(peerUdid, messageStr);
        }
    }
    UnlockHcMutex(g_broadcastMutex);
}

static void PostOnDeviceNotTrusted(const char *peerUdid)
{
    if (peerUdid == NULL) {
        LOGE("The peerUdid is NULL!");
        return;
    }
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (entry->listener->onDeviceNotTrusted != NULL) {
            LOGI("[Broadcaster]: PostOnDeviceNotTrusted! [AppId]: %" LOG_PUB "s", entry->appId);
            entry->listener->onDeviceNotTrusted(peerUdid);
        }
    }
    UnlockHcMutex(g_broadcastMutex);
}

static void PostOnLastGroupDeleted(const char *peerUdid, int groupType)
{
    if (peerUdid == NULL) {
        LOGE("The peerUdid is NULL!");
        return;
    }
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (entry->listener->onLastGroupDeleted != NULL) {
            LOGI("[Broadcaster]: PostOnLastGroupDeleted! [AppId]: %" LOG_PUB "s, [GroupType]: %" LOG_PUB "d",
                entry->appId, groupType);
            entry->listener->onLastGroupDeleted(peerUdid, groupType);
        }
    }
    UnlockHcMutex(g_broadcastMutex);
}

static void PostOnTrustedDeviceNumChanged(int curTrustedDeviceNum)
{
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (entry->listener->onTrustedDeviceNumChanged != NULL) {
            LOGI("[Broadcaster]: PostOnTrustedDeviceNumChanged! [AppId]: %" LOG_PUB "s", entry->appId);
            entry->listener->onTrustedDeviceNumChanged(curTrustedDeviceNum);
        }
    }
    UnlockHcMutex(g_broadcastMutex);
}

static int32_t UpdateListenerIfExist(const char *appId, const DataChangeListener *listener)
{
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (IsStrEqual(entry->appId, appId)) {
            if (memcpy_s(entry->listener, sizeof(DataChangeListener),
                listener, sizeof(DataChangeListener)) != HC_SUCCESS) {
                UnlockHcMutex(g_broadcastMutex);
                LOGE("Failed to copy listener!");
                return HC_ERR_MEMORY_COPY;
            }
            UnlockHcMutex(g_broadcastMutex);
            LOGI("Successfully updated a listener. [AppId]: %" LOG_PUB "s", appId);
            return HC_SUCCESS;
        }
    }
    UnlockHcMutex(g_broadcastMutex);
    return HC_ERR_LISTENER_NOT_EXIST;
}

static int32_t AddListenerIfNotExist(const char *appId, const DataChangeListener *listener)
{
    uint32_t appIdLen = HcStrlen(appId) + 1;
    char *copyAppId = (char *)HcMalloc(appIdLen, 0);
    if (copyAppId == NULL) {
        LOGE("Failed to allocate copyAppId memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (strcpy_s(copyAppId, appIdLen, appId) != HC_SUCCESS) {
        LOGE("Failed to copy appId!");
        HcFree(copyAppId);
        return HC_ERR_MEMORY_COPY;
    }
    DataChangeListener *copyListener = (DataChangeListener *)HcMalloc(sizeof(DataChangeListener), 0);
    if (copyListener == NULL) {
        LOGE("Failed to allocate saveCallback memory!");
        HcFree(copyAppId);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(copyListener, sizeof(DataChangeListener),
        listener, sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("Failed to copy listener!");
        HcFree(copyAppId);
        HcFree(copyListener);
        return HC_ERR_MEMORY_COPY;
    }
    ListenerEntry entry;
    entry.appId = copyAppId;
    entry.listener = copyListener;
    (void)LockHcMutex(g_broadcastMutex);
    if (g_listenerEntryVec.pushBack(&g_listenerEntryVec, &entry) == NULL) {
        LOGE("Failed to push listener entity!");
        HcFree(copyAppId);
        HcFree(copyListener);
        UnlockHcMutex(g_broadcastMutex);
        return HC_ERR_ALLOC_MEMORY;
    }
    UnlockHcMutex(g_broadcastMutex);
    LOGI("Successfully added a listener. [AppId]: %" LOG_PUB "s", appId);
    return HC_SUCCESS;
}

static Broadcaster g_broadcaster = {
    .postOnGroupCreated = PostOnGroupCreated,
    .postOnGroupDeleted = PostOnGroupDeleted,
    .postOnDeviceBound = PostOnDeviceBound,
    .postOnDeviceUnBound = PostOnDeviceUnBound,
    .postOnDeviceNotTrusted = PostOnDeviceNotTrusted,
    .postOnLastGroupDeleted = PostOnLastGroupDeleted,
    .postOnTrustedDeviceNumChanged = PostOnTrustedDeviceNumChanged
};

bool IsBroadcastSupported(void)
{
    return true;
}

int32_t InitBroadcastManager(void)
{
    if (g_broadcastMutex == NULL) {
        g_broadcastMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_broadcastMutex == NULL) {
            LOGE("Failed to allocate broadcast mutex memory!");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (InitHcMutex(g_broadcastMutex, false) != HC_SUCCESS) {
            LOGE("Init mutex failed");
            HcFree(g_broadcastMutex);
            g_broadcastMutex = NULL;
            return HC_ERROR;
        }
    }
    g_listenerEntryVec = CREATE_HC_VECTOR(ListenerEntryVec);
    LOGI("[Broadcaster]: Init broadcast manager module successfully!");
    return HC_SUCCESS;
}

void DestroyBroadcastManager(void)
{
    uint32_t index;
    ListenerEntry *entry = NULL;
    (void)LockHcMutex(g_broadcastMutex);
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        HcFree(entry->appId);
        HcFree(entry->listener);
    }
    DESTROY_HC_VECTOR(ListenerEntryVec, &g_listenerEntryVec);
    UnlockHcMutex(g_broadcastMutex);
    DestroyHcMutex(g_broadcastMutex);
    HcFree(g_broadcastMutex);
    g_broadcastMutex = NULL;
}

const Broadcaster *GetBroadcaster(void)
{
    return &g_broadcaster;
}

int32_t AddListener(const char *appId, const DataChangeListener *listener)
{
    if ((appId == NULL) || (listener == NULL)) {
        LOGE("The input appId or listener is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (UpdateListenerIfExist(appId, listener) == HC_SUCCESS) {
        return HC_SUCCESS;
    }
    return AddListenerIfNotExist(appId, listener);
}

int32_t RemoveListener(const char *appId)
{
    if (appId == NULL) {
        LOGE("The input appId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    ListenerEntry *entry = NULL;
    FOR_EACH_HC_VECTOR(g_listenerEntryVec, index, entry) {
        if (IsStrEqual(entry->appId, appId)) {
            HcFree(entry->appId);
            HcFree(entry->listener);
            ListenerEntry tempEntry;
            HC_VECTOR_POPELEMENT(&g_listenerEntryVec, &tempEntry, index);
            LOGI("Successfully removed a listener. [AppId]: %" LOG_PUB "s", appId);
            return HC_SUCCESS;
        }
    }
    LOGI("The listener does not exist! [AppId]: %" LOG_PUB "s", appId);
    return HC_SUCCESS;
}
