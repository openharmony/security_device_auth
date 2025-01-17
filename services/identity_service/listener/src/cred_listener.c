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

#include "cred_listener.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "securec.h"

typedef struct {
    char *appId;
    CredChangeListener *listener;
} CredListenerEntry;

DECLARE_HC_VECTOR(CredListenerEntryVec, CredListenerEntry);
IMPLEMENT_HC_VECTOR(CredListenerEntryVec, CredListenerEntry, 1);
static CredListenerEntryVec g_credListenerVec;
static HcMutex *g_credListenerMutex = NULL;

void OnCredAdd(const char *credId, const char *credInfo)
{
    if (credId == NULL) {
        LOGE("[CredListener]: The credId is NULL!");
        return;
    }
    if (credInfo == NULL) {
        credInfo = "";
    }
    uint32_t index;
    CredListenerEntry *entry = NULL;
    (void)LockHcMutex(g_credListenerMutex);
    FOR_EACH_HC_VECTOR(g_credListenerVec, index, entry) {
        if (entry != NULL && entry->listener != NULL && entry->listener->onCredAdd != NULL) {
            LOGI("[CredListener]: OnCredAdd! [AppId]: %s", entry->appId);
            entry->listener->onCredAdd(credId, credInfo);
        }
    }
    UnlockHcMutex(g_credListenerMutex);
}

void OnCredDelete(const char *credId, const char *credInfo)
{
    if (credId == NULL) {
        LOGE("[CredListener]: The credId is NULL!");
        return;
    }
    if (credInfo == NULL) {
        credInfo = "";
    }
    uint32_t index;
    CredListenerEntry *entry = NULL;
    (void)LockHcMutex(g_credListenerMutex);
    FOR_EACH_HC_VECTOR(g_credListenerVec, index, entry) {
        if (entry != NULL && entry->listener != NULL && entry->listener->onCredDelete != NULL) {
            LOGI("[CredListener]: OnCredDelete! [AppId]: %s", entry->appId);
            entry->listener->onCredDelete(credId, credInfo);
        }
    }
    UnlockHcMutex(g_credListenerMutex);
}

void OnCredUpdate(const char *credId, const char *credInfo)
{
    if (credId == NULL) {
        LOGE("[CredListener]: The credId is NULL!");
        return;
    }
    if (credInfo == NULL) {
        credInfo = "";
    }
    uint32_t index;
    CredListenerEntry *entry = NULL;
    (void)LockHcMutex(g_credListenerMutex);
    FOR_EACH_HC_VECTOR(g_credListenerVec, index, entry) {
        if (entry != NULL && entry->listener != NULL && entry->listener->onCredUpdate != NULL) {
            LOGI("[CredListener]: OnCredUpdate! [AppId]: %s", entry->appId);
            entry->listener->onCredUpdate(credId, credInfo);
        }
    }
    UnlockHcMutex(g_credListenerMutex);
}
static int32_t UpdateListenerIfExist(const char *appId, const CredChangeListener *listener)
{
    uint32_t index;
    (void)LockHcMutex(g_credListenerMutex);
    CredListenerEntry *entry = NULL;
    FOR_EACH_HC_VECTOR(g_credListenerVec, index, entry) {
        if (strcmp(entry->appId, appId) == 0) {
            if (memcpy_s(entry->listener, sizeof(CredChangeListener),
                listener, sizeof(CredChangeListener)) != IS_SUCCESS) {
                UnlockHcMutex(g_credListenerMutex);
                LOGE("[CredListener]: Failed to copy listener!");
                return IS_ERR_MEMORY_COPY;
            }
            UnlockHcMutex(g_credListenerMutex);
            LOGI("[CredListener]: Successfully updated a listener. [AppId]: %s", appId);
            return IS_SUCCESS;
        }
    }
    UnlockHcMutex(g_credListenerMutex);
    return IS_ERR_LISTENER_NOT_EXIST;
}

static int32_t AddListenerIfNotExist(const char *appId, const CredChangeListener *listener)
{
    uint32_t appIdLen = HcStrlen(appId) + 1;
    char *copyAppId = (char *)HcMalloc(appIdLen, 0);
    if (copyAppId == NULL) {
        LOGE("[CredListener]: Failed to allocate copyAppId memory!");
        return IS_ERR_ALLOC_MEMORY;
    }
    if (strcpy_s(copyAppId, appIdLen, appId) != IS_SUCCESS) {
        LOGE("[CredListener]: Failed to copy appId!");
        HcFree(copyAppId);
        return IS_ERR_MEMORY_COPY;
    }
    CredChangeListener *copyListener = (CredChangeListener *)HcMalloc(sizeof(CredChangeListener), 0);
    if (copyListener == NULL) {
        LOGE("[CredListener]: Failed to allocate saveCallback memory!");
        HcFree(copyAppId);
        return IS_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(copyListener, sizeof(CredChangeListener),
        listener, sizeof(CredChangeListener)) != IS_SUCCESS) {
        LOGE("[CredListener]: Failed to copy listener!");
        HcFree(copyAppId);
        HcFree(copyListener);
        return IS_ERR_MEMORY_COPY;
    }
    CredListenerEntry entry;
    entry.appId = copyAppId;
    entry.listener = copyListener;
    (void)LockHcMutex(g_credListenerMutex);
    if (g_credListenerVec.pushBack(&g_credListenerVec, &entry) == NULL) {
        HcFree(copyAppId);
        HcFree(copyListener);
        UnlockHcMutex(g_credListenerMutex);
        return IS_ERR_MEMORY_COPY;
    }
    UnlockHcMutex(g_credListenerMutex);
    LOGI("[CredListener]: Successfully added a listener. [AppId]: %s", appId);
    return IS_SUCCESS;
}

bool IsCredListenerSupported(void)
{
    return true;
}

int32_t InitCredListener(void)
{
    if (g_credListenerMutex == NULL) {
        g_credListenerMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_credListenerMutex == NULL) {
            LOGE("[CredListener]: Failed to allocate cred listener mutex memory!");
            return IS_ERR_ALLOC_MEMORY;
        }
        if (InitHcMutex(g_credListenerMutex, false) != IS_SUCCESS) {
            LOGE("[CredListener]: Init mutex failed");
            HcFree(g_credListenerMutex);
            g_credListenerMutex = NULL;
            return IS_ERR_INIT_FAILED;
        }
    }
    g_credListenerVec = CREATE_HC_VECTOR(CredListenerEntryVec);
    LOGI("[CredListener]: Init cred listener module successfully!");
    return IS_SUCCESS;
}

void DestroyCredListener(void)
{
    (void)LockHcMutex(g_credListenerMutex);
    uint32_t index;
    CredListenerEntry *entry = NULL;
    FOR_EACH_HC_VECTOR(g_credListenerVec, index, entry) {
        if (entry == NULL) {
            continue;
        }
        HcFree(entry->appId);
        HcFree(entry->listener);
    }
    DESTROY_HC_VECTOR(CredListenerEntryVec, &g_credListenerVec);
    UnlockHcMutex(g_credListenerMutex);
    DestroyHcMutex(g_credListenerMutex);
    HcFree(g_credListenerMutex);
    g_credListenerMutex = NULL;
}

int32_t AddCredListener(const char *appId, const CredChangeListener *listener)
{
    if ((appId == NULL) || (listener == NULL)) {
        LOGE("[CredListener]: The input appId or listener is NULL!");
        return IS_ERR_INVALID_PARAMS;
    }
    if (UpdateListenerIfExist(appId, listener) == IS_SUCCESS) {
        return IS_SUCCESS;
    }
    return AddListenerIfNotExist(appId, listener);
}

int32_t RemoveCredListener(const char *appId)
{
    if (appId == NULL) {
        LOGE("[CredListener]: The input appId is NULL!");
        return IS_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    CredListenerEntry *entry = NULL;
    FOR_EACH_HC_VECTOR(g_credListenerVec, index, entry) {
        if (entry != NULL && strcmp(entry->appId, appId) == 0) {
            HcFree(entry->appId);
            HcFree(entry->listener);
            CredListenerEntry tempEntry;
            HC_VECTOR_POPELEMENT(&g_credListenerVec, &tempEntry, index);
            LOGI("[CredListener]: Successfully removed a cred listener. [AppId]: %s", appId);
            return IS_SUCCESS;
        }
    }
    LOGI("[CredListener]: The cred listener does not exist! [AppId]: %s", appId);
    return IS_SUCCESS;
}
