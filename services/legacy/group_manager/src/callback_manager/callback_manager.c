/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "callback_manager.h"
#include "channel_manager.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "securec.h"

typedef struct {
    char *appId;
    DeviceAuthCallback *callback;
} CallbackEntry;

DECLARE_HC_VECTOR(GMCallbackEntryVec, CallbackEntry);
IMPLEMENT_HC_VECTOR(GMCallbackEntryVec, CallbackEntry, 1)
static GMCallbackEntryVec g_callbackVec;
static HcMutex *g_callbackMutex = NULL;

static int32_t UpdateCallbackIfExist(const char *appId, const DeviceAuthCallback *callback)
{
    uint32_t index;
    CallbackEntry *entry = NULL;
    (void)LockHcMutex(g_callbackMutex);
    FOR_EACH_HC_VECTOR(g_callbackVec, index, entry) {
        if (strcmp(entry->appId, appId) == 0) {
            if (memcpy_s(entry->callback, sizeof(DeviceAuthCallback),
                callback, sizeof(DeviceAuthCallback)) != EOK) {
                UnlockHcMutex(g_callbackMutex);
                LOGE("Failed to copy service callback!");
                return HC_ERR_MEMORY_COPY;
            }
            UnlockHcMutex(g_callbackMutex);
            LOGI("Successfully updated a callback! [AppId]: %" LOG_PUB "s", appId);
            return HC_SUCCESS;
        }
    }
    UnlockHcMutex(g_callbackMutex);
    return HC_ERR_CALLBACK_NOT_FOUND;
}

static int32_t AddCallbackIfNotExist(const char *appId, const DeviceAuthCallback *callback)
{
    uint32_t appIdLen = HcStrlen(appId) + 1;
    char *copyAppId = (char *)HcMalloc(appIdLen, 0);
    if (copyAppId == NULL) {
        LOGE("Failed to allocate copyAppId memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (strcpy_s(copyAppId, appIdLen, appId) != EOK) {
        LOGE("Failed to copy appId!");
        HcFree(copyAppId);
        return HC_ERR_MEMORY_COPY;
    }
    DeviceAuthCallback *copyCallback = (DeviceAuthCallback *)HcMalloc(sizeof(DeviceAuthCallback), 0);
    if (copyCallback == NULL) {
        LOGE("Failed to allocate copyCallback memory!");
        HcFree(copyAppId);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(copyCallback, sizeof(DeviceAuthCallback), callback, sizeof(DeviceAuthCallback)) != EOK) {
        LOGE("Failed to copy service callback!");
        HcFree(copyAppId);
        HcFree(copyCallback);
        return HC_ERR_MEMORY_COPY;
    }
    CallbackEntry entry;
    entry.appId = copyAppId;
    entry.callback = copyCallback;
    (void)LockHcMutex(g_callbackMutex);
    if (g_callbackVec.pushBack(&g_callbackVec, &entry) == NULL) {
        LOGE("Failed to push callback to vector!");
        HcFree(copyAppId);
        HcFree(copyCallback);
        UnlockHcMutex(g_callbackMutex);
        return HC_ERR_MEMORY_COPY;
    }
    UnlockHcMutex(g_callbackMutex);
    LOGI("Successfully added a callback! [AppId]: %" LOG_PUB "s", appId);
    return HC_SUCCESS;
}

bool ProcessTransmitCallback(int64_t reqId, const uint8_t *data, uint32_t dataLen, const DeviceAuthCallback *callback)
{
    if ((callback != NULL) && (callback->onTransmit != NULL)) {
        LOGI("[Service][In]: ProcessTransmitCallback! [DataLen]: %" LOG_PUB "u, [ReqId]: %" LOG_PUB PRId64,
            dataLen, reqId);
        bool res = callback->onTransmit(reqId, data, dataLen);
        LOGI("[Service][Out]: ProcessTransmitCallback!");
        return res;
    }
    LOGE("[OnTransmit]: Currently, the service callback is NULL! [ReqId]: %" LOG_PUB PRId64, reqId);
    return false;
}

void ProcessSessionKeyCallback(int64_t reqId, const uint8_t *sessionKey, uint32_t sessionKeyLen,
    const DeviceAuthCallback *callback)
{
    if ((callback != NULL) && (callback->onSessionKeyReturned != NULL)) {
        LOGI("[Service][In]: ProcessSessionKeyCallback! [ReqId]: %" LOG_PUB PRId64, reqId);
        callback->onSessionKeyReturned(reqId, sessionKey, sessionKeyLen);
        LOGI("[Service][Out]: ProcessSessionKeyCallback!");
        return;
    }
    LOGE("[OnSessionKeyReturned]: Currently, the service callback is NULL! [ReqId]: %" LOG_PUB PRId64, reqId);
}

void ProcessFinishCallback(int64_t reqId, int operationCode, const char *returnData,
    const DeviceAuthCallback *callback)
{
    if ((callback != NULL) && (callback->onFinish != NULL)) {
        LOGI("[Service][In]: ProcessFinishCallback! [ReqId]: %" LOG_PUB PRId64, reqId);
        callback->onFinish(reqId, operationCode, returnData);
        LOGI("[Service][Out]: ProcessFinishCallback!");
        return;
    }
    LOGE("[OnFinish]: Currently, the service callback is NULL! [ReqId]: %" LOG_PUB PRId64, reqId);
}

void ProcessErrorCallback(int64_t reqId, int operationCode, int errorCode, const char *errorReturn,
    const DeviceAuthCallback *callback)
{
    if ((callback != NULL) && (callback->onError != NULL)) {
        LOGI("[Service][In]: ProcessErrorCallback! [ReqId]: %" LOG_PUB PRId64, reqId);
        callback->onError(reqId, operationCode, errorCode, errorReturn);
        LOGI("[Service][Out]: ProcessErrorCallback!");
        return;
    }
    LOGE("[OnError]: Currently, the service callback is NULL! [ReqId]: %" LOG_PUB PRId64, reqId);
}

char *ProcessRequestCallback(int64_t reqId, int operationCode, const char *reqParams,
    const DeviceAuthCallback *callback)
{
    if ((callback != NULL) && (callback->onRequest != NULL)) {
        LOGI("[Service][In]: ProcessRequestCallback! [ReqId]: %" LOG_PUB PRId64, reqId);
        char *returnData = callback->onRequest(reqId, operationCode, reqParams);
        LOGI("[Service][Out]: ProcessRequestCallback!");
        return returnData;
    }
    LOGE("[OnRequest]: Currently, the service callback is NULL! [ReqId]: %" LOG_PUB PRId64, reqId);
    return NULL;
}

const DeviceAuthCallback *GetGMCallbackByAppId(const char *appId)
{
    uint32_t index;
    CallbackEntry *entry = NULL;
    (void)LockHcMutex(g_callbackMutex);
    FOR_EACH_HC_VECTOR(g_callbackVec, index, entry) {
        if (strcmp(entry->appId, appId) == 0) {
            UnlockHcMutex(g_callbackMutex);
            return entry->callback;
        }
    }
    UnlockHcMutex(g_callbackMutex);
    return NULL;
}

int32_t RegGroupManagerCallback(const char *appId, const DeviceAuthCallback *callback)
{
    if ((appId == NULL) || (callback == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (UpdateCallbackIfExist(appId, callback) == HC_SUCCESS) {
        return HC_SUCCESS;
    }
    return AddCallbackIfNotExist(appId, callback);
}

int32_t UnRegGroupManagerCallback(const char *appId)
{
    SET_LOG_MODE(NORMAL_MODE);
    if (appId == NULL) {
        LOGE("The input appId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    CallbackEntry *entry = NULL;
    (void)LockHcMutex(g_callbackMutex);
    FOR_EACH_HC_VECTOR(g_callbackVec, index, entry) {
        if (strcmp(entry->appId, appId) == 0) {
            HcFree(entry->appId);
            HcFree(entry->callback);
            CallbackEntry tempEntry;
            HC_VECTOR_POPELEMENT(&g_callbackVec, &tempEntry, index);
            UnlockHcMutex(g_callbackMutex);
            LOGI("Successfully removed a callback. [AppId]: %" LOG_PUB "s", appId);
            return HC_SUCCESS;
        }
    }
    UnlockHcMutex(g_callbackMutex);
    LOGI("The callback does not exist! [AppId]: %" LOG_PUB "s", appId);
    return HC_SUCCESS;
}

int32_t InitCallbackManager(void)
{
    if (g_callbackMutex == NULL) {
        g_callbackMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_callbackMutex == NULL) {
            LOGE("Failed to allocate broadcast mutex memory!");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (InitHcMutex(g_callbackMutex, false) != HC_SUCCESS) {
            LOGE("Init mutex failed!");
            HcFree(g_callbackMutex);
            g_callbackMutex = NULL;
            return HC_ERROR;
        }
    }
    g_callbackVec = CREATE_HC_VECTOR(GMCallbackEntryVec);
    return HC_SUCCESS;
}

void DestroyCallbackManager(void)
{
    uint32_t index;
    CallbackEntry *entry = NULL;
    (void)LockHcMutex(g_callbackMutex);
    FOR_EACH_HC_VECTOR(g_callbackVec, index, entry) {
        HcFree(entry->appId);
        HcFree(entry->callback);
    }
    DESTROY_HC_VECTOR(GMCallbackEntryVec, &g_callbackVec);
    UnlockHcMutex(g_callbackMutex);
    DestroyHcMutex(g_callbackMutex);
    HcFree(g_callbackMutex);
    g_callbackMutex = NULL;
}