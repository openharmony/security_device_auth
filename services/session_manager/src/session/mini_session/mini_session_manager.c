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
#include "mini_session_manager.h"
#include "account_task_manager.h"
#include "callback_manager.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_string_vector.h"
#include "hc_time.h"
#include "hc_types.h"
#include "hidump_adapter.h"
#include "key_manager.h"
#include "os_account_adapter.h"
#include "pseudonym_manager.h"
#include "security_label_adapter.h"
#include "securec.h"
#include "string_util.h"
#include "uint8buff_utils.h"

#define TIME_OUT_VALUE_LIGHT_AUTH 300
#define MAX_SESSION_NUM_LIGHT_AUTH 30

typedef struct {
    LightSession *session;
    int64_t createTime;
} LightSessionInfo;

DECLARE_HC_VECTOR(LightSessionInfoVec, LightSessionInfo)
IMPLEMENT_HC_VECTOR(LightSessionInfoVec, LightSessionInfo, 1)

static LightSessionInfoVec g_lightSessionInfoList;
static HcMutex g_lightSessionMutex;

static int32_t CopySessionRandom(LightSession *session, const DataBuff *randomBuff)
{
    session->randomVal = (uint8_t *)HcMalloc(randomBuff->length, 0);
    if (session->randomVal == NULL) {
        LOGE("HcMalloc randomVal failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(session->randomVal, randomBuff->length, randomBuff->data, randomBuff->length) != EOK) {
        LOGE("Copy randomVal failed.");
        HcFree(session->randomVal);
        session->randomVal = NULL;
        return HC_ERR_MEMORY_COPY;
    }
    session->randomLen = randomBuff->length;
    return HC_SUCCESS;
}

static int32_t CopySessionServiceId(LightSession *session, const char *serviceId)
{
    uint32_t serviceIdLen = HcStrlen(serviceId) + 1;
    session->serviceId = (char *)HcMalloc(serviceIdLen, 0);
    if (session->serviceId == NULL) {
        LOGE("HcMalloc serviceId failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(session->serviceId, serviceIdLen, serviceId, serviceIdLen) != EOK) {
        LOGE("Copy serviceId failed.");
        HcFree(session->serviceId);
        session->serviceId = NULL;
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static void DestroyLightSession(LightSession *session)
{
    if (session == NULL) {
        return;
    }
    if (session->serviceId != NULL) {
        HcFree(session->serviceId);
    }
    if (session->randomVal != NULL) {
        HcFree(session->randomVal);
    }
    HcFree(session);
}

static LightSession *CreateSession(const LightSessionInitParams *params)
{
    if (params == NULL || params->callback == NULL) {
        LOGE("invalid params");
        return NULL;
    }
    LightSession *session = (LightSession *)HcMalloc(sizeof(LightSession), 0);
    if (session == NULL) {
        LOGE("Failed to alloc session");
        return NULL;
    }
    session->requestId = params->requestId;
    session->osAccountId = params->osAccountId;
    session->opCode = params->opCode;
    if (CopySessionRandom(session, &params->randomBuff) != HC_SUCCESS) {
        DestroyLightSession(session);
        return NULL;
    }
    if (CopySessionServiceId(session, params->serviceId) != HC_SUCCESS) {
        DestroyLightSession(session);
        return NULL;
    }
    if (memcpy_s(&session->callback, sizeof(DeviceAuthCallback), params->callback,
        sizeof(DeviceAuthCallback)) != EOK) {
        LOGE("Copy callback failed.");
        DestroyLightSession(session);
        return NULL;
    }
    return session;
}

static void RemoveTimeOutSession(void)
{
    uint32_t index = 0;
    while (index < g_lightSessionInfoList.size(&(g_lightSessionInfoList))) {
        LightSessionInfo *lightSessionInfo = g_lightSessionInfoList.getp(&(g_lightSessionInfoList), index);
        int64_t runningTime = HcGetIntervalTime(lightSessionInfo->createTime);
        if (runningTime < TIME_OUT_VALUE_LIGHT_AUTH) {
            index++;
            continue;
        }
        LightSession *session = lightSessionInfo->session;
        LOGI("session timeout. [Id]: %" LOG_PUB PRId64, session->requestId);
        LOGI("session timeout. [TimeLimit(/s)]: %" LOG_PUB "d, [RunningTime(/s)]: %" LOG_PUB PRId64,
            TIME_OUT_VALUE_LIGHT_AUTH, runningTime);
        ProcessErrorCallback(session->requestId, session->opCode, HC_ERR_TIME_OUT, NULL, &session->callback);
        DestroyLightSession(session);
        HC_VECTOR_POPELEMENT(&g_lightSessionInfoList, lightSessionInfo, index);
    }
}

int32_t InitLightSessionManager(void)
{
    int32_t res = InitHcMutex(&g_lightSessionMutex, false);
    if (res != HC_SUCCESS) {
        LOGE("Init light session mutex failed.");
        return res;
    }
    g_lightSessionInfoList = CREATE_HC_VECTOR(LightSessionInfoVec);
    return HC_SUCCESS;
}

void DestroyLightSessionManager(void)
{
    uint32_t index;
    LightSessionInfo *entry;
    (void)LockHcMutex(&g_lightSessionMutex);
    FOR_EACH_HC_VECTOR(g_lightSessionInfoList, index, entry) {
        if (entry == NULL) {
            continue;
        }
        DestroyLightSession(entry->session);
    }
    DESTROY_HC_VECTOR(LightSessionInfoVec, &g_lightSessionInfoList);
    UnlockHcMutex(&g_lightSessionMutex);
    DestroyHcMutex(&g_lightSessionMutex);
}

int32_t QueryLightSession(int64_t requestId, int32_t osAccountId, uint8_t **randomVal,
    uint32_t *randomLen, char **serviceId)
{
    (void)LockHcMutex(&g_lightSessionMutex);
    RemoveTimeOutSession();
    uint32_t index = 0;
    LightSessionInfo *entry;
    FOR_EACH_HC_VECTOR(g_lightSessionInfoList, index, entry) {
        if (entry == NULL || entry->session == NULL) {
            continue;
        }
        if (requestId == entry->session->requestId && osAccountId == entry->session->osAccountId) {
            Uint8Buff sessionRandom = { entry->session->randomVal, entry->session->randomLen };
            Uint8Buff tempRandomBuff = { NULL, 0 };
            int32_t ret = DeepCopyUint8Buff(&sessionRandom, &tempRandomBuff);
            if (ret != HC_SUCCESS) {
                LOGE("Deep copy random value failed");
                UnlockHcMutex(&g_lightSessionMutex);
                return HC_ERR_MEMORY_COPY;
            }
            char *tempServiceId = NULL;
            ret = DeepCopyString(entry->session->serviceId, &tempServiceId);
            if (ret != HC_SUCCESS) {
                LOGE("Deep copy service id failed");
                FreeUint8Buff(&tempRandomBuff);
                UnlockHcMutex(&g_lightSessionMutex);
                return HC_ERR_MEMORY_COPY;
            }
            *randomLen = tempRandomBuff.length;
            *randomVal = tempRandomBuff.val;
            *serviceId = tempServiceId;
            UnlockHcMutex(&g_lightSessionMutex);
            return HC_SUCCESS;
        }
    }
    LOGI("Light session not exists. ");
    UnlockHcMutex(&g_lightSessionMutex);
    return HC_ERR_SESSION_NOT_EXIST;
}

int32_t AddLightSession(const LightSessionInitParams *params)
{
    if (params == NULL || params->callback == NULL || params->serviceId == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    (void)LockHcMutex(&g_lightSessionMutex);
    RemoveTimeOutSession();
    if (g_lightSessionInfoList.size(&g_lightSessionInfoList) >= MAX_SESSION_NUM_LIGHT_AUTH) {
        LOGE("Reach max session num!");
        UnlockHcMutex(&g_lightSessionMutex);
        return HC_ERR_OUT_OF_LIMIT;
    }
    LightSessionInfo newLightSessionInfo;
    LightSession *newSession = CreateSession(params);
    if (newSession == NULL) {
        LOGE("create session fail.");
        UnlockHcMutex(&g_lightSessionMutex);
        return HC_ERR_MEMORY_COPY;
    }
    newLightSessionInfo.session = newSession;
    newLightSessionInfo.createTime = HcGetCurTime();
    if (g_lightSessionInfoList.pushBackT(&g_lightSessionInfoList, newLightSessionInfo) == NULL) {
        LOGE("push session to list fail.");
        DestroyLightSession(newSession);
        UnlockHcMutex(&g_lightSessionMutex);
        return HC_ERR_MEMORY_COPY;
    }
    UnlockHcMutex(&g_lightSessionMutex);
    return HC_SUCCESS;
}

int32_t DeleteLightSession(int64_t requestId, int32_t osAccountId)
{
    (void)LockHcMutex(&g_lightSessionMutex);
    RemoveTimeOutSession();
    uint32_t index = 0;
    LightSessionInfo *ptr = NULL;
    FOR_EACH_HC_VECTOR(g_lightSessionInfoList, index, ptr) {
        if (ptr == NULL) {
            continue;
        }
        LightSession *session = ptr->session;
        if (session == NULL) {
            continue;
        }
        if (requestId == session->requestId && osAccountId == session->osAccountId) {
            DestroyLightSession(session);
            HC_VECTOR_POPELEMENT(&g_lightSessionInfoList, ptr, index);
            LOGI("Light session delete. [ReqId]: %" LOG_PUB PRId64 ", [OsAccountId]: %"
                LOG_PUB "d", requestId, osAccountId);
            UnlockHcMutex(&g_lightSessionMutex);
            return HC_SUCCESS;
        }
    }
    UnlockHcMutex(&g_lightSessionMutex);
    return HC_SUCCESS;
}