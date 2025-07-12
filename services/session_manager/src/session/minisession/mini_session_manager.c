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
#include "common_defs.h"

#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_string_vector.h"
#include "hc_types.h"
#include "key_manager.h"
#include "securec.h"
#include "hidump_adapter.h"
#include "os_account_adapter.h"
#include "pseudonym_manager.h"
#include "security_label_adapter.h"
#include "account_task_manager.h"
#include "mini_session_manager.h"
#include "hc_time.h"

#define TIME_OUT_VALUE_DD 300
#define MAX_SESSION_NUM_DD 30

typedef struct {
    LightSession *session;
    int64_t createTime;
} LightSessionInfo;

DECLARE_HC_VECTOR(LightSessionInfoVec, LightSessionInfo)
IMPLEMENT_HC_VECTOR(LightSessionInfoVec, LightSessionInfo, 1)

static LightSessionInfoVec g_lightSessionInfoList;

static LightSession *CreateSession(int64_t requestId, int32_t osAccountId, const char *serviceId, uint8_t *randomVal)
{
    LightSession *newSession = (LightSession *)HcMalloc(sizeof(LightSession), 0);
    if (newSession == NULL) {
        LOGE("Failed to alloc newSession");
        return NULL;
    }
    newSession->osAccountId = osAccountId;
    if (memcpy_s(newSession->randomVal, RETURN_RANDOM_LEN, randomVal, RETURN_RANDOM_LEN) != EOK) {
        LOGE("Copy randomVal failed.");
        HcFree(newSession);
        return NULL;
    }
    newSession->requestId = requestId;
    uint32_t serviceIdLen = HcStrlen(serviceId) + 1;
    newSession->serviceId = (char *)HcMalloc(serviceIdLen, 0);
    if (newSession->serviceId == NULL) {
        LOGE("Copy serviceId failed.");
        HcFree(newSession);
        return NULL;
    }
    if (memcpy_s(newSession->serviceId, serviceIdLen, serviceId, serviceIdLen) != EOK) {
        LOGE("Copy serviceId failed.");
        HcFree(newSession->serviceId);
        HcFree(newSession);
        return NULL;
    }
    return newSession;
}

static void DestroyLightSession(LightSession *lightSessionEntry)
{
    if (lightSessionEntry == NULL) {
        return;
    }
    if (lightSessionEntry->serviceId == NULL) {
        HcFree(lightSessionEntry);
        return;
    }
    HcFree(lightSessionEntry->serviceId);
    HcFree(lightSessionEntry);
}

static void RemoveTimeOutSession(void)
{
    uint32_t index = 0;
    while (index < g_lightSessionInfoList.size(&(g_lightSessionInfoList))) {
        LightSessionInfo *lightSessionInfo = g_lightSessionInfoList.getp(&(g_lightSessionInfoList), index);
        int64_t runningTime = HcGetIntervalTime(lightSessionInfo->createTime);
        if (runningTime < TIME_OUT_VALUE_DD) {
            index++;
            continue;
        }
        LightSession *session = lightSessionInfo->session;
        LOGI("session timeout. [Id]: %" LOG_PUB PRId64, session->requestId);
        LOGI("session timeout. [TimeLimit(/s)]: %" LOG_PUB "d, [RunningTime(/s)]: %" LOG_PUB PRId64,
            TIME_OUT_VALUE_DD, runningTime);
        DestroyLightSession(session);
        HC_VECTOR_POPELEMENT(&g_lightSessionInfoList, lightSessionInfo, index);
    }
}

int32_t InitLightSessionManager(void)
{
    g_lightSessionInfoList = CREATE_HC_VECTOR(LightSessionInfoVec);
    return HC_SUCCESS;
}

void DestroyLightSessionManager(void)
{
    uint32_t index;
    LightSessionInfo *entry;
    FOR_EACH_HC_VECTOR(g_lightSessionInfoList, index, entry) {
        if (entry == NULL) {
            continue;
        }
        DestroyLightSession(entry->session);
    }
    DESTROY_HC_VECTOR(LightSessionInfoVec, &g_lightSessionInfoList);
}

int32_t QueryLightSession(int64_t requestId, int32_t osAccountId, LightSession **lightSession)
{
    RemoveTimeOutSession();
    uint32_t index = 0;
    LightSessionInfo *entry;
    FOR_EACH_HC_VECTOR(g_lightSessionInfoList, index, entry) {
        if (entry == NULL) {
            continue;
        }
        if (requestId == entry->session->requestId && osAccountId == entry->session->osAccountId) {
            *lightSession = entry->session;
            LOGI("Light session found. [ReqId]: %" LOG_PUB PRId64 ", [OsAccountId]: %" LOG_PUB "d",
                requestId, osAccountId);
            return HC_SUCCESS;
        }
    }
    *lightSession = NULL;
    LOGI("Light session not exists. ");
    return HC_ERR_SESSION_NOT_EXIST;
}

int32_t AddLightSession(int64_t requestId, int32_t osAccountId, const char *serviceId, uint8_t *randomVal)
{
    RemoveTimeOutSession();
    if (g_lightSessionInfoList.size(&g_lightSessionInfoList) >= MAX_SESSION_NUM_DD) {
        LOGE("Reach max session num!");
        return HC_ERR_OUT_OF_LIMIT;
    }
    LightSessionInfo newLightSessionInfo;
    LightSession *newSession = CreateSession(requestId, osAccountId, serviceId, randomVal);
    if (newSession == NULL) {
        LOGE("create session fail.");
        return HC_ERR_MEMORY_COPY;
    }
    newLightSessionInfo.session = newSession;
    newLightSessionInfo.createTime = HcGetCurTime();
    if (g_lightSessionInfoList.pushBackT(&g_lightSessionInfoList, newLightSessionInfo) == NULL) {
        LOGE("push session to list fail.");
        DestroyLightSession(newSession);
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t DeleteLightSession(int64_t requestId, int32_t osAccountId)
{
    RemoveTimeOutSession();
    uint32_t index = 0;
    LightSessionInfo *ptr = NULL;
    FOR_EACH_HC_VECTOR(g_lightSessionInfoList, index, ptr) {
        LightSession *session = ptr->session;
        if (session == NULL) {
            continue;
        }
        if (requestId == session->requestId && osAccountId == session->osAccountId) {
            DestroyLightSession(session);
            HC_VECTOR_POPELEMENT(&g_lightSessionInfoList, ptr, index);
            LOGI("Light session delete. [ReqId]: %" LOG_PUB PRId64 ", [OsAccountId]: %"
                LOG_PUB "d", requestId, osAccountId);
            return HC_SUCCESS;
        }
    }
    return HC_SUCCESS;
}