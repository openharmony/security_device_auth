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

IMPLEMENT_HC_VECTOR(LightSessionVec, LightSession, 1)

static LightSessionVec g_lightsession;

static LightSession *CreateSession(int64_t requestId, int32_t osAccountId, const char *serviceId, uint8_t *randomVal)
{
    LightSession *newSession = (LightSession *)HcMalloc(sizeof(LightSession), 0);
    if (newSession == NULL) {
        LOGE("Failed to alloc newSession");
        return NULL;
    }
    newSession->createTime = HcGetCurTime();
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
    while (index < g_lightsession.size(&(g_lightsession))) {
        LightSession *session = g_lightsession.getp(&(g_lightsession), index);
        int64_t runningTime = HcGetIntervalTime(session->createTime);
        if (runningTime < TIME_OUT_VALUE_DD) {
            index++;
            continue;
        }
        LOGI("session timeout. [Id]: %" LOG_PUB PRId64, session->requestId);
        LOGI("session timeout. [TimeLimit(/s)]: %" LOG_PUB "d, [RunningTime(/s)]: %" LOG_PUB PRId64,
            TIME_OUT_VALUE_DD, runningTime);
        DestroyLightSession(session);
        g_lightsession.eraseElement(&(g_lightsession), session, index);
    }
}

int32_t InitLightSessionManager(void)
{
    g_lightsession = CREATE_HC_VECTOR(LightSessionVec);
    return HC_SUCCESS;
}

void DestroyLightSessionManager(void)
{
    uint32_t index;
    LightSession *entry;
    FOR_EACH_HC_VECTOR(g_lightsession, index, entry) {
        if (entry == NULL) {
            continue;
        }
        DestroyLightSession(entry);
    }
    DESTROY_HC_VECTOR(LightSessionVec, &g_lightsession);
}

int32_t QueryLightSession(int64_t requestId, int32_t osAccountId, LightSession **lightSession)
{
    RemoveTimeOutSession();
    uint32_t index = 0;
    LightSession *data = NULL;
    FOR_EACH_HC_VECTOR(g_lightsession, index, data) {
        if (data == NULL) {
            continue;
        }
        if (requestId == data->requestId && osAccountId == data->osAccountId) {
            *lightSession = data;
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
    if (g_lightsession.size(&g_lightsession) >= MAX_SESSION_NUM_DD) {
        LOGE("Reach max session num!");
        return HC_ERR_OUT_OF_LIMIT;
    }
    LightSession *newSession = CreateSession(requestId, osAccountId, serviceId, randomVal);
    if (newSession == NULL) {
        LOGE("create session fail.");
        return HC_ERR_MEMORY_COPY;
    }
    if (g_lightsession.pushBackT(&g_lightsession, *newSession) == NULL) {
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
    LightSession *session = NULL;
    FOR_EACH_HC_VECTOR(g_lightsession, index, session) {
        if (session == NULL) {
            continue;
        }
        if (requestId == session->requestId && osAccountId == session->osAccountId) {
            DestroyLightSession(session);
            g_lightsession.eraseElement(&(g_lightsession), session, index);
            LOGI("Light session delete. [ReqId]: %" LOG_PUB PRId64 ", [OsAccountId]: %"
                LOG_PUB "d", requestId, osAccountId);
            return HC_SUCCESS;
        }
    }
    return HC_SUCCESS;
}