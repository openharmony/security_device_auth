/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#include "dev_session_mgr.h"

#include <inttypes.h>
#include "callback_manager.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_time.h"
#include "hc_vector.h"
#include "task_manager.h"
#include "critical_handler.h"

typedef struct {
    DevSession *session;
    int64_t createTime;
} SessionInfo;

typedef struct {
    HcTaskBase base;
    int64_t sessionId;
} StartSessionTask;

typedef struct {
    HcTaskBase base;
    int64_t sessionId;
    CJson *receivedMsg;
} ProcSessionTask;

DECLARE_HC_VECTOR(SessionInfoList, SessionInfo)
IMPLEMENT_HC_VECTOR(SessionInfoList, SessionInfo, 1)

static SessionInfoList g_sessionInfoList;
static HcMutex g_sessionMutex;

static int32_t GetSessionInfo(int64_t sessionId, SessionInfo **returnObj)
{
    uint32_t index;
    SessionInfo *ptr;
    FOR_EACH_HC_VECTOR(g_sessionInfoList, index, ptr) {
        DevSession *session = ptr->session;
        if (session->id == sessionId) {
            *returnObj = ptr;
            return HC_SUCCESS;
        }
    }
    return HC_ERR_SESSION_NOT_EXIST;
}

void RemoveTimeoutSession(void)
{
    uint32_t index = 0;
    while (index < g_sessionInfoList.size(&(g_sessionInfoList))) {
        SessionInfo *sessionInfo = g_sessionInfoList.getp(&(g_sessionInfoList), index);
        int64_t runningTime = HcGetIntervalTime(sessionInfo->createTime);
        if (runningTime < TIME_OUT_VALUE) {
            index++;
            continue;
        }
        DevSession *session = sessionInfo->session;
        LOGI("session timeout. [AppId]: %" LOG_PUB "s, [Id]: %" LOG_PUB PRId64, session->appId, session->id);
        LOGI("session timeout. [TimeLimit(/s)]: %" LOG_PUB "d, [RunningTime(/s)]: %" LOG_PUB PRId64,
            TIME_OUT_VALUE, runningTime);
        ProcessErrorCallback(session->id, session->opCode, HC_ERR_TIME_OUT, NULL, &session->callback);
        session->destroy(session);
        g_sessionInfoList.eraseElement(&(g_sessionInfoList), sessionInfo, index);
    }
}

static int32_t CheckEnvForOpenSession(int64_t sessionId)
{
    SessionInfo *sessionInfo;
    int32_t res = GetSessionInfo(sessionId, &sessionInfo);
    if (res == HC_SUCCESS) {
        LOGE("session has existed. [Id]: %" LOG_PUB PRId64, sessionId);
        return HC_ERR_REQUEST_EXIST;
    }
    uint32_t curSessionNum = HC_VECTOR_SIZE(&g_sessionInfoList);
    if (curSessionNum >= MAX_AUTH_SESSION_COUNT) {
        LOGE("The number of sessions has reached the maximum limit. [CurNum]: %" LOG_PUB "u, [NumLimit]: %" LOG_PUB "d",
            curSessionNum, MAX_AUTH_SESSION_COUNT);
        return HC_ERR_SESSION_IS_FULL;
    }
    return HC_SUCCESS;
}

static int32_t AddNewSessionToList(DevSession *session)
{
    SessionInfo newSessionInfo;
    newSessionInfo.session = session;
    newSessionInfo.createTime = HcGetCurTime();
    if (g_sessionInfoList.pushBackT(&g_sessionInfoList, newSessionInfo) == NULL) {
        LOGE("push session to list fail.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t InitDevSessionManager(void)
{
    int32_t res = InitHcMutex(&g_sessionMutex, false);
    if (res != HC_SUCCESS) {
        LOGE("Init session mutex failed.");
        return res;
    }
    g_sessionInfoList = CREATE_HC_VECTOR(SessionInfoList);
    return HC_SUCCESS;
}

void DestroyDevSessionManager(void)
{
    uint32_t index;
    SessionInfo *ptr;
    (void)LockHcMutex(&g_sessionMutex);
    FOR_EACH_HC_VECTOR(g_sessionInfoList, index, ptr) {
        ptr->session->destroy(ptr->session);
    }
    DESTROY_HC_VECTOR(SessionInfoList, &g_sessionInfoList);
    UnlockHcMutex(&g_sessionMutex);
    DestroyHcMutex(&g_sessionMutex);
}

bool IsSessionExist(int64_t sessionId)
{
    (void)LockHcMutex(&g_sessionMutex);
    SessionInfo *sessionInfo;
    int32_t res = GetSessionInfo(sessionId, &sessionInfo);
    UnlockHcMutex(&g_sessionMutex);
    return res == HC_SUCCESS;
}

int32_t OpenDevSession(int64_t sessionId, const char *appId, SessionInitParams *params)
{
    if ((appId == NULL) || (params == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    (void)LockHcMutex(&g_sessionMutex);
    RemoveTimeoutSession();
    int32_t res = CheckEnvForOpenSession(sessionId);
    if (res != HC_SUCCESS) {
        UnlockHcMutex(&g_sessionMutex);
        return res;
    }
    DevSession *session;
    res = CreateDevSession(sessionId, appId, params, &session);
    if (res != HC_SUCCESS) {
        LOGE("create session fail. [AppId]: %" LOG_PUB "s, [Id]: %" LOG_PUB PRId64, appId, sessionId);
        UnlockHcMutex(&g_sessionMutex);
        return res;
    }
    res = AddNewSessionToList(session);
    if (res != HC_SUCCESS) {
        session->destroy(session);
        UnlockHcMutex(&g_sessionMutex);
        return res;
    }
    LOGI("create session success. [AppId]: %" LOG_PUB "s, [CurNum]: %" LOG_PUB "u, [Id]: %" LOG_PUB PRId64,
        appId, HC_VECTOR_SIZE(&g_sessionInfoList), sessionId);
    UnlockHcMutex(&g_sessionMutex);
    return HC_SUCCESS;
}

int32_t StartDevSession(int64_t sessionId)
{
    (void)LockHcMutex(&g_sessionMutex);
    RemoveTimeoutSession();
    SessionInfo *sessionInfo;
    int32_t res = GetSessionInfo(sessionId, &sessionInfo);
    if (res != HC_SUCCESS) {
        LOGE("session not found. [Id]: %" LOG_PUB PRId64, sessionId);
        UnlockHcMutex(&g_sessionMutex);
        return res;
    }
    DevSession *session = sessionInfo->session;
    res = session->start(session);
    UnlockHcMutex(&g_sessionMutex);
    return res;
}

int32_t ProcessDevSession(int64_t sessionId, const CJson *receviedMsg, bool *isFinish)
{
    if ((receviedMsg == NULL) || (isFinish == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    (void)LockHcMutex(&g_sessionMutex);
    RemoveTimeoutSession();
    SessionInfo *sessionInfo;
    int32_t res = GetSessionInfo(sessionId, &sessionInfo);
    if (res != HC_SUCCESS) {
        LOGE("session not found. [Id]: %" LOG_PUB PRId64, sessionId);
        UnlockHcMutex(&g_sessionMutex);
        return res;
    }
    DevSession *session = sessionInfo->session;
    res = session->process(session, receviedMsg, isFinish);
    UnlockHcMutex(&g_sessionMutex);
    return res;
}

void CloseDevSession(int64_t sessionId)
{
    (void)LockHcMutex(&g_sessionMutex);
    RemoveTimeoutSession();
    uint32_t index;
    SessionInfo *ptr;
    FOR_EACH_HC_VECTOR(g_sessionInfoList, index, ptr) {
        DevSession *session = ptr->session;
        if (session->id == sessionId) {
            session->destroy(session);
            HC_VECTOR_POPELEMENT(&g_sessionInfoList, ptr, index);
            LOGI("close session success. [CurNum]: %" LOG_PUB "u, [Id]: %" LOG_PUB PRId64,
                HC_VECTOR_SIZE(&g_sessionInfoList), sessionId);
            UnlockHcMutex(&g_sessionMutex);
            return;
        }
    }
    LOGI("session not exist. [Id]: %" LOG_PUB PRId64, sessionId);
    UnlockHcMutex(&g_sessionMutex);
}

void CancelDevSession(int64_t sessionId, const char *appId)
{
    if (appId == NULL) {
        LOGE("appId is NULL.");
        return;
    }
    (void)LockHcMutex(&g_sessionMutex);
    RemoveTimeoutSession();
    uint32_t index;
    SessionInfo *ptr;
    FOR_EACH_HC_VECTOR(g_sessionInfoList, index, ptr) {
        DevSession *session = ptr->session;
        if (session->id == sessionId && strcmp(session->appId, appId) == 0) {
            session->destroy(session);
            HC_VECTOR_POPELEMENT(&g_sessionInfoList, ptr, index);
            LOGI("cancel session success. [CurNum]: %" LOG_PUB "u, [Id]: %" LOG_PUB PRId64,
                HC_VECTOR_SIZE(&g_sessionInfoList), sessionId);
            UnlockHcMutex(&g_sessionMutex);
            return;
        }
    }
    LOGI("session not exist. [Id]: %" LOG_PUB PRId64, sessionId);
    UnlockHcMutex(&g_sessionMutex);
}

static void DoStartSession(HcTaskBase *task)
{
    LOGI("start session task begin.");
    if (task == NULL) {
        LOGE("The input task is NULL, can't start session!");
        DecreaseCriticalCnt();
        return;
    }
    StartSessionTask *realTask = (StartSessionTask *)task;
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(realTask->sessionId);
    int32_t res = StartDevSession(realTask->sessionId);
    if (res != HC_SUCCESS) {
        LOGE("start session fail.[Res]: %" LOG_PUB "d", res);
        CloseDevSession(realTask->sessionId);
    }
    DecreaseCriticalCnt();
}

static void DoProcSession(HcTaskBase *task)
{
    LOGI("proc session task begin.");
    if (task == NULL) {
        LOGE("The input task is NULL, can't start session!");
        DecreaseCriticalCnt();
        return;
    }
    ProcSessionTask *realTask = (ProcSessionTask *)task;
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(realTask->sessionId);
    bool isFinish = false;
    int32_t res = ProcessDevSession(realTask->sessionId, realTask->receivedMsg, &isFinish);
    if (res != HC_SUCCESS) {
        LOGE("ProcessDevSession fail. [Res]: %" LOG_PUB "d", res);
        CloseDevSession(realTask->sessionId);
        DecreaseCriticalCnt();
        return;
    }
    LOGI("ProcessDevSession success. [State]: %" LOG_PUB "s", isFinish ? "FINISH" : "CONTINUE");
    if (isFinish) {
        CloseDevSession(realTask->sessionId);
    }
    DecreaseCriticalCnt();
}

static void InitStartSessionTask(StartSessionTask *task, int64_t sessionId)
{
    task->base.doAction = DoStartSession;
    task->base.destroy = NULL;
    task->sessionId = sessionId;
}

static void DestroyProcSessionTask(HcTaskBase *task)
{
    ProcSessionTask *realTask = (ProcSessionTask *)task;
    FreeJson(realTask->receivedMsg);
    DecreaseCriticalCnt();
}

static void InitProcSessionTask(ProcSessionTask *task, int64_t sessionId, CJson *receivedMsg)
{
    task->base.doAction = DoProcSession;
    task->base.destroy = DestroyProcSessionTask;
    task->sessionId = sessionId;
    task->receivedMsg = receivedMsg;
}

int32_t PushStartSessionTask(int64_t sessionId)
{
    StartSessionTask *task = (StartSessionTask *)HcMalloc(sizeof(StartSessionTask), 0);
    if (task == NULL) {
        LOGE("Failed to allocate memory for task!");
        return HC_ERR_ALLOC_MEMORY;
    }
    InitStartSessionTask(task, sessionId);
    if (PushTask((HcTaskBase*)task) != HC_SUCCESS) {
        LOGE("push start session task fail.");
        HcFree(task);
        return HC_ERR_INIT_TASK_FAIL;
    }
    IncreaseCriticalCnt(ADD_ONE);
    LOGI("push start session task success.");
    return HC_SUCCESS;
}

int32_t PushProcSessionTask(int64_t sessionId, CJson *receivedMsg)
{
    ProcSessionTask *task = (ProcSessionTask *)HcMalloc(sizeof(ProcSessionTask), 0);
    if (task == NULL) {
        LOGE("Failed to allocate memory for task!");
        return HC_ERR_ALLOC_MEMORY;
    }
    InitProcSessionTask(task, sessionId, receivedMsg);
    if (PushTask((HcTaskBase*)task) != HC_SUCCESS) {
        LOGE("push start session task fail.");
        HcFree(task);
        return HC_ERR_INIT_TASK_FAIL;
    }
    IncreaseCriticalCnt(ADD_TWO);
    LOGI("push start session task success.");
    return HC_SUCCESS;
}