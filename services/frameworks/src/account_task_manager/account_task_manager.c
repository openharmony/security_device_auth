/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "account_task_manager.h"

#include <pthread.h>
#include <unistd.h>
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_vector.h"
#include "plugin_adapter.h"
#include "account_auth_plugin_proxy.h"

#define UNLOAD_DELAY_TIME 3

typedef struct {
    int32_t taskId;
} AccountTaskRecord;

DECLARE_HC_VECTOR(AccountTaskRecordList, AccountTaskRecord)
IMPLEMENT_HC_VECTOR(AccountTaskRecordList, AccountTaskRecord, 1)

static AccountTaskRecordList g_taskList;
static bool g_isPluginLoaded = false;
static bool g_isAsyncTaskRunning = false;
static bool g_hasAccountAuthPlugin = false;
static HcMutex g_taskMutex;
static bool g_isInit = false;

static void LoadAccountAuthPlugin(void)
{
    if (g_isPluginLoaded) {
        LOGI("[ACCOUNT_TASK_MGR]: plugin is loaded.");
        return;
    }
    DEV_AUTH_LOAD_PLUGIN();
    g_isPluginLoaded = true;
    LOGI("[ACCOUNT_TASK_MGR]: load plugin successfully.");
}

static bool IsPluginUnloadNeeded(void)
{
    if (!g_isPluginLoaded) {
        LOGI("[ACCOUNT_TASK_MGR]: plugin is unloaded.");
        return false;
    }
    if (g_isAsyncTaskRunning) {
        LOGI("[ACCOUNT_TASK_MGR]: async task is running, can't unload plugin.");
        return false;
    }
    if (g_taskList.size(&g_taskList) > 0) {
        LOGI("[ACCOUNT_TASK_MGR]: task exist.");
        return false;
    }
    return true;
}

void *ExecuteUnload(void *arg)
{
    LOGI("[ACCOUNT_TASK_MGR]: unload task execute.");
    sleep(UNLOAD_DELAY_TIME);
    LockHcMutex(&g_taskMutex);
    if (IsPluginUnloadNeeded()) {
        DEV_AUTH_UNLOAD_PLUGIN();
        g_isPluginLoaded = false;
        LOGI("[ACCOUNT_TASK_MGR]: unload plugin successfully.");
    }
    UnlockHcMutex(&g_taskMutex);
    return NULL;
}

static void UnloadAccountAuthPlugin(void)
{
    if (!IsPluginUnloadNeeded()) {
        return;
    }
    pthread_t tid;
    pthread_create(&tid, NULL, ExecuteUnload, NULL);
    pthread_detach(tid);
}

static int32_t AddAccountTaskRecord(int32_t taskId)
{
    AccountTaskRecord taskRecord;
    taskRecord.taskId = taskId;
    if (g_taskList.pushBackT(&g_taskList, taskRecord) == NULL) {
        LOGE("[ACCOUNT_TASK_MGR]: push task record failed, taskId: %d", taskId);
        return HC_ERR_MEMORY_COPY;
    }
    LOGI("[ACCOUNT_TASK_MGR]: add task record succeeded, taskId: %d", taskId);
    return HC_SUCCESS;
}

static void RemoveAccountTaskRecord(int32_t taskId)
{
    uint32_t index;
    AccountTaskRecord *ptr;
    FOR_EACH_HC_VECTOR(g_taskList, index, ptr) {
        if (ptr->taskId == taskId) {
            HC_VECTOR_POPELEMENT(&g_taskList, ptr, index);
            LOGI("[ACCOUNT_TASK_MGR]: remove task record succeeded, taskId: %d", taskId);
            return;
        }
    }
    LOGI("[ACCOUNT_TASK_MGR]: task record not exist, taskId: %d", taskId);
}

int32_t InitAccountTaskManager(void)
{
    if (g_isInit) {
        LOGI("[ACCOUNT_TASK_MGR]: has been initialized.");
        return HC_SUCCESS;
    }
    int32_t res = InitHcMutex(&g_taskMutex, true);
    if (res != HC_SUCCESS) {
        LOGE("[ACCOUNT_TASK_MGR]: init account task mutex failed.");
        return res;
    }
    DEV_AUTH_LOAD_PLUGIN();
    g_hasAccountAuthPlugin = HasAccountAuthPlugin();
    DEV_AUTH_UNLOAD_PLUGIN();
    g_taskList = CREATE_HC_VECTOR(AccountTaskRecordList);
    g_isInit = true;
    return HC_SUCCESS;
}

void DestroyAccountTaskManager(void)
{
    if (!g_isInit) {
        LOGI("[ACCOUNT_TASK_MGR]: has not been initialized.");
        return;
    }
    g_isInit = false;
    (void)LockHcMutex(&g_taskMutex);
    DESTROY_HC_VECTOR(AccountTaskRecordList, &g_taskList);
    UnlockHcMutex(&g_taskMutex);
    DestroyHcMutex(&g_taskMutex);
}

bool HasAccountPlugin(void)
{
    return g_hasAccountAuthPlugin;
}

int32_t ExecuteAccountAuthCmd(int32_t osAccountId, int32_t cmdId, const CJson *in, CJson *out)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    (void)LockHcMutex(&g_taskMutex);
    LoadAccountAuthPlugin();
    int32_t res = ExcuteCredMgrCmd(osAccountId, cmdId, in, out);
    UnloadAccountAuthPlugin();
    UnlockHcMutex(&g_taskMutex);
    return res;
}

int32_t CreateAccountAuthSession(int32_t *sessionId, const CJson *in, CJson *out)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    (void)LockHcMutex(&g_taskMutex);
    LoadAccountAuthPlugin();
    int32_t res = CreateAuthSession(sessionId, in, out);
    if (res != HC_SUCCESS) {
        LOGE("[ACCOUNT_TASK_MGR]: create auth session failed!");
        UnloadAccountAuthPlugin();
        UnlockHcMutex(&g_taskMutex);
        return res;
    }
    res = AddAccountTaskRecord(*sessionId);
    if (res != HC_SUCCESS) {
        DestroyAuthSession(*sessionId);
        UnloadAccountAuthPlugin();
    }
    UnlockHcMutex(&g_taskMutex);
    return res;
}

int32_t ProcessAccountAuthSession(int32_t *sessionId, const CJson *in, CJson *out, int32_t *status)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    (void)LockHcMutex(&g_taskMutex);
    LoadAccountAuthPlugin();
    int32_t res = ProcessAuthSession(sessionId, in, out, status);
    UnlockHcMutex(&g_taskMutex);
    return res;
}

int32_t DestroyAccountAuthSession(int32_t sessionId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    (void)LockHcMutex(&g_taskMutex);
    LoadAccountAuthPlugin();
    int32_t res = DestroyAuthSession(sessionId);
    RemoveAccountTaskRecord(sessionId);
    UnloadAccountAuthPlugin();
    UnlockHcMutex(&g_taskMutex);
    return res;
}

int32_t LoadAccountAndAddTaskRecord(int32_t taskId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    (void)LockHcMutex(&g_taskMutex);
    LoadAccountAuthPlugin();
    int32_t res = AddAccountTaskRecord(taskId);
    if (res != HC_SUCCESS) {
        UnloadAccountAuthPlugin();
    }
    UnlockHcMutex(&g_taskMutex);
    return res;
}

void RemoveAccountTaskRecordAndUnload(int32_t taskId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return;
    }
    (void)LockHcMutex(&g_taskMutex);
    RemoveAccountTaskRecord(taskId);
    UnloadAccountAuthPlugin();
    UnlockHcMutex(&g_taskMutex);
}

void NotifyAsyncTaskStart(void)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return;
    }
    (void)LockHcMutex(&g_taskMutex);
    if (g_isAsyncTaskRunning) {
        LOGI("[ACCOUNT_TASK_MGR]: async task is already started.");
        UnlockHcMutex(&g_taskMutex);
        return;
    }
    g_isAsyncTaskRunning = true;
    UnlockHcMutex(&g_taskMutex);
}

void NotifyAsyncTaskStop(void)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return;
    }
    (void)LockHcMutex(&g_taskMutex);
    if (!g_isAsyncTaskRunning) {
        LOGI("[ACCOUNT_TASK_MGR]: async task is already stopped.");
        UnlockHcMutex(&g_taskMutex);
        return;
    }
    g_isAsyncTaskRunning = false;
    UnloadAccountAuthPlugin();
    UnlockHcMutex(&g_taskMutex);
}