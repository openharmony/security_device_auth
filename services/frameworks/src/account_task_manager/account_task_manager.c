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
#include "plugin_adapter.h"
#include "account_auth_plugin_proxy.h"

#define UNLOAD_DELAY_TIME 3

static bool g_isPluginLoaded = false;
static bool g_hasAccountAuthPlugin = false;
static HcMutex g_taskMutex = { 0 };
static bool g_isInit = false;
static bool g_isInUnloadStatus = false;
static uint32_t g_loadCount = 0;

static void LoadAccountAuthPlugin(void)
{
    (void)LockHcMutex(&g_taskMutex);
    g_loadCount++;
    LOGI("[ACCOUNT_TASK_MGR]: load count increase to: %" LOG_PUB "d.", g_loadCount);
    g_isInUnloadStatus = false;
    if (g_isPluginLoaded) {
        UnlockHcMutex(&g_taskMutex);
        LOGI("[ACCOUNT_TASK_MGR]: plugin is loaded.");
        return;
    }
    DEV_AUTH_LOAD_PLUGIN();
    g_isPluginLoaded = true;
    UnlockHcMutex(&g_taskMutex);
    LOGI("[ACCOUNT_TASK_MGR]: load plugin successfully.");
}

static bool ShouldUnloadPlugin(void)
{
    (void)LockHcMutex(&g_taskMutex);
    if (!g_isPluginLoaded) {
        UnlockHcMutex(&g_taskMutex);
        LOGI("[ACCOUNT_TASK_MGR]: plugin is not loaded.");
        return false;
    }
    if (g_loadCount > 0) {
        UnlockHcMutex(&g_taskMutex);
        LOGI("[ACCOUNT_TASK_MGR]: plugin is in use.");
        return false;
    }
    UnlockHcMutex(&g_taskMutex);
    return true;
}

void *ExecuteUnload(void *arg)
{
    LOGI("[ACCOUNT_TASK_MGR]: unload task execute.");
    sleep(UNLOAD_DELAY_TIME);
    LockHcMutex(&g_taskMutex);
    if (ShouldUnloadPlugin() && g_isInUnloadStatus) {
        g_isPluginLoaded = false;
        g_isInUnloadStatus = false;
        LOGI("[ACCOUNT_TASK_MGR]: unload plugin successfully.");
    } else {
        LOGI("[ACCOUNT_TASK_MGR]: no need to unload.");
    }
    UnlockHcMutex(&g_taskMutex);
    return NULL;
}

static void UnloadAccountAuthPlugin(void)
{
    LockHcMutex(&g_taskMutex);
    if (g_loadCount > 0) {
        g_loadCount--;
    }
    LOGI("[ACCOUNT_TASK_MGR]: load count decrease to: %" LOG_PUB "d.", g_loadCount);
    if (!ShouldUnloadPlugin() || g_isInUnloadStatus) {
        UnlockHcMutex(&g_taskMutex);
        return;
    }
    g_isInUnloadStatus = true;
    pthread_t tid;
    pthread_create(&tid, NULL, ExecuteUnload, NULL);
    pthread_detach(tid);
    UnlockHcMutex(&g_taskMutex);
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
    (void)LockHcMutex(&g_taskMutex);
    g_isPluginLoaded = false;
    g_isInUnloadStatus = false;
    g_loadCount = 0;
    UnlockHcMutex(&g_taskMutex);
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
    g_isInUnloadStatus = false;
    g_isPluginLoaded = false;
    g_loadCount = 0;
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
    LoadAccountAuthPlugin();
    int32_t res = ExcuteCredMgrCmd(osAccountId, cmdId, in, out);
    UnloadAccountAuthPlugin();
    return res;
}

int32_t CreateAccountAuthSession(int32_t *sessionId, const CJson *in, CJson *out)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    LoadAccountAuthPlugin();
    int32_t res = CreateAuthSession(sessionId, in, out);
    if (res != HC_SUCCESS) {
        LOGE("[ACCOUNT_TASK_MGR]: create auth session failed!");
        UnloadAccountAuthPlugin();
    }
    return res;
}

int32_t ProcessAccountAuthSession(int32_t *sessionId, const CJson *in, CJson *out, int32_t *status)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    return ProcessAuthSession(sessionId, in, out, status);
}

int32_t DestroyAccountAuthSession(int32_t sessionId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    int32_t res = DestroyAuthSession(sessionId);
    UnloadAccountAuthPlugin();
    return res;
}

void IncreaseLoadCount(void)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return;
    }
    LoadAccountAuthPlugin();
}

void DecreaseLoadCount(void)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return;
    }
    UnloadAccountAuthPlugin();
}