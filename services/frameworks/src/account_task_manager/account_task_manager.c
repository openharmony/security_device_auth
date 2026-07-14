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

#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_vector.h"
#include "plugin_adapter.h"
#include "account_auth_plugin_proxy.h"

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
#include "trust_database_plugin_proxy.h"
#endif

#define UNLOAD_DELAY_TIME 3

typedef struct {
    int32_t sessionId;
} AuthSessionRecord;

DECLARE_HC_VECTOR(AuthSessionRecordList, AuthSessionRecord)
IMPLEMENT_HC_VECTOR(AuthSessionRecordList, AuthSessionRecord, 1)

static AuthSessionRecordList g_sessionList;
static bool g_isPluginLoaded = false;
static bool g_hasAccountAuthPlugin = false;
static HcMutex g_taskMutex = { 0 };
static bool g_isInit = false;
static bool g_isInUnloadStatus = false;
static uint32_t g_loadCount = 0;
#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
static bool g_hasTrustDatabasePlugin = false;
#endif

static void LoadAccountAuthPlugin(void)
{
    (void)LockHcMutex(&g_taskMutex);
    g_loadCount++;
    g_isInUnloadStatus = false;
    if (g_isPluginLoaded) {
        UnlockHcMutex(&g_taskMutex);
        return;
    }
    DEV_AUTH_LOAD_PLUGIN();
    g_isPluginLoaded = true;
    UnlockHcMutex(&g_taskMutex);
}

static bool ShouldUnloadPlugin(void)
{
    (void)LockHcMutex(&g_taskMutex);
    if (!g_isPluginLoaded) {
        UnlockHcMutex(&g_taskMutex);
        return false;
    }
    if (g_loadCount > 0) {
        UnlockHcMutex(&g_taskMutex);
        return false;
    }
    UnlockHcMutex(&g_taskMutex);
    return true;
}

static void UnloadAccountAuthPlugin(void)
{
    LockHcMutex(&g_taskMutex);
    if (g_loadCount > 0) {
        g_loadCount--;
    }
    if (!ShouldUnloadPlugin() || g_isInUnloadStatus) {
        UnlockHcMutex(&g_taskMutex);
        return;
    }
    g_isInUnloadStatus = true;
    UnlockHcMutex(&g_taskMutex);
}

static int32_t AddAuthSessionRecord(int32_t sessionId)
{
    LockHcMutex(&g_taskMutex);
    AuthSessionRecord sessionRecord;
    sessionRecord.sessionId = sessionId;
    if (g_sessionList.pushBackT(&g_sessionList, sessionRecord) == NULL) {
        UnlockHcMutex(&g_taskMutex);
        LOGE("[ACCOUNT_TASK_MGR]: add session record failed, sessionId: %" LOG_PUB "d", sessionId);
        return HC_ERR_MEMORY_COPY;
    }
    UnlockHcMutex(&g_taskMutex);
    return HC_SUCCESS;
}

static bool IsAuthSessionRecordExist(int32_t sessionId)
{
    LockHcMutex(&g_taskMutex);
    uint32_t index;
    AuthSessionRecord *ptr;
    FOR_EACH_HC_VECTOR(g_sessionList, index, ptr) {
        if (ptr->sessionId == sessionId) {
            UnlockHcMutex(&g_taskMutex);
            return true;
        }
    }
    UnlockHcMutex(&g_taskMutex);
    return false;
}

static void RemoveAuthSessionRecord(int32_t sessionId)
{
    LockHcMutex(&g_taskMutex);
    uint32_t index;
    AuthSessionRecord *ptr;
    FOR_EACH_HC_VECTOR(g_sessionList, index, ptr) {
        if (ptr->sessionId == sessionId) {
            HC_VECTOR_POPELEMENT(&g_sessionList, ptr, index);
            UnlockHcMutex(&g_taskMutex);
            return;
        }
    }
    UnlockHcMutex(&g_taskMutex);
    LOGE("[ACCOUNT_TASK_MGR]: session record not exist, sessionId: %" LOG_PUB "d", sessionId);
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
    (void)LockHcMutex(&g_taskMutex);
    DEV_AUTH_LOAD_PLUGIN();
    g_hasAccountAuthPlugin = HasAccountAuthPlugin();
#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
    g_hasTrustDatabasePlugin = HasTrustDatabasePlugin();
#endif
    g_sessionList = CREATE_HC_VECTOR(AuthSessionRecordList);
    g_isPluginLoaded = true;
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
    g_hasAccountAuthPlugin = false;
#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
    g_hasTrustDatabasePlugin = false;
#endif
    DESTROY_HC_VECTOR(AuthSessionRecordList, &g_sessionList);
    g_isPluginLoaded = false;
    g_isInUnloadStatus = false;
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
        return res;
    }
    res = AddAuthSessionRecord(*sessionId);
    if (res != HC_SUCCESS) {
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
    if (!IsAuthSessionRecordExist(*sessionId)) {
        LOGE("[ACCOUNT_TASK_MGR]: auth session record not exist!");
        return HC_ERR_SESSION_NOT_EXIST;
    }
    return ProcessAuthSession(sessionId, in, out, status);
}

int32_t DestroyAccountAuthSession(int32_t sessionId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    if (!IsAuthSessionRecordExist(sessionId)) {
        LOGE("[ACCOUNT_TASK_MGR]: auth session record not exist!");
        return HC_ERR_SESSION_NOT_EXIST;
    }
    int32_t res = DestroyAuthSession(sessionId);
    RemoveAuthSessionRecord(sessionId);
    UnloadAccountAuthPlugin();
    return res;
}

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
bool HasTrustRelationDbPlugin(void)
{
    return g_hasTrustDatabasePlugin;
}

int32_t AddDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    LoadAccountAuthPlugin();
    int32_t res = InsertDeviceTrustRelation(osAccountId, userId, groupId, udid);
    UnloadAccountAuthPlugin();
    return res;
}

int32_t DelDeviceTrustRelation(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    LoadAccountAuthPlugin();
    int32_t res = DeleteDeviceTrustRelation(osAccountId, userId, groupId, udid);
    UnloadAccountAuthPlugin();
    return res;
}

bool IsDeviceExistInGroupForUser(int32_t osAccountId, const char *userId, const char *groupId,
    const char *udid)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return false;
    }
    LoadAccountAuthPlugin();
    bool res = IsDeviceReferencedByGroupAndUser(osAccountId, userId, groupId, udid);
    UnloadAccountAuthPlugin();
    return res;
}

bool IsDeviceExistInGroup(int32_t osAccountId, const char *groupId, const char *udid)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return false;
    }
    LoadAccountAuthPlugin();
    bool res = IsDeviceReferencedByGroup(osAccountId, groupId, udid);
    UnloadAccountAuthPlugin();
    return res;
}

bool IsDeviceExistInUser(int32_t osAccountId, const char *userId, const char *udid)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return false;
    }
    LoadAccountAuthPlugin();
    bool res = IsDeviceReferencedByUser(osAccountId, userId, udid);
    UnloadAccountAuthPlugin();
    return res;
}

int32_t AddCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    LoadAccountAuthPlugin();
    int32_t res = InsertCredTrustRelation(osAccountId, userId, credId);
    UnloadAccountAuthPlugin();
    return res;
}

int32_t DelCredTrustRelation(int32_t osAccountId, const char *userId, const char *credId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    LoadAccountAuthPlugin();
    int32_t res = DeleteCredTrustRelation(osAccountId, userId, credId);
    UnloadAccountAuthPlugin();
    return res;
}

bool IsCredReferencedByUser(int32_t osAccountId, const char *userId, const char *credId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return false;
    }
    LoadAccountAuthPlugin();
    bool res = IsCredRelationReferencedByUser(osAccountId, userId, credId);
    UnloadAccountAuthPlugin();
    return res;
}

bool IsCredReferenced(int32_t osAccountId, const char *credId)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return false;
    }
    LoadAccountAuthPlugin();
    bool res = IsCredRelationReferenced(osAccountId, credId);
    UnloadAccountAuthPlugin();
    return res;
}

int32_t NotifyAccountSwitch(int32_t osAccountId, const char *fromUserId, const char *toUserId,
    AccountSwitchGroupCallback groupCallback, AccountSwitchCredCallback credCallback)
{
    if (!g_isInit) {
        LOGE("[ACCOUNT_TASK_MGR]: has not been initialized!");
        return HC_ERROR;
    }
    LoadAccountAuthPlugin();
    int32_t res = OnAccountSwitch(osAccountId, fromUserId, toUserId, groupCallback, credCallback);
    UnloadAccountAuthPlugin();
    return res;
}
#endif

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