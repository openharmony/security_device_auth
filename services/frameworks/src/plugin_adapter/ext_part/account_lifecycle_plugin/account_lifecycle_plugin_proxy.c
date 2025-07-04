/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "account_lifecycle_plugin_proxy.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "task_manager.h"
#include "account_task_manager.h"
#include "alg_loader.h"
#include "identity_service.h"
#include "critical_handler.h"

static AccountLifecyleExtPlug *g_accountLifeCyclePlugin = NULL;
static AccountLifecyleExtPlugCtx *g_accountPluginCtx = NULL;

typedef struct {
    HcTaskBase base;
    ExtWorkerTask *extTask;
    int32_t taskId;
} WorkerTask;

static void DoWorkerTask(HcTaskBase *task)
{
    LOGD("[ACCOUNT_LIFE_PLUGIN]: Do worker task begin.");
    if (task == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: The input task is NULL, cannot do task!");
        DecreaseCriticalCnt();
        return;
    }
    WorkerTask *workerTask = (WorkerTask *)task;
    if (workerTask->extTask == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: The inner task is NULL, cannot do task!");
        DecreaseCriticalCnt();
        return;
    }
    if (workerTask->extTask->execute == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: The ext func is NULL, cannot do task!");
        DecreaseCriticalCnt();
        return;
    }
    workerTask->extTask->execute(workerTask->extTask);
    DecreaseCriticalCnt();
    LOGD("[ACCOUNT_LIFE_PLUGIN]: Do worker task end.");
}

static void DestroyExtWorkerTask(ExtWorkerTask *task)
{
    if (task == NULL || task->destroy == NULL) {
        LOGI("[ACCOUNT_LIFE_PLUGIN]: The destroy func is NULL, cannot destroy task!");
        return;
    }
    task->destroy(task);
}

static void DestroyWorkerTask(HcTaskBase *workerTask)
{
    LOGD("[ACCOUNT_LIFE_PLUGIN]: Destroy worker task begin.");
    if (workerTask == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: The inner task is NULL, cannot do task!");
        DecreaseCriticalCnt();
        return;
    }
    DestroyExtWorkerTask(((WorkerTask *)workerTask)->extTask);
    RemoveAccountTaskRecordAndUnload(((WorkerTask *)workerTask)->taskId);
    DecreaseCriticalCnt();
    LOGD("[ACCOUNT_LIFE_PLUGIN]: Destroy worker task end.");
}

static int32_t ExecuteWorkerTask(struct ExtWorkerTask *extTask)
{
    if (extTask == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: The input task is NULL.");
        return HC_ERR_INVALID_PARAMS;
    }
    WorkerTask *baseTask = (WorkerTask *)HcMalloc(sizeof(WorkerTask), 0);
    if (baseTask == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Failed to allocate task memory!");
        DestroyExtWorkerTask(extTask);
        return HC_ERR_ALLOC_MEMORY;
    }
    baseTask->extTask = extTask;
    baseTask->base.doAction = DoWorkerTask;
    baseTask->base.destroy = DestroyWorkerTask;
    Uint8Buff taskIdBuff = { (uint8_t *)(&baseTask->taskId), sizeof(int32_t) };
    int32_t res = GetLoaderInstance()->generateRandom(&taskIdBuff);
    if (res != HC_SUCCESS) {
        LOGE("Generate taskId failed, res: %" LOG_PUB "d.", res);
        DestroyExtWorkerTask(extTask);
        HcFree(baseTask);
        return res;
    }
    res = LoadAccountAndAddTaskRecord(baseTask->taskId);
    if (res != HC_SUCCESS) {
        LOGE("Add account task record failed, res: %" LOG_PUB "d.", res);
        DestroyExtWorkerTask(extTask);
        HcFree(baseTask);
        return res;
    }
    if (PushTask((HcTaskBase *)baseTask) != HC_SUCCESS) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Push worker task fail.");
        RemoveAccountTaskRecordAndUnload(baseTask->taskId);
        DestroyExtWorkerTask(extTask);
        HcFree(baseTask);
        return HC_ERR_INIT_TASK_FAIL;
    }
    IncreaseCriticalCnt(ADD_TWO);
    return HC_SUCCESS;
}


static int32_t InitAccountLifecyclePluginCtx(void)
{
    g_accountPluginCtx = (AccountLifecyleExtPlugCtx *)HcMalloc(sizeof(AccountLifecyleExtPlugCtx), 0);
    if (g_accountPluginCtx == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Malloc memory failed.");
        return HC_ERROR;
    }
    const DeviceGroupManager *gmInstace = GetGmInstance();
    if (gmInstace == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Gm instance is null.");
        HcFree(g_accountPluginCtx);
        g_accountPluginCtx = NULL;
        return HC_ERR_INVALID_PARAMS;
    }
#ifdef DEV_AUTH_IS_ENABLE
    const CredManager *cmInstace = GetCredMgrInstance();
    if (cmInstace == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Cm instance is null.");
        HcFree(g_accountPluginCtx);
        g_accountPluginCtx = NULL;
        return HC_ERR_INVALID_PARAMS;
    }
    g_accountPluginCtx->addCredential = cmInstace->addCredential;
    g_accountPluginCtx->exportCredential = cmInstace->exportCredential;
    g_accountPluginCtx->deleteCredential = cmInstace->deleteCredential;
    g_accountPluginCtx->updateCredInfo = cmInstace->updateCredInfo;
    g_accountPluginCtx->queryCredInfoByCredId = QueryCredInfoByCredIdAndUid;
    g_accountPluginCtx->queryCredentialByParams = cmInstace->queryCredentialByParams;
    g_accountPluginCtx->destroyInfo = cmInstace->destroyInfo;
#endif
    g_accountPluginCtx->createGroup = gmInstace->createGroup;
    g_accountPluginCtx->deleteGroup = gmInstace->deleteGroup;
    g_accountPluginCtx->getGroupInfo = gmInstace->getGroupInfo;
    g_accountPluginCtx->getRegisterInfo = gmInstace->getRegisterInfo;
    g_accountPluginCtx->regCallback = gmInstace->regCallback;
    g_accountPluginCtx->unRegCallback = gmInstace->unRegCallback;
    g_accountPluginCtx->executeWorkerTask = ExecuteWorkerTask;
    g_accountPluginCtx->notifyAsyncTaskStart = NotifyAsyncTaskStart;
    g_accountPluginCtx->notifyAsyncTaskStop = NotifyAsyncTaskStop;
    return HC_SUCCESS;
}

int32_t SetAccountLifecyclePlugin(const CJson *inputParams, AccountLifecyleExtPlug *accountLifeCyclePlugin)
{
    g_accountLifeCyclePlugin = accountLifeCyclePlugin;
    if (g_accountLifeCyclePlugin == NULL || g_accountLifeCyclePlugin->base.init == NULL) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Input params are invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = InitAccountLifecyclePluginCtx();
    if (res != HC_SUCCESS) {
        LOGE("[ACCOUNT_LIFE_PLUGIN]: Get account life ctx failed.");
        return HC_ERROR;
    }
    return g_accountLifeCyclePlugin->base.init(&g_accountLifeCyclePlugin->base,
        inputParams, (const ExtPluginCtx *)g_accountPluginCtx);
}

void DestoryAccountLifecyclePlugin(void)
{
    if (g_accountLifeCyclePlugin != NULL && g_accountLifeCyclePlugin->base.destroy != NULL) {
        g_accountLifeCyclePlugin->base.destroy(&g_accountLifeCyclePlugin->base);
        g_accountLifeCyclePlugin = NULL;
    }
    if (g_accountPluginCtx != NULL) {
        HcFree(g_accountPluginCtx);
        g_accountPluginCtx = NULL;
    }
}