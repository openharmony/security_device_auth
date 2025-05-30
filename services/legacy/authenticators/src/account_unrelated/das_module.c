/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "das_module.h"
#include "common_defs.h"
#include "hc_log.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "das_task_main.h"
#include "das_token_manager.h"

#define DAS_CLIENT_STEP_MASK 0xF00F
#define DAS_CLIENT_FIRST_MESSAGE 0x0001

DECLARE_HC_VECTOR(TaskInModuleVec, void *);
IMPLEMENT_HC_VECTOR(TaskInModuleVec, void *, 1)

static TaskInModuleVec g_taskInModuleVec;

static int32_t RegisterDasLocalIdentity(const TokenManagerParams *params)
{
    return RegisterLocalIdentityInTask(params);
}

static int32_t UnregisterDasLocalIdentity(const TokenManagerParams *params)
{
    return UnregisterLocalIdentityInTask(params);
}

static int32_t DeleteDasPeerAuthInfo(const TokenManagerParams *params)
{
    return DeletePeerAuthInfoInTask(params);
}

static int32_t GetDasPublicKey(const TokenManagerParams *params, Uint8Buff *returnPk)
{
    return GetPublicKeyInTask(params, returnPk);
}

static bool IsDasMsgNeedIgnore(const CJson *in)
{
    int32_t message = 0;
    if (GetIntFromJson(in, FIELD_MESSAGE, &message) != HC_SUCCESS) {
        LOGD("There is no message code."); // There is no message code in the client's createTask request params
        return false;
    }
    if (((uint32_t)message & DAS_CLIENT_STEP_MASK) == DAS_CLIENT_FIRST_MESSAGE) {
        return false;
    }

    LOGI("The message needs to ignore, message: %" LOG_PUB "d.", message);
    return true;
}

static int CreateDasTask(int32_t *taskId, const CJson *in, CJson *out)
{
    if (taskId == NULL || in == NULL || out == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    if (IsDasMsgNeedIgnore(in)) {
        return HC_ERR_IGNORE_MSG;
    }
    Task *task = CreateTaskT(taskId, in, out);
    if (task == NULL) {
        LOGE("Create das task failed.");
        return HC_ERR_ALLOC_MEMORY;
    }

    if (g_taskInModuleVec.pushBackT(&g_taskInModuleVec, (void *)task) == NULL) {
        LOGE("Failed to push task!");
        task->destroyTask(task);
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int ProcessDasTask(int32_t taskId, const CJson* in, CJson* out, int32_t *status)
{
    if (status == NULL || in == NULL || out == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    uint32_t index;
    void **ptr = NULL;
    FOR_EACH_HC_VECTOR(g_taskInModuleVec, index, ptr) {
        Task *temp = (Task *)*ptr;
        if (taskId == temp->taskId) {
            return temp->processTask(temp, in, out, status);
        }
    }

    LOGE("Task doesn't exist, taskId: %" LOG_PUB "d.", taskId);
    return HC_ERR_TASK_ID_IS_NOT_MATCH;
}

static void DestroyDasTask(int taskId)
{
    uint32_t index;
    void **ptr = NULL;
    FOR_EACH_HC_VECTOR(g_taskInModuleVec, index, ptr) {
        Task *temp = (Task *)(*ptr);
        if (taskId == temp->taskId) {
            temp->destroyTask(temp);
            void *tempPtr = NULL;
            HC_VECTOR_POPELEMENT(&g_taskInModuleVec, &tempPtr, index);
            return;
        }
    }
}

static int32_t InitDasModule(void)
{
    int32_t res = InitDasProtocolEntities();
    if (res != HC_SUCCESS) {
        LOGE("Init das protocol entities failed.");
        return res;
    }
    g_taskInModuleVec = CREATE_HC_VECTOR(TaskInModuleVec);
    return HC_SUCCESS;
}

static void DestroyDasModule(void)
{
    uint32_t index;
    void **ptr = NULL;
    FOR_EACH_HC_VECTOR(g_taskInModuleVec, index, ptr) {
        ((Task *)(*ptr))->destroyTask((Task *)(*ptr));
    }
    DESTROY_HC_VECTOR(TaskInModuleVec, &g_taskInModuleVec);
    DestroyDasProtocolEntities();
}

static DasAuthModule g_dasModule = {
    .base.moduleType = DAS_MODULE,
    .base.init = InitDasModule,
    .base.destroy = DestroyDasModule,
    .base.isMsgNeedIgnore = IsDasMsgNeedIgnore,
    .base.createTask = CreateDasTask,
    .base.processTask = ProcessDasTask,
    .base.destroyTask = DestroyDasTask,
    .registerLocalIdentity = RegisterDasLocalIdentity,
    .unregisterLocalIdentity = UnregisterDasLocalIdentity,
    .deletePeerAuthInfo = DeleteDasPeerAuthInfo,
    .getPublicKey = GetDasPublicKey
};

const AuthModuleBase *GetDasModule(void)
{
    return (const AuthModuleBase *)&g_dasModule;
}
