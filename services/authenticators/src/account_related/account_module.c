/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "account_module.h"
#include "account_auth_plugin_proxy.h"
#include "account_module_defines.h"
#include "account_multi_task_manager.h"
#include "account_version_util.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "json_utils.h"
#include "pake_v2_auth_client_task.h"
#include "pake_v2_auth_server_task.h"

#define ACCOUNT_CLIENT_FIRST_MESSAGE 0x0000
#define ACCOUNT_CLIENT_STEP_MASK 0x000F

typedef struct {
    AuthModuleBase base;
} AccountModule;

static bool IsAccountMsgNeedIgnore(const CJson *in)
{
    int32_t opCode;
    if (GetIntFromJson(in, FIELD_OPERATION_CODE, &opCode) != HC_SUCCESS) {
        LOGE("Get opCode failed.");
        return true;
    }
    const char *key = NULL;
    if (opCode == OP_BIND) {
        key = FIELD_MESSAGE;
    } else if (opCode == AUTHENTICATE) {
        key = FIELD_STEP;
    } else {
        LOGE("Invalid opCode: %d.", opCode);
        return true;
    }
    uint32_t message;
    if (GetIntFromJson(in, key, (int32_t *)&message) == HC_SUCCESS) {
        if ((message & ACCOUNT_CLIENT_STEP_MASK) != ACCOUNT_CLIENT_FIRST_MESSAGE) {
            LOGI("The message is repeated, ignore it, code: %u", message);
            return true;
        }
    }
    return false;
}

static int CreateAccountTask(int32_t *taskId, const CJson *in, CJson *out)
{
    if (taskId == NULL || in == NULL || out == NULL) {
        LOGE("Params is null in account task.");
        return HC_ERR_NULL_PTR;
    }
    if (IsAccountMsgNeedIgnore(in)) {
        return HC_ERR_IGNORE_MSG;
    }
    if (HasAccountAuthPlugin() == HC_SUCCESS) {
        return CreateAuthSession(taskId, in, out);
    }
    AccountMultiTaskManager *authManager = GetAccountMultiTaskManager();
    if (authManager == NULL) {
        LOGE("Get multi auth manager instance failed.");
        return HC_ERROR;
    }
    if (authManager->isTaskNumUpToMax() == true) {
        LOGE("Account auth task is full.");
        return HC_ERR_ACCOUNT_TASK_IS_FULL;
    }
    AccountTask *newTask = CreateAccountTaskT(taskId, in, out);
    if (newTask == NULL) {
        LOGE("Create account related task failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = authManager->addTaskToManager(newTask);
    if (res != HC_SUCCESS) {
        LOGE("Add new task into task manager failed, res: %d.", res);
        newTask->destroyTask(newTask);
    }
    return res;
}

static int ProcessAccountTask(int32_t taskId, const CJson *in, CJson *out, int32_t *status)
{
    if (HasAccountAuthPlugin() == HC_SUCCESS) {
        return ProcessAuthSession(&taskId, in, out, status);
    }
    AccountMultiTaskManager *authManager = GetAccountMultiTaskManager();
    if (authManager == NULL) {
        LOGE("Get multi auth manager instance failed.");
        return HC_ERROR;
    }
    AccountTask *currentTask = authManager->getTaskFromManager(taskId);
    if (currentTask == NULL) {
        LOGE("Get task from manager failed, taskId: %d.", taskId);
        return HC_ERR_TASK_ID_IS_NOT_MATCH;
    }
    LOGD("Begin process account related task, taskId: %d.", taskId);
    return currentTask->processTask(currentTask, in, out, status);
}

static void DestroyAccountTask(int taskId)
{
    if (HasAccountAuthPlugin() == HC_SUCCESS) {
        (void)DestroyAuthSession(taskId);
        return;
    }
    AccountMultiTaskManager *authManager = GetAccountMultiTaskManager();
    if (authManager == NULL) {
        LOGE("Get multi auth manager instance failed.");
        return;
    }
    LOGI("Delete taskId:%d from task manager.", taskId);
    authManager->deleteTaskFromManager(taskId);
}

static int32_t InitAccountModule(void)
{
    InitVersionInfos();
    InitAccountMultiTaskManager();
    return HC_SUCCESS;
}

static void DestroyAccountModule(void)
{
    DestroyAccountMultiTaskManager();
    DestroyVersionInfos();
}

static AccountModule g_module = {
    .base.moduleType = ACCOUNT_MODULE,
    .base.init = InitAccountModule,
    .base.destroy = DestroyAccountModule,
    .base.isMsgNeedIgnore = IsAccountMsgNeedIgnore,
    .base.createTask = CreateAccountTask,
    .base.processTask = ProcessAccountTask,
    .base.destroyTask = DestroyAccountTask,
};

const AuthModuleBase *GetAccountModule(void)
{
    return (const AuthModuleBase *)&g_module;
}
