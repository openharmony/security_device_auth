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

#include "mk_agree.h"

#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "mk_agree_task.h"

#define FIELD_EVENT "event"
#define FIELD_ERR_CODE "errCode"

typedef enum {
    START_EVENT = 0,
    START_MK_AGREE_REQUEST_EVENT,
    SEND_MK_AGREE_RESPONSE_EVENT,
    FAIL_EVENT,
    UNKNOWN_EVENT
} EventEnum;

typedef enum {
    CLIENT_INIT_STATE = 0,
    SERVER_WAIT_REQUEST_STATE,
    CLIENT_WAIT_RESPONSE_STATE,
    FINISH_STATE,
    FAIL_STATE
} StateEnum;

typedef struct {
    BaseCmd base;
    MkAgreeTaskBase *task;
} MkAgreeCmd;

typedef struct {
    int32_t curState;
    int32_t eventType;
    int32_t (*stateProcessFunc)(BaseCmd *, const CJson *, CJson **);
    void (*exceptionHandleFunc)(int32_t, CJson **);
    int32_t nextState;
} CmdStateNode;

static void ProcessMkAgreeError(int32_t errorCode, CJson **out)
{
    (void)errorCode;
    (void)out;
}

static void InformPeerError(int32_t errorCode, CJson **out)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("Failed to create json!");
        return;
    }
    if (AddIntToJson(json, FIELD_EVENT, FAIL_EVENT) != HC_SUCCESS) {
        LOGE("Failed to add event!");
        FreeJson(json);
        return;
    }
    if (AddIntToJson(json, FIELD_ERR_CODE, errorCode) != HC_SUCCESS) {
        LOGE("Failed to add error code!");
        FreeJson(json);
        return;
    }
    *out = json;
    return;
}

static int32_t ThrowException(BaseCmd *cmd, const CJson *in, CJson **out)
{
    LOGI("throw exception.");
    (void)cmd;
    (void)in;
    (void)out;
    return HC_ERR_UNSUPPORTED_OPCODE;
}

static int32_t AddEventByState(const BaseCmd *cmd, CJson *sendData)
{
    if (cmd->curState == CLIENT_INIT_STATE) {
        return AddIntToJson(sendData, FIELD_EVENT, START_MK_AGREE_REQUEST_EVENT);
    } else if (cmd->curState == SERVER_WAIT_REQUEST_STATE) {
        return AddIntToJson(sendData, FIELD_EVENT, SEND_MK_AGREE_RESPONSE_EVENT);
    } else {
        LOGE("Invalid state!");
        return HC_ERR_INVALID_PARAMS;
    }
}

static int32_t ProcessMkAgreeTask(BaseCmd *cmd, const CJson *in, CJson **out)
{
    LOGI("process mk agree task, current state is: %d", cmd->curState);
    CJson *sendData = CreateJson();
    if (sendData == NULL) {
        LOGE("Failed to create sendData!");
        return HC_ERR_JSON_CREATE;
    }
    MkAgreeCmd *impl = (MkAgreeCmd *)cmd;
    int32_t res = impl->task->process(impl->task, in, sendData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to process mk agree task!");
        FreeJson(sendData);
        return res;
    }
    if (cmd->curState == CLIENT_WAIT_RESPONSE_STATE) {
        FreeJson(sendData);
        return HC_SUCCESS;
    }
    CJson *sendToPeer = GetObjFromJson(sendData, FIELD_SEND_TO_PEER);
    if (sendToPeer == NULL) {
        LOGE("sendToPeer is null!");
        FreeJson(sendData);
        return HC_ERR_JSON_GET;
    }
    *out = DuplicateJson(sendToPeer);
    FreeJson(sendData);
    if (*out == NULL) {
        LOGE("Failed to duplicate send data!");
        return HC_ERR_JSON_FAIL;
    }
    res = AddEventByState(cmd, *out);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add event!");
        FreeJson(*out);
        *out = NULL;
        return res;
    }
    return HC_SUCCESS;
}

static const CmdStateNode STATE_MACHINE[] = {
    { CLIENT_INIT_STATE, START_EVENT, ProcessMkAgreeTask, InformPeerError, CLIENT_WAIT_RESPONSE_STATE },
    { SERVER_WAIT_REQUEST_STATE, START_MK_AGREE_REQUEST_EVENT, ProcessMkAgreeTask, InformPeerError, FINISH_STATE },
    { SERVER_WAIT_REQUEST_STATE, FAIL_EVENT, ThrowException, ProcessMkAgreeError, FAIL_STATE },
    { CLIENT_WAIT_RESPONSE_STATE, SEND_MK_AGREE_RESPONSE_EVENT, ProcessMkAgreeTask, ProcessMkAgreeError, FINISH_STATE },
    { CLIENT_WAIT_RESPONSE_STATE, FAIL_EVENT, ThrowException, ProcessMkAgreeError, FAIL_STATE },
};

static int32_t DecodeEvent(const CJson *in)
{
    if (in == NULL) {
        LOGI("start event.");
        return START_EVENT;
    }
    int32_t event;
    if (GetIntFromJson(in, FIELD_EVENT, &event) != HC_SUCCESS) {
        LOGE("Failed to get event from received msg!");
        return UNKNOWN_EVENT;
    }
    if (event < START_EVENT || event > UNKNOWN_EVENT) {
        LOGE("Invalid event!");
        return UNKNOWN_EVENT;
    }
    return event;
}

static int32_t SwitchState(BaseCmd *cmd, const CJson *in, CJson **out, CmdState *returnState)
{
    int32_t eventType = DecodeEvent(in);
    for (uint32_t i = 0; i < sizeof(STATE_MACHINE) / sizeof(STATE_MACHINE[0]); i++) {
        if ((STATE_MACHINE[i].curState == cmd->curState) && (STATE_MACHINE[i].eventType == eventType)) {
            int32_t res = STATE_MACHINE[i].stateProcessFunc(cmd, in, out);
            if (res != HC_SUCCESS) {
                STATE_MACHINE[i].exceptionHandleFunc(res, out);
                cmd->curState = cmd->failState;
                return res;
            }
            LOGI("event: %d, curState: %d, nextState: %d", eventType, cmd->curState, STATE_MACHINE[i].nextState);
            cmd->curState = STATE_MACHINE[i].nextState;
            *returnState = (cmd->curState == cmd->finishState) ? CMD_STATE_FINISH : CMD_STATE_CONTINUE;
            return HC_SUCCESS;
        }
    }
    LOGI("Unsupported event type. Ignore process. [Event]: %d, [CurState]: %d", eventType, cmd->curState);
    return HC_SUCCESS;
}

static int32_t StartMkAgreeCmd(BaseCmd *cmd, CJson **out)
{
    if ((cmd == NULL) || (out == NULL)) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (cmd->curState != cmd->beginState) {
        LOGE("Invalid state!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    CmdState state;
    return SwitchState(cmd, NULL, out, &state);
}

static int32_t ProcessMkAgreeCmd(BaseCmd *cmd, const CJson *in, CJson **out, CmdState *returnState)
{
    if ((cmd == NULL) || (in == NULL) || (out == NULL) || (returnState == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((cmd->curState == cmd->finishState) || (cmd->curState == cmd->failState)) {
        LOGE("Invalid state!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return SwitchState(cmd, in, out, returnState);
}

static void DestroyMkAgreeCmd(BaseCmd *cmd)
{
    if (cmd == NULL) {
        LOGE("cmd is null.");
        return;
    }
    MkAgreeCmd *impl = (MkAgreeCmd *)cmd;
    if (impl->task != NULL) {
        impl->task->destroy(impl->task);
    }
    HcFree(impl);
}

static int32_t InitMkAgreeTask(MkAgreeCmd *cmd, const MkAgreeParams *params, bool isClient)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("Failed to create json param!");
        return HC_ERR_JSON_CREATE;
    }
    if (AddBoolToJson(json, FIELD_IS_CLIENT, isClient) != HC_SUCCESS) {
        LOGE("Failed to add isClient!");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(json, FIELD_OS_ACCOUNT_ID, params->osAccountId) != HC_SUCCESS) {
        LOGE("Failed to add osAccountId!");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(json, FIELD_REAL_INFO, params->peerInfo) != HC_SUCCESS) {
        LOGE("Failed to add peerInfo!");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(json, FIELD_INDEX_KEY, params->pdidIndex) != HC_SUCCESS) {
        LOGE("Failed to add pdidIndex!");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    int32_t res = CreateMkAgreeTask(TASK_TYPE_PAKE, json, &cmd->task);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        LOGE("Failed to create mk agree task!");
    }
    return res;
}

static int32_t InitMkAgreeCmd(MkAgreeCmd *cmd, const MkAgreeParams *params,
    bool isClient, int32_t strategy)
{
    int32_t res = InitMkAgreeTask(cmd, params, isClient);
    if (res != HC_SUCCESS) {
        LOGE("Failed to init mk agree task!");
        return res;
    }
    cmd->base.type = MK_AGREE_CMD_TYPE;
    cmd->base.strategy = strategy;
    cmd->base.isCaller = isClient;
    cmd->base.beginState = isClient ? CLIENT_INIT_STATE : SERVER_WAIT_REQUEST_STATE;
    cmd->base.finishState = FINISH_STATE;
    cmd->base.failState = FAIL_STATE;
    cmd->base.curState = cmd->base.beginState;
    cmd->base.start = StartMkAgreeCmd;
    cmd->base.process = ProcessMkAgreeCmd;
    cmd->base.destroy = DestroyMkAgreeCmd;
    return HC_SUCCESS;
}

BaseCmd *CreateMkAgreeCmd(const void *baseParams, bool isClient, int32_t strategy)
{
    if (baseParams == NULL) {
        LOGE("Invalid input params!");
        return NULL;
    }
    MkAgreeCmd *cmd = (MkAgreeCmd *)HcMalloc(sizeof(MkAgreeCmd), 0);
    if (cmd == NULL) {
        LOGE("Failed to allocate memory for cmd!");
        return NULL;
    }
    const MkAgreeParams *params = (const MkAgreeParams *)baseParams;
    int32_t res = InitMkAgreeCmd(cmd, params, isClient, strategy);
    if (res != HC_SUCCESS) {
        HcFree(cmd);
        return NULL;
    }
    return (BaseCmd *)cmd;
}