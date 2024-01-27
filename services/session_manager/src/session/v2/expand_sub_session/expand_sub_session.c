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

#include "expand_sub_session.h"

#include "alg_loader.h"
#include "base_cmd.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_vector.h"
#include "json_utils.h"

#include "auth_code_import.h"
#include "mk_agree.h"
#include "pub_key_exchange.h"
#include "save_trusted_info.h"

#define TAG_LEN 16

#define EXPAND_SUB_SESSION_AAD "expand_sub_session_add"
#define EXPAND_SUB_SESSION_AAD_LEN 22

#define CRYPTO_ALG_AES_GCM_256 "AES_GCM_256"

#define FIELD_ENC_DATA "encData"
#define FIELD_ID "id"
#define FIELD_DATA "data"

DECLARE_HC_VECTOR(CmdList, BaseCmd *)
IMPLEMENT_HC_VECTOR(CmdList, BaseCmd *, 1)

typedef BaseCmd *(*CreateCmdFunc)(const void *params, bool isCaller, int32_t strategy);

typedef struct {
    int32_t type;
    CreateCmdFunc createCmdFunc;
} CmdComponent;

typedef struct {
    ExpandSubSession base;
    Uint8Buff nonce;
    Uint8Buff encKey;
    CmdList cmdList;
} ExpandSubSessionImpl;

static const CmdComponent CMD_COMPONENT_LIB[] = {
#ifdef ENABLE_AUTH_CODE_IMPORT
    {
        AUTH_CODE_IMPORT_CMD_TYPE,
        CreateAuthCodeImportCmd,
    },
#endif
#ifdef ENABLE_PUB_KEY_EXCHANGE
    {
        PUB_KEY_EXCHANGE_CMD_TYPE,
        CreatePubKeyExchangeCmd,
    },
#endif
#ifdef ENABLE_SAVE_TRUSTED_INFO
    {
        SAVE_TRUSTED_INFO_CMD_TYPE,
        CreateSaveTrustedInfoCmd,
    },
#endif
#ifdef ENABLE_PSEUDONYM
    {
        MK_AGREE_CMD_TYPE,
        CreateMkAgreeCmd,
    }
#endif
};

static const CmdComponent *GetCmdComponent(int32_t type)
{
    for (uint32_t i = 0; i < sizeof(CMD_COMPONENT_LIB) / sizeof(CMD_COMPONENT_LIB[0]); i++) {
        if (CMD_COMPONENT_LIB[i].type == type) {
            return &CMD_COMPONENT_LIB[i];
        }
    }
    return NULL;
}

static int32_t EncryptMsg(ExpandSubSessionImpl *impl, Uint8Buff *rawData, Uint8Buff *returnEncData)
{
    uint32_t encDataLen = rawData->length + TAG_LEN;
    uint8_t *encDataVal = (uint8_t *)HcMalloc(encDataLen, 0);
    if (encDataVal == NULL) {
        LOGE("allocate encDataVal memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff encData = { encDataVal, encDataLen };
    GcmParam gcmParam = { impl->nonce.val, impl->nonce.length,
        (uint8_t *)EXPAND_SUB_SESSION_AAD, EXPAND_SUB_SESSION_AAD_LEN };
    int32_t res = GetLoaderInstance()->aesGcmEncrypt(&impl->encKey, rawData,
        &gcmParam, false, &encData);
    if (res != HC_SUCCESS) {
        LOGE("aesGcmEncrypt rawData failed.");
        HcFree(encDataVal);
        return res;
    }
    returnEncData->val = encDataVal;
    returnEncData->length = encDataLen;
    return HC_SUCCESS;
}

static int32_t DecryptMsg(ExpandSubSessionImpl *impl, Uint8Buff *encData, Uint8Buff *returnRawData)
{
    uint32_t rawDataLen = encData->length - TAG_LEN;
    uint8_t *rawDataVal = (uint8_t *)HcMalloc(rawDataLen, 0);
    if (rawDataVal == NULL) {
        LOGE("allocate rawDataVal memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff rawData = { rawDataVal, rawDataLen };
    GcmParam gcmParam = { impl->nonce.val, impl->nonce.length,
        (uint8_t *)EXPAND_SUB_SESSION_AAD, EXPAND_SUB_SESSION_AAD_LEN };
    int32_t res = GetLoaderInstance()->aesGcmDecrypt(&impl->encKey, encData,
        &gcmParam, false, &rawData);
    if (res != HC_SUCCESS) {
        LOGE("aesGcmDecrypt rawData failed.");
        HcFree(rawDataVal);
        return res;
    }
    returnRawData->val = rawDataVal;
    returnRawData->length = rawDataLen;
    return HC_SUCCESS;
}

static int32_t GetRecvEncData(const CJson *receviedMsg, Uint8Buff *recvEncData)
{
    const char *base64Str = GetStringFromJson(receviedMsg, FIELD_ENC_DATA);
    if (base64Str == NULL) {
        LOGE("get encData from json failed.");
        return HC_ERR_JSON_GET;
    }
    uint32_t recvEncDataLen = HcStrlen(base64Str) / BYTE_TO_BASE64_MULTIPLIER * BYTE_TO_BASE64_DIVISOR;
    uint8_t *recvEncDataVal = (uint8_t *)HcMalloc(recvEncDataLen, 0);
    if (recvEncDataVal == NULL) {
        LOGE("allocate recvEncDataVal memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    uint32_t outLen = 0;
    if (GetLoaderInstance()->base64Decode(base64Str, HcStrlen(base64Str),
        recvEncDataVal, recvEncDataLen, &outLen) != HC_SUCCESS) {
        LOGE("base64 decode fail.");
        HcFree(recvEncDataVal);
        return HC_ERR_CONVERT_FAILED;
    }
    recvEncData->val = recvEncDataVal;
    recvEncData->length = outLen;
    return HC_SUCCESS;
}

static int32_t GetRecvCmdList(ExpandSubSessionImpl *impl, const CJson *receviedMsg, CJson **cmdList)
{
    Uint8Buff recvEncData;
    int32_t res = GetRecvEncData(receviedMsg, &recvEncData);
    if (res != HC_SUCCESS) {
        return res;
    }
    Uint8Buff recvRawData;
    res = DecryptMsg(impl, &recvEncData, &recvRawData);
    FreeUint8Buff(&recvEncData);
    if (res != HC_SUCCESS) {
        LOGE("decryptMsg fail.");
        return res;
    }
    CJson *rawRecvJson = CreateJsonFromString((const char *)(recvRawData.val));
    FreeUint8Buff(&recvRawData);
    if (rawRecvJson == NULL) {
        LOGE("create json from recvRawData fail.");
        return HC_ERR_JSON_CREATE;
    }
    *cmdList = rawRecvJson;
    return HC_SUCCESS;
}

static int32_t AddSendCmdDataToList(int32_t cmdType, const CJson *sendCmdData, CJson *sendCmdList)
{
    CJson *sendCmd = CreateJson();
    if (sendCmd == NULL) {
        LOGE("allocate sendCmd memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddIntToJson(sendCmd, FIELD_ID, cmdType) != HC_SUCCESS) {
        LOGE("add cmdType to json fail.");
        FreeJson(sendCmd);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToJson(sendCmd, FIELD_DATA, sendCmdData) != HC_SUCCESS) {
        LOGE("add cmdData to json fail.");
        FreeJson(sendCmd);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToArray(sendCmdList, sendCmd) != HC_SUCCESS) {
        LOGE("add cmdData to json fail.");
        FreeJson(sendCmd);
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t ProcCmd(BaseCmd *cmd, const CJson *recvCmdData, CJson *sendCmdList, bool *isFinish)
{
    CmdState cmdState;
    CJson *sendCmdData = NULL;
    int32_t res = cmd->process(cmd, recvCmdData, &sendCmdData, &cmdState);
    if (res != HC_SUCCESS) {
        if (sendCmdData != NULL) {
            (void)AddSendCmdDataToList(cmd->type, sendCmdData, sendCmdList);
            FreeJson(sendCmdData);
        }
        return res;
    }
    if (sendCmdData != NULL) {
        res = AddSendCmdDataToList(cmd->type, sendCmdData, sendCmdList);
        FreeJson(sendCmdData);
    }
    *isFinish = (cmdState == CMD_STATE_FINISH);
    return res;
}

static int32_t ProcRecvCmd(ExpandSubSessionImpl *impl, const CJson *recvCmd, CJson *sendCmdList)
{
    int32_t cmdType;
    if (GetIntFromJson(recvCmd, FIELD_ID, &cmdType) != HC_SUCCESS) {
        LOGE("get cmdType from recvCmd fail.");
        return HC_ERR_JSON_GET;
    }
    CJson *recvCmdData = GetObjFromJson(recvCmd, FIELD_DATA);
    if (recvCmdData == NULL) {
        LOGE("get recvCmdData from recvCmd fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t index;
    BaseCmd **iter;
    FOR_EACH_HC_VECTOR(impl->cmdList, index, iter) {
        BaseCmd *cmd = *iter;
        if (cmd->type != cmdType) {
            continue;
        }
        bool isFinish = false;
        int32_t res = ProcCmd(cmd, recvCmdData, sendCmdList, &isFinish);
        if (res == HC_SUCCESS && !isFinish) {
            return HC_SUCCESS;
        }
        if (res != HC_SUCCESS && cmd->strategy == CONTINUE_IF_ERROR) {
            res = HC_SUCCESS;
        }
        BaseCmd *popCmd = NULL;
        HC_VECTOR_POPELEMENT(&impl->cmdList, &popCmd, index);
        popCmd->destroy(popCmd);
        return res;
    }
    LOGE("cmd not found. [Cmd]: %d", cmdType);
    return HC_ERR_JSON_GET;
}

static int32_t ProcAllRecvCmds(ExpandSubSessionImpl *impl, const CJson *receviedMsg, CJson *sendCmdList)
{
    CJson *recvCmdList;
    int32_t res = GetRecvCmdList(impl, receviedMsg, &recvCmdList);
    if (res != HC_SUCCESS) {
        return res;
    }
    int32_t cmdNum = GetItemNum(recvCmdList);
    for (int32_t i = 0; i < cmdNum; i++) {
        res = ProcRecvCmd(impl, GetItemFromArray(recvCmdList, i), sendCmdList);
        if (res != HC_SUCCESS) {
            FreeJson(recvCmdList);
            return res;
        }
    }
    LOGI("proc all recv cmd success. [CmdNum]: %u", cmdNum);
    FreeJson(recvCmdList);
    return HC_SUCCESS;
}

static int32_t StartCmd(BaseCmd *cmd, CJson *sendCmdList)
{
    CJson *sendCmdData = NULL;
    int32_t res = cmd->start(cmd, &sendCmdData);
    if (res != HC_SUCCESS) {
        LOGE("start cmd error. [Cmd]: %d", cmd->type);
        if (sendCmdData != NULL) {
            (void)AddSendCmdDataToList(cmd->type, sendCmdData, sendCmdList);
            FreeJson(sendCmdData);
        }
        return res;
    }
    res = AddSendCmdDataToList(cmd->type, sendCmdData, sendCmdList);
    FreeJson(sendCmdData);
    return res;
}

static int32_t StartNewCmds(ExpandSubSessionImpl *impl, CJson *sendCmdList)
{
    uint32_t index;
    BaseCmd **iter;
    FOR_EACH_HC_VECTOR(impl->cmdList, index, iter) {
        BaseCmd *cmd = *iter;
        if ((!cmd->isCaller) || (cmd->curState != cmd->beginState)) {
            continue;
        }
        int32_t res = StartCmd(cmd, sendCmdList);
        if (res != HC_SUCCESS && cmd->strategy == ABORT_IF_ERROR) {
            return res;
        }
    }
    return HC_SUCCESS;
}

static int32_t BuildEncData(ExpandSubSessionImpl *impl, CJson *sendCmdList, CJson *sendMsg)
{
    char *rawSendStr = PackJsonToString(sendCmdList);
    if (rawSendStr == NULL) {
        LOGE("pack rawSendStr to string fail.");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    Uint8Buff sendEncData = { NULL, 0 };
    Uint8Buff sendRawData = { (uint8_t *)rawSendStr, HcStrlen(rawSendStr) + 1 };
    int32_t res = EncryptMsg(impl, &sendRawData, &sendEncData);
    FreeJsonString(rawSendStr);
    if (res != HC_SUCCESS) {
        LOGE("encryptMsg fail.");
        return res;
    }
    uint32_t base64StrLen = (sendEncData.length / BYTE_TO_BASE64_DIVISOR +
        (sendEncData.length % BYTE_TO_BASE64_DIVISOR != 0)) * BYTE_TO_BASE64_MULTIPLIER + 1;
    char *base64Str = (char *)HcMalloc(base64StrLen, 0);
    if (base64Str == NULL) {
        LOGE("allocate base64Str memory fail.");
        FreeUint8Buff(&sendEncData);
        return HC_ERR_ALLOC_MEMORY;
    }
    uint32_t outLen = 0;
    res = GetLoaderInstance()->base64Encode(sendEncData.val, sendEncData.length, base64Str, base64StrLen, &outLen);
    FreeUint8Buff(&sendEncData);
    if (res != HC_SUCCESS) {
        LOGE("base64 encode fail.");
        HcFree(base64Str);
        return HC_ERR_CONVERT_FAILED;
    }
    if (AddStringToJson(sendMsg, FIELD_ENC_DATA, base64Str) != HC_SUCCESS) {
        LOGE("add encData to json fail.");
        HcFree(base64Str);
        return HC_ERR_JSON_ADD;
    }
    HcFree(base64Str);
    return HC_SUCCESS;
}

static int32_t PackSendMsg(ExpandSubSessionImpl *impl, CJson *sendCmdList, CJson **returnSendMsg)
{
    CJson *sendMsg = CreateJson();
    if (sendMsg == NULL) {
        LOGE("allocate sendMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = BuildEncData(impl, sendCmdList, sendMsg);
    if (res != HC_SUCCESS) {
        FreeJson(sendMsg);
        return res;
    }
    *returnSendMsg = sendMsg;
    LOGI("pack send msg success.");
    return HC_SUCCESS;
}

static int32_t AddExpandProcess(ExpandSubSession *self, int32_t cmdType, void *params,
    bool isCaller, int32_t strategy)
{
    if ((self == NULL) || (params == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_NULL_PTR;
    }
    ExpandSubSessionImpl *impl = (ExpandSubSessionImpl *)self;
    if (impl->base.state != EXPAND_STATE_INIT) {
        LOGE("invalid state. [State]: %d", impl->base.state);
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    const CmdComponent *component = GetCmdComponent(cmdType);
    if (component == NULL) {
        LOGE("no cmd component found. cmdType = %d.", cmdType);
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    BaseCmd *instance = component->createCmdFunc(params, isCaller, strategy);
    if (instance == NULL) {
        LOGE("create cmd instance fail.");
        return HC_ERR_NULL_PTR;
    }
    if (impl->cmdList.pushBackT(&impl->cmdList, instance) == NULL) {
        LOGE("push cmd to list fail.");
        instance->destroy(instance);
        return HC_ERR_ALLOC_MEMORY;
    }
    LOGI("add expand process success. [Cmd]: %d, [IsCaller]: %s", cmdType, isCaller ? "Client" : "Server");
    return HC_SUCCESS;
}

static int32_t StartExpandSubSession(ExpandSubSession *self, CJson **returnSendMsg)
{
    if ((self == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ExpandSubSessionImpl *impl = (ExpandSubSessionImpl *)self;
    if (impl->base.state != EXPAND_STATE_INIT) {
        LOGE("invalid state. [State]: %d", impl->base.state);
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    if (HC_VECTOR_SIZE(&impl->cmdList) == 0) {
        LOGE("The list of cmd is empty.");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    CJson *sendCmdList = CreateJsonArray();
    if (sendCmdList == NULL) {
        LOGE("allocate sendCmdList memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = StartNewCmds(impl, sendCmdList);
    if (res != HC_SUCCESS) {
        if (GetItemNum(sendCmdList) > 0) {
            (void)PackSendMsg(impl, sendCmdList, returnSendMsg);
        }
        FreeJson(sendCmdList);
        return res;
    }
    res = PackSendMsg(impl, sendCmdList, returnSendMsg);
    FreeJson(sendCmdList);
    if (res == HC_SUCCESS) {
        impl->base.state = EXPAND_STATE_RUNNING;
    }
    return res;
}

static int32_t ProcessExpandSubSession(ExpandSubSession *self, const CJson *receviedMsg,
    CJson **returnSendMsg)
{
    if ((self == NULL) || (receviedMsg == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ExpandSubSessionImpl *impl = (ExpandSubSessionImpl *)self;
    if ((impl->base.state != EXPAND_STATE_INIT) && (impl->base.state != EXPAND_STATE_RUNNING)) {
        LOGE("invalid state. [State]: %d", impl->base.state);
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    CJson *sendCmdList = CreateJsonArray();
    if (sendCmdList == NULL) {
        LOGE("allocate sendCmdList memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res;
    do {
        res = ProcAllRecvCmds(impl, receviedMsg, sendCmdList);
        if (res != HC_SUCCESS) {
            break;
        }
        res = StartNewCmds(impl, sendCmdList);
    } while (0);
    if (GetItemNum(sendCmdList) > 0) {
        (void)PackSendMsg(impl, sendCmdList, returnSendMsg);
    }
    FreeJson(sendCmdList);
    if (res == HC_SUCCESS) {
        impl->base.state = HC_VECTOR_SIZE(&impl->cmdList) > 0 ? EXPAND_STATE_RUNNING : EXPAND_STATE_FINISH;
    }
    return res;
}

static void DestroyExpandSubSession(ExpandSubSession *self)
{
    if (self == NULL) {
        LOGD("self is NULL.");
        return;
    }
    ExpandSubSessionImpl *impl = (ExpandSubSessionImpl *)self;
    ClearFreeUint8Buff(&(impl->nonce));
    ClearFreeUint8Buff(&(impl->encKey));
    uint32_t index;
    BaseCmd **iter;
    FOR_EACH_HC_VECTOR(impl->cmdList, index, iter) {
        (*iter)->destroy(*iter);
    }
    DESTROY_HC_VECTOR(CmdList, &impl->cmdList);
    HcFree(impl);
}

int32_t CreateExpandSubSession(const Uint8Buff *nonce, const Uint8Buff *encKey, ExpandSubSession **returnObj)
{
    if ((nonce == NULL) || (nonce->val == NULL)) {
        LOGE("nonce is NULL");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((encKey == NULL) || (encKey->val == NULL)) {
        LOGE("encKey is NULL");
        return HC_ERR_INVALID_PARAMS;
    }
    if (returnObj == NULL) {
        LOGE("returnObj is NULL");
        return HC_ERR_INVALID_PARAMS;
    }
    ExpandSubSessionImpl *impl = (ExpandSubSessionImpl *)HcMalloc(sizeof(ExpandSubSessionImpl), 0);
    if (impl == NULL) {
        LOGE("allocate impl memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyUint8Buff(nonce, &(impl->nonce)) != HC_SUCCESS) {
        LOGE("copy nonce fail.");
        HcFree(impl);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyUint8Buff(encKey, &(impl->encKey)) != HC_SUCCESS) {
        LOGE("copy encKey fail.");
        ClearFreeUint8Buff(&impl->nonce);
        HcFree(impl);
        return HC_ERR_ALLOC_MEMORY;
    }
    impl->base.addCmd = AddExpandProcess;
    impl->base.start = StartExpandSubSession;
    impl->base.process = ProcessExpandSubSession;
    impl->base.destroy = DestroyExpandSubSession;
    impl->base.state = EXPAND_STATE_INIT;
    impl->cmdList = CREATE_HC_VECTOR(CmdList);
    *returnObj = (ExpandSubSession *)impl;
    return HC_SUCCESS;
}

bool IsCmdSupport(int32_t cmdId)
{
    return GetCmdComponent(cmdId) != NULL;
}
