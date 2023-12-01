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

#include "auth_code_import.h"

#include "alg_loader.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "identity_defines.h"

#define START_CMD_EVENT_NAME "StartCmd"
#define GEN_AUTH_CODE_EVENT_NAME "GenAuthCode"
#define IMPORT_AUTH_CODE_EVENT_NAME "ImportAuthCode"
#define FAIL_EVENT_NAME "CmdFail"

#define FIELD_USER_TYPE_CLIENT "userTypeC"
#define FIELD_USER_TYPE_SERVER "userTypeS"
#define FIELD_AUTH_ID_CLIENT "authIdC"
#define FIELD_AUTH_ID_SERVER "authIdS"
#define FIELD_AUTH_CODE "authCode"
#define FIELD_CLIENT_RESULT "clientResult"

#define FIELD_EVENT "event"
#define FIELD_ERR_CODE "errCode"
#define FIELD_ERR_MSG "errMsg"

typedef struct {
    int32_t userTypeSelf;
    int32_t userTypePeer;
    char *groupId;
    char *appId;
    Uint8Buff authIdSelf;
    Uint8Buff authIdPeer;
    Uint8Buff authCode;
} CmdParams;

typedef struct {
    BaseCmd base;
    CmdParams params;
} AuthCodeImportCmd;

typedef enum {
    START_EVENT = 0,
    CLIENT_SEND_DEV_IFNO_EVENT,
    SERVER_SEND_AUTH_CODE_EVENT,
    FAIL_EVENT,
    UNKNOWN_EVENT,
} EventEnum;

typedef enum {
    CREATE_AS_CLIENT_STATE = 0,
    CREATE_AS_SERVER_STATE,
    CLIENT_START_REQ_STATE,
    /* FINISH STATE */
    CLIENT_FINISH_STATE,
    SERVER_FINISH_STATE,
    /* FAIL STATE */
    FAIL_STATE
} StateEnum;

typedef struct {
    int32_t curState;
    int32_t eventType;
    int32_t (*stateProcessFunc)(BaseCmd *self, const CJson *inputEvent, CJson **outputEvent);
    void (*exceptionHandleFunc)(int32_t errorCode, CJson **outputEvent);
    int32_t nextState;
} CmdStateNode;

static int32_t BuildKeyAliasMsg(const Uint8Buff *serviceId, const Uint8Buff *keyType,
    const Uint8Buff *authId, Uint8Buff *keyAliasMsg)
{
    uint32_t usedLen = 0;
    if (memcpy_s(keyAliasMsg->val, keyAliasMsg->length, serviceId->val, serviceId->length) != EOK) {
        LOGE("Copy serviceId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen = usedLen + serviceId->length;
    if (memcpy_s(keyAliasMsg->val + usedLen, keyAliasMsg->length - usedLen, keyType->val, keyType->length) != EOK) {
        LOGE("Copy keyType failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen = usedLen + keyType->length;
    if (memcpy_s(keyAliasMsg->val + usedLen, keyAliasMsg->length - usedLen, authId->val, authId->length) != EOK) {
        LOGE("Copy authId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t CalKeyAlias(const Uint8Buff *serviceId, const Uint8Buff *keyType,
    const Uint8Buff *authId, Uint8Buff *keyAlias)
{
    Uint8Buff keyAliasMsg = { NULL, 0 };
    keyAliasMsg.length = serviceId->length + authId->length + keyType->length;
    keyAliasMsg.val = (uint8_t *)HcMalloc(keyAliasMsg.length, 0);
    if (keyAliasMsg.val == NULL) {
        LOGE("Malloc mem failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = BuildKeyAliasMsg(serviceId, keyType, authId, &keyAliasMsg);
    if (res != HC_SUCCESS) {
        HcFree(keyAliasMsg.val);
        return res;
    }
    res = GetLoaderInstance()->sha256(&keyAliasMsg, keyAlias);
    HcFree(keyAliasMsg.val);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 failed.");
        return res;
    }
    return HC_SUCCESS;
}

static int32_t CalServiceId(const char *appId, const char *groupId, Uint8Buff *serviceId)
{
    uint32_t groupIdLen = HcStrlen(groupId);
    uint32_t appIdLen = HcStrlen(appId);
    Uint8Buff serviceIdPlain = { NULL, 0 };
    serviceIdPlain.length = appIdLen + groupIdLen;
    serviceIdPlain.val = (uint8_t *)HcMalloc(serviceIdPlain.length, 0);
    if (serviceIdPlain.val == NULL) {
        LOGE("malloc serviceIdPlain.val failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(serviceIdPlain.val, serviceIdPlain.length, appId, appIdLen) != EOK) {
        LOGE("Copy service id: pkgName failed.");
        HcFree(serviceIdPlain.val);
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(serviceIdPlain.val + appIdLen,  serviceIdPlain.length - appIdLen, groupId, groupIdLen) != EOK) {
        LOGE("Copy service id: groupId failed.");
        HcFree(serviceIdPlain.val);
        return HC_ERR_MEMORY_COPY;
    }
    int32_t res = GetLoaderInstance()->sha256(&serviceIdPlain, serviceId);
    HcFree(serviceIdPlain.val);
    if (res != HC_SUCCESS) {
        LOGE("Service id Sha256 failed.");
        return res;
    }
    return HC_SUCCESS;
}

static int32_t GenerateKeyAlias(const CmdParams *params, Uint8Buff *keyAlias)
{
    uint8_t serviceIdVal[SHA256_LEN] = { 0 };
    Uint8Buff serviceId = { serviceIdVal, SHA256_LEN };
    int32_t res = CalServiceId(params->appId, params->groupId, &serviceId);
    if (res != HC_SUCCESS) {
        LOGE("CombineServiceId failed, res: %x.", res);
        return res;
    }
    Uint8Buff keyTypeBuff = { GetKeyTypePair(KEY_ALIAS_AUTH_TOKEN), KEY_TYPE_PAIR_LEN };
    return CalKeyAlias(&serviceId, &keyTypeBuff, &params->authIdPeer, keyAlias);
}

static int32_t ClientSendDevInfoBuildEvent(const CmdParams *params, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(json, FIELD_EVENT, CLIENT_SEND_DEV_IFNO_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_AUTH_ID_CLIENT, params->authIdSelf.val,
        params->authIdSelf.length) != HC_SUCCESS) {
        LOGE("add authIdC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(json, FIELD_USER_TYPE_CLIENT, params->userTypeSelf) != HC_SUCCESS) {
        LOGE("add userTypeC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t GetAuthIdPeerFromInput(const CJson *inputEvent, CmdParams *params, bool isClient)
{
    const char *authIdPeerStr = isClient ? GetStringFromJson(inputEvent, FIELD_AUTH_ID_SERVER) :
        GetStringFromJson(inputEvent, FIELD_AUTH_ID_CLIENT);
    if (authIdPeerStr == NULL) {
        LOGE("get authIdPeerStr from inputEvent fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t authIdPeerStrLen = HcStrlen(authIdPeerStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (authIdPeerStrLen == 0) {
        LOGE("Invalid authIdPeerStrLen: %u.", authIdPeerStrLen);
        return HC_ERR_CONVERT_FAILED;
    }
    if (InitUint8Buff(&params->authIdPeer, authIdPeerStrLen) != HC_SUCCESS) {
        LOGE("allocate authIdPeer memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (HexStringToByte(authIdPeerStr, params->authIdPeer.val, params->authIdPeer.length) != HC_SUCCESS) {
        LOGE("HexStringToByte for authIdPeerStr failed.");
        return HC_ERR_CONVERT_FAILED;
    }
    return HC_SUCCESS;
}

static int32_t ServerGenAuthCodeParseEvent(const CJson *inputEvent, CmdParams *params)
{
    int32_t res = GetAuthIdPeerFromInput(inputEvent, params, false);
    if (res != HC_SUCCESS) {
        return res;
    }
    int32_t userTypeC;
    if (GetIntFromJson(inputEvent, FIELD_USER_TYPE_CLIENT, &userTypeC) != HC_SUCCESS) {
        LOGE("get userTypeC from json fail.");
        return HC_ERR_JSON_GET;
    }
    params->userTypePeer = userTypeC;
    return HC_SUCCESS;
}

static int32_t ServerGenAuthCodeProcEvent(CmdParams *params)
{
    uint8_t authCodeVal[AUTH_CODE_LEN] = { 0 };
    Uint8Buff authCode = { authCodeVal, AUTH_CODE_LEN };
    int32_t res = GetLoaderInstance()->generateRandom(&authCode);
    if (res != HC_SUCCESS) {
        LOGE("generate auth code failed, res:%d", res);
        return res;
    }
    if (DeepCopyUint8Buff(&authCode, &params->authCode) != HC_SUCCESS) {
        LOGE("copy authcode fail.");
        return HC_ERR_MEMORY_COPY;
    }
    uint8_t keyAliasVal[KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAlias = { keyAliasVal, KEY_ALIAS_LEN };
    res = GenerateKeyAlias(params, &keyAlias);
    if (res != HC_SUCCESS) {
        LOGE("GenerateKeyAliasInIso failed, res:%d", res);
        return res;
    }
    LOGI("AuthCode alias(HEX): %x %x %x %x****.", keyAliasVal[DEV_AUTH_ZERO], keyAliasVal[DEV_AUTH_ONE],
        keyAliasVal[DEV_AUTH_TWO], keyAliasVal[DEV_AUTH_THREE]);
    ExtraInfo exInfo = { params->authIdPeer, params->userTypePeer, PAIR_TYPE_BIND };
    res = GetLoaderInstance()->importSymmetricKey(&keyAlias, &authCode, KEY_PURPOSE_MAC, &exInfo);
    if (res != HC_SUCCESS) {
        LOGE("import sym key fail.");
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ServerSendAuthCodeBuildEvent(const CmdParams *params, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(json, FIELD_EVENT, SERVER_SEND_AUTH_CODE_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_AUTH_ID_SERVER, params->authIdSelf.val,
        params->authIdSelf.length) != HC_SUCCESS) {
        LOGE("add authIdS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(json, FIELD_USER_TYPE_SERVER, params->userTypeSelf) != HC_SUCCESS) {
        LOGE("add userTypeS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_AUTH_CODE, params->authCode.val, params->authCode.length) != HC_SUCCESS) {
        LOGE("add authCode to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t ClientImportAuthCodeParseEvent(const CJson *inputEvent, CmdParams *params)
{
    int32_t userTypeS;
    if (GetIntFromJson(inputEvent, FIELD_USER_TYPE_SERVER, &userTypeS) != HC_SUCCESS) {
        LOGE("get userTypeS from json fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t res = GetAuthIdPeerFromInput(inputEvent, params, true);
    if (res != HC_SUCCESS) {
        return res;
    }
    uint8_t authCodeVal[AUTH_CODE_LEN] = { 0 };
    Uint8Buff authCode = { authCodeVal, AUTH_CODE_LEN };
    if (GetByteFromJson(inputEvent, FIELD_AUTH_CODE, authCode.val, authCode.length) != HC_SUCCESS) {
        LOGE("get authCode from json fail.");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyUint8Buff(&authCode, &params->authCode) != HC_SUCCESS) {
        LOGE("copy authCode fail.");
        (void)memset_s(authCodeVal, AUTH_CODE_LEN, 0, AUTH_CODE_LEN);
        return HC_ERR_MEMORY_COPY;
    }
    params->userTypePeer = userTypeS;
    return HC_SUCCESS;
}

static int32_t ClientImportAuthCodeProcEvent(const CmdParams *params)
{
    uint8_t keyAliasVal[KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAlias = { keyAliasVal, KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAlias(params, &keyAlias);
    if (res != HC_SUCCESS) {
        LOGE("GenerateKeyAliasInIso failed, res:%d", res);
        return res;
    }

    LOGI("AuthCode alias(HEX): %x %x %x %x****.", keyAliasVal[DEV_AUTH_ZERO], keyAliasVal[DEV_AUTH_ONE],
        keyAliasVal[DEV_AUTH_TWO], keyAliasVal[DEV_AUTH_THREE]);
    ExtraInfo exInfo = { params->authIdPeer, params->userTypePeer, PAIR_TYPE_BIND };
    res = GetLoaderInstance()->importSymmetricKey(&keyAlias, &(params->authCode), KEY_PURPOSE_MAC, &exInfo);
    if (res != HC_SUCCESS) {
        LOGE("import sym key fail.");
        return res;
    }
    return HC_SUCCESS;
}

static void ReturnError(int32_t errorCode, CJson **outputEvent)
{
    (void)errorCode;
    (void)outputEvent;
    return;
}

static void NotifyPeerError(int32_t errorCode, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return;
    }
    if (AddIntToJson(json, FIELD_EVENT, FAIL_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return;
    }
    if (AddIntToJson(json, FIELD_ERR_CODE, errorCode) != HC_SUCCESS) {
        LOGE("add errorCode to json fail.");
        FreeJson(json);
        return;
    }
    *outputEvent = json;
    return;
}

static int32_t ThrowException(BaseCmd *self, const CJson *baseEvent, CJson **outputEvent)
{
    (void)self;
    (void)outputEvent;
    int32_t peerErrorCode = HC_ERR_PEER_ERROR;
    (void)GetIntFromJson(baseEvent, FIELD_ERR_CODE, &peerErrorCode);
    LOGE("An exception occurred in the peer cmd. [Code]: %d", peerErrorCode);
    return peerErrorCode;
}

static int32_t ClientSendDevInfo(BaseCmd *self, const CJson *inputEvent, CJson **outputEvent)
{
    (void)inputEvent;
    AuthCodeImportCmd *impl = (AuthCodeImportCmd *)self;
    return ClientSendDevInfoBuildEvent(&impl->params, outputEvent);
}

static int32_t ServerGenAuthCode(BaseCmd *self, const CJson *inputEvent, CJson **outputEvent)
{
    AuthCodeImportCmd *impl = (AuthCodeImportCmd *)self;
    int32_t res = ServerGenAuthCodeParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = ServerGenAuthCodeProcEvent(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ServerSendAuthCodeBuildEvent(&impl->params, outputEvent);
}

static int32_t ClientImportAuthCode(BaseCmd *self, const CJson *inputEvent, CJson **outputEvent)
{
    (void)outputEvent;
    AuthCodeImportCmd *impl = (AuthCodeImportCmd *)self;
    int32_t res = ClientImportAuthCodeParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ClientImportAuthCodeProcEvent(&impl->params);
}

static const CmdStateNode STATE_MACHINE[] = {
    { CREATE_AS_CLIENT_STATE, START_EVENT, ClientSendDevInfo, NotifyPeerError, CLIENT_START_REQ_STATE },
    { CREATE_AS_SERVER_STATE, CLIENT_SEND_DEV_IFNO_EVENT, ServerGenAuthCode, NotifyPeerError, SERVER_FINISH_STATE },
    { CREATE_AS_SERVER_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
    { CLIENT_START_REQ_STATE, SERVER_SEND_AUTH_CODE_EVENT, ClientImportAuthCode, ReturnError, CLIENT_FINISH_STATE },
    { CLIENT_START_REQ_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
};

static int32_t DecodeEvent(const CJson *receviedMsg)
{
    if (receviedMsg == NULL) {
        return START_EVENT;
    }
    int32_t event;
    if (GetIntFromJson(receviedMsg, FIELD_EVENT, &event) != HC_SUCCESS) {
        LOGE("get event from receviedMsg fail.");
        return UNKNOWN_EVENT;
    }
    if (START_EVENT <= event && event <= UNKNOWN_EVENT) {
        return event;
    }
    LOGE("unknown event.");
    return UNKNOWN_EVENT;
}

static int32_t SwitchState(BaseCmd *self, const CJson *receviedMsg, CJson **returnSendMsg, CmdState *returnState)
{
    int32_t eventType = DecodeEvent(receviedMsg);
    for (uint32_t i = 0; i < sizeof(STATE_MACHINE) / sizeof(STATE_MACHINE[0]); i++) {
        if ((STATE_MACHINE[i].curState == self->curState) && (STATE_MACHINE[i].eventType == eventType)) {
            int32_t res = STATE_MACHINE[i].stateProcessFunc(self, receviedMsg, returnSendMsg);
            if (res != HC_SUCCESS) {
                STATE_MACHINE[i].exceptionHandleFunc(res, returnSendMsg);
                self->curState = self->failState;
                return res;
            }
            LOGI("event: %d, curState: %d, nextState: %d", eventType, self->curState, STATE_MACHINE[i].nextState);
            self->curState = STATE_MACHINE[i].nextState;
            *returnState = (self->curState == self->finishState) ? CMD_STATE_FINISH : CMD_STATE_CONTINUE;
            return HC_SUCCESS;
        }
    }
    LOGI("Unsupported event type. Ignore process. [Event]: %d, [CurState]: %d", eventType, self->curState);
    return HC_SUCCESS;
}

static int32_t StartAuthCodeImportCmd(BaseCmd *self, CJson **returnSendMsg)
{
    if ((self == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if (self->curState != self->beginState) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    CmdState state;
    return SwitchState(self, NULL, returnSendMsg, &state);
}

static int32_t ProcessAuthCodeImportCmd(BaseCmd *self, const CJson *receviedMsg,
    CJson **returnSendMsg, CmdState *returnState)
{
    if ((self == NULL) || (receviedMsg == NULL) || (returnSendMsg == NULL) || (returnState == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((self->curState == self->finishState) || (self->curState == self->failState)) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return SwitchState(self, receviedMsg, returnSendMsg, returnState);
}

static void DestroyAuthCodeImportCmd(BaseCmd *self)
{
    if (self == NULL) {
        LOGD("self is null.");
        return;
    }
    AuthCodeImportCmd *impl = (AuthCodeImportCmd *)self;
    ClearFreeUint8Buff(&impl->params.authCode);
    ClearFreeUint8Buff(&impl->params.authIdSelf);
    ClearFreeUint8Buff(&impl->params.authIdPeer);
    HcFree(impl->params.groupId);
    HcFree(impl->params.appId);
    HcFree(impl);
}

static bool IsAuthCodeImportParamsValid(const AuthCodeImportParams *params)
{
    if ((params == NULL) || (params->appId == NULL) || (params->authId.val == NULL) ||
        (params->authId.length == 0) || (params->groupId == NULL)) {
        return false;
    }
    return true;
}

static int32_t InitAuthCodeImportCmd(AuthCodeImportCmd *instance, const AuthCodeImportParams *params,
    bool isCaller, int32_t strategy)
{
    if (DeepCopyUint8Buff(&params->authId, &(instance->params.authIdSelf)) != HC_SUCCESS) {
        LOGE("copy authIdSelf fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyString(params->appId, &(instance->params.appId)) != HC_SUCCESS) {
        LOGE("copy appId fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyString(params->groupId, &(instance->params.groupId)) != HC_SUCCESS) {
        LOGE("copy groupId fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    instance->params.userTypeSelf = params->userType;
    instance->base.type = AUTH_CODE_IMPORT_CMD_TYPE;
    instance->base.strategy = strategy;
    instance->base.isCaller = isCaller;
    instance->base.beginState = isCaller ? CREATE_AS_CLIENT_STATE : CREATE_AS_SERVER_STATE;
    instance->base.finishState = isCaller ? CLIENT_FINISH_STATE : SERVER_FINISH_STATE;
    instance->base.failState = FAIL_STATE;
    instance->base.curState = instance->base.beginState;
    instance->base.start = StartAuthCodeImportCmd;
    instance->base.process = ProcessAuthCodeImportCmd;
    instance->base.destroy = DestroyAuthCodeImportCmd;
    return HC_SUCCESS;
}

BaseCmd *CreateAuthCodeImportCmd(const void *baseParams, bool isCaller, int32_t strategy)
{
    const AuthCodeImportParams *params = (const AuthCodeImportParams *)baseParams;
    if (!IsAuthCodeImportParamsValid(params)) {
        LOGE("invalid params.");
        return NULL;
    }
    AuthCodeImportCmd *instance = (AuthCodeImportCmd *)HcMalloc(sizeof(AuthCodeImportCmd), 0);
    if (instance == NULL) {
        LOGE("allocate instance memory fail.");
        return NULL;
    }
    int32_t res = InitAuthCodeImportCmd(instance, params, isCaller, strategy);
    if (res != HC_SUCCESS) {
        DestroyAuthCodeImportCmd((BaseCmd *)instance);
        return NULL;
    }
    return (BaseCmd *)instance;
}
