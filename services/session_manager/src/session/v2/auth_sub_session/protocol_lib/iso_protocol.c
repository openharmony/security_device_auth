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

#include "iso_protocol.h"

#include "alg_loader.h"
#include "device_auth_defines.h"
#include "hc_log.h"

#define RAND_BYTE_LEN 16
#define ISO_TOKEN_LEN 32
#define ISO_AUTH_ID_MAX_LEN 256
#define ISO_SESSION_KEY_LEN 32

#define GENERATE_SESSION_KEY_STR "hichain_iso_session_key"

#define START_AUTH_EVENT_NAME "StartAuth"
#define CLEINT_START_REQ_EVENT_NAME "StartReq"
#define SERVER_START_RSP_EVENT_NAME "StartRsp"
#define CLEINT_FINISH_REQ_EVENT_NAME "FinishReq"
#define SERVER_FINISH_RSP_EVENT_NAME "FinishRsp"
#define FAIL_EVENT_NAME "AuthFail"

#define FIELD_RAND_CLIENT "randC"
#define FIELD_RAND_SERVER "randS"
#define FIELD_AUTH_ID_CLIENT "authIdC"
#define FIELD_AUTH_ID_SERVER "authIdS"
#define FIELD_TOKEN_CLIENT "tokenC"
#define FIELD_TOKEN_SERVER "tokenS"
#define FIELD_AUTH_RESULT_MAC "authResultMac"

#define FIELD_PROTOCOL_TYPE "protocolType"
#define FIELD_EVENT "event"
#define FIELD_PROTOCOL_DATA "protocolData"
#define FIELD_ERR_CODE "errCode"
#define FIELD_ERR_MSG "errMsg"

typedef struct {
    Uint8Buff psk;
    Uint8Buff randSelf;
    Uint8Buff randPeer;
    Uint8Buff authIdSelf;
    Uint8Buff authIdPeer;
    Uint8Buff tokenSelf;
    Uint8Buff tokenPeer;
    Uint8Buff authResultMac;
} IsoParams;

typedef struct {
    BaseProtocol base;
    IsoParams params;
} IsoProtocol;

typedef struct {
    int32_t curState;
    int32_t eventType;
    int32_t (*stateProcessFunc)(IsoProtocol *impl, const CJson *inputEvent, CJson **outputEvent);
    void (*exceptionHandleFunc)(int32_t errorCode, CJson **outputEvent);
    int32_t nextState;
} ProtocolStateNode;

static int32_t BuildSelfTokenMessage(uint8_t *message, int32_t messageLen,
    const IsoParams *params, const ProtectedMsg *msg)
{
    int32_t usedLen = 0;
    if (memcpy_s(message, messageLen, params->randSelf.val, params->randSelf.length) != EOK) {
        LOGE("Memcpy randSelf failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->randSelf.length;
    if (memcpy_s(message + usedLen, messageLen - usedLen, params->randPeer.val, params->randPeer.length) != EOK) {
        LOGE("Memcpy randPeer failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->randPeer.length;
    if (memcpy_s(message + usedLen, messageLen - usedLen, params->authIdPeer.val, params->authIdPeer.length) != EOK) {
        LOGE("Memcpy authIdPeer failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->authIdPeer.length;
    if (memcpy_s(message + usedLen, messageLen - usedLen, params->authIdSelf.val, params->authIdSelf.length) != EOK) {
        LOGE("Memcpy authIdSelf failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->authIdSelf.length;
    if (msg->selfMsg.length > 0 && msg->selfMsg.val != NULL) {
        if (memcpy_s(message + usedLen, messageLen - usedLen, msg->selfMsg.val, msg->selfMsg.length) != EOK) {
            LOGE("Memcpy selfMsg failed.");
            return HC_ERR_MEMORY_COPY;
        }
        usedLen += msg->selfMsg.length;
    }
    if (msg->peerMsg.length > 0 && msg->peerMsg.val != NULL) {
        if (memcpy_s(message + usedLen, messageLen - usedLen, msg->peerMsg.val, msg->peerMsg.length) != EOK) {
            LOGE("Memcpy peerMsg failed.");
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static int32_t BuildPeerTokenMessage(uint8_t *message, int32_t messageLen,
    const IsoParams *params, const ProtectedMsg *msg)
{
    int32_t usedLen = 0;
    if (memcpy_s(message, messageLen, params->randPeer.val, params->randPeer.length) != EOK) {
        LOGE("Memcpy randPeer failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->randPeer.length;
    if (memcpy_s(message + usedLen, messageLen - usedLen, params->randSelf.val, params->randSelf.length) != EOK) {
        LOGE("Memcpy randSelf failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->randSelf.length;
    if (memcpy_s(message + usedLen, messageLen - usedLen, params->authIdSelf.val, params->authIdSelf.length) != EOK) {
        LOGE("Memcpy authIdSelf failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->authIdSelf.length;
    if (memcpy_s(message + usedLen, messageLen - usedLen, params->authIdPeer.val, params->authIdPeer.length) != EOK) {
        LOGE("Memcpy authIdPeer failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->authIdPeer.length;
    if (msg->peerMsg.length > 0 && msg->peerMsg.val != NULL) {
        if (memcpy_s(message + usedLen, messageLen - usedLen, msg->peerMsg.val, msg->peerMsg.length) != EOK) {
            LOGE("Memcpy peerMsg failed.");
            return HC_ERR_MEMORY_COPY;
        }
        usedLen += msg->peerMsg.length;
    }
    if (msg->selfMsg.length > 0 && msg->selfMsg.val != NULL) {
        if (memcpy_s(message + usedLen, messageLen - usedLen, msg->selfMsg.val, msg->selfMsg.length) != EOK) {
            LOGE("Memcpy selfMsg failed.");
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static int32_t IsoCalToken(const IsoProtocol *protocol, Uint8Buff *token, bool isSelf)
{
    const IsoParams *params = &(protocol->params);
    const ProtectedMsg *msg = &(protocol->base.protectedMsg);
    int32_t length = params->randSelf.length + params->randPeer.length +
                     params->authIdSelf.length + params->authIdPeer.length +
                     msg->selfMsg.length + msg->peerMsg.length;
    uint8_t *message = (uint8_t *)HcMalloc(length, 0);
    if (message == NULL) {
        LOGE("Malloc for message failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = isSelf ? BuildSelfTokenMessage(message, length, params, msg) :
                           BuildPeerTokenMessage(message, length, params, msg);
    if (res != HC_SUCCESS) {
        HcFree(message);
        return res;
    }
    Uint8Buff messageBuf = { message, length };
    res = GetLoaderInstance()->computeHmac(&params->psk, &messageBuf, token, false);
    HcFree(message);
    if (res != HC_SUCCESS) {
        LOGE("ComputeHmac for token failed, res: %x.", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t IsoCombineHkdfSalt(IsoParams *params, Uint8Buff *hkdfSaltBuf, bool isClient)
{
    if (isClient) {
        if (memcpy_s(hkdfSaltBuf->val, hkdfSaltBuf->length, params->randSelf.val, params->randSelf.length) != EOK) {
            LOGE("Memcpy randSelf failed.");
            return HC_ERR_MEMORY_COPY;
        }
        if (memcpy_s(hkdfSaltBuf->val + params->randSelf.length, hkdfSaltBuf->length - params->randSelf.length,
            params->randPeer.val, params->randPeer.length) != EOK) {
            LOGE("Memcpy randPeer failed.");
            return HC_ERR_MEMORY_COPY;
        }
    } else {
        if (memcpy_s(hkdfSaltBuf->val, hkdfSaltBuf->length, params->randPeer.val, params->randPeer.length) != EOK) {
            LOGE("Memcpy randPeer failed.");
            return HC_ERR_MEMORY_COPY;
        }
        if (memcpy_s(hkdfSaltBuf->val + params->randPeer.length, hkdfSaltBuf->length - params->randPeer.length,
            params->randSelf.val, params->randSelf.length) != EOK) {
            LOGE("Memcpy randSelf failed.");
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static int32_t IsoGenSessionKey(IsoProtocol *impl, bool isClient)
{
    int32_t hkdfSaltLen = impl->params.randPeer.length + impl->params.randSelf.length;
    uint8_t *hkdfSalt = (uint8_t *)HcMalloc(hkdfSaltLen, 0);
    if (hkdfSalt == NULL) {
        LOGE("Malloc for hkdfSalt failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff hkdfSaltBuf = { hkdfSalt, hkdfSaltLen };
    int32_t res = IsoCombineHkdfSalt(&impl->params, &hkdfSaltBuf, isClient);
    if (res != HC_SUCCESS) {
        LOGE("IsoCombineHkdfSalt failed, res: %d", res);
        HcFree(hkdfSalt);
        return res;
    }
    Uint8Buff keyInfoBuf = { (uint8_t *)GENERATE_SESSION_KEY_STR, HcStrlen(GENERATE_SESSION_KEY_STR) };
    uint8_t sessionKeyVal[ISO_SESSION_KEY_LEN] = { 0 };
    Uint8Buff sessionKey = { sessionKeyVal, ISO_SESSION_KEY_LEN };
    res = GetLoaderInstance()->computeHkdf(&impl->params.psk, &hkdfSaltBuf, &keyInfoBuf, &sessionKey, false);
    HcFree(hkdfSalt);
    if (res != HC_SUCCESS) {
        LOGE("ComputeHkdf for sessionKey failed, res: %d", res);
        return res;
    }
    if (DeepCopyUint8Buff(&sessionKey, &impl->base.sessionKey) != HC_SUCCESS) {
        LOGE("copy sessionkey fail.");
        (void)memset_s(sessionKeyVal, ISO_SESSION_KEY_LEN, 0, ISO_SESSION_KEY_LEN);
        return HC_ERR_ALLOC_MEMORY;
    }
    (void)memset_s(sessionKeyVal, ISO_SESSION_KEY_LEN, 0, ISO_SESSION_KEY_LEN);
    return HC_SUCCESS;
}

static int32_t IsoGenAuthResultMac(const IsoParams *params, Uint8Buff *authResultMac)
{
    int32_t returnCode = 0;
    Uint8Buff messageBuf = { (uint8_t *)&returnCode, sizeof(int32_t) };
    int32_t res = GetLoaderInstance()->computeHmac(&params->psk, &messageBuf, authResultMac, false);
    if (res != HC_SUCCESS) {
        LOGE("Compute authResultMac failed, res: %x.", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ClientGenRandomProcEvent(IsoParams *params)
{
    uint8_t randCVal[RAND_BYTE_LEN] = { 0 };
    Uint8Buff randC = { randCVal, RAND_BYTE_LEN };
    int32_t res = GetLoaderInstance()->generateRandom(&randC);
    if (res != HC_SUCCESS) {
        LOGE("Generate randSelf failed, res: %x.", res);
        return res;
    }
    if (DeepCopyUint8Buff(&randC, &params->randSelf) != HC_SUCCESS) {
        LOGE("copy randC fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t ClientGenRandomBuildEvent(const IsoParams *params, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(json, FIELD_EVENT, CLEINT_START_REQ_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_RAND_CLIENT, params->randSelf.val, params->randSelf.length) != HC_SUCCESS) {
        LOGE("add randC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_AUTH_ID_CLIENT, params->authIdSelf.val,
        params->authIdSelf.length) != HC_SUCCESS) {
        LOGE("add authIdC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t ClientGenRandom(IsoProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    (void)inputEvent;
    int32_t res = ClientGenRandomProcEvent(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ClientGenRandomBuildEvent(&impl->params, outputEvent);
}

static int32_t ServerGenTokenParseEvent(const CJson *inputEvent, IsoParams *params)
{
    uint8_t randCVal[RAND_BYTE_LEN] = { 0 };
    Uint8Buff randC = { randCVal, RAND_BYTE_LEN };
    if (GetByteFromJson(inputEvent, FIELD_RAND_CLIENT, randC.val, randC.length) != HC_SUCCESS) {
        LOGE("get randC from receviedMsg fail.");
        return HC_ERR_JSON_GET;
    }
    const char *authIdCStr = GetStringFromJson(inputEvent, FIELD_AUTH_ID_CLIENT);
    if (authIdCStr == NULL) {
        LOGE("get authIdCStr from receviedMsg fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t authIdCLen = HcStrlen(authIdCStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (authIdCLen == 0 || authIdCLen > ISO_AUTH_ID_MAX_LEN) {
        LOGE("Invalid authIdCLen: %u.", authIdCLen);
        return HC_ERR_CONVERT_FAILED;
    }
    uint8_t authIdCVal[ISO_AUTH_ID_MAX_LEN] = { 0 };
    Uint8Buff authIdC = { authIdCVal, authIdCLen };
    if (HexStringToByte(authIdCStr, authIdC.val, authIdC.length) != HC_SUCCESS) {
        LOGE("HexStringToByte for authIdC failed.");
        return HC_ERR_CONVERT_FAILED;
    }
    if (DeepCopyUint8Buff(&randC, &params->randPeer) != HC_SUCCESS) {
        LOGE("copy randC fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyUint8Buff(&authIdC, &params->authIdPeer) != HC_SUCCESS) {
        LOGE("copy randC fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t ServerGenTokenProcEvent(IsoProtocol *impl)
{
    uint8_t randSVal[RAND_BYTE_LEN] = { 0 };
    Uint8Buff randS = { randSVal, RAND_BYTE_LEN };
    int32_t res = GetLoaderInstance()->generateRandom(&randS);
    if (res != HC_SUCCESS) {
        LOGE("Generate randSelf failed, res: %x.", res);
        return res;
    }
    if (DeepCopyUint8Buff(&randS, &impl->params.randSelf) != HC_SUCCESS) {
        LOGE("copy randS fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    uint8_t tokenValS[SHA256_LEN] = { 0 };
    Uint8Buff tokenS = { tokenValS, SHA256_LEN };
    res = IsoCalToken(impl, &tokenS, true);
    if (res != HC_SUCCESS) {
        LOGE("IsoCalServerToken failed, res: %x.", res);
        return res;
    }
    if (DeepCopyUint8Buff(&tokenS, &impl->params.tokenSelf) != HC_SUCCESS) {
        LOGE("copy tokenS fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t ServerGenTokenBuildEvent(const IsoParams *params, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(json, FIELD_EVENT, SERVER_START_RSP_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_RAND_SERVER, params->randSelf.val, params->randSelf.length) != HC_SUCCESS) {
        LOGE("add randS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_AUTH_ID_SERVER, params->authIdSelf.val,
        params->authIdSelf.length) != HC_SUCCESS) {
        LOGE("add authIdS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_TOKEN_SERVER, params->tokenSelf.val, params->tokenSelf.length) != HC_SUCCESS) {
        LOGE("add tokenS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t ServerGenToken(IsoProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    int32_t res = ServerGenTokenParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = ServerGenTokenProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ServerGenTokenBuildEvent(&impl->params, outputEvent);
}

static int32_t ClientGenTokenParseEvent(const CJson *inputEvent, IsoParams *params)
{
    uint8_t randSVal[RAND_BYTE_LEN] = { 0 };
    Uint8Buff randS = { randSVal, RAND_BYTE_LEN };
    if (GetByteFromJson(inputEvent, FIELD_RAND_SERVER, randS.val, randS.length) != HC_SUCCESS) {
        LOGE("get randS from inputEvent fail.");
        return HC_ERR_JSON_GET;
    }
    const char *authIdSStr = GetStringFromJson(inputEvent, FIELD_AUTH_ID_SERVER);
    if (authIdSStr == NULL) {
        LOGE("get authIdSStr from inputEvent fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t authIdSLen = HcStrlen(authIdSStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (authIdSLen == 0 || authIdSLen > ISO_AUTH_ID_MAX_LEN) {
        LOGE("Invalid authIdSLen: %u.", authIdSLen);
        return HC_ERR_CONVERT_FAILED;
    }
    uint8_t authIdSVal[ISO_AUTH_ID_MAX_LEN] = { 0 };
    Uint8Buff authIdS = { authIdSVal, authIdSLen };
    if (HexStringToByte(authIdSStr, authIdS.val, authIdS.length) != HC_SUCCESS) {
        LOGE("HexStringToByte for authIdS failed.");
        return HC_ERR_CONVERT_FAILED;
    }
    uint8_t tokenSVal[ISO_TOKEN_LEN] = { 0 };
    Uint8Buff tokenS = { tokenSVal, ISO_TOKEN_LEN };
    if (GetByteFromJson(inputEvent, FIELD_TOKEN_SERVER, tokenS.val, tokenS.length) != HC_SUCCESS) {
        LOGE("get tokenS from receviedMsg fail.");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyUint8Buff(&randS, &params->randPeer) != HC_SUCCESS) {
        LOGE("copy randS fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyUint8Buff(&authIdS, &params->authIdPeer) != HC_SUCCESS) {
        LOGE("copy authIdS fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyUint8Buff(&tokenS, &params->tokenPeer) != HC_SUCCESS) {
        LOGE("copy tokenS fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t ClientGenTokenProcEvent(IsoProtocol *impl)
{
    uint8_t tokenValS[SHA256_LEN] = { 0 };
    Uint8Buff tokenS = { tokenValS, SHA256_LEN };
    int32_t res = IsoCalToken(impl, &tokenS, false);
    if (res != HC_SUCCESS) {
        LOGE("IsoCalServerToken failed, res: %d", res);
        return res;
    }
    if ((impl->params.tokenPeer.length != tokenS.length) ||
        (memcmp(impl->params.tokenPeer.val, tokenS.val, tokenS.length) != 0)) {
        LOGE("The server token is inconsistent!");
        return PROOF_MISMATCH;
    }
    uint8_t tokenValC[SHA256_LEN] = { 0 };
    Uint8Buff tokenC = { tokenValC, SHA256_LEN };
    res = IsoCalToken(impl, &tokenC, true);
    if (res != HC_SUCCESS) {
        LOGE("IsoCalClientToken failed, res: %d", res);
        return res;
    }
    if (DeepCopyUint8Buff(&tokenC, &impl->params.tokenSelf) != HC_SUCCESS) {
        LOGE("copy tokenS fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t ClientGenTokenBuildEvent(const IsoParams *params, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(json, FIELD_EVENT, CLEINT_FINISH_REQ_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_TOKEN_CLIENT, params->tokenSelf.val, params->tokenSelf.length) != HC_SUCCESS) {
        LOGE("add tokenC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t ClientGenToken(IsoProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    int32_t res = ClientGenTokenParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = ClientGenTokenProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ClientGenTokenBuildEvent(&impl->params, outputEvent);
}

static int32_t ServerGenSessKeyParseEvent(const CJson *inputEvent, IsoParams *params)
{
    uint8_t tokenCVal[ISO_TOKEN_LEN] = { 0 };
    Uint8Buff tokenC = { tokenCVal, ISO_TOKEN_LEN };
    if (GetByteFromJson(inputEvent, FIELD_TOKEN_CLIENT, tokenC.val, tokenC.length) != HC_SUCCESS) {
        LOGE("get tokenC from receviedMsg fail.");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyUint8Buff(&tokenC, &params->tokenPeer) != HC_SUCCESS) {
        LOGE("copy tokenC fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t ServerGenSessKeyProcEvent(IsoProtocol *impl)
{
    uint8_t tokenValC[SHA256_LEN] = { 0 };
    Uint8Buff tokenC = { tokenValC, SHA256_LEN };
    int32_t res = IsoCalToken(impl, &tokenC, false);
    if (res != HC_SUCCESS) {
        LOGE("IsoCalClientToken failed, res: %d", res);
        return res;
    }
    if ((impl->params.tokenPeer.length != tokenC.length) ||
        (memcmp(impl->params.tokenPeer.val, tokenC.val, tokenC.length) != 0)) {
        LOGE("The client token is inconsistent!");
        return PROOF_MISMATCH;
    }
    uint8_t authResultMacVal[SHA256_LEN] = { 0 };
    Uint8Buff authResultMac = { authResultMacVal, SHA256_LEN };
    res = IsoGenAuthResultMac(&impl->params, &authResultMac);
    if (res != HC_SUCCESS) {
        return res;
    }
    if (DeepCopyUint8Buff(&authResultMac, &impl->params.authResultMac) != HC_SUCCESS) {
        LOGE("copy authResultMac fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    res = IsoGenSessionKey(impl, false);
    if (res != HC_SUCCESS) {
        LOGE("IsoGenSessionKey failed, res: %d", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ServerGenSessKeyBuildEvent(const IsoParams *params, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(json, FIELD_EVENT, SERVER_FINISH_RSP_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_AUTH_RESULT_MAC, params->authResultMac.val,
        params->authResultMac.length) != HC_SUCCESS) {
        LOGE("add authResultMac to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t ServerGenSessKey(IsoProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    int32_t res = ServerGenSessKeyParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = ServerGenSessKeyProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ServerGenSessKeyBuildEvent(&impl->params, outputEvent);
}

static int32_t ClientGenSessKeyParseEvent(const CJson *inputEvent, IsoParams *params)
{
    uint8_t authResultMacVal[HMAC_LEN] = { 0 };
    Uint8Buff authResultMac = { authResultMacVal, HMAC_LEN };
    if (GetByteFromJson(inputEvent, FIELD_AUTH_RESULT_MAC, authResultMac.val,
        authResultMac.length) != HC_SUCCESS) {
        LOGE("get authResultMac from inputEvent fail.");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyUint8Buff(&authResultMac, &params->authResultMac) != HC_SUCCESS) {
        LOGE("copy authResultMac fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t ClientGenSessKeyProcEvent(IsoProtocol *impl)
{
    uint8_t authResultMacVal[SHA256_LEN] = { 0 };
    Uint8Buff authResultMac = { authResultMacVal, SHA256_LEN };
    int32_t res = IsoGenAuthResultMac(&impl->params, &authResultMac);
    if (res != HC_SUCCESS) {
        return res;
    }
    if (memcmp(impl->params.authResultMac.val, authResultMac.val, SHA256_LEN) != 0) {
        LOGE("The authResultMac is isconsistent!");
        return HC_ERR_PEER_ERROR;
    }
    res = IsoGenSessionKey(impl, true);
    if (res != HC_SUCCESS) {
        LOGE("IsoGenSessionKey failed, res: %x.", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ClientGenSessKey(IsoProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    (void)outputEvent;
    int32_t res = ClientGenSessKeyParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ClientGenSessKeyProcEvent(impl);
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

static int32_t ThrowException(IsoProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    (void)impl;
    (void)outputEvent;
    int32_t peerErrorCode = HC_ERR_PEER_ERROR;
    (void)GetIntFromJson(inputEvent, FIELD_ERR_CODE, &peerErrorCode);
    LOGE("An exception occurred in the peer protocol. [Code]: %d", peerErrorCode);
    return peerErrorCode;
}

static const ProtocolStateNode STATE_MACHINE[] = {
    { CREATE_AS_CLIENT_STATE, START_AUTH_EVENT, ClientGenRandom, ReturnError, CLIENT_REQ_STATE },
    { CREATE_AS_SERVER_STATE, CLEINT_START_REQ_EVENT, ServerGenToken, NotifyPeerError, SERVER_RSP_STATE },
    { CLIENT_REQ_STATE, SERVER_START_RSP_EVENT, ClientGenToken, NotifyPeerError, CLIENT_FINISH_REQ_STATE },
    { CLIENT_REQ_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
    { SERVER_RSP_STATE, CLEINT_FINISH_REQ_EVENT, ServerGenSessKey, NotifyPeerError, SERVER_FINISH_STATE },
    { SERVER_RSP_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
    { CLIENT_FINISH_REQ_STATE, SERVER_FINISH_RSP_EVENT, ClientGenSessKey, NotifyPeerError, CLIENT_FINISH_STATE },
    { CLIENT_FINISH_REQ_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
};

static int32_t DecodeEvent(const CJson *receviedMsg)
{
    if (receviedMsg == NULL) {
        return START_AUTH_EVENT;
    }
    int32_t event;
    if (GetIntFromJson(receviedMsg, FIELD_EVENT, &event) != HC_SUCCESS) {
        LOGE("get event from receviedMsg fail.");
        return UNKNOWN_EVENT;
    }
    if (START_AUTH_EVENT <= event && event <= UNKNOWN_EVENT) {
        return event;
    }
    LOGE("unknown event.");
    return UNKNOWN_EVENT;
}

static int32_t IsoProtocolSwitchState(BaseProtocol *self, const CJson *receviedMsg, CJson **returnSendMsg)
{
    int32_t eventType = DecodeEvent(receviedMsg);
    for (uint32_t i = 0; i < sizeof(STATE_MACHINE) / sizeof(STATE_MACHINE[0]); i++) {
        if ((STATE_MACHINE[i].curState == self->curState) && (STATE_MACHINE[i].eventType == eventType)) {
            int32_t res = STATE_MACHINE[i].stateProcessFunc((IsoProtocol *)self, receviedMsg, returnSendMsg);
            if (res != HC_SUCCESS) {
                STATE_MACHINE[i].exceptionHandleFunc(res, returnSendMsg);
                self->curState = self->failState;
                return res;
            }
            LOGI("event: %d, curState: %d, nextState: %d", eventType, self->curState, STATE_MACHINE[i].nextState);
            self->curState = STATE_MACHINE[i].nextState;
            return HC_SUCCESS;
        }
    }
    LOGI("Unsupported event type. Ignore process. [Event]: %d, [CurState]: %d", eventType, self->curState);
    return HC_SUCCESS;
}

static int32_t StartIsoProtocol(BaseProtocol *self, CJson **returnSendMsg)
{
    if ((self == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((self->curState == self->finishState) || (self->curState == self->failState)) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return IsoProtocolSwitchState(self, NULL, returnSendMsg);
}

static int32_t ProcessIsoProtocol(BaseProtocol *self, const CJson *receviedMsg, CJson **returnSendMsg)
{
    if ((self == NULL) || (receviedMsg == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((self->curState == self->finishState) || (self->curState == self->failState)) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return IsoProtocolSwitchState(self, receviedMsg, returnSendMsg);
}

static int32_t SetIsoPsk(BaseProtocol *self, const Uint8Buff *psk)
{
    if ((self == NULL) || (psk == NULL) || (psk->val == NULL) || (psk->length == 0)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    IsoProtocol *impl = (IsoProtocol *)self;
    if (DeepCopyUint8Buff(psk, &impl->params.psk) != HC_SUCCESS) {
        LOGE("copy psk fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    LOGI("set psk success.");
    return HC_SUCCESS;
}

static int32_t SetIsoSelfProtectedMsg(BaseProtocol *self, const Uint8Buff *selfMsg)
{
    if ((self == NULL) || !IsUint8BuffValid(selfMsg, PROTECTED_MSG_MAX_LEN)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if (DeepCopyUint8Buff(selfMsg, &self->protectedMsg.selfMsg) != HC_SUCCESS) {
        LOGE("copy protected self msg fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t SetIsoPeerProtectedMsg(BaseProtocol *self, const Uint8Buff *peerMsg)
{
    if ((self == NULL) || !IsUint8BuffValid(peerMsg, PROTECTED_MSG_MAX_LEN)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if (DeepCopyUint8Buff(peerMsg, &self->protectedMsg.peerMsg) != HC_SUCCESS) {
        LOGE("copy protected peer msg fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t GetIsoSessionKey(BaseProtocol *self, Uint8Buff *returnSessionKey)
{
    if ((self == NULL) || (returnSessionKey == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if (self->curState != self->finishState) {
        LOGE("The protocol has not been completed, unable to obtain the protocol result!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return DeepCopyUint8Buff(&self->sessionKey, returnSessionKey);
}

static void DestroyIsoProtocol(BaseProtocol *self)
{
    if (self == NULL) {
        LOGD("self is null.");
        return;
    }
    IsoProtocol *impl = (IsoProtocol *)self;
    ClearFreeUint8Buff(&impl->base.protectedMsg.selfMsg);
    ClearFreeUint8Buff(&impl->base.protectedMsg.peerMsg);
    ClearFreeUint8Buff(&impl->base.sessionKey);
    ClearFreeUint8Buff(&impl->params.psk);
    ClearFreeUint8Buff(&impl->params.randSelf);
    ClearFreeUint8Buff(&impl->params.randPeer);
    ClearFreeUint8Buff(&impl->params.authIdSelf);
    ClearFreeUint8Buff(&impl->params.authIdPeer);
    ClearFreeUint8Buff(&impl->params.tokenSelf);
    ClearFreeUint8Buff(&impl->params.tokenPeer);
    ClearFreeUint8Buff(&impl->params.authResultMac);
    HcFree(impl);
}

int32_t CreateIsoProtocol(const void *baseParams, bool isClient, BaseProtocol **returnObj)
{
    const IsoInitParams *params = (const IsoInitParams *)baseParams;
    if ((params == NULL) || (returnObj == NULL) ||
        !IsUint8BuffValid(&params->authId, ISO_AUTH_ID_MAX_LEN)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    IsoProtocol *instance = (IsoProtocol *)HcMalloc(sizeof(IsoProtocol), 0);
    if (instance == NULL) {
        LOGE("allocate instance memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyUint8Buff(&params->authId, &instance->params.authIdSelf) != HC_SUCCESS) {
        HcFree(instance);
        return HC_ERR_ALLOC_MEMORY;
    }
    instance->base.name = PROTOCOL_TYPE_ISO;
    instance->base.beginState = isClient ? CREATE_AS_CLIENT_STATE : CREATE_AS_SERVER_STATE;
    instance->base.finishState = isClient ? CLIENT_FINISH_STATE : SERVER_FINISH_STATE;
    instance->base.failState = FAIL_STATE;
    instance->base.curState = instance->base.beginState;
    instance->base.start = StartIsoProtocol;
    instance->base.process = ProcessIsoProtocol;
    instance->base.setPsk = SetIsoPsk;
    instance->base.setSelfProtectedMsg = SetIsoSelfProtectedMsg;
    instance->base.setPeerProtectedMsg = SetIsoPeerProtectedMsg;
    instance->base.getSessionKey = GetIsoSessionKey;
    instance->base.destroy = DestroyIsoProtocol;
    *returnObj = (BaseProtocol *)instance;
    return HC_SUCCESS;
}
