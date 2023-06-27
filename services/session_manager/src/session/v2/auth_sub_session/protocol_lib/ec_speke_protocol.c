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

#include "ec_speke_protocol.h"

#include "alg_loader.h"
#include "device_auth_defines.h"
#include "hc_log.h"

#define EC_SPEKE_AUTH_ID_MAX_LEN 256
#define EC_SPEKE_SALT_LEN 16
#define EC_SPEKE_KCF_CODE_LEN 1
#define EC_SPEKE_SECRET_LEN 32
#define EC_SPEKE_EC_KEY_LEN 32
#define EC_SPEKE_SESSION_KEY_LEN 32
#define HICHAIN_SPEKE_BASE_INFO "hichain_speke_base_info"
#define SHARED_SECRET_DERIVED_FACTOR "hichain_speke_shared_secret_info"
#define HICHAIN_SPEKE_SESSIONKEY_INFO "hichain_speke_sessionkey_info"

// X25519 define
#define EC_SPEKE_PRIVATE_KEY_AND_MASK_HIGH 0xF8
#define EC_SPEKE_PRIVATE_KEY_AND_MASK_LOW  0x7F
#define EC_SPEKE_PRIVATE_KEY_OR_MASK_LOW   0x40

// event field define
#define FIELD_PROTOCOL_TYPE "protocolType"
#define FIELD_EVENT "event"
#define FIELD_PROTOCOL_DATA "protocolData"
#define FIELD_ERR_CODE "errCode"
#define FIELD_ERR_MSG "errMsg"

// protocol data field define
#define FIELD_SALT "salt"
#define FIELD_AUTH_ID_CLIENT "authIdC"
#define FIELD_AUTH_ID_SERVER "authIdS"
#define FIELD_EPK_CLIENT "epkC"
#define FIELD_EPK_SERVER "epkS"
#define FIELD_KCF_DATA_CLIENT "kcfDataC"
#define FIELD_KCF_DATA_SERVER "kcfDataS"

static const uint8_t KCF_CODE_CLIENT[EC_SPEKE_KCF_CODE_LEN] = { 0x04 };
static const uint8_t KCF_CODE_SERVER[EC_SPEKE_KCF_CODE_LEN] = { 0x03 };

typedef struct {
    EcSpekeCurveType curveType;
    Uint8Buff psk;
    Uint8Buff salt;
    Uint8Buff base;
    Uint8Buff eskSelf;
    Uint8Buff epkSelf;
    Uint8Buff epkPeer;
    Uint8Buff authIdSelf;
    Uint8Buff authIdPeer;
    Uint8Buff kcfDataSelf;
    Uint8Buff kcfDataPeer;
    Uint8Buff sharedSecret;
} EcSpekeParams;

typedef struct {
    BaseProtocol base;
    EcSpekeParams params;
} EcSpekeProtocol;

typedef struct {
    int32_t curState;
    int32_t eventType;
    int32_t (*stateProcessFunc)(EcSpekeProtocol *impl, const CJson *inputEvent, CJson **outputEvent);
    void (*exceptionHandleFunc)(int32_t errorCode, CJson **outputEvent);
    int32_t nextState;
} ProtocolStateNode;

static int32_t EcSpekeClientStartReqBuildEvent(const EcSpekeParams *params, CJson **outputEvent)
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
    if (AddByteToJson(json, FIELD_AUTH_ID_CLIENT, params->authIdSelf.val,
        params->authIdSelf.length) != HC_SUCCESS) {
        LOGE("add authIdC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t GetAuthIdPeerFromInput(const CJson *inputEvent, EcSpekeParams *params, bool isClient)
{
    const char *authIdPeerStr = isClient ? GetStringFromJson(inputEvent, FIELD_AUTH_ID_SERVER) :
        GetStringFromJson(inputEvent, FIELD_AUTH_ID_CLIENT);
    if (authIdPeerStr == NULL) {
        LOGE("get authIdPeerStr from inputEvent fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t authIdPeerStrLen = HcStrlen(authIdPeerStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (authIdPeerStrLen == 0 || authIdPeerStrLen > EC_SPEKE_AUTH_ID_MAX_LEN) {
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

static int32_t GetSaltFromInput(const CJson *inputEvent, EcSpekeParams *params)
{
    if (InitUint8Buff(&params->salt, EC_SPEKE_SALT_LEN) != HC_SUCCESS) {
        LOGE("allocate salt memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(inputEvent, FIELD_SALT, params->salt.val, params->salt.length) != HC_SUCCESS) {
        LOGE("get salt from inputEvent fail.");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

static int32_t GetEpkPeerFromInput(const CJson *inputEvent, EcSpekeParams *params, bool isClient)
{
    const char *epkPeerStr = isClient ? GetStringFromJson(inputEvent, FIELD_EPK_SERVER) :
        GetStringFromJson(inputEvent, FIELD_EPK_CLIENT);
    if (epkPeerStr == NULL) {
        LOGE("get epkPeerStr from inputEvent fail.");
        return HC_ERR_JSON_GET;
    }
    if (InitUint8Buff(&params->epkPeer, HcStrlen(epkPeerStr) / BYTE_TO_HEX_OPER_LENGTH) != HC_SUCCESS) {
        LOGE("allocate epkPeerStr memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (HexStringToByte(epkPeerStr, params->epkPeer.val, params->epkPeer.length) != HC_SUCCESS) {
        LOGE("HexStringToByte for epkPeerStr failed.");
        return HC_ERR_CONVERT_FAILED;
    }
    return HC_SUCCESS;
}

static int32_t GetKcfDataPeerFromInput(const CJson *inputEvent, EcSpekeParams *params, bool isClient)
{
    if (InitUint8Buff(&params->kcfDataPeer, SHA256_LEN) != HC_SUCCESS) {
        LOGE("allocate kcfDataPeer fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(inputEvent, (isClient ? FIELD_KCF_DATA_SERVER : FIELD_KCF_DATA_CLIENT),
        params->kcfDataPeer.val, params->kcfDataPeer.length) != HC_SUCCESS) {
        LOGE("get kcfDataPeer from inputEvent fail.");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

static int32_t EcSpekeClientStartReq(EcSpekeProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    (void)inputEvent;
    return EcSpekeClientStartReqBuildEvent(&impl->params, outputEvent);
}

static int32_t EcSpekeServerStartRspParseEvent(const CJson *inputEvent, EcSpekeParams *params)
{
    return GetAuthIdPeerFromInput(inputEvent, params, false);
}

static int32_t CalSalt(EcSpekeParams *params)
{
    if (InitUint8Buff(&params->salt, EC_SPEKE_SALT_LEN) != HC_SUCCESS) {
        LOGE("allocate salt memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GetLoaderInstance()->generateRandom(&params->salt);
    if (res != HC_SUCCESS) {
        LOGE("Generate salt failed, res: %x.", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t CalSecret(EcSpekeParams *params, Uint8Buff *secret)
{
    Uint8Buff keyInfo = { (uint8_t *)HICHAIN_SPEKE_BASE_INFO, HcStrlen(HICHAIN_SPEKE_BASE_INFO) };
    int32_t res = GetLoaderInstance()->computeHkdf(&(params->psk), &(params->salt), &keyInfo, secret, false);
    if (res != HC_SUCCESS) {
        LOGE("Derive secret from psk failed, res: %x.", res);
        return res;
    }
    ClearFreeUint8Buff(&params->psk);
    return HC_SUCCESS;
}

static int32_t EcSpekeCalBase(EcSpekeParams *params, Uint8Buff *secret)
{
    Algorithm algo;
    int32_t res;
    if (params->curveType == CURVE_TYPE_256) {
        algo = P256;
        /* P256 requires buffer for both X and Y coordinates. */
        res = InitUint8Buff(&params->base, 2 * EC_SPEKE_EC_KEY_LEN);
    } else if (params->curveType == CURVE_TYPE_25519) {
        algo = X25519;
        res = InitUint8Buff(&params->base, EC_SPEKE_EC_KEY_LEN);
    } else {
        LOGE("Unsupported curve type: %d", params->curveType);
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    if (res != HC_SUCCESS) {
        LOGE("allocate base memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    res = GetLoaderInstance()->hashToPoint(secret, algo, &params->base);
    if (res != HC_SUCCESS) {
        LOGE("HashToPoint from secret to base failed, res: %x", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t EcSpekeCalEskSelf(EcSpekeParams *params)
{
    if (InitUint8Buff(&params->eskSelf, EC_SPEKE_EC_KEY_LEN) != HC_SUCCESS) {
        LOGE("allocate eskSelf memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res;
    if (params->curveType == CURVE_TYPE_256) {
        res = GetLoaderInstance()->generateRandom(&(params->eskSelf));
        if (res != HC_SUCCESS) {
            LOGE("GenerateRandom for eskSelf failed, res: %x", res);
            return res;
        }
    } else if (params->curveType == CURVE_TYPE_25519) {
        res = GetLoaderInstance()->generateRandom(&(params->eskSelf));
        if (res != HC_SUCCESS) {
            LOGE("GenerateRandom for eskSelf failed, res: %x", res);
            return res;
        }
        params->eskSelf.val[EC_SPEKE_EC_KEY_LEN - 1] &= EC_SPEKE_PRIVATE_KEY_AND_MASK_HIGH;
        params->eskSelf.val[0] &= EC_SPEKE_PRIVATE_KEY_AND_MASK_LOW;
        params->eskSelf.val[0] |= EC_SPEKE_PRIVATE_KEY_OR_MASK_LOW;
    } else {
        LOGE("Unsupported curve type: %d", params->curveType);
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    return HC_SUCCESS;
}

static int32_t EcSpekeCalEpkSelf(EcSpekeParams *params)
{
    int32_t res;
    Algorithm algo;
    if (params->curveType == CURVE_TYPE_256) {
        algo = P256;
        /* P256 requires buffer for both X and Y coordinates. */
        res = InitUint8Buff(&params->epkSelf, 2 * EC_SPEKE_EC_KEY_LEN);
    } else if (params->curveType == CURVE_TYPE_25519) {
        algo = X25519;
        res = InitUint8Buff(&params->epkSelf, EC_SPEKE_EC_KEY_LEN);
    } else {
        LOGE("Unsupported curve type: %d", params->curveType);
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    if (res != HC_SUCCESS) {
        LOGE("allocate epkSelf memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    KeyBuff eskSelfBuff = { params->eskSelf.val, params->eskSelf.length, false };
    KeyBuff baseBuff = { params->base.val, params->base.length, false };
    res = GetLoaderInstance()->agreeSharedSecret(&eskSelfBuff, &baseBuff, algo, &params->epkSelf);
    if (res != HC_SUCCESS) {
        LOGE("AgreeSharedSecret for epkSelf failed, res: %x", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t CheckEpkPeerValid(EcSpekeParams *params)
{
    /* P256 requires buffer for both X and Y coordinates. */
    uint32_t epkPeerValidLen = (params->curveType == CURVE_TYPE_256) ?
        (2 * EC_SPEKE_EC_KEY_LEN) : EC_SPEKE_EC_KEY_LEN;
    if (params->epkPeer.length != epkPeerValidLen) {
        LOGE("Invalid epkPeer length: %u", params->epkPeer.length);
        return HC_ERR_BAD_MESSAGE;
    }
    Algorithm algo = (params->curveType == CURVE_TYPE_256) ? P256 : X25519;
    if (!GetLoaderInstance()->checkEcPublicKey(&params->epkPeer, algo)) {
        LOGE("Check EC_SPEKE publicKey fail.");
        return HC_ERR_BAD_MESSAGE;
    }
    return HC_SUCCESS;
}

static int32_t CalP(EcSpekeParams *params, Uint8Buff *p)
{
    KeyBuff eskSelfBuff = { params->eskSelf.val, params->eskSelf.length, false };
    KeyBuff epkPeerBuff = { params->epkPeer.val, params->epkPeer.length, false };
    Algorithm algo = (params->curveType == CURVE_TYPE_256) ? P256 : X25519;
    int32_t res = GetLoaderInstance()->agreeSharedSecret(&eskSelfBuff, &epkPeerBuff, algo, p);
    ClearFreeUint8Buff(&params->eskSelf);
    if (res != HC_SUCCESS) {
        LOGE("AgreeSharedSecret for p failed, res: %x", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t CalSidSelf(EcSpekeParams *params, Uint8Buff *sidSelf)
{
    uint32_t sidSelfMsgLen = params->authIdSelf.length + EC_SPEKE_EC_KEY_LEN;
    Uint8Buff sidSelfMsg = { NULL, 0 };
    if (InitUint8Buff(&sidSelfMsg, sidSelfMsgLen) != HC_SUCCESS) {
        LOGE("allocate sidSelfMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(sidSelfMsg.val, sidSelfMsg.length, params->authIdSelf.val, params->authIdSelf.length) != EOK) {
        LOGE("Memcpy for authIdSelf failed.");
        ClearFreeUint8Buff(&sidSelfMsg);
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(sidSelfMsg.val + params->authIdSelf.length, sidSelfMsg.length - params->authIdSelf.length,
        params->epkSelf.val, EC_SPEKE_EC_KEY_LEN) != EOK) { // only need x-coordinate
        LOGE("Memcpy for epkSelf_X failed.");
        ClearFreeUint8Buff(&sidSelfMsg);
        return HC_ERR_MEMORY_COPY;
    }
    int32_t res = GetLoaderInstance()->sha256(&sidSelfMsg, sidSelf);
    ClearFreeUint8Buff(&sidSelfMsg);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for sidSelf failed, res: %x", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t CalSidPeer(EcSpekeParams *params, Uint8Buff *sidPeer)
{
    uint32_t sidPeerMsgLen = params->authIdPeer.length + EC_SPEKE_EC_KEY_LEN;
    Uint8Buff sidPeerMsg = { NULL, 0 };
    if (InitUint8Buff(&sidPeerMsg, sidPeerMsgLen) != HC_SUCCESS) {
        LOGE("allocate sidPeerMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(sidPeerMsg.val, sidPeerMsg.length, params->authIdPeer.val, params->authIdPeer.length) != EOK) {
        LOGE("Memcpy for authIdPeer failed.");
        ClearFreeUint8Buff(&sidPeerMsg);
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(sidPeerMsg.val + params->authIdPeer.length, sidPeerMsg.length - params->authIdPeer.length,
        params->epkPeer.val, EC_SPEKE_EC_KEY_LEN) != EOK) { // only need x-coordinate
        LOGE("Memcpy for epkPeer_X failed.");
        ClearFreeUint8Buff(&sidPeerMsg);
        return HC_ERR_MEMORY_COPY;
    }
    int32_t res = GetLoaderInstance()->sha256(&sidPeerMsg, sidPeer);
    ClearFreeUint8Buff(&sidPeerMsg);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for sidPeer failed, res: %x", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t CalSid(EcSpekeParams *params, Uint8Buff *sid)
{
    uint8_t sidSelfVal[SHA256_LEN] = { 0 };
    uint8_t sidPeerVal[SHA256_LEN] = { 0 };
    Uint8Buff sidSelf = { sidSelfVal, SHA256_LEN };
    Uint8Buff sidPeer = { sidPeerVal, SHA256_LEN };
    int32_t res = CalSidSelf(params, &sidSelf);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = CalSidPeer(params, &sidPeer);
    if (res != HC_SUCCESS) {
        return res;
    }
    Uint8Buff *maxSid = &sidSelf;
    Uint8Buff *minSid = &sidPeer;
    if (GetLoaderInstance()->bigNumCompare(&sidSelf, &sidPeer) > 0) {
        maxSid = &sidPeer;
        minSid = &sidSelf;
    }
    if (memcpy_s(sid->val, sid->length, maxSid->val, maxSid->length) != EOK) {
        LOGE("Memcpy for maxSid failed.");
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(sid->val + maxSid->length, sid->length - maxSid->length, minSid->val, minSid->length) != EOK) {
        LOGE("Memcpy for minSid failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t CombineSharedSecretMsg(const Uint8Buff *p, const Uint8Buff *sid, Uint8Buff *sharedSecretMsg)
{
    uint32_t usedLen = 0;
    if (memcpy_s(sharedSecretMsg->val, sharedSecretMsg->length, sid->val, sid->length) != EOK) {
        LOGE("Memcpy for sidHex failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += sid->length;
    // Only need x-coordinate
    if (memcpy_s(sharedSecretMsg->val + usedLen, sharedSecretMsg->length - usedLen,
        p->val, EC_SPEKE_EC_KEY_LEN) != EOK) {
        LOGE("Memcpy for tmpSharedSecret failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += EC_SPEKE_EC_KEY_LEN;
    if (memcpy_s(sharedSecretMsg->val + usedLen, sharedSecretMsg->length - usedLen,
        SHARED_SECRET_DERIVED_FACTOR, HcStrlen(SHARED_SECRET_DERIVED_FACTOR)) != EOK) {
        LOGE("Memcpy for sharedSecret derived factor failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GenerateSharedSecretMsg(EcSpekeParams *params, Uint8Buff *sharedSecretMsg)
{
    uint32_t pLen = (params->curveType == CURVE_TYPE_256) ? (2 * EC_SPEKE_EC_KEY_LEN) : EC_SPEKE_EC_KEY_LEN;
    Uint8Buff p = { NULL, 0 };
    if (InitUint8Buff(&p, pLen) != HC_SUCCESS) {
        LOGE("allocate p memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = CalP(params, &p);
    if (res != HC_SUCCESS) {
        ClearFreeUint8Buff(&p);
        return res;
    }
    // sid is composed of client sid and server sid, so need twice SHA256_LEN
    uint8_t sidVal[SHA256_LEN * 2] = { 0 };
    Uint8Buff sid = { sidVal, SHA256_LEN * 2 };
    res = CalSid(params, &sid);
    if (res != HC_SUCCESS) {
        ClearFreeUint8Buff(&p);
        return res;
    }
    res = CombineSharedSecretMsg(&p, &sid, sharedSecretMsg);
    (void)memset_s(sid.val, sid.length, 0, sid.length);
    ClearFreeUint8Buff(&p);
    return res;
}

/*
 * '|' means joint
 * P = eskSelf . epkPeer
 *
 * sidSelf = hash(idSelf | epkSelf_X)
 * sidPeer = hash(idPeer | epkPeer_X)
 * sid = MAX(sidSelf, sidPeer) | MIN(sidSelf, sidPeer)
 *
 * derivedFactor = "hichain_speke_shared_secret_info"
 * hash = sha256
 * sharedSecret = hash(hex(sid) | P_X | derivedFactor)
 */
static int32_t CalSharedSecret(EcSpekeParams *params)
{
    uint32_t sharedSecretMsgLen = SHA256_LEN * 2 + EC_SPEKE_EC_KEY_LEN + HcStrlen(SHARED_SECRET_DERIVED_FACTOR);
    Uint8Buff sharedSecretMsg = { NULL, 0 };
    if (InitUint8Buff(&sharedSecretMsg, sharedSecretMsgLen) != HC_SUCCESS) {
        LOGE("allocate sharedSecretMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateSharedSecretMsg(params, &sharedSecretMsg);
    if (res != HC_SUCCESS) {
        ClearFreeUint8Buff(&sharedSecretMsg);
        return res;
    }
    if (InitUint8Buff(&params->sharedSecret, SHA256_LEN)) {
        LOGE("allocate sharedSecret memory fail.");
        ClearFreeUint8Buff(&sharedSecretMsg);
        return HC_ERR_ALLOC_MEMORY;
    }
    res = GetLoaderInstance()->sha256(&sharedSecretMsg, &params->sharedSecret);
    ClearFreeUint8Buff(&sharedSecretMsg);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for sharedSecret failed, res: %x", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t CombineProtectedMsg(EcSpekeProtocol *impl, bool isVerify, Uint8Buff *kcfDataMsg, uint32_t usedLen)
{
    Uint8Buff *firstProtectedMsg = isVerify ? &(impl->base.protectedMsg.peerMsg) : &(impl->base.protectedMsg.selfMsg);
    Uint8Buff *secondProtectedMsg = isVerify ? &(impl->base.protectedMsg.selfMsg) : &(impl->base.protectedMsg.peerMsg);
    if (IsUint8BuffValid(firstProtectedMsg, PROTECTED_MSG_MAX_LEN)) {
        if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
            firstProtectedMsg->val, firstProtectedMsg->length) != EOK) {
            LOGE("Memcpy firstProtectedMsg failed.");
            return HC_ERR_MEMORY_COPY;
        }
        usedLen += firstProtectedMsg->length;
    }
    if (IsUint8BuffValid(secondProtectedMsg, PROTECTED_MSG_MAX_LEN)) {
        if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
            secondProtectedMsg->val, secondProtectedMsg->length) != EOK) {
            LOGE("Memcpy secondProtectedMsg failed.");
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static int32_t GenerateKcfDataMsg(EcSpekeProtocol *impl, bool isClient, bool isVerify, Uint8Buff *kcfDataMsg)
{
    EcSpekeParams *params = &impl->params;
    const uint8_t *kcfCode = ((isClient && !isVerify) || (!isClient && isVerify)) ? KCF_CODE_CLIENT : KCF_CODE_SERVER;
    if (memcpy_s(kcfDataMsg->val, kcfDataMsg->length, kcfCode, EC_SPEKE_KCF_CODE_LEN) != HC_SUCCESS) {
        LOGE("Memcpy for kcfCode failed.");
        return HC_ERR_MEMORY_COPY;
    }
    uint32_t usedLen = EC_SPEKE_KCF_CODE_LEN;
    Uint8Buff *epkClient = isClient ? &params->epkSelf : &params->epkPeer;
    Uint8Buff *epkServer = isClient ? &params->epkPeer : &params->epkSelf;
    if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
        epkClient->val, EC_SPEKE_EC_KEY_LEN) != EOK) { // Only the x-coordinate of epk is required
        LOGE("Memcpy for epkClient failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += EC_SPEKE_EC_KEY_LEN;
    if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
        epkServer->val, EC_SPEKE_EC_KEY_LEN) != EOK) { // Only the x-coordinate of epk is required
        LOGE("Memcpy for epkServer failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += EC_SPEKE_EC_KEY_LEN;
    if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
        params->sharedSecret.val, params->sharedSecret.length) != EOK) {
        LOGE("Memcpy for sharedSecret failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->sharedSecret.length;
    if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
        params->base.val, EC_SPEKE_EC_KEY_LEN) != EOK) { // Only the x-coordinate of base is required
        LOGE("Memcpy for base_X failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += EC_SPEKE_EC_KEY_LEN;
    return CombineProtectedMsg(impl, isVerify, kcfDataMsg, usedLen);
}

/*
 * kcfdataClient = SHA256(byte(0x04), PK_CLIENT_X, PK_SERVER_X, sharedSecret, base_X)
 * kcfdataServer = SHA256(byte(0x03), PK_CLIENT_X, PK_SERVER_X, sharedSecret, base_X)
 */
static int32_t CalKcfDataSelf(EcSpekeProtocol *impl, bool isClient)
{
    uint32_t kcfDataMsgLen = EC_SPEKE_KCF_CODE_LEN + EC_SPEKE_EC_KEY_LEN + EC_SPEKE_EC_KEY_LEN +
        SHA256_LEN + EC_SPEKE_EC_KEY_LEN + impl->base.protectedMsg.selfMsg.length +
        impl->base.protectedMsg.peerMsg.length;
    Uint8Buff kcfDataMsg = { NULL, 0 };
    if (InitUint8Buff(&kcfDataMsg, kcfDataMsgLen) != HC_SUCCESS) {
        LOGE("allocate kcfDataMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateKcfDataMsg(impl, isClient, false, &kcfDataMsg);
    if (res != HC_SUCCESS) {
        ClearFreeUint8Buff(&kcfDataMsg);
        return res;
    }
    if (InitUint8Buff(&impl->params.kcfDataSelf, SHA256_LEN) != HC_SUCCESS) {
        LOGE("allocate kcfDataSelf memory fail.");
        ClearFreeUint8Buff(&kcfDataMsg);
        return HC_ERR_ALLOC_MEMORY;
    }
    res = GetLoaderInstance()->sha256(&kcfDataMsg, &impl->params.kcfDataSelf);
    ClearFreeUint8Buff(&kcfDataMsg);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for kcfDataSelf failed, res: %x", res);
        return res;
    }
    return HC_SUCCESS;
}

/*
 * kcfdataClient = SHA256(byte(0x04), PK_CLIENT_X, PK_SERVER_X, sharedSecret, base_X)
 * kcfdataServer = SHA256(byte(0x03), PK_CLIENT_X, PK_SERVER_X, sharedSecret, base_X)
 */
static int32_t VerifyKcfDataPeer(EcSpekeProtocol *impl, bool isClient)
{
    uint32_t kcfDataMsgLen = EC_SPEKE_KCF_CODE_LEN + EC_SPEKE_EC_KEY_LEN + EC_SPEKE_EC_KEY_LEN +
        SHA256_LEN + EC_SPEKE_EC_KEY_LEN + impl->base.protectedMsg.selfMsg.length +
        impl->base.protectedMsg.peerMsg.length;
    Uint8Buff kcfDataMsg = { NULL, 0 };
    if (InitUint8Buff(&kcfDataMsg, kcfDataMsgLen) != HC_SUCCESS) {
        LOGE("allocate kcfDataMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateKcfDataMsg(impl, isClient, true, &kcfDataMsg);
    if (res != HC_SUCCESS) {
        ClearFreeUint8Buff(&kcfDataMsg);
        return res;
    }
    uint8_t kcfDataPeerVal[SHA256_LEN] = { 0 };
    Uint8Buff kcfDataPeer = { kcfDataPeerVal, SHA256_LEN };
    res = GetLoaderInstance()->sha256(&kcfDataMsg, &kcfDataPeer);
    ClearFreeUint8Buff(&kcfDataMsg);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 for kcfDataPeer failed, res: %x", res);
        return res;
    }
    if (memcmp(kcfDataPeer.val, impl->params.kcfDataPeer.val, kcfDataPeer.length) != 0) {
        LOGE("verify kcfData fail.");
        (void)memset_s(kcfDataPeer.val, kcfDataPeer.length, 0, kcfDataPeer.length);
        return PROOF_MISMATCH;
    }
    return HC_SUCCESS;
}

static int32_t CalSessionKey(EcSpekeProtocol *impl)
{
    if (InitUint8Buff(&impl->base.sessionKey, EC_SPEKE_SESSION_KEY_LEN) != HC_SUCCESS) {
        LOGE("allocate sessionKey memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff keyInfo = { (uint8_t *)HICHAIN_SPEKE_SESSIONKEY_INFO, HcStrlen(HICHAIN_SPEKE_SESSIONKEY_INFO) };
    int32_t res = GetLoaderInstance()->computeHkdf(&impl->params.sharedSecret, &impl->params.salt, &keyInfo,
        &impl->base.sessionKey, false);
    ClearFreeUint8Buff(&impl->params.salt);
    ClearFreeUint8Buff(&impl->params.sharedSecret);
    if (res != HC_SUCCESS) {
        LOGE("ComputeHkdf for sessionKey failed, res: %x", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t EcSpekeServerStartRspProcEvent(EcSpekeProtocol *impl)
{
    int32_t res = CalSalt(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    uint8_t secretVal[EC_SPEKE_SECRET_LEN] = { 0 };
    Uint8Buff secret = { secretVal, EC_SPEKE_SECRET_LEN };
    res = CalSecret(&impl->params, &secret);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = EcSpekeCalBase(&impl->params, &secret);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = EcSpekeCalEskSelf(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return EcSpekeCalEpkSelf(&impl->params);
}

static int32_t EcSpekeServerStartRspBuildEvent(const EcSpekeParams *params, CJson **outputEvent)
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
    if (AddByteToJson(json, FIELD_SALT, params->salt.val, params->salt.length) != HC_SUCCESS) {
        LOGE("add salt to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_EPK_SERVER, params->epkSelf.val, params->epkSelf.length) != HC_SUCCESS) {
        LOGE("add epkS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_AUTH_ID_SERVER, params->authIdSelf.val,
        params->authIdSelf.length) != HC_SUCCESS) {
        LOGE("add authIdS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t EcSpekeServerStartRsp(EcSpekeProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    int32_t res = EcSpekeServerStartRspParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = EcSpekeServerStartRspProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return EcSpekeServerStartRspBuildEvent(&impl->params, outputEvent);
}

static int32_t EcSpekeClientFinishReqParseEvent(const CJson *inputEvent, EcSpekeParams *params)
{
    int32_t res = GetSaltFromInput(inputEvent, params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = GetEpkPeerFromInput(inputEvent, params, true);
    if (res != HC_SUCCESS) {
        return res;
    }
    return GetAuthIdPeerFromInput(inputEvent, params, true);
}

static int32_t EcSpekeClientFinishReqProcEvent(EcSpekeProtocol *impl)
{
    uint8_t secretVal[EC_SPEKE_SECRET_LEN] = { 0 };
    Uint8Buff secret = { secretVal, EC_SPEKE_SECRET_LEN };
    int32_t res = CalSecret(&impl->params, &secret);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = EcSpekeCalBase(&impl->params, &secret);
    (void)memset_s(secret.val, secret.length, 0, secret.length);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = EcSpekeCalEskSelf(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = EcSpekeCalEpkSelf(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = CheckEpkPeerValid(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = CalSharedSecret(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return CalKcfDataSelf(impl, true);
}

static int32_t EcSpekeClientFinishReqBuildEvent(EcSpekeParams *params, CJson **outputEvent)
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
    if (AddByteToJson(json, FIELD_EPK_CLIENT, params->epkSelf.val, params->epkSelf.length) != HC_SUCCESS) {
        LOGE("add epkC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(json, FIELD_KCF_DATA_CLIENT, params->kcfDataSelf.val,
        params->kcfDataSelf.length) != HC_SUCCESS) {
        LOGE("add kcfDataC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t EcSpekeClientFinishReq(EcSpekeProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    int32_t res = EcSpekeClientFinishReqParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = EcSpekeClientFinishReqProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return EcSpekeClientFinishReqBuildEvent(&impl->params, outputEvent);
}

static int32_t EcSpekeServerFinishRspParseEvent(const CJson *inputEvent, EcSpekeParams *params)
{
    int32_t res = GetEpkPeerFromInput(inputEvent, params, false);
    if (res != HC_SUCCESS) {
        return res;
    }
    return GetKcfDataPeerFromInput(inputEvent, params, false);
}

static int32_t EcSpekeServerFinishRspProcEvent(EcSpekeProtocol *impl)
{
    int32_t res = CheckEpkPeerValid(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = CalSharedSecret(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = VerifyKcfDataPeer(impl, false);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = CalKcfDataSelf(impl, false);
    if (res != HC_SUCCESS) {
        return res;
    }
    return CalSessionKey(impl);
}

static int32_t EcSpekeServerFinishRspBuildEvent(EcSpekeParams *params, CJson **outputEvent)
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
    if (AddByteToJson(json, FIELD_KCF_DATA_SERVER, params->kcfDataSelf.val,
        params->kcfDataSelf.length) != HC_SUCCESS) {
        LOGE("add kcfDataS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t EcSpekeServerFinishRsp(EcSpekeProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    int32_t res = EcSpekeServerFinishRspParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = EcSpekeServerFinishRspProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return EcSpekeServerFinishRspBuildEvent(&impl->params, outputEvent);
}

static int32_t EcSpekeClientFinishParseEvent(const CJson *inputEvent, EcSpekeParams *params)
{
    return GetKcfDataPeerFromInput(inputEvent, params, true);
}

static int32_t EcSpekeClientFinishProcEvent(EcSpekeProtocol *impl)
{
    int32_t res = VerifyKcfDataPeer(impl, true);
    if (res != HC_SUCCESS) {
        return res;
    }
    return CalSessionKey(impl);
}

static int32_t EcSpekeClientFinish(EcSpekeProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    (void)outputEvent;
    int32_t res = EcSpekeClientFinishParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return EcSpekeClientFinishProcEvent(impl);
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

static int32_t ThrowException(EcSpekeProtocol *impl, const CJson *inputEvent, CJson **outputEvent)
{
    (void)impl;
    (void)outputEvent;
    int32_t peerErrorCode = HC_ERR_PEER_ERROR;
    (void)GetIntFromJson(inputEvent, FIELD_ERR_CODE, &peerErrorCode);
    LOGE("An exception occurred in the peer protocol. [Code]: %d", peerErrorCode);
    return peerErrorCode;
}

static const ProtocolStateNode STATE_MACHINE[] = {
    { CREATE_AS_CLIENT_STATE, START_AUTH_EVENT, EcSpekeClientStartReq, ReturnError, CLIENT_REQ_STATE },
    { CREATE_AS_SERVER_STATE, CLEINT_START_REQ_EVENT, EcSpekeServerStartRsp, NotifyPeerError, SERVER_RSP_STATE },
    { CLIENT_REQ_STATE, SERVER_START_RSP_EVENT, EcSpekeClientFinishReq, NotifyPeerError, CLIENT_FINISH_REQ_STATE },
    { CLIENT_REQ_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
    { SERVER_RSP_STATE, CLEINT_FINISH_REQ_EVENT, EcSpekeServerFinishRsp, NotifyPeerError, SERVER_FINISH_STATE },
    { SERVER_RSP_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
    { CLIENT_FINISH_REQ_STATE, SERVER_FINISH_RSP_EVENT, EcSpekeClientFinish, NotifyPeerError, CLIENT_FINISH_STATE },
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

static int32_t EcSpekeProtocolSwitchState(BaseProtocol *self, const CJson *receviedMsg, CJson **returnSendMsg)
{
    int32_t eventType = DecodeEvent(receviedMsg);
    for (uint32_t i = 0; i < sizeof(STATE_MACHINE) / sizeof(STATE_MACHINE[0]); i++) {
        if ((STATE_MACHINE[i].curState == self->curState) && (STATE_MACHINE[i].eventType == eventType)) {
            int32_t res = STATE_MACHINE[i].stateProcessFunc((EcSpekeProtocol *)self, receviedMsg, returnSendMsg);
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

static int32_t StartEcSpekeProtocol(BaseProtocol *self, CJson **returnSendMsg)
{
    if ((self == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((self->curState == self->finishState) || (self->curState == self->failState)) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return EcSpekeProtocolSwitchState(self, NULL, returnSendMsg);
}

static int32_t ProcessEcSpekeProtocol(BaseProtocol *self, const CJson *receviedMsg, CJson **returnSendMsg)
{
    if ((self == NULL) || (receviedMsg == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((self->curState == self->finishState) || (self->curState == self->failState)) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return EcSpekeProtocolSwitchState(self, receviedMsg, returnSendMsg);
}

static int32_t SetEcSpekePsk(BaseProtocol *self, const Uint8Buff *psk)
{
    if ((self == NULL) || (psk == NULL) || (psk->val == NULL) || (psk->length == 0)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    EcSpekeProtocol *impl = (EcSpekeProtocol *)self;
    if (DeepCopyUint8Buff(psk, &impl->params.psk) != HC_SUCCESS) {
        LOGE("copy psk fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    LOGI("set psk success.");
    return HC_SUCCESS;
}

static int32_t SetEcSpekeSelfProtectedMsg(BaseProtocol *self, const Uint8Buff *selfMsg)
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

static int32_t SetEcSpekePeerProtectedMsg(BaseProtocol *self, const Uint8Buff *peerMsg)
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

static int32_t GetEcSpekeSessionKey(BaseProtocol *self, Uint8Buff *returnSessionKey)
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

static void DestroyEcSpekeProtocol(BaseProtocol *self)
{
    if (self == NULL) {
        LOGD("self is null.");
        return;
    }
    EcSpekeProtocol *impl = (EcSpekeProtocol *)self;
    ClearFreeUint8Buff(&impl->base.protectedMsg.selfMsg);
    ClearFreeUint8Buff(&impl->base.protectedMsg.peerMsg);
    ClearFreeUint8Buff(&impl->base.sessionKey);
    ClearFreeUint8Buff(&impl->params.psk);
    ClearFreeUint8Buff(&impl->params.salt);
    ClearFreeUint8Buff(&impl->params.base);
    ClearFreeUint8Buff(&impl->params.eskSelf);
    ClearFreeUint8Buff(&impl->params.epkSelf);
    ClearFreeUint8Buff(&impl->params.epkPeer);
    ClearFreeUint8Buff(&impl->params.authIdSelf);
    ClearFreeUint8Buff(&impl->params.authIdPeer);
    ClearFreeUint8Buff(&impl->params.kcfDataSelf);
    ClearFreeUint8Buff(&impl->params.kcfDataPeer);
    ClearFreeUint8Buff(&impl->params.sharedSecret);
    HcFree(impl);
}

static int32_t BuildEcSpekeProtocolObj(const EcSpekeInitParams *params, bool isClient, EcSpekeProtocol *instance)
{
    if (DeepCopyUint8Buff(&params->authId, &instance->params.authIdSelf) != HC_SUCCESS) {
        return HC_ERR_ALLOC_MEMORY;
    }
    instance->base.name = PROTOCOL_TYPE_EC_SPEKE;
    instance->base.beginState = isClient ? CREATE_AS_CLIENT_STATE : CREATE_AS_SERVER_STATE;
    instance->base.finishState = isClient ? CLIENT_FINISH_STATE : SERVER_FINISH_STATE;
    instance->base.failState = FAIL_STATE;
    instance->base.curState = instance->base.beginState;
    instance->base.start = StartEcSpekeProtocol;
    instance->base.process = ProcessEcSpekeProtocol;
    instance->base.setPsk = SetEcSpekePsk;
    instance->base.setSelfProtectedMsg = SetEcSpekeSelfProtectedMsg;
    instance->base.setPeerProtectedMsg = SetEcSpekePeerProtectedMsg;
    instance->base.getSessionKey = GetEcSpekeSessionKey;
    instance->base.destroy = DestroyEcSpekeProtocol;
    instance->params.curveType = params->curveType;
    return HC_SUCCESS;
}

static bool IsCurveTypeValid(int32_t curveType)
{
    return (curveType == CURVE_TYPE_256 || curveType == CURVE_TYPE_25519);
}

int32_t CreateEcSpekeProtocol(const void *baseParams, bool isClient, BaseProtocol **returnObj)
{
    const EcSpekeInitParams *params = (const EcSpekeInitParams *)baseParams;
    if ((params == NULL) || (returnObj == NULL) ||
        !IsUint8BuffValid(&params->authId, EC_SPEKE_AUTH_ID_MAX_LEN)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsCurveTypeValid(params->curveType)) {
        LOGE("invalid curve type. [CurveType]: %d", params->curveType);
        return HC_ERR_INVALID_PARAMS;
    }
    EcSpekeProtocol *instance = (EcSpekeProtocol *)HcMalloc(sizeof(EcSpekeProtocol), 0);
    if (instance == NULL) {
        LOGE("allocate instance memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = BuildEcSpekeProtocolObj(params, isClient, instance);
    if (res != HC_SUCCESS) {
        DestroyEcSpekeProtocol((BaseProtocol *)instance);
        return res;
    }
    *returnObj = (BaseProtocol *)instance;
    return HC_SUCCESS;
}
