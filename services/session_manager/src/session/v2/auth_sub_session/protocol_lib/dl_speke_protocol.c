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

#include "dl_speke_protocol.h"

#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"

#define DL_SPEKE_AUTH_ID_MAX_LEN 256
#define DL_SPEKE_SALT_LEN 16
#define DL_SPEKE_KCF_CODE_LEN 1
#define DL_SPEKE_SECRET_LEN 32
#define DL_SPEKE_SESSION_KEY_LEN 32
#define DL_SPEKE_EXP_LEN 1
#define DL_SPEKE_ESK_SMALL_LEN 28
#define DL_SPEKE_ESK_LEN 32
#define DL_SPEKE_PRIME_SMALL_LEN 256
#define DL_SPEKE_PRIME_LEN 384
#define HICHAIN_SPEKE_BASE_INFO "hichain_speke_base_info"
#define SHARED_SECRET_DERIVED_FACTOR "hichain_speke_shared_secret_info"
#define HICHAIN_SPEKE_SESSIONKEY_INFO "hichain_speke_sessionkey_info"

#define FIELD_EVENT "event"
#define FIELD_ERR_CODE "errCode"

#define FIELD_SALT "salt"
#define FIELD_AUTH_ID_CLIENT "authIdC"
#define FIELD_AUTH_ID_SERVER "authIdS"
#define FIELD_EPK_CLIENT "epkC"
#define FIELD_EPK_SERVER "epkS"
#define FIELD_KCF_DATA_CLIENT "kcfDataC"
#define FIELD_KCF_DATA_SERVER "kcfDataS"

static const uint8_t KCF_CODE_CLIENT[DL_SPEKE_KCF_CODE_LEN] = { 0x04 };
static const uint8_t KCF_CODE_SERVER[DL_SPEKE_KCF_CODE_LEN] = { 0x03 };

static const char * const LARGE_PRIME_NUMBER_HEX_384 =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"\
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"\
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"\
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"\
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"\
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"\
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"\
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"\
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"\
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"\
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"\
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

static const char * const LARGE_PRIME_NUMBER_HEX_256 =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"\
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"\
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"\
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"\
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"\
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"\
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"\
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

typedef struct {
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
    uint32_t innerKeyLen;
    const char *largePrimeNumHex;
    DlSpekePrimeMod primeMod;
} DlSpekeParams;

typedef struct {
    BaseProtocol base;
    DlSpekeParams params;
} DlSpekeProtocol;

typedef struct {
    int32_t curState;
    int32_t eventType;
    int32_t (*stateProcessFunc)(DlSpekeProtocol *impl, const CJson *inputData, CJson **outputData);
    void (*exceptionHandleFunc)(int32_t errorCode, CJson **outputData);
    int32_t nextState;
} ProtocolStateNode;

static int32_t DlSpekeClientStartReqBuildEvent(const DlSpekeParams *params, CJson **outputData)
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
    bool isOnly256ModSupported = (((uint32_t)params->primeMod | DL_SPEKE_PRIME_MOD_256) == DL_SPEKE_PRIME_MOD_256);
    if (AddBoolToJson(json, FIELD_SUPPORT_256_MOD, isOnly256ModSupported) != HC_SUCCESS) {
        LOGE("Add isOnly256ModSupported failed.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    *outputData = json;
    return HC_SUCCESS;
}

static int32_t GetAuthIdPeerFromInput(const CJson *inputData, DlSpekeParams *params, bool isClient)
{
    const char *authIdPeerStr = isClient ? GetStringFromJson(inputData, FIELD_AUTH_ID_SERVER) :
        GetStringFromJson(inputData, FIELD_AUTH_ID_CLIENT);
    if (authIdPeerStr == NULL) {
        LOGE("get authIdPeerStr from inputData fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t authIdPeerStrLen = HcStrlen(authIdPeerStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (authIdPeerStrLen == 0 || authIdPeerStrLen > DL_SPEKE_AUTH_ID_MAX_LEN) {
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

static int32_t GetSaltFromInput(const CJson *inputData, DlSpekeParams *params)
{
    if (InitUint8Buff(&params->salt, DL_SPEKE_SALT_LEN) != HC_SUCCESS) {
        LOGE("allocate salt memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(inputData, FIELD_SALT, params->salt.val, params->salt.length) != HC_SUCCESS) {
        LOGE("get salt from inputData fail.");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

static int32_t GetEpkPeerFromInput(const CJson *inputData, DlSpekeParams *params, bool isClient)
{
    const char *epkPeerStr = isClient ? GetStringFromJson(inputData, FIELD_EPK_SERVER) :
        GetStringFromJson(inputData, FIELD_EPK_CLIENT);
    if (epkPeerStr == NULL) {
        LOGE("get epkPeerStr from inputData fail.");
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

static int32_t GetKcfDataPeerFromInput(const CJson *inputData, DlSpekeParams *params, bool isClient)
{
    if (InitUint8Buff(&params->kcfDataPeer, SHA256_LEN) != HC_SUCCESS) {
        LOGE("allocate kcfDataPeer fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(inputData, (isClient ? FIELD_KCF_DATA_SERVER : FIELD_KCF_DATA_CLIENT),
        params->kcfDataPeer.val, params->kcfDataPeer.length) != HC_SUCCESS) {
        LOGE("get kcfDataPeer from inputData fail.");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

static int32_t DlSpekeClientStartReq(DlSpekeProtocol *impl, const CJson *inputData, CJson **outputData)
{
    (void)inputData;
    return DlSpekeClientStartReqBuildEvent(&impl->params, outputData);
}

static int32_t SetSelfKeyLenByMod(const CJson *inputData, DlSpekeParams *params)
{
    bool isOnly256ModSupported = true;
    if (GetBoolFromJson(inputData, FIELD_SUPPORT_256_MOD, &isOnly256ModSupported) != HC_SUCCESS) {
        LOGE("Get isOnly256ModSupported failed.");
        return HC_ERR_JSON_GET;
    }
    params->primeMod = isOnly256ModSupported ?
        (params->primeMod & DL_SPEKE_PRIME_MOD_256) : (params->primeMod & DL_SPEKE_PRIME_MOD_384);
    if (((uint32_t)params->primeMod & DL_SPEKE_PRIME_MOD_384) != 0) {
        params->eskSelf.length = DL_SPEKE_ESK_LEN;
        params->innerKeyLen = DL_SPEKE_PRIME_LEN;
        return HC_SUCCESS;
    }
    if (((uint32_t)params->primeMod & DL_SPEKE_PRIME_MOD_256) != 0) {
        params->eskSelf.length = DL_SPEKE_ESK_SMALL_LEN;
        params->innerKeyLen = DL_SPEKE_PRIME_SMALL_LEN;
        return HC_SUCCESS;
    }
    LOGE("Unsupported DL SPEKE mod: %x.", params->primeMod);
    return HC_ERR_NOT_SUPPORT;
}

static int32_t DlSpekeServerStartRspParseEvent(const CJson *inputData, DlSpekeParams *params)
{
    int32_t res = SetSelfKeyLenByMod(inputData, params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return GetAuthIdPeerFromInput(inputData, params, false);
}

static int32_t CalSalt(DlSpekeParams *params)
{
    if (InitUint8Buff(&params->salt, DL_SPEKE_SALT_LEN) != HC_SUCCESS) {
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

static int32_t CalSecret(DlSpekeParams *params, Uint8Buff *secret)
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

static int32_t SetSelfKeyLenByEpkPeerAndMod(DlSpekeParams *params)
{
    if ((params->epkPeer.length == DL_SPEKE_PRIME_LEN) &&
        (((uint32_t)params->primeMod & DL_SPEKE_PRIME_MOD_384) != 0)) {
        params->eskSelf.length = DL_SPEKE_ESK_LEN;
        params->innerKeyLen = DL_SPEKE_PRIME_LEN;
        return HC_SUCCESS;
    }
    if ((params->epkPeer.length == DL_SPEKE_PRIME_SMALL_LEN) &&
        (((uint32_t)params->primeMod & DL_SPEKE_PRIME_MOD_256) != 0)) {
        params->eskSelf.length = DL_SPEKE_ESK_SMALL_LEN;
        params->innerKeyLen = DL_SPEKE_PRIME_SMALL_LEN;
        return HC_SUCCESS;
    }
    LOGE("DL SPEKE mod: %x, Invalid epkPeer length: %u.", params->primeMod, params->epkPeer.length);
    return HC_ERR_INVALID_LEN;
}

static int32_t DlSpekeCalBase(DlSpekeParams *params, Uint8Buff *secret)
{
    if (InitUint8Buff(&params->base, params->innerKeyLen) != HC_SUCCESS) {
        LOGE("Failed to init base!");
        return HC_ERR_ALLOC_MEMORY;
    }
    uint8_t expVal[DL_SPEKE_EXP_LEN] = { 2 };
    Uint8Buff exp = { expVal, DL_SPEKE_EXP_LEN };
    params->largePrimeNumHex = (params->innerKeyLen == DL_SPEKE_PRIME_SMALL_LEN) ?
        LARGE_PRIME_NUMBER_HEX_256 : LARGE_PRIME_NUMBER_HEX_384;
    int32_t res = GetLoaderInstance()->bigNumExpMod(secret, &exp, params->largePrimeNumHex, &params->base);
    if (res != HC_SUCCESS) {
        LOGE("BigNumExpMod for base failed, res: %x.", res);
    }
    return res;
}

static int32_t DlSpekeCalEskSelf(DlSpekeParams *params)
{
    if (InitUint8Buff(&params->eskSelf, params->eskSelf.length) != HC_SUCCESS) {
        LOGE("Failed to init eskSelf!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int res = GetLoaderInstance()->generateRandom(&(params->eskSelf));
    if (res != HC_SUCCESS) {
        LOGE("GenerateRandom for eskSelf failed, res: %x.", res);
    }
    return res;
}

static int32_t DlSpekeCalEpkSelf(DlSpekeParams *params)
{
    if (InitUint8Buff(&params->epkSelf, params->innerKeyLen) != HC_SUCCESS) {
        LOGE("Failed to init epkSelf!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GetLoaderInstance()->bigNumExpMod(&params->base, &(params->eskSelf),
        params->largePrimeNumHex, &(params->epkSelf));
    if (res != HC_SUCCESS) {
        LOGE("BigNumExpMod for epkSelf failed, res: %x.", res);
    }
    return res;
}

static bool IsEpkPeerLenValid(DlSpekeParams *params)
{
    if ((params->epkPeer.length == DL_SPEKE_PRIME_LEN) &&
        (((uint32_t)params->primeMod & DL_SPEKE_PRIME_MOD_384) != 0)) {
        return true;
    }
    if ((params->epkPeer.length == DL_SPEKE_PRIME_SMALL_LEN) &&
        (((uint32_t)params->primeMod & DL_SPEKE_PRIME_MOD_256) != 0)) {
        return true;
    }
    LOGE("Invalid epkPeer length: %u.", params->epkPeer.length);
    return false;
}

static int32_t CheckEpkPeerValid(DlSpekeParams *params)
{
    if (!IsEpkPeerLenValid(params)) {
        return HC_ERR_INVALID_LEN;
    }
    if (!GetLoaderInstance()->checkDlPublicKey(&params->epkPeer, params->largePrimeNumHex)) {
        LOGE("Check EC_SPEKE publicKey fail.");
        return HC_ERR_BAD_MESSAGE;
    }
    return HC_SUCCESS;
}

static int32_t CalTmpSharedSecret(DlSpekeParams *params, Uint8Buff *tmpSharedSecret)
{
    int32_t res = GetLoaderInstance()->bigNumExpMod(&(params->epkPeer), &(params->eskSelf),
        params->largePrimeNumHex, tmpSharedSecret);
    if (res != HC_SUCCESS) {
        LOGE("Cal tmpSharedSecret failed, res: %x", res);
    }
    return res;
}

static int32_t CalSidSelf(DlSpekeParams *params, Uint8Buff *sidSelf)
{
    uint32_t sidSelfMsgLen = params->authIdSelf.length + params->innerKeyLen;
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
        params->epkSelf.val, params->innerKeyLen) != EOK) { // only need x-coordinate
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

static int32_t CalSidPeer(DlSpekeParams *params, Uint8Buff *sidPeer)
{
    uint32_t sidPeerMsgLen = params->authIdPeer.length + params->innerKeyLen;
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
        params->epkPeer.val, params->innerKeyLen) != EOK) { // only need x-coordinate
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

static int32_t CalSid(DlSpekeParams *params, Uint8Buff *sid)
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

static int32_t CombineSharedSecretMsg(DlSpekeParams *params, const Uint8Buff *tmpSharedSecret, const Uint8Buff *sid,
    Uint8Buff *sharedSecretMsg)
{
    uint32_t usedLen = 0;
    if (memcpy_s(sharedSecretMsg->val, sharedSecretMsg->length, sid->val, sid->length) != EOK) {
        LOGE("Memcpy for sidHex failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += sid->length;
    // Only need x-coordinate
    if (memcpy_s(sharedSecretMsg->val + usedLen, sharedSecretMsg->length - usedLen,
        tmpSharedSecret->val, params->innerKeyLen) != EOK) {
        LOGE("Memcpy for tmpSharedSecret failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->innerKeyLen;
    if (memcpy_s(sharedSecretMsg->val + usedLen, sharedSecretMsg->length - usedLen,
        SHARED_SECRET_DERIVED_FACTOR, HcStrlen(SHARED_SECRET_DERIVED_FACTOR)) != EOK) {
        LOGE("Memcpy for sharedSecret derived factor failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GenerateSharedSecretMsg(DlSpekeParams *params, Uint8Buff *sharedSecretMsg)
{
    Uint8Buff tmpSharedSecret = { NULL, 0 };
    if (InitUint8Buff(&tmpSharedSecret, params->innerKeyLen) != HC_SUCCESS) {
        LOGE("allocate p memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = CalTmpSharedSecret(params, &tmpSharedSecret);
    if (res != HC_SUCCESS) {
        ClearFreeUint8Buff(&tmpSharedSecret);
        return res;
    }
    // sid is composed of client sid and server sid, so need twice SHA256_LEN
    uint8_t sidVal[SHA256_LEN * 2] = { 0 };
    Uint8Buff sid = { sidVal, SHA256_LEN * 2 };
    res = CalSid(params, &sid);
    if (res != HC_SUCCESS) {
        ClearFreeUint8Buff(&tmpSharedSecret);
        return res;
    }
    res = CombineSharedSecretMsg(params, &tmpSharedSecret, &sid, sharedSecretMsg);
    (void)memset_s(sid.val, sid.length, 0, sid.length);
    ClearFreeUint8Buff(&tmpSharedSecret);
    return res;
}

static int32_t CalSharedSecret(DlSpekeParams *params)
{
    uint32_t sharedSecretMsgLen = SHA256_LEN * 2 + params->innerKeyLen + HcStrlen(SHARED_SECRET_DERIVED_FACTOR);
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
    }
    return res;
}

static int32_t CombineProtectedMsg(DlSpekeProtocol *impl, bool isVerify, Uint8Buff *kcfDataMsg, uint32_t usedLen)
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

static int32_t GenerateKcfDataMsg(DlSpekeProtocol *impl, bool isClient, bool isVerify, Uint8Buff *kcfDataMsg)
{
    DlSpekeParams *params = &impl->params;
    const uint8_t *kcfCode = ((isClient && !isVerify) || (!isClient && isVerify)) ? KCF_CODE_CLIENT : KCF_CODE_SERVER;
    if (memcpy_s(kcfDataMsg->val, kcfDataMsg->length, kcfCode, DL_SPEKE_KCF_CODE_LEN) != HC_SUCCESS) {
        LOGE("Memcpy for kcfCode failed.");
        return HC_ERR_MEMORY_COPY;
    }
    uint32_t usedLen = DL_SPEKE_KCF_CODE_LEN;
    Uint8Buff *epkClient = isClient ? &params->epkSelf : &params->epkPeer;
    Uint8Buff *epkServer = isClient ? &params->epkPeer : &params->epkSelf;
    if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
        epkClient->val, params->innerKeyLen) != EOK) { // Only the x-coordinate of epk is required
        LOGE("Memcpy for epkClient failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->innerKeyLen;
    if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
        epkServer->val, params->innerKeyLen) != EOK) { // Only the x-coordinate of epk is required
        LOGE("Memcpy for epkServer failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->innerKeyLen;
    if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
        params->sharedSecret.val, params->sharedSecret.length) != EOK) {
        LOGE("Memcpy for sharedSecret failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->sharedSecret.length;
    if (memcpy_s(kcfDataMsg->val + usedLen, kcfDataMsg->length - usedLen,
        params->base.val, params->innerKeyLen) != EOK) { // Only the x-coordinate of base is required
        LOGE("Memcpy for base_X failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen += params->innerKeyLen;
    return CombineProtectedMsg(impl, isVerify, kcfDataMsg, usedLen);
}

static int32_t CalKcfDataSelf(DlSpekeProtocol *impl, bool isClient)
{
    uint32_t kcfDataMsgLen = DL_SPEKE_KCF_CODE_LEN + impl->params.innerKeyLen + impl->params.innerKeyLen +
        SHA256_LEN + impl->params.innerKeyLen + impl->base.protectedMsg.selfMsg.length +
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
    }
    return res;
}

static int32_t VerifyKcfDataPeer(DlSpekeProtocol *impl, bool isClient)
{
    uint32_t kcfDataMsgLen = DL_SPEKE_KCF_CODE_LEN + impl->params.innerKeyLen + impl->params.innerKeyLen +
        SHA256_LEN + impl->params.innerKeyLen + impl->base.protectedMsg.selfMsg.length +
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

static int32_t CalSessionKey(DlSpekeProtocol *impl)
{
    if (InitUint8Buff(&impl->base.sessionKey, DL_SPEKE_SESSION_KEY_LEN) != HC_SUCCESS) {
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
    }
    return res;
}

static int32_t DlSpekeServerStartRspProcEvent(DlSpekeProtocol *impl)
{
    int32_t res = CalSalt(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    uint8_t secretVal[DL_SPEKE_SECRET_LEN] = { 0 };
    Uint8Buff secret = { secretVal, DL_SPEKE_SECRET_LEN };
    res = CalSecret(&impl->params, &secret);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DlSpekeCalBase(&impl->params, &secret);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DlSpekeCalEskSelf(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return DlSpekeCalEpkSelf(&impl->params);
}

static int32_t DlSpekeServerStartRspBuildEvent(const DlSpekeParams *params, CJson **outputData)
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
    *outputData = json;
    return HC_SUCCESS;
}

static int32_t DlSpekeServerStartRsp(DlSpekeProtocol *impl, const CJson *inputData, CJson **outputData)
{
    int32_t res = DlSpekeServerStartRspParseEvent(inputData, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DlSpekeServerStartRspProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return DlSpekeServerStartRspBuildEvent(&impl->params, outputData);
}

static int32_t DlSpekeClientFinishReqParseEvent(const CJson *inputData, DlSpekeParams *params)
{
    int32_t res = GetSaltFromInput(inputData, params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = GetEpkPeerFromInput(inputData, params, true);
    if (res != HC_SUCCESS) {
        return res;
    }
    return GetAuthIdPeerFromInput(inputData, params, true);
}

static int32_t DlSpekeClientFinishReqProcEvent(DlSpekeProtocol *impl)
{
    uint8_t secretVal[DL_SPEKE_SECRET_LEN] = { 0 };
    Uint8Buff secret = { secretVal, DL_SPEKE_SECRET_LEN };
    int32_t res = CalSecret(&impl->params, &secret);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DlSpekeCalBase(&impl->params, &secret);
    (void)memset_s(secret.val, secret.length, 0, secret.length);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DlSpekeCalEskSelf(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DlSpekeCalEpkSelf(&impl->params);
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

static int32_t DlSpekeClientFinishReqBuildEvent(DlSpekeParams *params, CJson **outputData)
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
    *outputData = json;
    return HC_SUCCESS;
}

static int32_t DlSpekeClientFinishReq(DlSpekeProtocol *impl, const CJson *inputData, CJson **outputData)
{
    int32_t res = DlSpekeClientFinishReqParseEvent(inputData, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = SetSelfKeyLenByEpkPeerAndMod(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DlSpekeClientFinishReqProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return DlSpekeClientFinishReqBuildEvent(&impl->params, outputData);
}

static int32_t DlSpekeServerFinishRspParseEvent(const CJson *inputData, DlSpekeParams *params)
{
    int32_t res = GetEpkPeerFromInput(inputData, params, false);
    if (res != HC_SUCCESS) {
        return res;
    }
    return GetKcfDataPeerFromInput(inputData, params, false);
}

static int32_t DlSpekeServerFinishRspProcEvent(DlSpekeProtocol *impl)
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

static int32_t DlSpekeServerFinishRspBuildEvent(DlSpekeParams *params, CJson **outputData)
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
    *outputData = json;
    return HC_SUCCESS;
}

static int32_t DlSpekeServerFinishRsp(DlSpekeProtocol *impl, const CJson *inputData, CJson **outputData)
{
    int32_t res = DlSpekeServerFinishRspParseEvent(inputData, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DlSpekeServerFinishRspProcEvent(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    return DlSpekeServerFinishRspBuildEvent(&impl->params, outputData);
}

static int32_t DlSpekeClientFinishParseEvent(const CJson *inputData, DlSpekeParams *params)
{
    return GetKcfDataPeerFromInput(inputData, params, true);
}

static int32_t DlSpekeClientFinishProcEvent(DlSpekeProtocol *impl)
{
    int32_t res = VerifyKcfDataPeer(impl, true);
    if (res != HC_SUCCESS) {
        return res;
    }
    return CalSessionKey(impl);
}

static int32_t DlSpekeClientFinish(DlSpekeProtocol *impl, const CJson *inputData, CJson **outputData)
{
    (void)outputData;
    int32_t res = DlSpekeClientFinishParseEvent(inputData, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return DlSpekeClientFinishProcEvent(impl);
}

static void ReturnError(int32_t errorCode, CJson **outputData)
{
    (void)errorCode;
    (void)outputData;
    return;
}

static void NotifyPeerError(int32_t errorCode, CJson **outputData)
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
    *outputData = json;
    return;
}

static int32_t ThrowException(DlSpekeProtocol *impl, const CJson *inputData, CJson **outputData)
{
    (void)impl;
    (void)outputData;
    int32_t peerErrorCode = HC_ERR_PEER_ERROR;
    (void)GetIntFromJson(inputData, FIELD_ERR_CODE, &peerErrorCode);
    LOGE("An exception occurred in the peer protocol. [Code]: %d", peerErrorCode);
    return peerErrorCode;
}

static const ProtocolStateNode STATE_MACHINE[] = {
    { CREATE_AS_CLIENT_STATE, START_AUTH_EVENT, DlSpekeClientStartReq, ReturnError, CLIENT_REQ_STATE },
    { CREATE_AS_SERVER_STATE, CLEINT_START_REQ_EVENT, DlSpekeServerStartRsp, NotifyPeerError, SERVER_RSP_STATE },
    { CLIENT_REQ_STATE, SERVER_START_RSP_EVENT, DlSpekeClientFinishReq, NotifyPeerError, CLIENT_FINISH_REQ_STATE },
    { CLIENT_REQ_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
    { SERVER_RSP_STATE, CLEINT_FINISH_REQ_EVENT, DlSpekeServerFinishRsp, NotifyPeerError, SERVER_FINISH_STATE },
    { SERVER_RSP_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
    { CLIENT_FINISH_REQ_STATE, SERVER_FINISH_RSP_EVENT, DlSpekeClientFinish, NotifyPeerError, CLIENT_FINISH_STATE },
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

static int32_t DlSpekeProtocolSwitchState(BaseProtocol *self, const CJson *receviedMsg, CJson **returnSendMsg)
{
    int32_t eventType = DecodeEvent(receviedMsg);
    for (uint32_t i = 0; i < sizeof(STATE_MACHINE) / sizeof(STATE_MACHINE[0]); i++) {
        if ((STATE_MACHINE[i].curState == self->curState) && (STATE_MACHINE[i].eventType == eventType)) {
            int32_t res = STATE_MACHINE[i].stateProcessFunc((DlSpekeProtocol *)self, receviedMsg, returnSendMsg);
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

static int32_t StartDlSpekeProtocol(BaseProtocol *self, CJson **returnSendMsg)
{
    if ((self == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((self->curState == self->finishState) || (self->curState == self->failState)) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return DlSpekeProtocolSwitchState(self, NULL, returnSendMsg);
}

static int32_t ProcessDlSpekeProtocol(BaseProtocol *self, const CJson *receviedMsg, CJson **returnSendMsg)
{
    if ((self == NULL) || (receviedMsg == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((self->curState == self->finishState) || (self->curState == self->failState)) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return DlSpekeProtocolSwitchState(self, receviedMsg, returnSendMsg);
}

static int32_t SetDlSpekePsk(BaseProtocol *self, const Uint8Buff *psk)
{
    if ((self == NULL) || (psk == NULL) || (psk->val == NULL) || (psk->length == 0)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    DlSpekeProtocol *impl = (DlSpekeProtocol *)self;
    if (DeepCopyUint8Buff(psk, &impl->params.psk) != HC_SUCCESS) {
        LOGE("copy psk fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    LOGI("set psk success.");
    return HC_SUCCESS;
}

static int32_t SetDlSpekeSelfProtectedMsg(BaseProtocol *self, const Uint8Buff *selfMsg)
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

static int32_t SetDlSpekePeerProtectedMsg(BaseProtocol *self, const Uint8Buff *peerMsg)
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

static int32_t GetDlSpekeSessionKey(BaseProtocol *self, Uint8Buff *returnSessionKey)
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

static void DestroyDlSpekeProtocol(BaseProtocol *self)
{
    if (self == NULL) {
        LOGD("self is null.");
        return;
    }
    DlSpekeProtocol *impl = (DlSpekeProtocol *)self;
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

static int32_t BuildDlSpekeProtocolObj(const DlSpekeInitParams *params, bool isClient, DlSpekeProtocol *instance)
{
    if (DeepCopyUint8Buff(&params->authId, &instance->params.authIdSelf) != HC_SUCCESS) {
        LOGE("Failed to set self authId!");
        return HC_ERR_ALLOC_MEMORY;
    }
    instance->params.primeMod = params->primeMod;
    instance->base.name = PROTOCOL_TYPE_DL_SPEKE;
    instance->base.beginState = isClient ? CREATE_AS_CLIENT_STATE : CREATE_AS_SERVER_STATE;
    instance->base.finishState = isClient ? CLIENT_FINISH_STATE : SERVER_FINISH_STATE;
    instance->base.failState = FAIL_STATE;
    instance->base.curState = instance->base.beginState;
    instance->base.start = StartDlSpekeProtocol;
    instance->base.process = ProcessDlSpekeProtocol;
    instance->base.setPsk = SetDlSpekePsk;
    instance->base.setSelfProtectedMsg = SetDlSpekeSelfProtectedMsg;
    instance->base.setPeerProtectedMsg = SetDlSpekePeerProtectedMsg;
    instance->base.getSessionKey = GetDlSpekeSessionKey;
    instance->base.destroy = DestroyDlSpekeProtocol;
    return HC_SUCCESS;
}

int32_t CreateDlSpekeProtocol(const void *baseParams, bool isClient, BaseProtocol **returnObj)
{
    if (baseParams == NULL || returnObj == NULL) {
        LOGE("null input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    const DlSpekeInitParams *params = (const DlSpekeInitParams *)baseParams;
    if (!IsUint8BuffValid(&params->authId, DL_SPEKE_AUTH_ID_MAX_LEN)) {
        LOGE("Invalid authId!");
        return HC_ERR_INVALID_PARAMS;
    }
    DlSpekeProtocol *instance = (DlSpekeProtocol *)HcMalloc(sizeof(DlSpekeProtocol), 0);
    if (instance == NULL) {
        LOGE("Failed to alloc memory for protocol instance!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = BuildDlSpekeProtocolObj(params, isClient, instance);
    if (res != HC_SUCCESS) {
        DestroyDlSpekeProtocol((BaseProtocol *)instance);
        return res;
    }
    *returnObj = (BaseProtocol *)instance;
    return HC_SUCCESS;
}
