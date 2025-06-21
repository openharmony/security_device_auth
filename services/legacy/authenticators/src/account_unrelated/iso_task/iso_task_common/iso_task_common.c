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

#include "iso_task_common.h"
#include <time.h>
#include "das_task_common.h"
#include "das_module_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "iso_protocol_common.h"
#include "protocol_common.h"
#include "hisysevent_common.h"

static int32_t ComputeHkdfByParams(const IsoParams *params, const Uint8Buff *hkdfSaltBuf, Uint8Buff *returnKeyBuf)
{
    Uint8Buff keyInfoBuf = { (uint8_t *)GENERATE_RETURN_KEY_STR, (uint32_t)HcStrlen(GENERATE_RETURN_KEY_STR) };
    KeyParams keyParam = {
        .keyBuff = { params->baseParams.sessionKey.val, params->baseParams.sessionKey.length, false },
        .isDeStorage = false,
        .osAccountId = params->baseParams.osAccountId
    };
    return params->baseParams.loader->computeHkdf(&keyParam, hkdfSaltBuf, &keyInfoBuf, returnKeyBuf);
}

static int GenerateReturnKey(IsoParams *params, uint8_t *returnKey, uint32_t returnKeyLen)
{
    uint32_t hkdfSaltLen = params->baseParams.randPeer.length + params->baseParams.randSelf.length;
    int res;
    uint8_t *hkdfSalt = (uint8_t *)HcMalloc(hkdfSaltLen, 0);
    if (hkdfSalt == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    if (params->isClient) {
        if (memcpy_s(hkdfSalt, hkdfSaltLen, params->baseParams.randSelf.val,
            params->baseParams.randSelf.length) != EOK) {
            LOGE("Copy randSelf failed.");
            res = HC_ERR_MEMORY_COPY;
            goto ERR;
        }
        if (memcpy_s(hkdfSalt + params->baseParams.randSelf.length, hkdfSaltLen - params->baseParams.randSelf.length,
            params->baseParams.randPeer.val, params->baseParams.randPeer.length) != EOK) {
            LOGE("Copy randPeer failed.");
            res = HC_ERR_MEMORY_COPY;
            goto ERR;
        }
    } else {
        if (memcpy_s(hkdfSalt, hkdfSaltLen, params->baseParams.randPeer.val,
            params->baseParams.randPeer.length) != EOK) {
            LOGE("Copy randPeer failed.");
            res = HC_ERR_MEMORY_COPY;
            goto ERR;
        }
        if (memcpy_s(hkdfSalt + params->baseParams.randPeer.length, hkdfSaltLen - params->baseParams.randPeer.length,
            params->baseParams.randSelf.val, params->baseParams.randSelf.length) != EOK) {
            LOGE("Copy randSelf failed.");
            res = HC_ERR_MEMORY_COPY;
            goto ERR;
        }
    }
    Uint8Buff hkdfSaltBuf = { hkdfSalt, hkdfSaltLen };
    Uint8Buff returnKeyBuf = { returnKey, returnKeyLen };
    res = ComputeHkdfByParams(params, &hkdfSaltBuf, &returnKeyBuf);
    if (res != HC_SUCCESS) {
        LOGE("computeHkdf for returnKey failed.");
        goto ERR;
    }
ERR:
    FreeAndCleanKey(&(params->baseParams.sessionKey));
    HcFree(hkdfSalt);
    return res;
}

int GenerateEncResult(const IsoParams *params, int message, CJson *sendToPeer, const char *aad)
{
    CJson *payload = NULL;
    uint8_t *out = NULL;
    uint8_t nonce[NONCE_SIZE] = { 0 };
    Uint8Buff nonceBuf = { nonce, sizeof(nonce) };
    int ret = params->baseParams.loader->generateRandom(&nonceBuf);
    if (ret != 0) {
        LOGE("Generate nonce failed, res: %" LOG_PUB "x.", ret);
        return ret;
    }

    int result = 0;
    Uint8Buff plainBuf = { (uint8_t *)&result, sizeof(int) };
    GcmParam encryptInfo;
    encryptInfo.nonce = nonce;
    encryptInfo.nonceLen = NONCE_SIZE;
    encryptInfo.aad = (uint8_t *)aad;
    encryptInfo.aadLen = (uint32_t)HcStrlen(aad);
    out = (uint8_t *)HcMalloc((sizeof(int) + TAG_LEN), 0);
    if (out == NULL) {
        ret = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    Uint8Buff outBuf = { out, sizeof(int) + TAG_LEN };
    KeyParams keyParams = {
        { params->baseParams.sessionKey.val, params->baseParams.sessionKey.length, false },
        false,
        params->baseParams.osAccountId
    };
    ret = params->baseParams.loader->aesGcmEncrypt(&keyParams, &plainBuf, &encryptInfo, &outBuf);
    if (ret != HC_SUCCESS) {
        goto ERR;
    }
    payload = CreateJson();
    if (payload == NULL) {
        ret = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(AddByteToJson(payload, FIELD_NONCE, nonce, sizeof(nonce)), ret);
    GOTO_ERR_AND_SET_RET(AddByteToJson(payload, FIELD_ENC_RESULT, out, sizeof(int) + TAG_LEN), ret);
    GOTO_ERR_AND_SET_RET(AddIntToJson(payload, FIELD_OPERATION_CODE, params->opCode), ret);
    GOTO_ERR_AND_SET_RET(AddObjToJson(sendToPeer, FIELD_PAYLOAD, payload), ret);
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToPeer, FIELD_MESSAGE, message), ret);
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToPeer, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED), ret);
ERR:
    FreeJson(payload);
    HcFree(out);
    return ret;
}

int SendResultToFinalSelf(IsoParams *params, CJson *out, bool isNeedReturnKey)
{
    CJson *sendToSelf = CreateJson();
    if (sendToSelf == NULL) {
        LOGE("Create sendToSelf json failed.");
        return HC_ERR_JSON_CREATE;
    }
    uint8_t *returnSessionKey = NULL;
    int res = 0;
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToSelf, FIELD_OPERATION_CODE, OP_BIND), res);
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToSelf, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED), res);
    if (isNeedReturnKey) {
        returnSessionKey = (uint8_t *)HcMalloc(params->keyLen, 0);
        if (returnSessionKey == NULL) {
            LOGE("Malloc for returnSessionKey failed.");
            res = HC_ERR_ALLOC_MEMORY;
            goto ERR;
        }
        res = GenerateReturnKey(params, returnSessionKey, params->keyLen);
        if (res != 0) {
            LOGE("gen return key failed, res:%" LOG_PUB "d", res);
            goto ERR;
        }
        GOTO_ERR_AND_SET_RET(AddByteToJson(sendToSelf, FIELD_SESSION_KEY, returnSessionKey, params->keyLen), res);
    }
    GOTO_ERR_AND_SET_RET(AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf), res);
ERR:
    ClearSensitiveStringInJson(sendToSelf, FIELD_SESSION_KEY);
    FreeJson(sendToSelf);
    if (returnSessionKey != NULL) {
        (void)memset_s(returnSessionKey, params->keyLen, 0, params->keyLen);
    }
    HcFree(returnSessionKey);
    return res;
}

int GenEncResult(IsoParams *params, int message, CJson *out, const char *aad, bool isNeedReturnKey)
{
    CJson *sendToSelf = CreateJson();
    if (sendToSelf == NULL) {
        LOGE("Create sendToSelf json failed.");
        return HC_ERR_JSON_CREATE;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == NULL) {
        LOGE("Create sendToPeer json failed.");
        FreeJson(sendToSelf);
        return HC_ERR_JSON_CREATE;
    }

    uint8_t *returnKey = NULL;
    int res = GenerateEncResult(params, message, sendToPeer, aad);
    if (res != 0) {
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToSelf, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED), res);
    if (isNeedReturnKey) {
        returnKey = (uint8_t *)HcMalloc(params->keyLen, 0);
        if (returnKey == NULL) {
            res = HC_ERR_ALLOC_MEMORY;
            goto ERR;
        }
        res = GenerateReturnKey(params, returnKey, params->keyLen);
        if (res != 0) {
            LOGE("gen return key failed, res:%" LOG_PUB "d", res);
            goto ERR;
        }
        GOTO_ERR_AND_SET_RET(AddByteToJson(sendToSelf, FIELD_SESSION_KEY, returnKey,
            params->keyLen), res);
    }
    GOTO_ERR_AND_SET_RET(AddIntToJson(sendToSelf, FIELD_OPERATION_CODE, params->opCode), res);
    GOTO_ERR_AND_SET_RET(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer), res);
    GOTO_ERR_AND_SET_RET(AddObjToJson(out, FIELD_SEND_TO_SELF, sendToSelf), res);
ERR:
    ClearSensitiveStringInJson(sendToSelf, FIELD_SESSION_KEY);
    FreeJson(sendToPeer);
    FreeJson(sendToSelf);
    if (returnKey != NULL) {
        (void)memset_s(returnKey, params->keyLen, 0, params->keyLen);
    }
    HcFree(returnKey);
    return res;
}

int CheckEncResult(IsoParams *params, const CJson *in, const char *aad)
{
    int result = 0;
    int res;
    uint8_t *nonce = NULL;
    uint8_t *encResult = NULL;

    nonce = (uint8_t *)HcMalloc(NONCE_SIZE, 0);
    if (nonce == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(GetByteFromJson(in, FIELD_NONCE, nonce, NONCE_SIZE), res);
    encResult = (uint8_t *)HcMalloc(sizeof(int) + TAG_LEN, 0);
    if (encResult == NULL) {
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(GetByteFromJson(in, FIELD_ENC_RESULT, encResult, sizeof(int) + TAG_LEN), res);
    Uint8Buff outBuf = { (uint8_t *)&result, sizeof(int) };
    Uint8Buff encResultBuf = { encResult, sizeof(int) + TAG_LEN };
    GcmParam gcmParam;
    gcmParam.aad = (uint8_t *)aad;
    gcmParam.aadLen = (uint32_t)HcStrlen(aad);
    gcmParam.nonce = nonce;
    gcmParam.nonceLen = NONCE_SIZE;

    KeyParams keyParams = {
        { params->baseParams.sessionKey.val, params->baseParams.sessionKey.length, false },
        false,
        params->baseParams.osAccountId
    };
    res = params->baseParams.loader->aesGcmDecrypt(&keyParams, &encResultBuf, &gcmParam, &outBuf);
    if (res != 0) {
        LOGE("decrypt result failed, res:%" LOG_PUB "d", res);
        goto ERR;
    }
ERR:
    HcFree(nonce);
    HcFree(encResult);
    return res;
}

static int32_t GenerateKeyAliasForIso(const IsoParams *params, Uint8Buff *keyAliasBuff)
{
    TokenManagerParams tokenParams = { 0 };
    tokenParams.serviceType.val = (uint8_t *)params->serviceType;
    tokenParams.serviceType.length = HcStrlen(params->serviceType);
    tokenParams.authId = params->baseParams.authIdPeer;
    if (params->isPeerFromUpgrade) {
        tokenParams.pkgName.val = (uint8_t *)GROUP_MANAGER_PACKAGE_NAME;
        tokenParams.pkgName.length = HcStrlen(GROUP_MANAGER_PACKAGE_NAME);
        tokenParams.userType = params->peerUserType;
    } else {
        tokenParams.pkgName.val = (uint8_t *)params->packageName;
        tokenParams.pkgName.length = HcStrlen(params->packageName);
        tokenParams.userType = KEY_ALIAS_AUTH_TOKEN;
    }
    int32_t res = GenerateKeyAlias(&tokenParams, keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate iso key alias!");
        return res;
    }
    if (params->isPeerFromUpgrade) {
        res = ToLowerCase(keyAliasBuff);
        if (res != HC_SUCCESS) {
            LOGE("Failed to convert psk alias to lower case!");
            return res;
        }
    }
    return HC_SUCCESS;
}

void DeleteAuthCode(const IsoParams *params)
{
    uint8_t keyAlias[ISO_KEY_ALIAS_LEN] = { 0 };
    uint8_t upgradeKeyAlias[ISO_UPGRADE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAlias, ISO_KEY_ALIAS_LEN };
    if (params->isPeerFromUpgrade) {
        keyAliasBuff.val = upgradeKeyAlias;
        keyAliasBuff.length = ISO_UPGRADE_KEY_ALIAS_LEN;
    }
    int32_t res = GenerateKeyAliasForIso(params, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate iso key alias!");
        return;
    }
    LOGI("AuthCode alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.",
        keyAliasBuff.val[DEV_AUTH_ZERO], keyAliasBuff.val[DEV_AUTH_ONE],
        keyAliasBuff.val[DEV_AUTH_TWO], keyAliasBuff.val[DEV_AUTH_THREE]);
    res = params->baseParams.loader->deleteKey(&keyAliasBuff, params->isPeerFromUpgrade,
        params->baseParams.osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete auth code!");
    }
}

void DestroyIsoParams(IsoParams *params)
{
    if (params == NULL) {
        return;
    }

    DestroyIsoBaseParams(&params->baseParams);

    if (params->packageName != NULL) {
        HcFree(params->packageName);
        params->packageName = NULL;
    }
    if (params->serviceType != NULL) {
        HcFree(params->serviceType);
        params->serviceType = NULL;
    }
    if (params->seed.val != NULL) {
        HcFree(params->seed.val);
        params->seed.val = NULL;
    }
    if (params->pinCodeString != NULL) {
        (void)memset_s(params->pinCodeString, HcStrlen(params->pinCodeString), 0, HcStrlen(params->pinCodeString));
        HcFree(params->pinCodeString);
        params->pinCodeString = NULL;
    }
    (void)memset_s(params, sizeof(IsoParams), 0, sizeof(IsoParams));
}

static int FillAuthId(IsoParams *params, const CJson *in)
{
    const char *authId = GetStringFromJson(in, FIELD_SELF_AUTH_ID);
    if (authId == NULL) {
        LOGE("get self authId failed");
        return HC_ERROR;
    }
    uint32_t authIdLen = HcStrlen(authId);
    if (authIdLen == 0 || authIdLen > MAX_AUTH_ID_LEN) {
        LOGE("Invalid authIdSelfLen: %" LOG_PUB "d.", authIdLen);
        return HC_ERR_INVALID_PARAMS;
    }
    params->baseParams.authIdSelf.length = authIdLen;
    params->baseParams.authIdSelf.val = (uint8_t *)HcMalloc(params->baseParams.authIdSelf.length, 0);
    if (params->baseParams.authIdSelf.val == NULL) {
        LOGE("malloc authIdSelf failed");
        return HC_ERROR;
    }
    if (memcpy_s(params->baseParams.authIdSelf.val, params->baseParams.authIdSelf.length,
        authId, HcStrlen(authId)) != EOK) {
        LOGE("Memcpy authIdSelf failed.");
        return HC_ERR_MEMORY_COPY;
    }

    if (params->opCode == OP_BIND) {
        params->baseParams.authIdPeer.length = 0;
        params->baseParams.authIdPeer.val = NULL;
    } else {
        authId = GetStringFromJson(in, FIELD_PEER_AUTH_ID);
        if (authId == NULL) {
            LOGE("get peer authId failed");
            return HC_ERROR;
        }
        authIdLen = HcStrlen(authId);
        if (authIdLen == 0 || authIdLen > MAX_AUTH_ID_LEN) {
            LOGE("Invalid authIdPeerLen %" LOG_PUB "d.", authIdLen);
            return HC_ERR_INVALID_PARAMS;
        }
        params->baseParams.authIdPeer.length = authIdLen;
        params->baseParams.authIdPeer.val = (uint8_t *)HcMalloc(params->baseParams.authIdPeer.length, 0);
        if (params->baseParams.authIdPeer.val == NULL) {
            LOGE("malloc authIdPeer failed");
            return HC_ERROR;
        }
        if (memcpy_s(params->baseParams.authIdPeer.val, params->baseParams.authIdPeer.length,
            authId, HcStrlen(authId)) != EOK) {
            LOGE("Memcpy authIdPeer failed.");
            return HC_ERR_MEMORY_COPY;
        }
    }

    return HC_SUCCESS;
}

static int FillPkgNameAndServiceType(IsoParams *params, const CJson *in)
{
    const char *serviceType = GetStringFromJson(in, FIELD_SERVICE_TYPE);
    if (serviceType == NULL) {
        LOGE("get serviceType failed");
        return HC_ERROR;
    }
    params->serviceType = (char *)HcMalloc((uint32_t)(HcStrlen(serviceType) + 1), 0);
    if (params->serviceType == NULL) {
        LOGE("malloc serviceType failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(params->serviceType, HcStrlen(serviceType) + 1, serviceType, HcStrlen(serviceType)) != EOK) {
        LOGE("memcpy serviceType failed.");
        return HC_ERR_MEMORY_COPY;
    }
    const char *packageName = GetStringFromJson(in, FIELD_PKG_NAME);
    if (packageName == NULL) {
        LOGE("get packageName failed");
        return HC_ERROR;
    }
    params->packageName = (char *)HcMalloc((uint32_t)(HcStrlen(packageName) + 1), 0);
    if (params->packageName == NULL) {
        LOGE("malloc packageName failed");
        return HC_ERROR;
    }
    if (memcpy_s(params->packageName, HcStrlen(packageName) + 1, packageName, HcStrlen(packageName)) != EOK) {
        LOGE("memcpy packageName failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

#ifdef ENABLE_P2P_BIND_LITE_PROTOCOL_CHECK
static bool CheckPinLenForStandardIso(const CJson *in, const char *pinCode)
{
    int32_t protocolExpandVal = INVALID_PROTOCOL_EXPAND_VALUE;
    (void)GetIntFromJson(in, FIELD_PROTOCOL_EXPAND, &protocolExpandVal);
    if (protocolExpandVal != LITE_PROTOCOL_STANDARD_MODE) {
        LOGI("not standard iso, no need to check.");
        return true;
    }
    return HcStrlen(pinCode) >= PIN_CODE_LEN_LONG;
}
#endif

static int FillPin(IsoParams *params, const CJson *in)
{
    if (params->opCode == OP_BIND) {
        const char *pinString = GetStringFromJson(in, FIELD_PIN_CODE);
        if (pinString == NULL) {
            LOGE("Get pin failed.");
            return HC_ERROR;
        }
        if (HcStrlen(pinString) < MIN_PIN_LEN || HcStrlen(pinString) > MAX_PIN_LEN) {
            LOGE("Pin is too short.");
            return HC_ERR_INVALID_PARAMS;
        }
    #ifdef ENABLE_P2P_BIND_LITE_PROTOCOL_CHECK
        if (!CheckPinLenForStandardIso(in, pinString)) {
            LOGE("Invalid pin code len!");
            return HC_ERR_INVALID_LEN;
        }
    #endif
        params->pinCodeString = (char *)HcMalloc(HcStrlen(pinString) + 1, 0);
        if (params->pinCodeString == NULL) {
            LOGE("malloc pinCode failed.");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (memcpy_s(params->pinCodeString, HcStrlen(pinString) + 1, pinString, HcStrlen(pinString)) != EOK) {
            LOGE("memcpy pinCodeString failed.");
            (void)memset_s(params->pinCodeString, HcStrlen(pinString) + 1, 0, HcStrlen(pinString) + 1);
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static int AllocSeed(IsoParams *params)
{
    params->seed.val = (uint8_t *)HcMalloc(SEED_LEN, 0);
    if (params->seed.val == NULL) {
        LOGE("Malloc for seed failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    params->seed.length = SEED_LEN;
    return HC_SUCCESS;
}

static int GetUserType(IsoParams *params, const CJson *in)
{
    int res = GetIntFromJson(in, FIELD_SELF_TYPE, &(params->selfUserType));
    if (res != 0) {
        LOGE("get userType failed: %" LOG_PUB "d", res);
        return res;
    }

    res = GetIntFromJson(in, FIELD_PEER_USER_TYPE, &(params->peerUserType));
    if (res != 0) {
        LOGD("get peer Type failed use default, res: %" LOG_PUB "d", res);
        params->peerUserType = 0; /* fill default value */
        res = HC_SUCCESS;
    }
    return res;
}

static int32_t GetUpgradeFlagAndKeyLength(IsoParams *params, const CJson *in)
{
    (void)GetBoolFromJson(in, FIELD_IS_PEER_FROM_UPGRADE, &params->isPeerFromUpgrade);
    if (params->opCode == OP_UNBIND || params->opCode == OP_BIND) {
        params->keyLen = 0;
        return HC_SUCCESS;
    }

    if (GetIntFromJson(in, FIELD_KEY_LENGTH, (int32_t *)&(params->keyLen)) != 0) {
        LOGD("Get key length failed, use default.");
        params->keyLen = DEFAULT_RETURN_KEY_LENGTH;
    }
    if (params->keyLen < MIN_OUTPUT_KEY_LEN || params->keyLen > MAX_OUTPUT_KEY_LEN) {
        LOGE("Output key length is invalid, keyLen: %" LOG_PUB "d.", params->keyLen);
        return HC_ERR_INVALID_LEN;
    }
    return HC_SUCCESS;
}

int InitIsoParams(IsoParams *params, const CJson *in)
{
    int res;
    if (GetIntFromJson(in, FIELD_OPERATION_CODE, &(params->opCode)) != 0) {
        LOGD("Get opCode failed, use default.");
        params->opCode = AUTHENTICATE;
    }
    if (params->opCode != OP_BIND && params->opCode != OP_UNBIND && params->opCode != AUTHENTICATE) {
        LOGE("Unsupported opCode: %" LOG_PUB "d.", params->opCode);
        res = HC_ERR_NOT_SUPPORT;
        goto ERR;
    }
    if (GetBoolFromJson(in, FIELD_IS_CLIENT, &(params->isClient)) != 0) {
        LOGE("get isClient failed");
        res = HC_ERR_JSON_GET;
        goto ERR;
    }
    res = InitIsoBaseParams(in, &params->baseParams);
    if (res != HC_SUCCESS) {
        LOGE("InitIsoBaseParams failed, res: %" LOG_PUB "x.", res);
        goto ERR;
    }
    res = GetUpgradeFlagAndKeyLength(params, in);
    if (res != HC_SUCCESS) {
        goto ERR;
    }
    res = GetUserType(params, in);
    if (res != HC_SUCCESS) {
        goto ERR;
    }
    res = FillAuthId(params, in);
    if (res != HC_SUCCESS) {
        goto ERR;
    }
    res = FillPkgNameAndServiceType(params, in);
    if (res != HC_SUCCESS) {
        goto ERR;
    }
    res = FillPin(params, in);
    if (res != HC_SUCCESS) {
        goto ERR;
    }
    res = AllocSeed(params);
    if (res != HC_SUCCESS) {
        goto ERR;
    }
    return HC_SUCCESS;
ERR:
    DestroyIsoParams(params);
    return res;
}

static int AuthGeneratePsk(const Uint8Buff *seed, IsoParams *params)
{
    uint8_t keyAliasVal[ISO_KEY_ALIAS_LEN] = { 0 };
    uint8_t upgradeKeyAliasVal[ISO_UPGRADE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAlias = { keyAliasVal, ISO_KEY_ALIAS_LEN };
    if (params->isPeerFromUpgrade) {
        keyAlias.val = upgradeKeyAliasVal;
        keyAlias.length = ISO_UPGRADE_KEY_ALIAS_LEN;
    }
    int32_t res = GenerateKeyAliasForIso(params, &keyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate iso key alias!");
        return res;
    }

    LOGI("AuthCode alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.", keyAlias.val[DEV_AUTH_ZERO],
        keyAlias.val[DEV_AUTH_ONE], keyAlias.val[DEV_AUTH_TWO], keyAlias.val[DEV_AUTH_THREE]);
    Uint8Buff pskBuf = { params->baseParams.psk, sizeof(params->baseParams.psk) };
    if (params->isPeerFromUpgrade) {
        KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, true, params->baseParams.osAccountId };
        res = params->baseParams.loader->computeHmacWithThreeStage(&keyAliasParams, seed, &pskBuf);
        ReportRadarEvent(res);
        return res;
    } else {
        KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, false, params->baseParams.osAccountId };
        return params->baseParams.loader->computeHmac(&keyAliasParams, seed, &pskBuf);
    }
}

static int AuthGeneratePskUsePin(const Uint8Buff *seed, IsoParams *params, const char *pinString)
{
    Uint8Buff messageBuf = { (uint8_t *)pinString, (uint32_t)HcStrlen(pinString) };
    Uint8Buff pskBuf = { params->baseParams.psk, sizeof(params->baseParams.psk) };
    uint8_t hash[SHA256_LEN] = { 0 };
    Uint8Buff hashBuf = { hash, sizeof(hash) };
    int res = params->baseParams.loader->sha256(&messageBuf, &hashBuf);
    if (res != 0) {
        LOGE("sha256 failed, res:%" LOG_PUB "d", res);
        return res;
    }
    KeyParams keyParams = { { hashBuf.val, hashBuf.length, false }, false, params->baseParams.osAccountId };
    return params->baseParams.loader->computeHmac(&keyParams, seed, &pskBuf);
}

int GenerateKeyAliasInIso(const IsoParams *params, uint8_t *keyAlias, uint32_t keyAliasLen, bool useOpposite)
{
    if (params == NULL || keyAlias == NULL || keyAliasLen == 0) {
        return HC_ERR_INVALID_PARAMS;
    }
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)params->packageName;
    tokenParams.pkgName.length = HcStrlen(params->packageName);
    tokenParams.serviceType.val = (uint8_t *)params->serviceType;
    tokenParams.serviceType.length = HcStrlen(params->serviceType);
    tokenParams.userType = KEY_ALIAS_AUTH_TOKEN;
    if (useOpposite) {
        tokenParams.authId = params->baseParams.authIdPeer;
    } else {
        tokenParams.authId = params->baseParams.authIdSelf;
    }
    Uint8Buff outKeyAlias = { keyAlias, keyAliasLen };
    return GenerateKeyAlias(&tokenParams, &outKeyAlias);
}

int GeneratePsk(const CJson *in, IsoParams *params)
{
    if (!params->isClient) {
        if (GetByteFromJson(in, FIELD_SEED, params->seed.val, params->seed.length) != 0) {
            LOGE("Get seed failed.");
            return HC_ERR_JSON_GET;
        }
    }
    int res;
    if (params->opCode == AUTHENTICATE || params->opCode == OP_UNBIND) {
        res = AuthGeneratePsk(&params->seed, params);
    } else {
        res = AuthGeneratePskUsePin(&params->seed, params, params->pinCodeString);
        if (params->pinCodeString != NULL) {
            (void)memset_s(params->pinCodeString, HcStrlen(params->pinCodeString), 0, HcStrlen(params->pinCodeString));
        }
    }
    if (res != HC_SUCCESS) {
        LOGE("Generate psk failed, res: %" LOG_PUB "x.", res);
        goto ERR;
    }
    return res;
ERR:
    (void)memset_s(params->baseParams.psk, sizeof(params->baseParams.psk), 0, sizeof(params->baseParams.psk));
    return res;
}

int GenerateSeed(IsoParams *params)
{
    uint8_t *random = (uint8_t *)HcMalloc(SEED_LEN, 0);
    if (random == NULL) {
        LOGE("malloc random failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff randomBuf = { random, SEED_LEN };
    int res = params->baseParams.loader->generateRandom(&randomBuf);
    if (res != 0) {
        LOGE("generate random failed, res:%" LOG_PUB "d", res);
        HcFree(random);
        return res;
    }
    clock_t times = 0;
    uint8_t *input = (uint8_t *)HcMalloc(SEED_LEN + sizeof(clock_t), 0);
    if (input == NULL) {
        LOGE("malloc failed");
        HcFree(random);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(input, SEED_LEN + sizeof(clock_t), random, SEED_LEN) != EOK) {
        LOGE("memcpy seed failed.");
        res = HC_ERR_MEMORY_COPY;
        goto ERR;
    }
    if (memcpy_s(input + SEED_LEN, sizeof(clock_t), &times, sizeof(clock_t)) != EOK) {
        LOGE("memcpy times failed.");
        res = HC_ERR_MEMORY_COPY;
        goto ERR;
    }
    Uint8Buff inputBuf = { input, SEED_LEN + sizeof(clock_t) };
    res = params->baseParams.loader->sha256(&inputBuf, &params->seed);
    if (res != HC_SUCCESS) {
        LOGE("sha256 failed.");
        goto ERR;
    }
ERR:
    HcFree(random);
    HcFree(input);
    return res;
}
