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

#include "alg_defs.h"
#include "alg_loader.h"
#include "das_standard_token_manager.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "identity_manager.h"
#include "os_account_adapter.h"

typedef struct {
    int32_t osAccountId;
    int32_t acquireType;
    char *deviceId;
    int32_t flag;
    Uint8Buff *publicKey;
    char *serviceType;
} CredentialRequestParamT;

static int32_t CombineServiceId(const Uint8Buff *pkgName, const Uint8Buff *serviceType, Uint8Buff *serviceId)
{
    int32_t res = HC_SUCCESS;
    Uint8Buff serviceIdPlain = { NULL, 0 };
    serviceIdPlain.length = pkgName->length + serviceType->length;
    serviceIdPlain.val = (uint8_t *)HcMalloc(serviceIdPlain.length, 0);
    if (serviceIdPlain.val == NULL) {
        LOGE("malloc serviceIdPlain.val failed.");
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    if (memcpy_s(serviceIdPlain.val, serviceIdPlain.length, pkgName->val, pkgName->length) != EOK) {
        LOGE("Copy service id: pkgName failed.");
        res = HC_ERR_MEMORY_COPY;
        goto ERR;
    }
    if (memcpy_s(serviceIdPlain.val + pkgName->length, serviceIdPlain.length - pkgName->length, serviceType->val,
        serviceType->length) != EOK) {
        LOGE("Copy service id: serviceType failed.");
        res = HC_ERR_MEMORY_COPY;
        goto ERR;
    }
    res = GetLoaderInstance()->sha256(&serviceIdPlain, serviceId);
    if (res != HC_SUCCESS) {
        LOGE("Service id Sha256 failed.");
        goto ERR;
    }
ERR:
    HcFree(serviceIdPlain.val);
    return res;
}

static int32_t CombineKeyAlias(
    const Uint8Buff *serviceId, const Uint8Buff *keyType, const Uint8Buff *authId, Uint8Buff *keyAliasHash)
{
    int32_t res = HC_SUCCESS;
    Uint8Buff keyAliasBuff = { NULL, 0 };
    keyAliasBuff.length = serviceId->length + authId->length + keyType->length;
    keyAliasBuff.val = (uint8_t *)HcMalloc(keyAliasBuff.length, 0);
    if (keyAliasBuff.val == NULL) {
        LOGE("Malloc mem failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    uint32_t totalLen = keyAliasBuff.length;
    uint32_t usedLen = 0;
    if (memcpy_s(keyAliasBuff.val, totalLen, serviceId->val, serviceId->length) != EOK) {
        LOGE("Copy serviceId failed.");
        res = HC_ERR_MEMORY_COPY;
        goto ERR;
    }
    usedLen = usedLen + serviceId->length;
    if (memcpy_s(keyAliasBuff.val + usedLen, totalLen - usedLen, keyType->val, keyType->length) != EOK) {
        LOGE("Copy keyType failed.");
        res = HC_ERR_MEMORY_COPY;
        goto ERR;
    }
    usedLen = usedLen + keyType->length;
    if (memcpy_s(keyAliasBuff.val + usedLen, totalLen - usedLen, authId->val, authId->length) != EOK) {
        LOGE("Copy authId failed.");
        res = HC_ERR_MEMORY_COPY;
        goto ERR;
    }
    res = GetLoaderInstance()->sha256(&keyAliasBuff, keyAliasHash);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 failed.");
        goto ERR;
    }
ERR:
    HcFree(keyAliasBuff.val);
    return res;
}

static int32_t CombineKeyAliasForPake(
    const Uint8Buff *serviceId, const Uint8Buff *keyType, const Uint8Buff *authId, Uint8Buff *outKeyAlias)
{
    int32_t res;
    Uint8Buff keyAliasHash = { NULL, SHA256_LEN };
    char *outKeyAliasHex = NULL;
    if (outKeyAlias->length != SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH) {
        res = HC_ERR_INVALID_LEN;
        goto ERR;
    }
    keyAliasHash.val = (uint8_t *)HcMalloc(keyAliasHash.length, 0);
    if (keyAliasHash.val == NULL) {
        LOGE("Malloc keyAliasHash failed");
        res = HC_ERR_ALLOC_MEMORY;
        goto ERR;
    }
    res = CombineKeyAlias(serviceId, keyType, authId, &keyAliasHash);
    if (res != HC_SUCCESS) {
        LOGE("CombineKeyAlias failed.");
        goto ERR;
    }
    uint32_t outKeyAliasHexLen = keyAliasHash.length * BYTE_TO_HEX_OPER_LENGTH + 1;
    outKeyAliasHex = (char *)HcMalloc(outKeyAliasHexLen, 0);
    res = ByteToHexString(keyAliasHash.val, keyAliasHash.length, outKeyAliasHex, outKeyAliasHexLen);
    if (res != HC_SUCCESS) {
        LOGE("ByteToHexString failed");
        goto ERR;
    }
    if (memcpy_s(outKeyAlias->val, outKeyAlias->length, outKeyAliasHex, strlen(outKeyAliasHex)) != EOK) {
        LOGE("memcpy outkeyalias failed.");
        res = HC_ERR_MEMORY_COPY;
        goto ERR;
    }
ERR:
    HcFree(keyAliasHash.val);
    HcFree(outKeyAliasHex);
    return res;
}

static int32_t GenerateKeyAliasInner(
    const char *pkgName, const char *serviceType, const char *authId, int keyAliasType, Uint8Buff *outKeyAlias)
{
    CHECK_PTR_RETURN_ERROR_CODE(pkgName, "pkgName");
    CHECK_PTR_RETURN_ERROR_CODE(serviceType, "serviceType");
    CHECK_PTR_RETURN_ERROR_CODE(authId, "authId");
    CHECK_PTR_RETURN_ERROR_CODE(outKeyAlias, "outKeyAlias");
    if (strlen(pkgName) == 0 || strlen(serviceType) == 0 || strlen(authId) == 0) {
        LOGE("Invalid zero length params exist.");
        return HC_ERR_INVALID_LEN;
    }
    Uint8Buff pkgNameBuff = { (uint8_t *)pkgName, strlen(pkgName) };
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, strlen(serviceType) };
    Uint8Buff authIdBuff = { NULL, HcStrlen(authId) };
    authIdBuff.val = (uint8_t *)HcMalloc(authIdBuff.length, 0);
    if (authIdBuff.val == NULL) {
        LOGE("Failed to allocate authIdBuff memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(authIdBuff.val, authIdBuff.length, authId, authIdBuff.length) != EOK) {
        LOGE("Failed to copy authId!");
        HcFree(authIdBuff.val);
        return HC_ERR_MEMORY_COPY;
    }
    if (pkgNameBuff.length > PACKAGE_NAME_MAX_LEN || serviceTypeBuff.length > SERVICE_TYPE_MAX_LEN ||
        authIdBuff.length > AUTH_ID_MAX_LEN || keyAliasType >= KEY_ALIAS_TYPE_END) {
        LOGE("Out of length params exist.");
        HcFree(authIdBuff.val);
        return HC_ERR_INVALID_LEN;
    }

    uint8_t serviceId[SHA256_LEN] = { 0 };
    Uint8Buff serviceIdBuff = { serviceId, SHA256_LEN };
    int32_t res = CombineServiceId(&pkgNameBuff, &serviceTypeBuff, &serviceIdBuff);
    if (res != HC_SUCCESS) {
        LOGE("CombineServiceId failed, res: %x.", res);
        HcFree(authIdBuff.val);
        return res;
    }

    Uint8Buff keyTypeBuff = { GetKeyTypePair(keyAliasType), KEY_TYPE_PAIR_LEN };
    res = CombineKeyAliasForPake(&serviceIdBuff, &keyTypeBuff, &authIdBuff, outKeyAlias);
    HcFree(authIdBuff.val);
    if (res != HC_SUCCESS) {
        LOGE("CombineKeyAlias failed, keyType: %d, res: %d", keyAliasType, res);
    }
    return res;
}

static void FreeCredParam(CredentialRequestParamT *param)
{
    if (param) {
        HcFree(param->deviceId);
        param->deviceId = NULL;

        HcFree(param->serviceType);
        param->serviceType = NULL;

        if (param->publicKey) {
            if (param->publicKey->val) {
                HcFree(param->publicKey->val);
            }
            HcFree(param->publicKey);
            param->publicKey = NULL;
        }

        HcFree(param);
    }
}

static int32_t DecodeServiceTypeAndPublicKey(CredentialRequestParamT *param, CJson *reqJson)
{
    if (!param || !reqJson) {
        LOGE("reqJson and param must not null ! ");
        return HC_ERR_INVALID_PARAMS;
    }

    const char *serviceType = GetStringFromJson(reqJson, FIELD_SERVICE_TYPE);
    if (serviceType == NULL) {
        param->serviceType = strdup(DEFAULT_SERVICE_TYPE);
    } else {
        param->serviceType = strdup(serviceType);
    }

    const char *publicKeyStr = GetStringFromJson(reqJson, FIELD_PUBLIC_KEY);
    if (publicKeyStr != NULL && HcStrlen(publicKeyStr) > 0) {
        if (HcStrlen(publicKeyStr) > PAKE_ED25519_KEY_STR_LEN) {
            LOGE("public key longer then %d.", PAKE_ED25519_KEY_STR_LEN);
            return HC_ERR_INVALID_LEN;
        }
        param->publicKey = (Uint8Buff *)HcMalloc(sizeof(Uint8Buff), 0);
        int32_t res = InitUint8Buff(param->publicKey, PAKE_ED25519_KEY_PAIR_LEN);
        if (res != HC_SUCCESS) {
            LOGE("allocate publicKey memory fail. res: %d", res);
            return HC_ERR_ALLOC_MEMORY;
        }
        if (GetByteFromJson(reqJson, FIELD_PUBLIC_KEY, param->publicKey->val, param->publicKey->length) !=
            HC_SUCCESS) {
            LOGE("get authPkC from reqJson fail.");
            return HC_ERR_JSON_GET;
        } else {
            LOGI("decode publicKey success.");
        }
    } else {
        param->publicKey = NULL;
    }

    return HC_SUCCESS;
}

static CredentialRequestParamT *DecodeRequestParam(const char *reqJsonStr)
{
    if (!reqJsonStr) {
        LOGE("reqJsonStr must not null ! ");
        return NULL;
    }
    CredentialRequestParamT *param = (CredentialRequestParamT *)HcMalloc(sizeof(CredentialRequestParamT), 0);
    if (param == NULL) {
        LOGE("Failed to ALLOC!");
        return NULL;
    }
    CJson *json = CreateJsonFromString(reqJsonStr);
    if (json == NULL) {
        LOGE("Failed to create json from string!");
        FreeCredParam(param);
        param = NULL;
        goto ERR;
    }
    if (GetIntFromJson(json, FIELD_OS_ACCOUNT_ID, &param->osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from reqJsonStr!");
        FreeCredParam(param);
        param = NULL;
        goto ERR;
    }
    if (GetIntFromJson(json, FIELD_ACQURIED_TYPE, &param->acquireType) != HC_SUCCESS) {
        LOGE("Failed to get acquireType from reqJsonStr!");
        FreeCredParam(param);
        param = NULL;
        goto ERR;
    }
    if (GetIntFromJson(json, FIELD_CRED_OP_FLAG, &param->flag) != HC_SUCCESS) {
        LOGI("reqJsonStr not contains flag!");
    }
    const char *deviceId = GetStringFromJson(json, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId from reqJsonStr!");
        FreeCredParam(param);
        param = NULL;
        goto ERR;
    } else {
        param->deviceId = strdup(deviceId);
    }
    if (DecodeServiceTypeAndPublicKey(param, json) != HC_SUCCESS) {
        LOGE("Failed to DecodeServiceTypeAndPublicKey from reqJsonStr!");
        goto ERR;
    }
ERR:
    FreeJson(json);
    return param;
}

static int32_t PackPublicKeyToJson(
    CJson *out, int32_t osAccountId, int32_t keyType, const char *authId, const char *serviceType)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((authId == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    Uint8Buff authIdBuff = { (uint8_t *)authId, HcStrlen(authId) };
    uint8_t returnPkBytes[PUBLIC_KEY_MAX_LENGTH] = { 0 };
    Uint8Buff returnPkBuff = { returnPkBytes, PUBLIC_KEY_MAX_LENGTH };
    int32_t res = GetStandardTokenManagerInstance()->getPublicKey(
        DEFAULT_PACKAGE_NAME, serviceType, &authIdBuff, keyType, &returnPkBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to getPublicKey!");
        return HC_ERR_LOCAL_IDENTITY_NOT_EXIST;
    }

    char returnPkHexStr[SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1] = { 0 };
    res = ByteToHexString(returnPkBuff.val, returnPkBuff.length, returnPkHexStr, sizeof(returnPkHexStr));
    if (res != HC_SUCCESS) {
        LOGE("Failed to get hex str for pk!");
        return HC_ERR_HASH_FAIL;
    }

    if (AddStringToJson(out, FIELD_PUBLIC_KEY, (const char *)returnPkHexStr) != HC_SUCCESS) {
        LOGE("Failed to ADD pubKey to returnData!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static char *PackResultToJson(CJson *out, int32_t res)
{
    if (out == NULL) {
        LOGE("param is null !");
        return NULL;
    }
    if (AddIntToJson(out, FIELD_CRED_OP_RESULT, res) != HC_SUCCESS) {
        LOGE("Failed to set result to json");
        return NULL;
    }

    return PackJsonToString(out);
}

static int32_t IsKeyExistReturnAliasIfNeeded(CredentialRequestParamT *param, Uint8Buff *outKeyAlias)
{
    if (param->acquireType != P2P_BIND) {
        LOGE("acquireType invalid! only P2P_BIND is allowed now!");
        return HC_ERR_INVALID_PARAMS;
    }
    // Caution: Only acquireType is P2P_BIND, keyType can be set to KEY_ALIAS_P2P_AUTH
    int32_t keyType = KEY_ALIAS_P2P_AUTH;
    param->osAccountId = DevAuthGetRealOsAccountLocalId(param->osAccountId);
    if ((param->deviceId == NULL) || (param->osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t keyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAliasInner(DEFAULT_PACKAGE_NAME, param->serviceType, param->deviceId,
        keyType, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate identity keyPair alias!");
        return res;
    }
    LOGI("KeyPair alias(HEX): %x%x%x%x****.", keyAliasVal[DEV_AUTH_ZERO], keyAliasVal[DEV_AUTH_ONE],
        keyAliasVal[DEV_AUTH_TWO], keyAliasVal[DEV_AUTH_THREE]);

    if ((outKeyAlias != NULL) &&
        (memcpy_s(outKeyAlias->val, outKeyAlias->length, keyAliasBuff.val, keyAliasBuff.length) != EOK)) {
        LOGE("memcpy outkeyalias failed.");
        return HC_ERR_MEMORY_COPY;
    }

    res = GetLoaderInstance()->checkKeyExist(&keyAliasBuff);
    if (res != HC_SUCCESS) {
        return HC_ERR_LOCAL_IDENTITY_NOT_EXIST;
    }
    return HC_SUCCESS;
}

static int32_t QueryCredential(const char *reqJsonStr, char **returnData)
{
    int32_t res;
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to CreateJson!");
        return HC_ERR_JSON_CREATE;
    }
    CredentialRequestParamT *param = DecodeRequestParam(reqJsonStr);
    if (param == NULL) {
        LOGE("Failed to DecodeCredParam from reqJsonStr!");
        res = HC_ERR_JSON_GET;
        goto ERR;
    }
    res = IsKeyExistReturnAliasIfNeeded(param, NULL);
    if (res != HC_SUCCESS) {
        LOGD("Key pair not exist.");
        goto ERR;
    }
    if (param->acquireType != P2P_BIND) {
        LOGE("acquireType invalid! only P2P_BIND is allowed now!");
        res = HC_ERR_INVALID_PARAMS;
        goto ERR;
    }
    // Caution: Only acquireType is P2P_BIND, keyType can be set to KEY_ALIAS_P2P_AUTH
    int32_t keyType = KEY_ALIAS_P2P_AUTH;
    if (RETURN_FLAG_PUBLIC_KEY == param->flag) {
        res = PackPublicKeyToJson(out, param->osAccountId, keyType, param->deviceId, param->serviceType);
        if (res != HC_SUCCESS) {
            LOGD("PackPublicKeyToJson failed");
            goto ERR;
        }
    }
ERR:
    if (returnData) {
        *returnData = PackResultToJson(out, res);
    }
    FreeJson(out);
    FreeCredParam(param);
    return res;
}

static int32_t GenarateCredential(const char *reqJsonStr, char **returnData)
{
    int32_t res;
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to CreateJson!");
        return HC_ERR_JSON_CREATE;
    }
    CredentialRequestParamT *param = DecodeRequestParam(reqJsonStr);
    if (param == NULL) {
        LOGE("Failed to DecodeCredParam from reqJsonStr!");
        res = HC_ERR_INVALID_PARAMS;
        goto ERR;
    }
    res = IsKeyExistReturnAliasIfNeeded(param, NULL);
    if (res == HC_SUCCESS) {
        LOGD("Key pair already exist.");
        res = HC_ERR_IDENTITY_DUPLICATED;
        goto ERR;
    }
    Uint8Buff authIdBuff = { (uint8_t *)param->deviceId, HcStrlen(param->deviceId) };
    if (param->acquireType != P2P_BIND) {
        LOGE("acquireType invalid! only P2P_BIND is allowed now!");
        res = HC_ERR_INVALID_PARAMS;
        goto ERR;
    }
    // Caution: Only acquireType is P2P_BIND, keyType can be set to KEY_ALIAS_P2P_AUTH
    int32_t keyType = KEY_ALIAS_P2P_AUTH;
    res = GetStandardTokenManagerInstance()->registerLocalIdentity(
        DEFAULT_PACKAGE_NAME, param->serviceType, &authIdBuff, keyType);
    if (res != HC_SUCCESS) {
        LOGE("Failed to registerLocalIdentity!");
        goto ERR;
    }
    if (RETURN_FLAG_PUBLIC_KEY == param->flag) {
        res = PackPublicKeyToJson(out, param->osAccountId, keyType, param->deviceId, param->serviceType);
        if (res != HC_SUCCESS) {
            LOGE("PackPublicKeyToJson failed");
            goto ERR;
        }
    }
ERR:
    if (returnData) {
        *returnData = PackResultToJson(out, res);
    }
    FreeJson(out);
    FreeCredParam(param);
    return res;
}

static int32_t ComputeAndSavePsk(const char *peerServiceType, const char *peerAuthId, int keyType)
{
    uint8_t selfKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff selfKeyAlias = { selfKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    uint8_t peerKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff peerKeyAlias = { peerKeyAliasVal, PAKE_KEY_ALIAS_LEN };

    char selfAuthId[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfAuthId, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return HC_ERR_DB;
    }

    res = GenerateKeyAliasInner(DEFAULT_PACKAGE_NAME, DEFAULT_SERVICE_TYPE, selfAuthId, keyType, &selfKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("generateKeyAlias self failed");
        return res;
    }
    LOGI("selfKeyAlias(HEX): %x%x%x%x****", selfKeyAliasVal[DEV_AUTH_ZERO], selfKeyAliasVal[DEV_AUTH_ONE],
        selfKeyAliasVal[DEV_AUTH_TWO], selfKeyAliasVal[DEV_AUTH_THREE]);

    res = GenerateKeyAliasInner(DEFAULT_PACKAGE_NAME, peerServiceType, peerAuthId, keyType, &peerKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("generateKeyAlias peer failed");
        return res;
    }
    LOGI("peerKeyAlias(HEX): %x%x%x%x****", peerKeyAliasVal[DEV_AUTH_ZERO], peerKeyAliasVal[DEV_AUTH_ONE],
        peerKeyAliasVal[DEV_AUTH_TWO], peerKeyAliasVal[DEV_AUTH_THREE]);
    res = GetLoaderInstance()->checkKeyExist(&selfKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("self auth keyPair not exist .");
        return res;
    }
    res = GetLoaderInstance()->checkKeyExist(&peerKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("peer auth pubKey not exist");
        return res;
    }

    uint8_t sharedKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff sharedKeyAlias = { sharedKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GenerateKeyAliasInner(DEFAULT_PACKAGE_NAME, peerServiceType, peerAuthId, KEY_ALIAS_PSK, &sharedKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("generateKeyAlias psk failed");
        return res;
    }
    LOGI("psk alias(HEX): %x%x%x%x****", sharedKeyAliasVal[DEV_AUTH_ZERO], sharedKeyAliasVal[DEV_AUTH_ONE],
        sharedKeyAliasVal[DEV_AUTH_TWO], sharedKeyAliasVal[DEV_AUTH_THREE]);

    KeyBuff selfKeyAliasBuff = { selfKeyAlias.val, selfKeyAlias.length, true };
    KeyBuff peerKeyAliasBuff = { peerKeyAlias.val, peerKeyAlias.length, true };
    return GetLoaderInstance()->agreeSharedSecretWithStorage(
        &selfKeyAliasBuff, &peerKeyAliasBuff, ED25519, PAKE_PSK_LEN, &sharedKeyAlias);
}

static int32_t IsSelfKeyPairExist(int keyType)
{
    if (keyType != KEY_ALIAS_P2P_AUTH) {
        LOGE("keyType invalid! only KEY_ALIAS_P2P_AUTH is allowed now!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint8_t selfKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff selfKeyAlias = { selfKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    char selfAuthId[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfAuthId, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return HC_ERR_DB;
    }

    res = GenerateKeyAliasInner(DEFAULT_PACKAGE_NAME, DEFAULT_SERVICE_TYPE, selfAuthId, keyType, &selfKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("generateKeyAlias self failed");
        return res;
    }
    LOGI("selfKeyAlias(HEX): %x%x%x%x****", selfKeyAliasVal[DEV_AUTH_ZERO], selfKeyAliasVal[DEV_AUTH_ONE],
        selfKeyAliasVal[DEV_AUTH_TWO], selfKeyAliasVal[DEV_AUTH_THREE]);

    res = GetLoaderInstance()->checkKeyExist(&selfKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("self keypair not exist");
        return res;
    }

    return HC_SUCCESS;
}

static int32_t CheckImportConditions(CredentialRequestParamT *param, Uint8Buff *outKeyAlias)
{
    if (param == NULL || outKeyAlias == NULL) {
        LOGE("invalid param!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (param->acquireType != P2P_BIND) {
        LOGE("acquireType invalid! only P2P_BIND is allowed now!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = IsKeyExistReturnAliasIfNeeded(param, outKeyAlias);
    if (res == HC_SUCCESS) {
        LOGD("Key pair already exist.");
        return HC_ERR_IDENTITY_DUPLICATED;
    }

    res = IsSelfKeyPairExist(KEY_ALIAS_P2P_AUTH);
    if (res != HC_SUCCESS) {
        LOGD("self Key pair not exist.");
        return HC_ERR_LOCAL_IDENTITY_NOT_EXIST;
    }

    return HC_SUCCESS;
}

static int32_t ImportCredential(const char *reqJsonStr, char **returnData)
{
    int32_t res;
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to CreateJson!");
        return HC_ERR_JSON_CREATE;
    }
    CredentialRequestParamT *param = DecodeRequestParam(reqJsonStr);
    if (param == NULL || param->publicKey == NULL) {
        LOGE("Failed to DecodeCredParam from reqJsonStr!");
        res = HC_ERR_JSON_GET;
        goto ERR;
    }
    uint8_t keyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAliasVal, PAKE_KEY_ALIAS_LEN };
    res = CheckImportConditions(param, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("CheckImportConditions failed.");
        goto ERR;
    }
    Uint8Buff authIdBuff = { (uint8_t *)param->deviceId, strlen(param->deviceId) };
    // Caution: Only acquireType is P2P_BIND, keyType can be set to KEY_ALIAS_P2P_AUTH
    int32_t keyType = KEY_ALIAS_P2P_AUTH;
    ExtraInfo exInfo = { authIdBuff, keyType, PAIR_TYPE_BIND };
    res = GetLoaderInstance()->importPublicKey(&keyAliasBuff, param->publicKey, ED25519, &exInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to importPublicKey!");
        goto ERR;
    }
    res = ComputeAndSavePsk(param->serviceType, param->deviceId, keyType);
    if (res != HC_SUCCESS) {
        LOGE("Failed to ComputeAndSavePsk, lets delete imported key!");
        if (GetStandardTokenManagerInstance()->unregisterLocalIdentity(
            DEFAULT_PACKAGE_NAME, param->serviceType, &authIdBuff, keyType) != HC_SUCCESS) {
            LOGE("Failed to delete imported PublicKey!");
        }
        goto ERR;
    }
ERR:
    if (returnData) {
        *returnData = PackResultToJson(out, res);
    }
    FreeJson(out);
    FreeCredParam(param);
    return res;
}

static int32_t DeleteCredential(const char *reqJsonStr, char **returnData)
{
    int32_t res;
    CJson *out = CreateJson();
    if (out == NULL) {
        LOGE("Failed to CreateJson!");
        return HC_ERR_JSON_CREATE;
    }
    CredentialRequestParamT *param = DecodeRequestParam(reqJsonStr);
    if (param == NULL) {
        LOGE("Failed to DecodeCredParam from reqJsonStr!");
        res = HC_ERR_JSON_GET;
        goto ERR;
    }
    if (param->acquireType != P2P_BIND) {
        LOGE("acquireType invalid! only P2P_BIND is allowed now!");
        res = HC_ERR_INVALID_PARAMS;
        goto ERR;
    }
    // Caution: Only acquireType is P2P_BIND, keyType can be set to KEY_ALIAS_P2P_AUTH
    int32_t keyType = KEY_ALIAS_P2P_AUTH;
    param->osAccountId = DevAuthGetRealOsAccountLocalId(param->osAccountId);
    if ((param->deviceId == NULL) || (param->osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        res = HC_ERR_INVALID_PARAMS;
        goto ERR;
    }
    Uint8Buff authIdBuff = { (uint8_t *)param->deviceId, strlen(param->deviceId) };
    res = GetStandardTokenManagerInstance()->unregisterLocalIdentity(
        DEFAULT_PACKAGE_NAME, param->serviceType, &authIdBuff, KEY_ALIAS_PSK);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete psk!");
        goto ERR;
    }
    res = GetStandardTokenManagerInstance()->unregisterLocalIdentity(
        DEFAULT_PACKAGE_NAME, param->serviceType, &authIdBuff, keyType);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete identity keyPair!");
        goto ERR;
    }
ERR:
    if (returnData) {
        *returnData = PackResultToJson(out, res);
    }
    FreeJson(out);
    FreeCredParam(param);
    return res;
}

static const CredentialOperator g_credentialOperator = {
    .queryCredential = QueryCredential,
    .genarateCredential = GenarateCredential,
    .importCredential = ImportCredential,
    .deleteCredential = DeleteCredential,
};

const CredentialOperator *GetCredentialOperator(void)
{
    return &g_credentialOperator;
}