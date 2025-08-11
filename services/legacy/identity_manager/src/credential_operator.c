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
#include "hisysevent_common.h"
#include "string_util.h"

typedef struct {
    int32_t osAccountId;
    int32_t peerOsAccountId;
    int32_t acquireType;
    char *deviceId;
    int32_t flag;
    Uint8Buff publicKey;
    char *serviceType;
} CredentialRequestParam;

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
        LOGE("Sha256 serviceId  failed.");
        goto ERR;
    }
ERR:
    HcFree(serviceIdPlain.val);
    return res;
}

static bool IsPeerDevice(const Uint8Buff *authId)
{
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d.", res);
        return false;
    }
    char *authIdStr = (char *)HcMalloc(authId->length + 1, 0);
    if (authIdStr == NULL) {
        LOGE("Failed to alloc memory for authIdStr!");
        return false;
    }
    if (memcpy_s(authIdStr, authId->length + 1, authId->val, authId->length) != EOK) {
        LOGE("Failed to copy authId!");
        HcFree(authIdStr);
        return false;
    }
    bool isPeerDevice = HcStrcmp(selfUdid, authIdStr) != 0;
    HcFree(authIdStr);
    return isPeerDevice;
}

static int32_t FillKeyAlias(const Uint8Buff *serviceId, const Uint8Buff *keyType, const Uint8Buff *authId,
    Uint8Buff *keyAliasBuff)
{
    uint32_t totalLen = keyAliasBuff->length;
    uint32_t usedLen = 0;
    if (memcpy_s(keyAliasBuff->val, totalLen, serviceId->val, serviceId->length) != EOK) {
        LOGE("Error occurs, Copy serviceId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen = usedLen + serviceId->length;
    if (memcpy_s(keyAliasBuff->val + usedLen, totalLen - usedLen, keyType->val, keyType->length) != EOK) {
        LOGE("Error occurs, Copy keyType failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen = usedLen + keyType->length;
    if (memcpy_s(keyAliasBuff->val + usedLen, totalLen - usedLen, authId->val, authId->length) != EOK) {
        LOGE("Error occurs, Copy authId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t FillKeyAliasWithPeerOsAccId(const Uint8Buff *serviceId, const Uint8Buff *keyType,
    const Uint8Buff *authId, int32_t peerOsAccountId, Uint8Buff *keyAliasBuff)
{
    uint32_t totalLen = keyAliasBuff->length;
    uint32_t usedLen = 0;
    if (memcpy_s(keyAliasBuff->val, totalLen, serviceId->val, serviceId->length) != EOK) {
        LOGE("Copy serviceId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen = usedLen + serviceId->length;
    if (memcpy_s(keyAliasBuff->val + usedLen, totalLen - usedLen, keyType->val, keyType->length) != EOK) {
        LOGE("Copy keyType failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen = usedLen + keyType->length;
    if (memcpy_s(keyAliasBuff->val + usedLen, totalLen - usedLen, authId->val, authId->length) != EOK) {
        LOGE("Copy authId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    usedLen = usedLen + authId->length;
    Uint8Buff peerOsAccIdBuff = { (uint8_t *)&peerOsAccountId, sizeof(peerOsAccountId) };
    if (memcpy_s(keyAliasBuff->val + usedLen, totalLen - usedLen, peerOsAccIdBuff.val,
        peerOsAccIdBuff.length) != EOK) {
        LOGE("Copy peerOsAccountId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t CombineKeyAlias(const Uint8Buff *serviceId, const Uint8Buff *keyType, const Uint8Buff *authId,
    int32_t peerOsAccountId, Uint8Buff *keyAliasHash)
{
    Uint8Buff keyAliasBuff = { NULL, 0 };
    bool isPeerDevice = IsPeerDevice(authId);
    if (isPeerDevice) {
        keyAliasBuff.length = serviceId->length + authId->length + keyType->length + sizeof(peerOsAccountId);
    } else {
        keyAliasBuff.length = serviceId->length + authId->length + keyType->length;
    }
    keyAliasBuff.val = (uint8_t *)HcMalloc(keyAliasBuff.length, 0);
    if (keyAliasBuff.val == NULL) {
        LOGE("Failed to alloc memory for key alias!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HC_SUCCESS;
    if (isPeerDevice) {
        res = FillKeyAliasWithPeerOsAccId(serviceId, keyType, authId, peerOsAccountId, &keyAliasBuff);
    } else {
        res = FillKeyAlias(serviceId, keyType, authId, &keyAliasBuff);
    }
    if (res != HC_SUCCESS) {
        LOGE("Failed to fill key alias!");
        HcFree(keyAliasBuff.val);
        return res;
    }
    res = GetLoaderInstance()->sha256(&keyAliasBuff, keyAliasHash);
    HcFree(keyAliasBuff.val);
    if (res != HC_SUCCESS) {
        LOGE("Sha256 failed!");
    }
    return res;
}

static int32_t CombineKeyAliasForPake(const Uint8Buff *serviceId, const Uint8Buff *keyType, const Uint8Buff *authId,
    int32_t peerOsAccountId, Uint8Buff *outKeyAlias)
{
    if (outKeyAlias->length != SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH) {
        LOGE("Invalid key alias len!");
        return HC_ERR_INVALID_LEN;
    }
    uint8_t keyAliasHashVal[SHA256_LEN] = { 0 };
    Uint8Buff keyAliasHash = { keyAliasHashVal, SHA256_LEN };
    int32_t res = CombineKeyAlias(serviceId, keyType, authId, peerOsAccountId, &keyAliasHash);
    if (res != HC_SUCCESS) {
        LOGE("Failed to combine key alias!");
        return res;
    }

    char outKeyAliasHex[SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1] = { 0 };
    res = ByteToHexString(keyAliasHash.val, keyAliasHash.length, outKeyAliasHex, sizeof(outKeyAliasHex));
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert key alias hash to hex!");
        return res;
    }
    if (memcpy_s(outKeyAlias->val, outKeyAlias->length, outKeyAliasHex, HcStrlen(outKeyAliasHex)) != EOK) {
        LOGE("Failed to copy out key alias hex!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t GenerateKeyAliasInner(const char *serviceType, const char *authId, int keyAliasType,
    int32_t peerOsAccountId, Uint8Buff *outKeyAlias)
{
    if (HcStrlen(serviceType) == 0 || HcStrlen(authId) == 0) {
        LOGE("Invalid param len!");
        return HC_ERR_INVALID_LEN;
    }
    if (keyAliasType >= KEY_ALIAS_TYPE_END) {
        LOGE("Invalid key type!");
        return HC_ERR_INVALID_PARAMS;
    }
    Uint8Buff pkgNameBuff = { (uint8_t *)DEFAULT_PACKAGE_NAME, HcStrlen(DEFAULT_PACKAGE_NAME) };
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, HcStrlen(serviceType) };
    Uint8Buff authIdBuff = { (uint8_t *)authId, HcStrlen(authId) };
    if (pkgNameBuff.length > PACKAGE_NAME_MAX_LEN || serviceTypeBuff.length > SERVICE_TYPE_MAX_LEN ||
        authIdBuff.length > AUTH_ID_MAX_LEN) {
        LOGE("Param len over max!");
        return HC_ERR_INVALID_LEN;
    }

    uint8_t serviceId[SHA256_LEN] = { 0 };
    Uint8Buff serviceIdBuff = { serviceId, SHA256_LEN };
    int32_t res = CombineServiceId(&pkgNameBuff, &serviceTypeBuff, &serviceIdBuff);
    if (res != HC_SUCCESS) {
        LOGE("CombineServiceId failed, res: %" LOG_PUB "d.", res);
        return res;
    }

    Uint8Buff keyTypeBuff = { GetKeyTypePair(keyAliasType), KEY_TYPE_PAIR_LEN };
    res = CombineKeyAliasForPake(&serviceIdBuff, &keyTypeBuff, &authIdBuff, peerOsAccountId, outKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("CombineKeyAlias failed, keyType: %" LOG_PUB "d, res: %" LOG_PUB "d", keyAliasType, res);
    }
    return res;
}

static void ClearCredParam(CredentialRequestParam *param)
{
    if (param == NULL) {
        return;
    }
    if (param->deviceId != NULL) {
        HcFree(param->deviceId);
        param->deviceId = NULL;
    }
    if (param->serviceType != NULL) {
        HcFree(param->serviceType);
        param->serviceType = NULL;
    }
    if (param->publicKey.val != NULL) {
        HcFree(param->publicKey.val);
        param->publicKey.val = NULL;
    }
}

static int32_t GetServTypeAndPubKey(const CJson *reqJson, bool isPubKeyNeeded, CredentialRequestParam *param)
{
    const char *serviceType = GetStringFromJson(reqJson, FIELD_SERVICE_TYPE);
    int32_t res = HC_SUCCESS;
    if (serviceType == NULL) {
        LOGI("serviceType not found, use default value.");
        res = DeepCopyString(DEFAULT_SERVICE_TYPE, &param->serviceType);
    } else {
        res = DeepCopyString(serviceType, &param->serviceType);
    }
    if (res != HC_SUCCESS) {
        LOGE("Failed to copy serviceType!");
        return res;
    }

    if (!isPubKeyNeeded) {
        return HC_SUCCESS;
    }
    
    const char *publicKeyStr = GetStringFromJson(reqJson, FIELD_PUBLIC_KEY);
    if (publicKeyStr == NULL) {
        LOGE("Failed to get public key!");
        return HC_ERR_JSON_GET;
    }
    if (HcStrlen(publicKeyStr) == 0 || HcStrlen(publicKeyStr) > PAKE_ED25519_KEY_STR_LEN) {
        LOGE("Invalid public key len!");
        return HC_ERR_INVALID_LEN;
    }
    if (InitUint8Buff(&param->publicKey, PAKE_ED25519_KEY_PAIR_LEN) != HC_SUCCESS) {
        LOGE("Failed to alloc memory for publicKey!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(reqJson, FIELD_PUBLIC_KEY, param->publicKey.val, param->publicKey.length) !=
        HC_SUCCESS) {
        LOGE("Failed to get public key bytes!");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

static int32_t GetAndCheckOsAccountId(const CJson *reqJson, CredentialRequestParam *param)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(reqJson, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    param->osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (param->osAccountId == INVALID_OS_ACCOUNT) {
        LOGE("Invalid osAccountId!");
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

static int32_t GetAndCheckAcquireType(const CJson *reqJson, CredentialRequestParam *param)
{
    if (GetIntFromJson(reqJson, FIELD_ACQURIED_TYPE, &param->acquireType) != HC_SUCCESS) {
        LOGE("Failed to get acquireType!");
        return HC_ERR_JSON_GET;
    }
    if (param->acquireType != P2P_BIND) {
        LOGE("acquireType invalid! only P2P_BIND is allowed now!");
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

static int32_t GetPeerOsAccountId(const CJson *reqJson, const char *deviceId, int32_t *peerOsAccountId)
{
    Uint8Buff authIdBuff = { (uint8_t *)deviceId, HcStrlen(deviceId) };
    if (!IsPeerDevice(&authIdBuff)) {
        LOGI("Not peer device operation, peer osAccountId is not needed.");
        return HC_SUCCESS;
    }
    if (GetIntFromJson(reqJson, FIELD_PEER_OS_ACCOUNT_ID, peerOsAccountId) != HC_SUCCESS) {
        LOGE("Failed to get peer osAccountId!");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

static int32_t GenerateRequestParamFromJson(const char *reqJsonStr, bool isPubKeyNeeded,
    CredentialRequestParam *param)
{
    CJson *reqJson = CreateJsonFromString(reqJsonStr);
    if (reqJson == NULL) {
        LOGE("Failed to create request json!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = HC_SUCCESS;
    do {
        res = GetAndCheckOsAccountId(reqJson, param);
        if (res != HC_SUCCESS) {
            break;
        }
        res = GetAndCheckAcquireType(reqJson, param);
        if (res != HC_SUCCESS) {
            break;
        }
        if (GetIntFromJson(reqJson, FIELD_CRED_OP_FLAG, &param->flag) != HC_SUCCESS) {
            LOGI("reqJsonStr not contains flag!");
        }
        const char *deviceId = GetStringFromJson(reqJson, FIELD_DEVICE_ID);
        if (deviceId == NULL) {
            LOGE("Failed to get deviceId!");
            res = HC_ERR_JSON_GET;
            break;
        }
        if (DeepCopyString(deviceId, &param->deviceId) != HC_SUCCESS) {
            LOGE("Failed to copy deviceId!");
            res = HC_ERR_MEMORY_COPY;
            break;
        }
        res = GetPeerOsAccountId(reqJson, deviceId, &param->peerOsAccountId);
        if (res != HC_SUCCESS) {
            break;
        }
        res = GetServTypeAndPubKey(reqJson, isPubKeyNeeded, param);
    } while (0);
    FreeJson(reqJson);
    if (res != HC_SUCCESS) {
        ClearCredParam(param);
    }
    return res;
}

static int32_t CheckKeyExistByParam(const CredentialRequestParam *param)
{
    uint8_t keyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t res = GenerateKeyAliasInner(param->serviceType, param->deviceId,
        KEY_ALIAS_P2P_AUTH, param->peerOsAccountId, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate identity key alias!");
        return res;
    }
    LOGI("Key alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****.", keyAliasVal[DEV_AUTH_ZERO],
        keyAliasVal[DEV_AUTH_ONE], keyAliasVal[DEV_AUTH_TWO], keyAliasVal[DEV_AUTH_THREE]);

    res = GetLoaderInstance()->checkKeyExist(&keyAliasBuff, false, param->osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Identity key not exists!");
        return HC_ERR_LOCAL_IDENTITY_NOT_EXIST;
    }
    return HC_SUCCESS;
}

static int32_t AddPubKeyToReturnData(const CredentialRequestParam *param, CJson *returnDataJson)
{
    TokenManagerParams params = {
        .osAccountId = param->osAccountId,
        .peerOsAccountId = param->peerOsAccountId,
        .pkgName = { (uint8_t *)DEFAULT_PACKAGE_NAME, HcStrlen(DEFAULT_PACKAGE_NAME) },
        .serviceType = { (uint8_t *)param->serviceType, HcStrlen(param->serviceType) },
        .authId = { (uint8_t *)param->deviceId, HcStrlen(param->deviceId) },
        .userType = KEY_ALIAS_P2P_AUTH,
        .isDirectAuthToken = true
    };
    uint8_t returnPkBytes[PUBLIC_KEY_MAX_LENGTH] = { 0 };
    Uint8Buff returnPkBuff = { returnPkBytes, PUBLIC_KEY_MAX_LENGTH };
    if (GetStandardTokenManagerInstance()->getPublicKey(&params, &returnPkBuff) != HC_SUCCESS) {
        LOGE("Failed to get public key!");
        return HC_ERR_LOCAL_IDENTITY_NOT_EXIST;
    }

    uint32_t pkHexLen = returnPkBuff.length * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *pkHexStr = (char *)HcMalloc(pkHexLen, 0);
    if (pkHexStr == NULL) {
        LOGE("Failed to alloc memory for pkHexStr!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = ByteToHexString(returnPkBuff.val, returnPkBuff.length, pkHexStr, pkHexLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert pk bytes to hex string!");
        HcFree(pkHexStr);
        return res;
    }
    if (AddStringToJson(returnDataJson, FIELD_PUBLIC_KEY, pkHexStr) != HC_SUCCESS) {
        LOGE("Failed to add pubKey to returnData!");
        HcFree(pkHexStr);
        return HC_ERR_JSON_ADD;
    }
    HcFree(pkHexStr);
    return HC_SUCCESS;
}

static int32_t GenerateReturnData(const CredentialRequestParam *param, char **returnData)
{
    if (param->flag != RETURN_FLAG_PUBLIC_KEY) {
        LOGI("No need to return public key.");
        return HC_SUCCESS;
    }
    CJson *returnDataJson = CreateJson();
    if (returnDataJson == NULL) {
        LOGE("Failed to create return data json!");
        return HC_ERR_JSON_CREATE;
    }

    int32_t res = AddPubKeyToReturnData(param, returnDataJson);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add public key to return data!");
        FreeJson(returnDataJson);
        return res;
    }

    char *jsonStr = PackJsonToString(returnDataJson);
    FreeJson(returnDataJson);
    if (jsonStr == NULL) {
        LOGE("Failed to convert return data json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }

    if (DeepCopyString(jsonStr, returnData) != HC_SUCCESS) {
        LOGE("Failed to copy return json string!");
        FreeJsonString(jsonStr);
        return HC_ERR_MEMORY_COPY;
    }
    FreeJsonString(jsonStr);
    return HC_SUCCESS;
}

static int32_t QueryCredential(const char *reqJsonStr, char **returnData)
{
    CredentialRequestParam param = { 0 };
    int32_t res = GenerateRequestParamFromJson(reqJsonStr, false, &param);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate request param!");
        return res;
    }
    res = CheckKeyExistByParam(&param);
    if (res != HC_SUCCESS) {
        LOGW("Query key not exists!");
        ClearCredParam(&param);
        return res;
    }
    if (returnData != NULL) {
        res = GenerateReturnData(&param, returnData);
    }
    ClearCredParam(&param);
    return res;
}

static int32_t RegisterIdentity(const CredentialRequestParam *param, int32_t keyType)
{
    TokenManagerParams params = {
        .peerOsAccountId = param->peerOsAccountId,
        .osAccountId = param->osAccountId,
        .pkgName = { (uint8_t *)DEFAULT_PACKAGE_NAME, HcStrlen(DEFAULT_PACKAGE_NAME) },
        .serviceType = { (uint8_t *)param->serviceType, HcStrlen(param->serviceType) },
        .authId = { (uint8_t *)param->deviceId, HcStrlen(param->deviceId) },
        .userType = keyType,
        .isDirectAuthToken = true
    };
    return GetStandardTokenManagerInstance()->registerLocalIdentity(&params);
}

static int32_t GenarateCredential(const char *reqJsonStr, char **returnData)
{
    CredentialRequestParam param = { 0 };
    int32_t res = GenerateRequestParamFromJson(reqJsonStr, false, &param);
    if (res != HC_SUCCESS) {
        LOGE("Generate request param from Json occurred error!");
        return res;
    }
    if (CheckKeyExistByParam(&param) == HC_SUCCESS) {
        LOGE("Key already exists!");
        ClearCredParam(&param);
        return HC_ERR_IDENTITY_DUPLICATED;
    }
    res = RegisterIdentity(&param, KEY_ALIAS_P2P_AUTH);
    if (res != HC_SUCCESS) {
        LOGE("Failed to registerLocalIdentity!");
        ClearCredParam(&param);
        return res;
    }
    if (returnData != NULL) {
        res = GenerateReturnData(&param, returnData);
    }
    ClearCredParam(&param);
    return res;
}

static int32_t ComputeAndSavePsk(int32_t osAccountId, const char *peerServiceType, const char *peerAuthId,
    int32_t peerOsAccountId)
{
    uint8_t selfKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff selfKeyAlias = { selfKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    uint8_t peerKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff peerKeyAlias = { peerKeyAliasVal, PAKE_KEY_ALIAS_LEN };

    char selfAuthId[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfAuthId, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return HC_ERR_DB;
    }

    res = GenerateKeyAliasInner(DEFAULT_SERVICE_TYPE, selfAuthId, KEY_ALIAS_P2P_AUTH, peerOsAccountId, &selfKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate self key alias!");
        return res;
    }
    LOGI("selfKeyAlias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****", selfKeyAliasVal[DEV_AUTH_ZERO],
        selfKeyAliasVal[DEV_AUTH_ONE], selfKeyAliasVal[DEV_AUTH_TWO], selfKeyAliasVal[DEV_AUTH_THREE]);

    res = GenerateKeyAliasInner(peerServiceType, peerAuthId, KEY_ALIAS_P2P_AUTH, peerOsAccountId, &peerKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate peer key alias!");
        return res;
    }
    LOGI("peerKeyAlias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****", peerKeyAliasVal[DEV_AUTH_ZERO],
        peerKeyAliasVal[DEV_AUTH_ONE], peerKeyAliasVal[DEV_AUTH_TWO], peerKeyAliasVal[DEV_AUTH_THREE]);
    res = GetLoaderInstance()->checkKeyExist(&selfKeyAlias, false, osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("self auth keyPair not exists!");
        return res;
    }
    res = GetLoaderInstance()->checkKeyExist(&peerKeyAlias, false, osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("peer auth pubKey not exists!");
        return res;
    }

    uint8_t sharedKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff sharedKeyAlias = { sharedKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GenerateKeyAliasInner(peerServiceType, peerAuthId, KEY_ALIAS_PSK, peerOsAccountId, &sharedKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate psk alias!");
        return res;
    }
    LOGI("psk alias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****", sharedKeyAliasVal[DEV_AUTH_ZERO],
        sharedKeyAliasVal[DEV_AUTH_ONE], sharedKeyAliasVal[DEV_AUTH_TWO], sharedKeyAliasVal[DEV_AUTH_THREE]);

    KeyParams selfKeyParams = { { selfKeyAlias.val, selfKeyAlias.length, true }, false, osAccountId };
    KeyBuff peerKeyBuff = { peerKeyAlias.val, peerKeyAlias.length, true };
    return GetLoaderInstance()->agreeSharedSecretWithStorage(
        &selfKeyParams, &peerKeyBuff, ED25519, PAKE_PSK_LEN, &sharedKeyAlias);
}

static int32_t IsSelfKeyPairExist(int32_t osAccountId)
{
    char selfAuthId[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfAuthId, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return HC_ERR_DB;
    }

    uint8_t selfKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff selfKeyAlias = { selfKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GenerateKeyAliasInner(DEFAULT_SERVICE_TYPE, selfAuthId, KEY_ALIAS_P2P_AUTH, DEFAULT_OS_ACCOUNT,
        &selfKeyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate self keypair alias!");
        return res;
    }
    LOGI("selfKeyAlias(HEX): %" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x%" LOG_PUB "x****", selfKeyAliasVal[DEV_AUTH_ZERO],
        selfKeyAliasVal[DEV_AUTH_ONE], selfKeyAliasVal[DEV_AUTH_TWO], selfKeyAliasVal[DEV_AUTH_THREE]);

    return GetLoaderInstance()->checkKeyExist(&selfKeyAlias, false, osAccountId);
}

static int32_t UnregisterIdentity(const CredentialRequestParam *param, int32_t keyType)
{
    TokenManagerParams params = {
        .osAccountId = param->osAccountId,
        .peerOsAccountId = param->peerOsAccountId,
        .pkgName = { (uint8_t *)DEFAULT_PACKAGE_NAME, HcStrlen(DEFAULT_PACKAGE_NAME) },
        .serviceType = { (uint8_t *)param->serviceType, HcStrlen(param->serviceType) },
        .authId = { (uint8_t *)param->deviceId, HcStrlen(param->deviceId) },
        .userType = keyType,
        .isDirectAuthToken = true
    };
    return GetStandardTokenManagerInstance()->unregisterLocalIdentity(&params);
}

static int32_t ImportCredential(const char *reqJsonStr, char **returnData)
{
    (void)returnData;
    CredentialRequestParam param = { 0 };
    int32_t res = GenerateRequestParamFromJson(reqJsonStr, true, &param);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate request param!");
        return res;
    }
    if (IsSelfKeyPairExist(param.osAccountId) != HC_SUCCESS) {
        LOGE("Self key pair not exists!");
        ClearCredParam(&param);
        return HC_ERR_LOCAL_IDENTITY_NOT_EXIST;
    }
    uint8_t keyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuff = { keyAliasVal, PAKE_KEY_ALIAS_LEN };
    res = GenerateKeyAliasInner(param.serviceType, param.deviceId, KEY_ALIAS_P2P_AUTH,
        param.peerOsAccountId, &keyAliasBuff);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate key alias!");
        ClearCredParam(&param);
        return res;
    }
    ExtraInfo exInfo = {
        .authId = { (uint8_t *)param.deviceId, HcStrlen(param.deviceId) },
        .userType = KEY_ALIAS_P2P_AUTH,
        .pairType = PAIR_TYPE_BIND
    };
    KeyParams keyParams = { { keyAliasBuff.val, keyAliasBuff.length, true }, false, param.osAccountId };
    res = GetLoaderInstance()->importPublicKey(&keyParams, &param.publicKey, ED25519, &exInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to importPublicKey!");
        ClearCredParam(&param);
        return res;
    }
    res = ComputeAndSavePsk(param.osAccountId, param.serviceType, param.deviceId, param.peerOsAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to ComputeAndSavePsk, delete imported key!");
        ReportRadarEvent(res);
        if (UnregisterIdentity(&param, KEY_ALIAS_P2P_AUTH) != HC_SUCCESS) {
            LOGW("Failed to delete imported public key!");
        }
    }
    ClearCredParam(&param);
    return res;
}

static int32_t DeleteCredential(const char *reqJsonStr, char **returnData)
{
    (void)returnData;
    CredentialRequestParam param = { 0 };
    int32_t res = GenerateRequestParamFromJson(reqJsonStr, false, &param);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate request param!");
        return res;
    }
    res = UnregisterIdentity(&param, KEY_ALIAS_PSK);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete psk!");
        ClearCredParam(&param);
        return res;
    }
    res = UnregisterIdentity(&param, KEY_ALIAS_P2P_AUTH);
    ClearCredParam(&param);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete identity key!");
    }
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