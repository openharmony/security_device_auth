/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "hc_log.h"
#include "identity_manager.h"
#include "asy_token_manager.h"
#include "pseudonym_manager.h"
#include "identity_service_defines.h"
#include "identity_operation.h"
#include "cert_operation.h"
#include "hal_error.h"
#include "account_module_defines.h"

static int32_t CreateUrlStr(uint8_t credType, int32_t keyType, char **urlStr)
{
    TrustType trustType = TRUST_TYPE_P2P;
    if (credType != ACCOUNT_UNRELATED) {
        trustType = TRUST_TYPE_UID;
    }
    CJson *urlJson = CreateCredUrlJson(PRE_SHARED, keyType, trustType);
    if (!urlJson) {
        LOGE("Failed to create CredUrlJson info!");
        return HC_ERR_ALLOC_MEMORY;
    }
    char *str = PackJsonToString(urlJson);
    FreeJson(urlJson);
    if (str == NULL) {
        LOGE("Failed to pack url json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    *urlStr = str;
    return HC_SUCCESS;
}

static int32_t ConvertISProofTypeToCertType(uint32_t protocolType, IdentityProofType *returnType)
{
    if (protocolType == PROOF_TYPE_PSK) {
        *returnType = PRE_SHARED;
        return HC_SUCCESS;
    } else if (protocolType == PROOF_TYPE_PKI) {
        *returnType = CERTIFICATED;
        return HC_SUCCESS;
    }
    return HC_ERR_NOT_SUPPORT;
}

static int32_t ConvertISAlgToCertAlg(uint32_t alg, Algorithm *returnAlg)
{
    if (alg == ALGO_TYPE_P256) {
        *returnAlg = P256;
        return HC_SUCCESS;
    }
    return HC_ERR_NOT_SUPPORT;
}

static int32_t ISSetISOEntity(IdentityInfo *info)
{
#ifdef ENABLE_ACCOUNT_AUTH_ISO
    ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (entity == NULL) {
        LOGE("Failed to alloc memory for ISO protocol entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    entity->protocolType = ALG_ISO;
    entity->expandProcessCmds = 0;
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity) == NULL) {
        HcFree(entity);
        LOGE("Failed to push protocol entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
#else
    (void)info;
    LOGE("ISO not support!");
    return HC_ERR_NOT_SUPPORT;
#endif
}

static int32_t ISSetEcSpekeEntity(IdentityInfo *info, bool isNeedRefreshPseudonymId)
{
#ifdef ENABLE_ACCOUNT_AUTH_EC_SPEKE
    ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (entity == NULL) {
        LOGE("Failed to alloc memory for ec-speke protocol entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    entity->protocolType = ALG_EC_SPEKE;
    entity->expandProcessCmds = 0;
#ifdef ENABLE_PSEUDONYM
    if (isNeedRefreshPseudonymId) {
        entity->expandProcessCmds |= CMD_MK_AGREE;
    }
#else
    (void)isNeedRefreshPseudonymId;
#endif
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity) == NULL) {
        HcFree(entity);
        LOGE("Failed to push protocol entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
#else
    (void)info;
    (void)isNeedRefreshPseudonymId;
    LOGE("ec speke not support!");
    return HC_ERR_NOT_SUPPORT;
#endif
}

static int32_t ISSetCertInfoAndEntity(int32_t osAccountId, const CJson *credAuthInfo,
    bool isPseudonym, IdentityInfo *info)
{
    const char *authId = GetStringFromJson(credAuthInfo, FIELD_DEVICE_ID);
    if (authId == NULL) {
        LOGE("Failed to get auth ID!");
        return HC_ERR_JSON_GET;
    }
    AccountToken *token = CreateAccountToken();
    if (token == NULL) {
        LOGE("Failed to create account token!");
        return HC_ERR_ALLOC_MEMORY;
    }
    const char *userId = GetStringFromJson(credAuthInfo, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get user ID!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = GetAccountAuthTokenManager()->getToken(osAccountId, token, userId, authId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get account token!");
        DestroyAccountToken(token);
        return res;
    }
    res = GenerateCertInfo(&token->pkInfoStr, &token->pkInfoSignature, &info->proof.certInfo);
    DestroyAccountToken(token);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate cert info!");
        return res;
    }
    uint32_t signAlg = 0;
    if (GetUnsignedIntFromJson(credAuthInfo, FIELD_ALGORITHM_TYPE, &signAlg) != HC_SUCCESS) {
        LOGE("Failed to get algorithm type!");
        return HC_ERR_JSON_GET;
    }
    res = ConvertISAlgToCertAlg(signAlg, &info->proof.certInfo.signAlg);
    if (res != HC_SUCCESS) {
        LOGE("unsupport algorithm type!");
        return res;
    }
    info->proof.certInfo.isPseudonym = isPseudonym;
    bool isNeedRefreshPseudonymId = GetPseudonymInstance()->isNeedRefreshPseudonymId(osAccountId, userId);
    res = ISSetEcSpekeEntity(info, isNeedRefreshPseudonymId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to set protocol entity!");
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ISSetPreShareUrlAndEntity(const CJson *credAuthInfo, IdentityInfo *info)
{
    uint8_t credType = ACCOUNT_UNRELATED;
    if (GetUint8FromJson(credAuthInfo, FIELD_CRED_TYPE, &credType) != HC_SUCCESS) {
        LOGE("get int from json failed!");
        return HC_ERR_JSON_GET;
    }
    uint8_t keyFormat;
    if (GetUint8FromJson(credAuthInfo, FIELD_KEY_FORMAT, &keyFormat) != HC_SUCCESS) {
        LOGE("get int from json failed!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = HC_ERROR;
    KeyType keyType;
    if (keyFormat == SYMMETRIC_KEY) {
        res = ISSetISOEntity(info);
        keyType = KEY_TYPE_SYM;
    } else if (keyFormat == ASYMMETRIC_KEY || keyFormat == ASYMMETRIC_PUB_KEY) {
        res = ISSetEcSpekeEntity(info, false);
        keyType = KEY_TYPE_ASYM;
    }
    if (res != HC_SUCCESS) {
        return res;
    }
    char *urlStr = NULL;
    res = CreateUrlStr(credType, keyType, &urlStr);
    if (res != HC_SUCCESS) {
        LOGE("Failed to create url string!");
        return res;
    }
    res = SetPreSharedUrlForProof(urlStr, &info->proof.preSharedUrl);
    FreeJsonString(urlStr);
    if (res != HC_SUCCESS) {
        LOGE("Failed to set preSharedUrl of proof!");
        return res;
    }
    info->proofType = PRE_SHARED;
    return HC_SUCCESS;
}

static int32_t ISSetCertProofAndEntity(const CJson *context, const CJson *credAuthInfo,
    bool isPseudonym, IdentityInfo *info)
{
    int32_t res = HC_ERROR;
    if (info->proofType == PRE_SHARED) {
        res = ISSetPreShareUrlAndEntity(credAuthInfo, info);
        if (res != HC_SUCCESS) {
            LOGE("Failed to set preshared url");
        }
    } else if (info->proofType == CERTIFICATED) {
        int32_t osAccountId = 0;
        if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
            LOGE("Failed to get osAccountId!");
            return HC_ERR_JSON_GET;
        }
        res = ISSetCertInfoAndEntity(osAccountId, credAuthInfo, isPseudonym, info);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get cert info!");
        }
    } else {
        res = HC_ERR_NOT_SUPPORT;
        LOGE("unknown proof type!");
    }
    return res;
}

static int32_t ISGetIdentityInfo(const CJson *context, bool isPseudonym, IdentityInfo **returnInfo)
{
    CJson *credAuthInfo = GetObjFromJson(context, FIELD_CREDENTIAL_OBJ);
    if (credAuthInfo == NULL) {
        LOGE("Get self credAuthInfo fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t proofType = 0;
    int32_t res = GetUnsignedIntFromJson(credAuthInfo, FIELD_PROOF_TYPE, &proofType);
    if (res != HC_SUCCESS) {
        LOGE("Get proofType fail.");
        return res;
    }
    if (isPseudonym && proofType != PROOF_TYPE_PKI) {
        return HC_SUCCESS;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to alloc memory for IdentityInfo!");
        return HC_ERR_JSON_GET;
    }
    info->IdInfoType = DEFAULT_ID_TYPE;
    do {
        res = ConvertISProofTypeToCertType(proofType, &info->proofType);
        if (res != HC_SUCCESS) {
            LOGE("unsupport proof type!");
            break;
        }
        res = ISSetCertProofAndEntity(context, credAuthInfo, isPseudonym, info);
        if (res != HC_SUCCESS) {
            LOGE("Failed to set cert proof and protocol entity!");
            break;
        }
    } while (0);
    if (res != HC_SUCCESS) {
        DestroyIdentityInfo(info);
        return res;
    }
    *returnInfo = info;
    return HC_SUCCESS;
}

static int32_t AddIdentityInfoToVec(const CJson *in, bool isPseudonym, IdentityInfoVec *vec)
{
    IdentityInfo *info = NULL;
    int32_t res = ISGetIdentityInfo(in, isPseudonym, &info);
    if (res != HC_SUCCESS) {
        LOGE("Get Identity by credAuthInfo fail.");
        return res;
    }
    if (info == NULL) {
        return HC_SUCCESS;
    }
    if (vec->pushBack(vec, (const IdentityInfo **)&info) == NULL) {
        DestroyIdentityInfo(info);
        LOGE("Failed to push protocol entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t GetCredInfosByPeerIdentity(const CJson *in, IdentityInfoVec *vec)
{
    if (in == NULL || vec == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = HC_ERROR;
#ifdef ENABLE_PSEUDONYM
    //try enable pseudonym
    res = AddIdentityInfoToVec(in, true, vec);
    if (res != HC_SUCCESS) {
        LOGE("add identity info to vec failed.");
        return res;
    }
#endif
    res = AddIdentityInfoToVec(in, false, vec);
    if (res != HC_SUCCESS) {
        LOGE("add identity info to vec failed.");
        return res;
    }
    return HC_SUCCESS;
}

static int32_t GetCredInfoByPeerUrl(const CJson *in, const Uint8Buff *presharedUrl, IdentityInfo **returnInfo)
{
    if (in == NULL || presharedUrl == NULL || returnInfo == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    IdentityInfo *info = NULL;
    int32_t res = ISGetIdentityInfo(in, false, &info);
    if (res != HC_SUCCESS) {
        LOGE("Get Identity by credAuthInfo fail.");
        return res;
    }
    if (memcmp(presharedUrl->val, info->proof.preSharedUrl.val, presharedUrl->length) != 0) {
        DestroyIdentityInfo(info);
        LOGE("peer presharedUrl is not equal.");
        return HC_ERR_MEMORY_COMPARE;
    }
    *returnInfo = info;
    return HC_SUCCESS;
}

static int32_t ComputeHkdfKeyAlias(const CJson *in, int32_t osAccountId, Uint8Buff *credIdByte, Uint8Buff *sharedSecret)
{
    uint8_t *pskVal = (uint8_t *)HcMalloc(PAKE_PSK_LEN, 0);
    if (pskVal == NULL) {
        LOGE("Failed to alloc memory for psk!");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff pskBuff = { pskVal, PAKE_PSK_LEN };
    uint8_t *nonceVal = (uint8_t *)HcMalloc(PAKE_NONCE_LEN, 0);
    if (nonceVal == NULL) {
        LOGE("Failed to alloc memory for nonce!");
        HcFree(pskVal);
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff nonceBuff = { nonceVal, PAKE_NONCE_LEN };
    int32_t ret = GetByteFromJson(in, FIELD_NONCE, nonceBuff.val, nonceBuff.length);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get nonce!");
        HcFree(pskVal);
        HcFree(nonceVal);
        return HC_ERR_JSON_GET;
    }
    Uint8Buff keyInfo = { (uint8_t *)TMP_AUTH_KEY_FACTOR, HcStrlen(TMP_AUTH_KEY_FACTOR) };
    KeyParams keyAliasParams = { { credIdByte->val, credIdByte->length, true }, false, osAccountId };
    ret = GetLoaderInstance()->computeHkdf(&keyAliasParams, &nonceBuff, &keyInfo, &pskBuff);
    HcFree(nonceVal);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to compute hkdf for psk!");
        HcFree(pskVal);
        return ret;
    }

    ret = ConvertPsk(&pskBuff, sharedSecret);
    HcFree(pskVal);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to convert psk!");
    }
    return ret;
}

static int32_t ComputeAuthToken(int32_t osAccountId, const char *userId, const Uint8Buff keyAlias, Uint8Buff *authToken)
{
    authToken->val = (uint8_t *)HcMalloc(AUTH_TOKEN_SIZE, 0);
    if (authToken->val == NULL) {
        LOGE("Failed to alloc memory for auth token!");
        return HC_ERR_ALLOC_MEMORY;
    }
    authToken->length = AUTH_TOKEN_SIZE;
    Uint8Buff userIdBuff = { (uint8_t *)userId, HcStrlen(userId) };
    Uint8Buff challenge = { (uint8_t *)KEY_INFO_PERSISTENT_TOKEN, HcStrlen(KEY_INFO_PERSISTENT_TOKEN) };
    KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, false, osAccountId };
    int32_t ret = GetLoaderInstance()->computeHkdf(&keyAliasParams, &userIdBuff, &challenge, authToken);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to computeHkdf from authCode to authToken!");
        FreeBuffData(authToken);
    }
    return ret;
}

static int32_t GenerateAuthTokenForAccessory(int32_t osAccountId, const char *credId, const CJson *credAuthInfo,
    Uint8Buff *authToken)
{
    const char *userIdSelf = GetStringFromJson(credAuthInfo, FIELD_USER_ID);
    if (userIdSelf == NULL) {
        LOGE("Failed to get self user ID!");
        return HC_ERR_JSON_GET;
    }
    Uint8Buff credIdByte = { NULL, 0 };
    int32_t ret = GetValidKeyAlias(osAccountId, credId, &credIdByte);
    if (ret == HAL_ERR_KEY_NOT_EXIST) {
        LOGE("Huks key not exist!");
        DelCredById(osAccountId, credId);
        return IS_ERR_HUKS_KEY_NOT_EXIST;
    }
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks check key exist failed");
        return IS_ERR_HUKS_CHECK_KEY_EXIST_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to check key exist in HUKS");
        return ret;
    }
    ret = ComputeAuthToken(osAccountId, userIdSelf, credIdByte, authToken);
    FreeBuffData(&credIdByte);
    return ret;
}

static int32_t GenerateTokenAliasForController(int32_t osAccountId, const char *credId, Uint8Buff *authToken)
{
    int32_t ret = GetValidKeyAlias(osAccountId, credId, authToken);
    if (ret == HAL_ERR_KEY_NOT_EXIST) {
        LOGE("Huks key not exist!");
        DelCredById(osAccountId, credId);
        return IS_ERR_HUKS_KEY_NOT_EXIST;
    }
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks check key exist failed");
        return IS_ERR_HUKS_CHECK_KEY_EXIST_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to check key exist in HUKS");
        return ret;
    }
    return HC_SUCCESS;
}

static int32_t GenerateAuthTokenByDevType(int32_t osAccountId, const CJson *in, Uint8Buff *authToken,
    bool *isTokenStored)
{
    const char *credId = GetStringFromJson(in, FIELD_CRED_ID);
    if (credId == NULL) {
        LOGE("Failed to get cred ID!");
        return HC_ERR_JSON_GET;
    }
    const CJson *credAuthInfo = GetObjFromJson(in, FIELD_CREDENTIAL_OBJ);
    if (credAuthInfo == NULL) {
        LOGE("Get credAuthInfo fail.");
        return HC_ERR_JSON_GET;
    }
    uint8_t localDevType = SUBJECT_ACCESSORY_DEVICE;
    if (GetUint8FromJson(credAuthInfo, FIELD_SUBJECT, &localDevType) != HC_SUCCESS) {
        LOGE("Failed to get subject!");
        return HC_ERR_JSON_GET;
    }
    int32_t ret = HC_ERROR;
    if (localDevType == SUBJECT_ACCESSORY_DEVICE) {
        *isTokenStored = false;
        ret = GenerateAuthTokenForAccessory(osAccountId, credId, credAuthInfo, authToken);
    } else {
        ret = GenerateTokenAliasForController(osAccountId, credId, authToken);
    }
    return ret;
}

static int32_t ISGetAccountSymSharedSecret(const CJson *in, Uint8Buff *sharedSecret)
{
    if (in == NULL || sharedSecret == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t osAccountId;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    bool isTokenStored = true;
    Uint8Buff authToken = { NULL, 0 };
    int32_t ret = GenerateAuthTokenByDevType(osAccountId, in, &authToken, &isTokenStored);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate auth token!");
        return ret;
    }
    uint8_t seed[SEED_SIZE] = { 0 };
    Uint8Buff seedBuff = { seed, SEED_SIZE };
    ret = GetByteFromJson(in, FIELD_SEED, seed, SEED_SIZE);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get seed!");
        FreeBuffData(&authToken);
        return HC_ERR_JSON_GET;
    }
    sharedSecret->val = (uint8_t *)HcMalloc(ISO_PSK_LEN, 0);
    if (sharedSecret->val == NULL) {
        LOGE("Failed to alloc sharedSecret memory!");
        FreeBuffData(&authToken);
        return HC_ERR_ALLOC_MEMORY;
    }
    sharedSecret->length = ISO_PSK_LEN;
    KeyParams keyParams = { { authToken.val, authToken.length, isTokenStored }, false, osAccountId };
    ret = GetLoaderInstance()->computeHmac(&keyParams, &seedBuff, sharedSecret);
    FreeBuffData(&authToken);
    if (ret != HC_SUCCESS) {
        LOGE("ComputeHmac for psk failed, ret: %d.", ret);
        FreeBuffData(sharedSecret);
    }
    return ret;
}

static int32_t AuthGeneratePsk(const CJson *in, const Uint8Buff *seed, Uint8Buff *sharedSecret)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *credId = GetStringFromJson(in, FIELD_CRED_ID);
    if (credId == NULL) {
        LOGE("Failed to get cred ID!");
        return HC_ERR_JSON_GET;
    }
    Uint8Buff credIdByte = { NULL, 0 };
    int32_t ret = GetValidKeyAlias(osAccountId, credId, &credIdByte);
    if (ret == HAL_ERR_KEY_NOT_EXIST) {
        LOGE("Huks key not exist!");
        DelCredById(osAccountId, credId);
        return IS_ERR_HUKS_KEY_NOT_EXIST;
    }
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks check key exist failed");
        return IS_ERR_HUKS_CHECK_KEY_EXIST_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to check key exist in HUKS");
        return ret;
    }
    KeyParams keyAliasParams = { { credIdByte.val, credIdByte.length, true }, false, osAccountId };
    ret = GetLoaderInstance()->computeHmac(&keyAliasParams, seed, sharedSecret);
    FreeBuffData(&credIdByte);
    return ret;
}

static int32_t GetSharedSecretForP2pInIso(const CJson *in, Uint8Buff *sharedSecret)
{
    uint8_t *seedVal = (uint8_t *)HcMalloc(SEED_LEN, 0);
    if (seedVal == NULL) {
        LOGE("Failed to alloc memory for seed!");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff seedBuff = { seedVal, SEED_LEN };
    int32_t ret = GetByteFromJson(in, FIELD_SEED, seedBuff.val, seedBuff.length);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get seed!");
        HcFree(seedVal);
        return HC_ERR_JSON_GET;
    }
    uint8_t *pskVal = (uint8_t *)HcMalloc(ISO_PSK_LEN, 0);
    if (pskVal == NULL) {
        LOGE("Failed to alloc memory for psk!");
        HcFree(seedVal);
        return HC_ERR_ALLOC_MEMORY;
    }
    sharedSecret->val = pskVal;
    sharedSecret->length = ISO_PSK_LEN;
    ret = AuthGeneratePsk(in, &seedBuff, sharedSecret);
    HcFree(seedVal);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate psk!");
        FreeBuffData(sharedSecret);
    }
    return ret;
}

static int32_t GetSharedSecretForP2pInPake(const CJson *in, Uint8Buff *sharedSecret)
{
    const char *credId = GetStringFromJson(in, FIELD_CRED_ID);
    if (credId == NULL) {
        LOGE("get credId from json failed");
        return HC_ERR_JSON_GET;
    }
    int32_t osAccountId;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    uint32_t credIdByteLen = HcStrlen(credId) / BYTE_TO_HEX_OPER_LENGTH;
    Uint8Buff credIdByte = { NULL, credIdByteLen };
    credIdByte.val = (uint8_t *)HcMalloc(credIdByteLen, 0);
    if (credIdByte.val == NULL) {
        LOGE("Failed to malloc credIdByteLen");
        return IS_ERR_ALLOC_MEMORY;
    }
    int32_t ret = HexStringToByte(credId, credIdByte.val, credIdByte.length);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credId to byte, invalid credId, ret = %d", ret);
        HcFree(credIdByte.val);
        return IS_ERR_INVALID_HEX_STRING;
    }
    LOGI("psk alias: %x %x %x %x****.", credIdByte.val[DEV_AUTH_ZERO], credIdByte.val[DEV_AUTH_ONE],
        credIdByte.val[DEV_AUTH_TWO], credIdByte.val[DEV_AUTH_THREE]);

    ret = GetLoaderInstance()->checkKeyExist(&credIdByte, false, osAccountId);
    if (ret != HC_SUCCESS) {
        HcFree(credIdByte.val);
        LOGE("psk not exist");
        return ret;
    }
    ret = ComputeHkdfKeyAlias(in, osAccountId, &credIdByte, sharedSecret);
    HcFree(credIdByte.val);
    if (ret != HC_SUCCESS) {
        LOGE("compute hkdf key alias failed.");
        FreeBuffData(sharedSecret);
    }
    return ret;
}

static int32_t GetSharedSecretForP2p(
    const CJson *in, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    int32_t ret;
    if (protocolType == ALG_ISO) {
        ret = GetSharedSecretForP2pInIso(in, sharedSecret);
        LOGI("get shared secret for p2p in iso result: %d", ret);
    } else {
        ret = GetSharedSecretForP2pInPake(in, sharedSecret);
        LOGI("get shared secret for p2p in pake result: %d", ret);
    }
    return ret;
}

static int32_t GetSharedSecretForUid(
    const CJson *in, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    if (protocolType != ALG_ISO) {
        LOGE("protocol type is not iso, not supported!");
        return HC_ERR_INVALID_PARAMS;
    }
    return ISGetAccountSymSharedSecret(in, sharedSecret);
}

static int32_t GetSharedSecretByUrl(
    const CJson *in, const Uint8Buff *presharedUrl, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    if (in == NULL || presharedUrl == NULL || sharedSecret == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }

    CJson *urlJson = CreateJsonFromString((const char *)presharedUrl->val);
    if (urlJson == NULL) {
        LOGE("Failed to create url json!");
        return HC_ERR_JSON_CREATE;
    }

    int32_t trustType = 0;
    if (GetIntFromJson(urlJson, PRESHARED_URL_TRUST_TYPE, &trustType) != HC_SUCCESS) {
        LOGE("Failed to get trust type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_GET;
    }
    FreeJson(urlJson);

    int32_t ret;
    switch (trustType) {
        case TRUST_TYPE_P2P:
            ret = GetSharedSecretForP2p(in, protocolType, sharedSecret);
            break;
        case TRUST_TYPE_UID:
            ret = GetSharedSecretForUid(in, protocolType, sharedSecret);
            break;
        default:
            LOGE("Invalid trust type!");
            ret = HC_ERR_INVALID_PARAMS;
            break;
    }
    return ret;
}

static int32_t GetCredInfoByPeerCert(const CJson *in, const CertInfo *certInfo, IdentityInfo **returnInfo)
{
    if (in == NULL || certInfo == NULL || returnInfo == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    IdentityInfo *info = NULL;
    int32_t res = ISGetIdentityInfo(in, certInfo->isPseudonym, &info);
    if (res != HC_SUCCESS) {
        LOGE("Get Identity by credAuthInfo fail.");
        return res;
    }
    *returnInfo = info;
    return HC_SUCCESS;
}

static int32_t GetSharedSecretByPeerCert(
    const CJson *in, const CertInfo *peerCertInfo, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    if (in == NULL || peerCertInfo == NULL || sharedSecret == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (protocolType != ALG_EC_SPEKE) {
        LOGE("protocol type is not ec speke, not support!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *credId = GetStringFromJson(in, FIELD_ACROSS_ACCOUNT_CRED_ID);
    if (credId != NULL) {
        LOGI("across account credential Id exists.");
    }
    return GetAccountAsymSharedSecret(osAccountId, credId, peerCertInfo, sharedSecret);
}

static const AuthIdentity g_authIdentity = {
    .getCredInfosByPeerIdentity = GetCredInfosByPeerIdentity,
    .getCredInfoByPeerUrl = GetCredInfoByPeerUrl,
    .getSharedSecretByUrl = GetSharedSecretByUrl,
    .getCredInfoByPeerCert = GetCredInfoByPeerCert,
    .getSharedSecretByPeerCert = GetSharedSecretByPeerCert,
};

const AuthIdentity *GetCredAuthIdentity(void)
{
    return &g_authIdentity;
}
