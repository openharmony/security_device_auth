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
#include "hc_log.h"
#include "identity_manager.h"

static int32_t SetProtocolsToIdentityInfo(IdentityInfo *info)
{
    ProtocolEntity *ecSpekeEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (ecSpekeEntity == NULL) {
        LOGE("Failed to alloc memory for ec speke entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    ecSpekeEntity->protocolType = ALG_EC_SPEKE;
    ecSpekeEntity->expandProcessCmds = 0;
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&ecSpekeEntity) == NULL) {
        LOGE("Failed to push ecSpeke entity!");
        HcFree(ecSpekeEntity);
        return HC_ERR_ALLOC_MEMORY;
    }

    return HC_SUCCESS;
}

static int32_t CombineQueryCredentialParams(const CJson *in, CJson *out)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from context!");
        return HC_ERR_JSON_GET;
    }
    const char *peerConnDeviceId = GetStringFromJson(in, FIELD_PEER_CONN_DEVICE_ID);
    if (peerConnDeviceId == NULL) {
        LOGE("Failed to get peerConnDeviceId from context, need peerConnDeviceId!");
        return HC_ERR_JSON_GET;
    }
    int32_t acquireType = ACQUIRE_TYPE_INVALID;
    if (GetIntFromJson(in, FIELD_ACQURIED_TYPE, &acquireType) != HC_SUCCESS) {
        LOGE("Failed to get acquireType from context!");
        return HC_ERR_JSON_GET;
    }
    if (acquireType != P2P_BIND) {
        LOGE("acquireType invalid! only P2P_BIND is allowed now!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t peerOsAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_PEER_OS_ACCOUNT_ID, &peerOsAccountId) != HC_SUCCESS) {
        LOGE("Failed to get peer osAccountId!");
        return HC_ERR_JSON_GET;
    }
    if (AddIntToJson(out, FIELD_PEER_OS_ACCOUNT_ID, peerOsAccountId) != HC_SUCCESS) {
        LOGE("Failed to add peer osAccountId!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(out, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add osAccountId to json error!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(out, FIELD_ACQURIED_TYPE, acquireType) != HC_SUCCESS) {
        LOGE("add acquireType to json error!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(out, FIELD_CRED_OP_FLAG, RETURN_FLAG_DEFAULT) != HC_SUCCESS) {
        LOGE("add flag to json error!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(out, FIELD_DEVICE_ID, peerConnDeviceId) != HC_SUCCESS) {
        LOGE("add device id to json error!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t IsPeerDevicePublicKeyExist(const CJson *in)
{
    CJson *paramsJson = CreateJson();
    if (paramsJson == NULL) {
        LOGE("alloc memory error!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = CombineQueryCredentialParams(in, paramsJson);
    if (ret != HC_SUCCESS) {
        LOGE("Prepare query credential parmaters return error!");
        FreeJson(paramsJson);
        return ret;
    }
    const CredentialOperator *credOperator = GetCredentialOperator();
    if (credOperator == NULL) {
        LOGE("credOperator is null!");
        FreeJson(paramsJson);
        return HC_ERR_NOT_SUPPORT;
    }
    char *requestParams = PackJsonToString(paramsJson);
    FreeJson(paramsJson);
    if (requestParams == NULL) {
        LOGE("Failed to pack query credentail params json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    ret = credOperator->queryCredential(requestParams, NULL);
    FreeJsonString(requestParams);
    return ret;
}

static int32_t CreateUrlStr(int32_t keyType, char **urlStr)
{
    CJson *urlJson = CreateCredUrlJson(PRE_SHARED, keyType, TRUST_TYPE_P2P);
    if (!urlJson) {
        LOGE("Failed to create CredUrlJson info!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddBoolToJson(urlJson, FIELD_IS_DIRECT_AUTH, true) != HC_SUCCESS) {
        LOGE("Failed to add isDirectAuth to preshared url!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    } else {
        LOGI("add isDirectAuth:true into urlJson!");
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

static int32_t GetCredInfosByPeerIdentity(const CJson *in, IdentityInfoVec *vec)
{
    int32_t keyType = KEY_TYPE_ASYM;
    (void)GetIntFromJson(in, FIELD_KEY_TYPE, &keyType);

    int32_t ret = IsPeerDevicePublicKeyExist(in);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get peer device public key!");
        return ret;
    }

    char *urlStr = NULL;
    ret = CreateUrlStr(keyType, &urlStr);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to create url string!");
        return ret;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to create identity info!");
        FreeJsonString(urlStr);
        return HC_ERR_ALLOC_MEMORY;
    }
    ret = SetPreSharedUrlForProof(urlStr, &info->proof.preSharedUrl);
    FreeJsonString(urlStr);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set preSharedUrl of proof!");
        DestroyIdentityInfo(info);
        return ret;
    }
    ret = SetProtocolsToIdentityInfo(info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set protocols!");
        DestroyIdentityInfo(info);
        return ret;
    }
    info->proofType = PRE_SHARED;
    info->IdInfoType = P2P_DIRECT_AUTH;
    if (vec->pushBack(vec, (const IdentityInfo **)&info) == NULL) {
        LOGE("Failed to push info!");
        DestroyIdentityInfo(info);
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t GetCredInfoByPeerUrl(const CJson *in, const Uint8Buff *presharedUrl, IdentityInfo **returnInfo)
{
    if (in == NULL || presharedUrl == NULL || returnInfo == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to create identity info!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = SetPreSharedUrlForProof((const char *)presharedUrl->val, &info->proof.preSharedUrl);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set preSharedUrl of proof!");
        DestroyIdentityInfo(info);
        return ret;
    }
    ret = SetProtocolsToIdentityInfo(info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set protocols!");
        DestroyIdentityInfo(info);
        return ret;
    }
    info->proofType = PRE_SHARED;
    info->IdInfoType = P2P_DIRECT_AUTH;
    *returnInfo = info;
    return HC_SUCCESS;
}

static int32_t GenerateSelfKeyAlias(const char *selfAuthId, Uint8Buff *selfKeyAlias)
{
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)DEFAULT_PACKAGE_NAME;
    tokenParams.pkgName.length = HcStrlen(DEFAULT_PACKAGE_NAME);
    tokenParams.serviceType.val = (uint8_t *)DEFAULT_SERVICE_TYPE;
    tokenParams.serviceType.length = HcStrlen(DEFAULT_SERVICE_TYPE);
    tokenParams.userType = KEY_ALIAS_P2P_AUTH;
    tokenParams.authId.val = (uint8_t *)selfAuthId;
    tokenParams.authId.length = HcStrlen(selfAuthId);
    return GenerateKeyAlias(&tokenParams, selfKeyAlias);
}

static int32_t GeneratePeerKeyAlias(const char *peerServiceType, const char *peerAuthId, int32_t peerOsAccountId,
    Uint8Buff *peerKeyAlias)
{
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)DEFAULT_PACKAGE_NAME;
    tokenParams.pkgName.length = HcStrlen(DEFAULT_PACKAGE_NAME);
    tokenParams.serviceType.val = (uint8_t *)peerServiceType;
    tokenParams.serviceType.length = HcStrlen(peerServiceType);
    tokenParams.userType = KEY_ALIAS_P2P_AUTH;
    tokenParams.authId.val = (uint8_t *)peerAuthId;
    tokenParams.authId.length = HcStrlen(peerAuthId);
    tokenParams.isDirectAuthToken = true;
    tokenParams.peerOsAccountId = peerOsAccountId;
    return GenerateKeyAlias(&tokenParams, peerKeyAlias);
}

/**
 * @brief compute shared key alias
 *
 * @param osAccountId
 * @param selfAuthId self device udid
 * @param peerAuthId  peer device udid
 * @param sharedKeyAlias
 * @return int32_t
 */
static int32_t ComputeAndSaveDirectAuthPsk(const CJson *in, const char *selfAuthId, const char *peerAuthId,
    const char *peerServiceType, const Uint8Buff *sharedKeyAlias)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    (void)GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId);
    int32_t peerOsAccountId = INVALID_OS_ACCOUNT;
    (void)GetIntFromJson(in, FIELD_PEER_OS_ACCOUNT_ID, &peerOsAccountId);
    uint8_t selfKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff selfKeyAlias = { selfKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t ret = GenerateSelfKeyAlias(selfAuthId, &selfKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate self key alias!");
        return ret;
    }
    LOGI("selfKeyAlias: %" LOG_PUB "x %" LOG_PUB "x %" LOG_PUB "x %" LOG_PUB "x****.", selfKeyAlias.val[DEV_AUTH_ZERO],
        selfKeyAlias.val[DEV_AUTH_ONE], selfKeyAlias.val[DEV_AUTH_TWO], selfKeyAlias.val[DEV_AUTH_THREE]);

    uint8_t peerKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff peerKeyAlias = { peerKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    ret = GeneratePeerKeyAlias(peerServiceType, peerAuthId, peerOsAccountId, &peerKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate peer key alias!");
        return ret;
    }
    LOGI("peerKeyAlias: %" LOG_PUB "x %" LOG_PUB "x %" LOG_PUB "x %" LOG_PUB "x****.", peerKeyAlias.val[DEV_AUTH_ZERO],
        peerKeyAlias.val[DEV_AUTH_ONE], peerKeyAlias.val[DEV_AUTH_TWO], peerKeyAlias.val[DEV_AUTH_THREE]);

    ret = GetLoaderInstance()->checkKeyExist(&selfKeyAlias, false, osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("self auth keyPair not exist!");
        return ret;
    }
    ret = GetLoaderInstance()->checkKeyExist(&peerKeyAlias, false, osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("peer auth pubKey not exist!");
        return ret;
    }

    KeyParams selfKeyParams = { { selfKeyAlias.val, selfKeyAlias.length, true }, false, osAccountId };
    KeyBuff peerKeyBuff = { peerKeyAlias.val, peerKeyAlias.length, true };
    return GetLoaderInstance()->agreeSharedSecretWithStorage(
        &selfKeyParams, &peerKeyBuff, ED25519, PAKE_PSK_LEN, sharedKeyAlias);
}

static int32_t GetDirectAuthPskAliasInner(const char *peerServiceType, const char *peerAuthId, int32_t peerOsAccountId,
    Uint8Buff *pskKeyAlias)
{
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)DEFAULT_PACKAGE_NAME;
    tokenParams.pkgName.length = HcStrlen(DEFAULT_PACKAGE_NAME);
    tokenParams.serviceType.val = (uint8_t *)peerServiceType;
    tokenParams.serviceType.length = HcStrlen(peerServiceType);
    tokenParams.userType = KEY_ALIAS_PSK;
    tokenParams.authId.val = (uint8_t *)peerAuthId;
    tokenParams.authId.length = HcStrlen(peerAuthId);
    tokenParams.isDirectAuthToken = true;
    tokenParams.peerOsAccountId = peerOsAccountId;
    return GenerateKeyAlias(&tokenParams, pskKeyAlias);
}

static int32_t GetDirectAuthPskAliasCreateIfNeeded(const CJson *in, Uint8Buff *pskKeyAlias)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    int32_t peerOsAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_PEER_OS_ACCOUNT_ID, &peerOsAccountId) != HC_SUCCESS) {
        LOGE("Failed to get peer osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *selfAuthId = GetStringFromJson(in, FIELD_AUTH_ID);
    if (selfAuthId == NULL) {
        LOGE("get authId from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *peerAuthId = GetStringFromJson(in, FIELD_PEER_CONN_DEVICE_ID);
    if (peerAuthId == NULL) {
        LOGE("get peerConnDeviceId from json fail.");
        return HC_ERR_JSON_GET;
    }
    const char *peerServiceType = GetStringFromJson(in, FIELD_SERVICE_TYPE);
    if (peerServiceType == NULL) {
        LOGI("get serviceType from json fail, replace by default");
        peerServiceType = DEFAULT_SERVICE_TYPE;
    }
    int32_t ret = GetDirectAuthPskAliasInner(peerServiceType, peerAuthId, peerOsAccountId, pskKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate psk key alias!");
        return ret;
    }
    LOGI("psk alias: %" LOG_PUB "x %" LOG_PUB "x %" LOG_PUB "x %" LOG_PUB "x****.", pskKeyAlias->val[DEV_AUTH_ZERO],
        pskKeyAlias->val[DEV_AUTH_ONE], pskKeyAlias->val[DEV_AUTH_TWO], pskKeyAlias->val[DEV_AUTH_THREE]);
    ret = GetLoaderInstance()->checkKeyExist(pskKeyAlias, false, osAccountId);
    if (ret != HC_SUCCESS) {
        ret = ComputeAndSaveDirectAuthPsk(in, selfAuthId, peerAuthId, peerServiceType, pskKeyAlias);
    }
    return ret;
}

static int32_t GetSharedSecretByUrl(
    const CJson *in, const Uint8Buff *presharedUrl, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    (void)protocolType;
    if (in == NULL || presharedUrl == NULL || sharedSecret == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t osAccountId;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    uint8_t pskKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskKeyAlias = { pskKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t ret = GetDirectAuthPskAliasCreateIfNeeded(in, &pskKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias for psk!");
        return ret;
    }
    uint8_t nonceVal[PAKE_NONCE_LEN] = { 0 };
    Uint8Buff nonceBuff = { nonceVal, PAKE_NONCE_LEN };
    if (GetByteFromJson(in, FIELD_NONCE, nonceBuff.val, nonceBuff.length) != HC_SUCCESS) {
        LOGE("Failed to get nonce!");
        return HC_ERR_JSON_GET;
    }
    uint8_t pskVal[PAKE_PSK_LEN] = { 0 };
    Uint8Buff pskBuff = { pskVal, PAKE_PSK_LEN };
    Uint8Buff keyInfo = { (uint8_t *)TMP_AUTH_KEY_FACTOR, HcStrlen(TMP_AUTH_KEY_FACTOR) };
    KeyParams keyAliasParams = { { pskKeyAlias.val, pskKeyAlias.length, true }, false, osAccountId };
    ret = GetLoaderInstance()->computeHkdf(&keyAliasParams, &nonceBuff, &keyInfo, &pskBuff);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to compute hkdf for psk!");
        return ret;
    }
    ret = ConvertPsk(&pskBuff, sharedSecret);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to convert psk!");
    }
    return ret;
}

static int32_t GetCredInfoByPeerCert(const CJson *in, const CertInfo *certInfo, IdentityInfo **returnInfo)
{
    // NOT SUPPORT FOR P2P AUTH
    (void)in;
    (void)certInfo;
    (void)returnInfo;
    return HC_ERR_ALG_FAIL;
}

static int32_t GetSharedSecretByPeerCert(
    const CJson *in, const CertInfo *peerCertInfo, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    // NOT SUPPORT P2P AUTH
    (void)in;
    (void)peerCertInfo;
    (void)protocolType;
    (void)sharedSecret;
    return HC_ERR_ALG_FAIL;
}

static const AuthIdentity g_authIdentity = {
    .getCredInfosByPeerIdentity = GetCredInfosByPeerIdentity,
    .getCredInfoByPeerUrl = GetCredInfoByPeerUrl,
    .getSharedSecretByUrl = GetSharedSecretByUrl,
    .getCredInfoByPeerCert = GetCredInfoByPeerCert,
    .getSharedSecretByPeerCert = GetSharedSecretByPeerCert,
};

const AuthIdentity *GetP2pAuthIdentity(void)
{
    return &g_authIdentity;
}