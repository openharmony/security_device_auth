/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#include "creds_manager.h"
#include "identity_operation.h"
#include "asy_token_manager.h"
#include "cert_operation.h"

#define FIELD_SP_CMDS "spCmds"

#include "hc_log.h"

static bool IsDirectAuth(const CJson *context)
{
    bool isDirectAuth = false;
    (void)GetBoolFromJson(context, FIELD_IS_DIRECT_AUTH, &isDirectAuth);
    return isDirectAuth;
}

static bool IsDeviceLevelAuth(const CJson *context)
{
    bool isDeviceLevel = false;
    (void)GetBoolFromJson(context, FIELD_IS_DEVICE_LEVEL, &isDeviceLevel);
    return isDeviceLevel;
}

static bool IsPinAuth(const CJson *context, const Uint8Buff *presharedUrl)
{
    const char *pinCode = GetStringFromJson(context, FIELD_PIN_CODE);
    if (pinCode != NULL) {
        return true;
    }

    CJson *urlJson = CreateJsonFromString((const char *)presharedUrl->val);
    if (urlJson == NULL) {
        LOGE("Failed to create url json!");
        return false;
    }
    int32_t keyType = 0;
    if (GetIntFromJson(urlJson, PRESHARED_URL_KEY_TYPE, &keyType) != HC_SUCCESS) {
        LOGE("Failed to get trust type!");
        FreeJson(urlJson);
        return false;
    }

    int32_t trustType = 0;
    if (GetIntFromJson(urlJson, PRESHARED_URL_TRUST_TYPE, &trustType) != HC_SUCCESS) {
        LOGE("Failed to get trust type!");
        FreeJson(urlJson);
        return false;
    }
    FreeJson(urlJson);

    return (keyType == KEY_TYPE_SYM) && (trustType == TRUST_TYPE_PIN);
}

static const AuthIdentity *getAuthIdentity(const CJson *in, const Uint8Buff *presharedUrl)
{
    AuthIdentityType identityType = AUTH_IDENTITY_TYPE_INVALID;

    if (IsPinAuth(in, presharedUrl)) {
        identityType = AUTH_IDENTITY_TYPE_PIN;
    } else {
        if (IsDirectAuth(in)) {
            identityType = AUTH_IDENTITY_TYPE_P2P;
        } else {
            identityType = AUTH_IDENTITY_TYPE_GROUP;
        }
    }
    LOGD("AuthIdentityType: %d", identityType);

    if (identityType == AUTH_IDENTITY_TYPE_INVALID) {
        LOGE("invalid AuthIdentityType !");
        return NULL;
    }
    return GetAuthIdentityByType(identityType);
}

int32_t GetCredInfosByPeerIdentity(CJson *in, IdentityInfoVec *vec)
{
    if (in == NULL || vec == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthIdentityType identityType = AUTH_IDENTITY_TYPE_INVALID;
    const char *pinCode = GetStringFromJson(in, FIELD_PIN_CODE);
    if (pinCode != NULL) {
        identityType = AUTH_IDENTITY_TYPE_PIN;
    } else {
        if (IsDirectAuth(in)) {
            identityType = AUTH_IDENTITY_TYPE_P2P;
        } else {
            identityType = AUTH_IDENTITY_TYPE_GROUP;
        }
    }
    if (identityType == AUTH_IDENTITY_TYPE_INVALID) {
        LOGE("invalid AuthIdentityType !");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGD("AuthIdentityType: %d", identityType);
    const AuthIdentity *authIdentity = GetAuthIdentityByType(identityType);
    if (authIdentity == NULL) {
        LOGI("getAuthIdentity failed.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = authIdentity->getCredInfosByPeerIdentity(in, vec);
    if (!IsDeviceLevelAuth(in) || identityType != AUTH_IDENTITY_TYPE_GROUP) {
        return ret;
    }
    // Device level auth also need to try auth with the direct auth identityInfo
    uint32_t identityCount = HC_VECTOR_SIZE(vec);
    authIdentity = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_P2P);
    if (authIdentity == NULL) {
        LOGE("get p2p auth identity failed!");
        return ret;
    }
    // Device level auth comes from old api: authDevice, it's context
    // does not contain acquireType, so we need add it into context here.
    if (AddIntToJson(in, FIELD_ACQURIED_TYPE, P2P_BIND) != HC_SUCCESS) {
        LOGE("Device level auth, add acquire type to context failed!");
        return ret;
    }
    int32_t res = authIdentity->getCredInfosByPeerIdentity(in, vec);
    if (res != HC_SUCCESS && (identityCount > 0)) {
        return HC_SUCCESS;
    }
    return res;
}

int32_t GetCredInfoByPeerUrl(const CJson *in, const Uint8Buff *presharedUrl, IdentityInfo **returnInfo)
{
    if (in == NULL || presharedUrl == NULL || returnInfo == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }

    const AuthIdentity *authIdentity = getAuthIdentity(in, presharedUrl);
    if (!authIdentity) {
        LOGI("getAuthIdentity failed.");
        return HC_ERR_INVALID_PARAMS;
    }

    return authIdentity->getCredInfoByPeerUrl(in, presharedUrl, returnInfo);
}

int32_t GetSharedSecretByUrl(
    const CJson *in, const Uint8Buff *presharedUrl, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    if (in == NULL || presharedUrl == NULL || sharedSecret == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }

#ifdef DEV_AUTH_FUNC_TEST // Add for coverage test
    const AuthIdentity *authIdentityTest = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_P2P);
    if (authIdentityTest == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    authIdentityTest->getSharedSecretByUrl(in, presharedUrl, protocolType, sharedSecret);

    authIdentityTest = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_PIN);
    if (authIdentityTest == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    authIdentityTest->getSharedSecretByUrl(in, presharedUrl, protocolType, sharedSecret);
#endif

    const AuthIdentity *authIdentity = getAuthIdentity(in, presharedUrl);
    if (!authIdentity) {
        LOGI("getAuthIdentity failed.");
        return HC_ERR_INVALID_PARAMS;
    }

    return authIdentity->getSharedSecretByUrl(in, presharedUrl, protocolType, sharedSecret);
}

int32_t GetCredInfoByPeerCert(const CJson *in, const CertInfo *certInfo, IdentityInfo **returnInfo)
{
    if (in == NULL || certInfo == NULL || returnInfo == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }

#ifdef DEV_AUTH_FUNC_TEST // Add for coverage test
    const AuthIdentity *authIdentityTest = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_P2P);
    if (authIdentityTest == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    authIdentityTest->getCredInfoByPeerCert(in, certInfo, returnInfo);

    authIdentityTest = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_PIN);
    if (authIdentityTest == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    authIdentityTest->getCredInfoByPeerCert(in, certInfo, returnInfo);
#endif

    const AuthIdentity *authIdentity = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_GROUP);
    if (authIdentity == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    return authIdentity->getCredInfoByPeerCert(in, certInfo, returnInfo);
}

int32_t GetSharedSecretByPeerCert(
    const CJson *in, const CertInfo *peerCertInfo, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    if (in == NULL || peerCertInfo == NULL || sharedSecret == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }

#ifdef DEV_AUTH_FUNC_TEST // Add for coverage test
    const AuthIdentity *authIdentityTest = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_P2P);
    if (authIdentityTest == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    authIdentityTest->getSharedSecretByPeerCert(in, peerCertInfo, protocolType, sharedSecret);

    authIdentityTest = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_PIN);
    if (authIdentityTest == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    authIdentityTest->getSharedSecretByPeerCert(in, peerCertInfo, protocolType, sharedSecret);
#endif

    const AuthIdentity *authIdentity = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_GROUP);
    if (authIdentity == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    return authIdentity->getSharedSecretByPeerCert(in, peerCertInfo, protocolType, sharedSecret);
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

static int32_t GetCertInfoIS(int32_t osAccountId, const CJson *credAuthInfo, CertInfo *certInfo)
{
    const char *userId = GetStringFromJson(credAuthInfo, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get user ID!");
        return HC_ERR_JSON_GET;
    }

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
    int32_t ret = GetAccountAuthTokenManager()->getToken(osAccountId, token, userId, authId);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get account token!");
        DestroyAccountToken(token);
        return ret;
    }
    ret = GenerateCertInfo(&token->pkInfoStr, &token->pkInfoSignature, certInfo);
    DestroyAccountToken(token);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate cert info!");
        return ret;
    }
    uint32_t signAlg = 0;
    if (GetUnsignedIntFromJson(credAuthInfo, FIELD_ALGORITHM_TYPE, &signAlg) != HC_SUCCESS) {
        LOGE("Failed to get algorithm type!");
        return HC_ERR_JSON_GET;
    }
    ret = ConvertISAlgToCertAlg(signAlg, &certInfo->signAlg);
    if (ret != HC_SUCCESS) {
        LOGE("unsupport algorithm type!");
        return ret;
    }
    certInfo->isPseudonym = false;
    return HC_SUCCESS;
}

static int32_t SetPreShareUrl(const CJson *context, const CJson *credAuthInfo, IdentityInfo *info)
{
    CJson *preShareUrl = CreateJson();
    if (preShareUrl == NULL) {
        LOGE("create preShareUrl failed!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t credType = 0;
    if (GetIntFromJson(credAuthInfo, FIELD_CRED_TYPE, &credType) != HC_SUCCESS) {
        LOGE("Get cred type failed!");
        FreeJson(preShareUrl);
        return HC_ERR_JSON_GET;
    }
    const char *pinCode = GetStringFromJson(context, FIELD_PIN_CODE);
    TrustType trustType;
    if (credType == ACCOUNTT_RELATED) {
        trustType = TRUST_TYPE_UID;
    } else if (pinCode != NULL) {
        trustType = TRUST_TYPE_PIN;
    } else {
        trustType = TRUST_TYPE_P2P;
    }
    if (AddIntToJson(preShareUrl, PRESHARED_URL_TRUST_TYPE, trustType) != HC_SUCCESS) {
        LOGE("Failed to add preshared url trust type!");
        FreeJson(preShareUrl);
        return HC_ERR_JSON_ADD;
    }
    info->proof.preSharedUrl.val = (uint8_t *)PackJsonToString(preShareUrl);
    FreeJson(preShareUrl);
    if (info->proof.preSharedUrl.val == NULL) {
        LOGE("Failed to pack preShareUrl string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    info->proof.preSharedUrl.length = HcStrlen((const char *)info->proof.preSharedUrl.val);
    return HC_SUCCESS;
}

static int32_t SetIdentityProof(const CJson *context, const CJson *credAuthInfo, IdentityInfo *info)
{
    int32_t res = HC_ERROR;
    if (info->proofType == PRE_SHARED) {
        res = SetPreShareUrl(context, credAuthInfo, info);
        if (res != HC_SUCCESS) {
            LOGE("Failed to set preshare url");
        }
    } else {
        int32_t osAccountId = 0;
        if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
            LOGE("Failed to get osAccountId!");
            return HC_ERR_JSON_GET;
        }
        res = GetCertInfoIS(osAccountId, credAuthInfo, &info->proof.certInfo);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get cert info!");
        }
    }
    return res;
}

static int32_t SetProtocolEntityIS(IdentityInfo *info)
{
    ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (entity == NULL) {
        LOGE("Failed to alloc memory for protocol entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (info->proofType == PRE_SHARED) {
#ifdef ENABLE_ACCOUNT_AUTH_ISO
        entity->protocolType = ALG_ISO;
        entity->expandProcessCmds = 0;
#else
        LOGE("ISO not support!");
        HcFree(entity);
        return HC_ERR_NOT_SUPPORT;
#endif
    } else if (info->proofType == CERTIFICATED) {
#ifdef ENABLE_ACCOUNT_AUTH_EC_SPEKE
        entity->protocolType = ALG_EC_SPEKE;
        entity->expandProcessCmds = 0;
#else
        LOGE("ec speke not support!");
        HcFree(entity);
        return HC_ERR_NOT_SUPPORT;
#endif
    } else {
        LOGE("unknown proof type!");
        HcFree(entity);
        return HC_ERR_INVALID_PARAMS;
    }
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity) == NULL) {
        HcFree(entity);
        LOGE("Failed to push protocol entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

int32_t GetIdentityInfoIS(const CJson *context, IdentityInfo **returnInfo)
{
    if (context == NULL || returnInfo == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *credAuthInfo = GetObjFromJson(context, FIELD_SELF_CREDENTIAL_OBJ);
    if (credAuthInfo == NULL) {
        LOGE("Get self credAuthInfo fail.");
        return HC_ERR_JSON_GET;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to alloc memory for IdentityInfo!");
        return HC_ERR_JSON_GET;
    }
    info->IdInfoType = DEFAULT_ID_TYPE;
    int res = HC_ERROR;
    do {
        uint32_t proofType = 0;
        res = GetUnsignedIntFromJson(credAuthInfo, FIELD_PROOF_TYPE, &proofType);
        if (res != HC_SUCCESS) {
            LOGE("Get proofType fail.");
            break;
        }
        res = ConvertISProofTypeToCertType(proofType, &info->proofType);
        if (res != HC_SUCCESS) {
            LOGE("unsupport proof type!");
            break;;
        }
        res = SetIdentityProof(context, credAuthInfo, info);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get protocol entity!");
            break;
        }
        res = SetProtocolEntityIS(info);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get protocol entity!");
            break;
        }
    } while (0);
    if (res != HC_SUCCESS) {
        DestroyIdentityInfo(info);
        return res;
    }
    *returnInfo = info;
    return res;
}