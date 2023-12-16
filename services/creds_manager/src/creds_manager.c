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

#include "creds_manager.h"

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
    int32_t identityCount = HC_VECTOR_SIZE(vec);
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