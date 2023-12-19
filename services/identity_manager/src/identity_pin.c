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

static int32_t SetDlSpekeProtocol(IdentityInfo *info)
{
#ifdef ENABLE_P2P_BIND_DL_SPEKE
    ProtocolEntity *dlSpekeEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (dlSpekeEntity == NULL) {
        LOGE("Failed to alloc memory for dl speke entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    dlSpekeEntity->protocolType = ALG_DL_SPEKE;
    dlSpekeEntity->expandProcessCmds = CMD_IMPORT_AUTH_CODE | CMD_ADD_TRUST_DEVICE;
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&dlSpekeEntity) == NULL) {
        LOGE("Failed to push dl speke entity!");
        HcFree(dlSpekeEntity);
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
#else
    (void)info;
    return HC_SUCCESS;
#endif
}

static int32_t SetIsoProtocol(IdentityInfo *info)
{
#ifdef ENABLE_P2P_BIND_ISO
    ProtocolEntity *isoEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (isoEntity == NULL) {
        LOGE("Failed to alloc memory for iso entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    isoEntity->protocolType = ALG_ISO;
    isoEntity->expandProcessCmds = CMD_IMPORT_AUTH_CODE | CMD_ADD_TRUST_DEVICE;
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&isoEntity) == NULL) {
        LOGE("Failed to push iso entity!");
        HcFree(isoEntity);
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
#else
    (void)info;
    return HC_SUCCESS;
#endif
}

static int32_t SetLiteProtocols(IdentityInfo *info)
{
    int32_t res = SetDlSpekeProtocol(info);
    if (res != HC_SUCCESS) {
        return res;
    }
    return SetIsoProtocol(info);
}

static int32_t SetLiteProtocolsForPinType(const CJson *in, IdentityInfo *info)
{
#ifndef ENABLE_P2P_BIND_LITE_PROTOCOL_CHECK
    (void)in;
    return SetLiteProtocols(info);
#else
    int32_t protocolExpandVal = INVALID_PROTOCOL_EXPAND_VALUE;
    (void)GetIntFromJson(in, FIELD_PROTOCOL_EXPAND, &protocolExpandVal);
    int32_t res = HC_SUCCESS;
    if (protocolExpandVal == LITE_PROTOCOL_STANDARD_MODE ||
        protocolExpandVal == LITE_PROTOCOL_COMPATIBILITY_MODE) {
        res = SetLiteProtocols(info);
    }
    return res;
#endif
}

static int32_t SetProtocolsForPinType(const CJson *in, IdentityInfo *info)
{
#ifdef ENABLE_P2P_BIND_EC_SPEKE
    ProtocolEntity *ecSpekeEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (ecSpekeEntity == NULL) {
        LOGE("Failed to alloc memory for ec speke entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    ecSpekeEntity->protocolType = ALG_EC_SPEKE;
    ecSpekeEntity->expandProcessCmds = CMD_EXCHANGE_PK | CMD_ADD_TRUST_DEVICE;
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&ecSpekeEntity) == NULL) {
        LOGE("Failed to push ec speke entity!");
        HcFree(ecSpekeEntity);
        return HC_ERR_ALLOC_MEMORY;
    }
#endif

    return SetLiteProtocolsForPinType(in, info);
}

static bool IsDirectAuth(const CJson *context)
{
    bool isDirectAuth = false;
    (void)GetBoolFromJson(context, FIELD_IS_DIRECT_AUTH, &isDirectAuth);
    return isDirectAuth;
}

static int32_t SetProtocolsForDirectAuth(IdentityInfo *info)
{
#ifdef ENABLE_P2P_AUTH_EC_SPEKE
    ProtocolEntity *ecSpekeEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (ecSpekeEntity == NULL) {
        LOGE("Failed to alloc memory for ec speke entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    ecSpekeEntity->protocolType = ALG_EC_SPEKE;
    ecSpekeEntity->expandProcessCmds = 0;
    info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&ecSpekeEntity);
#else
#endif

    return HC_SUCCESS;
}

static int32_t GetCredInfosByPeerIdentity(const CJson *in, IdentityInfoVec *vec)
{
    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to create identity info!");
        return HC_ERR_ALLOC_MEMORY;
    }
    CJson *urlJson = CreateCredUrlJson(PRE_SHARED, KEY_TYPE_SYM, TRUST_TYPE_PIN);
    if (!urlJson) {
        LOGE("Failed to create CredUrlJson info!");
        DestroyIdentityInfo(info);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (IsDirectAuth(in) && AddBoolToJson(urlJson, FIELD_IS_DIRECT_AUTH, true) != HC_SUCCESS) {
        LOGE("Failed to isDirectAuth to preshared url!");
        FreeJson(urlJson);
        DestroyIdentityInfo(info);
        return HC_ERR_JSON_ADD;
    }
    char *urlStr = PackJsonToString(urlJson);
    FreeJson(urlJson);
    if (urlStr == NULL) {
        LOGE("Failed to pack url json to string!");
        DestroyIdentityInfo(info);
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    int32_t ret = SetPreSharedUrlForProof(urlStr, &info->proof.preSharedUrl);
    FreeJsonString(urlStr);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set preSharedUrl of proof!");
        DestroyIdentityInfo(info);
        return ret;
    }
    if (IsDirectAuth(in)) {
        ret = SetProtocolsForDirectAuth(info);
        info->IdInfoType = P2P_DIRECT_AUTH;
    } else {
        ret = SetProtocolsForPinType(in, info);
    }
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set protocols!");
        DestroyIdentityInfo(info);
        return ret;
    }
    info->proofType = PRE_SHARED;
    vec->pushBack(vec, (const IdentityInfo **)&info);
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
    CJson *urlJson = CreateJsonFromString((const char *)presharedUrl->val);
    if (urlJson == NULL) {
        LOGE("Failed to create url json!");
        DestroyIdentityInfo(info);
        return HC_ERR_JSON_CREATE;
    }
    int32_t credentialType = PRE_SHARED;
    if (GetIntFromJson(urlJson, PRESHARED_URL_CREDENTIAL_TYPE, &credentialType) != HC_SUCCESS) {
        LOGE("Failed to get credential type!");
        DestroyIdentityInfo(info);
        FreeJson(urlJson);
        return HC_ERR_JSON_GET;
    }
    FreeJson(urlJson);
    int32_t ret = SetPreSharedUrlForProof((const char *)presharedUrl->val, &info->proof.preSharedUrl);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set preSharedUrl of proof!");
        DestroyIdentityInfo(info);
        return ret;
    }
    if (IsDirectAuth(in)) {
        ret = SetProtocolsForDirectAuth(info);
        info->IdInfoType = P2P_DIRECT_AUTH;
    } else {
        ret = SetProtocolsForPinType(in, info);
    }
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set protocols!");
        DestroyIdentityInfo(info);
        return ret;
    }
    info->proofType = credentialType;
    *returnInfo = info;
    return HC_SUCCESS;
}

static int32_t AuthGeneratePskUsePin(const Uint8Buff *seed, const char *pinCode, Uint8Buff *sharedSecret)
{
    Uint8Buff messageBuf = { (uint8_t *)pinCode, (uint32_t)strlen(pinCode) };
    uint8_t hash[SHA256_LEN] = { 0 };
    Uint8Buff hashBuf = { hash, sizeof(hash) };
    int ret = GetLoaderInstance()->sha256(&messageBuf, &hashBuf);
    if (ret != HC_SUCCESS) {
        LOGE("sha256 failed, ret:%d", ret);
        return ret;
    }
    return GetLoaderInstance()->computeHmac(&hashBuf, seed, sharedSecret, false);
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

static int32_t GetSharedSecretForPinInIso(const CJson *in, Uint8Buff *sharedSecret)
{
    const char *pinCode = GetStringFromJson(in, FIELD_PIN_CODE);
    if (pinCode == NULL) {
        LOGE("Failed to get pinCode!");
        return HC_ERR_JSON_GET;
    }
    if (HcStrlen(pinCode) < PIN_CODE_LEN_SHORT) {
        LOGE("Pin code is too short!");
        return HC_ERR_INVALID_LEN;
    }
#ifdef ENABLE_P2P_BIND_LITE_PROTOCOL_CHECK
    if (!CheckPinLenForStandardIso(in, pinCode)) {
        LOGE("Invalid pin code len!");
        return HC_ERR_INVALID_LEN;
    }
#endif
    uint8_t *seedVal = (uint8_t *)HcMalloc(SEED_LEN, 0);
    if (seedVal == NULL) {
        LOGE("Failed to alloc seed memory!");
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
        LOGE("Failed to alloc psk memory!");
        HcFree(seedVal);
        return HC_ERR_ALLOC_MEMORY;
    }
    sharedSecret->val = pskVal;
    sharedSecret->length = ISO_PSK_LEN;
    ret = AuthGeneratePskUsePin(&seedBuff, pinCode, sharedSecret);
    HcFree(seedVal);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate psk use pin!");
        FreeBuffData(sharedSecret);
    }
    return ret;
}

static int32_t GetSharedSecretForPinInPake(const CJson *in, Uint8Buff *sharedSecret)
{
    const char *pinCode = GetStringFromJson(in, FIELD_PIN_CODE);
    if (pinCode == NULL) {
        LOGE("Failed to get pinCode!");
        return HC_ERR_JSON_GET;
    }
    uint32_t pinLen = strlen(pinCode);
    if (pinLen < PIN_CODE_LEN_SHORT) {
        LOGE("Invalid pin code len!");
        return HC_ERR_INVALID_LEN;
    }
    sharedSecret->val = (uint8_t *)HcMalloc(pinLen, 0);
    if (sharedSecret->val == NULL) {
        LOGE("Failed to alloc sharedSecret memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(sharedSecret->val, pinLen, pinCode, pinLen) != HC_SUCCESS) {
        LOGE("Failed to memcpy pinCode!");
        FreeBuffData(sharedSecret);
        return HC_ERR_MEMORY_COPY;
    }
    sharedSecret->length = pinLen;
    return HC_SUCCESS;
}

static int32_t GetSharedSecretByUrl(
    const CJson *in, const Uint8Buff *presharedUrl, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    if (in == NULL || presharedUrl == NULL || sharedSecret == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret;
    if (protocolType == ALG_ISO) {
        ret = GetSharedSecretForPinInIso(in, sharedSecret);
        LOGI("get shared secret for pin in iso result: %d", ret);
    } else {
        ret = GetSharedSecretForPinInPake(in, sharedSecret);
        LOGI("get shared secret for pin in pake result: %d", ret);
    }

    return ret;
}

static int32_t GetCredInfoByPeerCert(const CJson *in, const CertInfo *certInfo, IdentityInfo **returnInfo)
{
    // NOT SUPPORT FOR PIN
    return HC_ERR_ALG_FAIL;
}

static int32_t GetSharedSecretByPeerCert(
    const CJson *in, const CertInfo *peerCertInfo, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    // NOT SUPPORT FOR PIN
    return HC_ERR_ALG_FAIL;
}

static const AuthIdentity g_authIdentity = {
    .getCredInfosByPeerIdentity = GetCredInfosByPeerIdentity,
    .getCredInfoByPeerUrl = GetCredInfoByPeerUrl,
    .getSharedSecretByUrl = GetSharedSecretByUrl,
    .getCredInfoByPeerCert = GetCredInfoByPeerCert,
    .getSharedSecretByPeerCert = GetSharedSecretByPeerCert,
};

const AuthIdentity *GetPinAuthIdentity(void)
{
    return &g_authIdentity;
}