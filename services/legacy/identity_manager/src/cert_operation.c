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

#include "cert_operation.h"

#include "account_task_manager.h"
#include "account_related_group_auth.h"
#include "alg_loader.h"
#include "asy_token_manager.h"
#include "group_data_manager.h"
#include "group_auth_data_operation.h"
#include "group_operation_common.h"
#include "hc_log.h"
#include "hc_types.h"
#include "identity_common.h"
#include "pseudonym_manager.h"
#include "sym_token_manager.h"

#define FIELD_SHARED_SECRET "sharedSecret"

static int32_t SetProtocolsForUidType(IdentityInfo *info)
{
#ifdef ENABLE_ACCOUNT_AUTH_ISO
    ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (entity == NULL) {
        LOGE("Failed to alloc memory for entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    entity->protocolType = ALG_ISO;
    entity->expandProcessCmds = CMD_ADD_TRUST_DEVICE;
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity) == NULL) {
        LOGE("Failed to push entity to vec");
        HcFree(entity);
        return HC_ERR_ALLOC_MEMORY;
    }
#else
    (void)info;
#endif

    return HC_SUCCESS;
}

static int32_t GetIdentityInfoByType(int32_t keyType, int32_t trustType, const char *groupId, IdentityInfo *info)
{
    CJson *urlJson = CreateJson();
    if (urlJson == NULL) {
        LOGE("Failed to create url json!");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_CREDENTIAL_TYPE, PRE_SHARED) != HC_SUCCESS) {
        LOGE("Failed to add credential type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_KEY_TYPE, keyType) != HC_SUCCESS) {
        LOGE("Failed to add key type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(urlJson, PRESHARED_URL_TRUST_TYPE, trustType) != HC_SUCCESS) {
        LOGE("Failed to add trust type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    if ((trustType == TRUST_TYPE_P2P || trustType == TRUST_TYPE_UID) &&
        AddStringToJson(urlJson, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add group id!");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    char *urlStr = PackJsonToString(urlJson);
    FreeJson(urlJson);
    if (urlStr == NULL) {
        LOGE("Failed to pack url json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }

    int32_t ret = SetPreSharedUrlForProof(urlStr, &info->proof.preSharedUrl);
    FreeJsonString(urlStr);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set preSharedUrl of proof!");
        return ret;
    }

    ret = SetProtocolsForUidType(info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set protocols!");
        return ret;
    }

    info->proofType = PRE_SHARED;
    return ret;
}

int32_t AddCertInfoToJson(const CertInfo *certInfo, CJson *out)
{
    if (certInfo == NULL || out == NULL) {
        LOGE("Invalid cert info or out!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (AddIntToJson(out, FIELD_SIGN_ALG, certInfo->signAlg) != HC_SUCCESS) {
        LOGE("add sign alg to json failed!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(out, FIELD_CERT_VERSION, certInfo->certVersion) != HC_SUCCESS) {
        LOGE("add cert version to json failed!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(out, FIELD_PK_INFO, (const char *)certInfo->pkInfoStr.val) != HC_SUCCESS) {
        LOGE("add pk info str to json failed!");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(out, FIELD_PK_INFO_SIGNATURE, certInfo->pkInfoSignature.val,
        certInfo->pkInfoSignature.length) != HC_SUCCESS) {
        LOGE("add pk info sign to json failed!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GetSelfUserId(int32_t osAccountId, char *userId, uint32_t userIdLen)
{
    GroupEntryVec accountVec = CreateGroupEntryVec();
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupType = IDENTICAL_ACCOUNT_GROUP;
    do {
        if (QueryGroups(osAccountId, &queryParams, &accountVec) != HC_SUCCESS) {
            LOGD("No identical-account group in db, no identical-account auth!");
            break;
        }
        uint32_t index = 0;
        TrustedGroupEntry **ptr = NULL;
        while (index < accountVec.size(&accountVec)) {
            ptr = accountVec.getp(&accountVec, index);
            if ((ptr == NULL) || (*ptr == NULL)) {
                index++;
                continue;
            }
            if (memcpy_s(userId, userIdLen, StringGet(&(*ptr)->userId), StringLength(&(*ptr)->userId)) != EOK) {
                LOGE("Error occurs, copy userId failed.");
                ClearGroupEntryVec(&accountVec);
                return HC_ERROR;
            }
            index++;
        }
    } while (0);
    ClearGroupEntryVec(&accountVec);
    return HC_SUCCESS;
}

static void GetLocalIdenticalGroup(int32_t osAccountId, CJson *param, QueryGroupParams *queryParams,
    GroupEntryVec *groupEntryVec)
{
    char selfUserId[USER_ID_LEN] = { 0 };
    int32_t ret = GetSelfUserId(osAccountId, selfUserId, USER_ID_LEN);
    if (ret != HC_SUCCESS) {
        LOGE("Get user id fail");
        return;
    }

    ret = AddStringToJson(param, FIELD_USER_ID, selfUserId);
    if (ret != HC_SUCCESS) {
        LOGE("add self userId to params fail");
        return;
    }

    BaseGroupAuth *groupAuth = GetAccountRelatedGroupAuth();
    if (groupAuth == NULL) {
        LOGE("Failed to get account group auth!");
        return;
    }

    ((AccountRelatedGroupAuth *)groupAuth)
        ->getAccountCandidateGroup(osAccountId, param, queryParams, groupEntryVec);
    if (groupEntryVec->size(groupEntryVec) == 0) {
        LOGE("group not found by self user id!");
    }
}

static TrustedGroupEntry *GetSelfGroupEntryByPeerCert(int32_t osAccountId, const CertInfo *certInfo)
{
    CJson *peerPkInfoJson = CreateJsonFromString((const char *)certInfo->pkInfoStr.val);
    if (peerPkInfoJson == NULL) {
        LOGE("Failed to create peer pkInfoJson!");
        return NULL;
    }
    const char *peerUserId = GetStringFromJson(peerPkInfoJson, FIELD_USER_ID);
    if (peerUserId == NULL) {
        LOGE("Failed to get peer userId!");
        FreeJson(peerPkInfoJson);
        return NULL;
    }
    CJson *param = CreateJson();
    if (param == NULL) {
        LOGE("Failed to create query param!");
        FreeJson(peerPkInfoJson);
        return NULL;
    }
    if (AddStringToJson(param, FIELD_USER_ID, peerUserId) != HC_SUCCESS) {
        LOGE("Failed to add peer userId to param!");
        FreeJson(param);
        FreeJson(peerPkInfoJson);
        return NULL;
    }
    FreeJson(peerPkInfoJson);
    BaseGroupAuth *groupAuth = GetAccountRelatedGroupAuth();
    if (groupAuth == NULL) {
        LOGE("Failed to get account group auth!");
        FreeJson(param);
        return NULL;
    }
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    QueryGroupParams queryParams = InitQueryGroupParams();
    ((AccountRelatedGroupAuth *)groupAuth)
        ->getAccountCandidateGroup(osAccountId, param, &queryParams, &groupEntryVec);
    if (groupEntryVec.size(&groupEntryVec) == 0) {
        LOGE("group not found by peer user id!");
        (void)GetLocalIdenticalGroup(osAccountId, param, &queryParams, &groupEntryVec);
        if (groupEntryVec.size(&groupEntryVec) == 0) {
            LOGE("can not find group");
            ClearGroupEntryVec(&groupEntryVec);
            FreeJson(param);
            return NULL;
        }
    }
    FreeJson(param);
    TrustedGroupEntry *returnEntry = DeepCopyGroupEntry(groupEntryVec.get(&groupEntryVec, 0));
    ClearGroupEntryVec(&groupEntryVec);
    return returnEntry;
}

static int32_t GetSelfDeviceEntryByPeerCert(
    int32_t osAccountId, const CertInfo *certInfo, TrustedDeviceEntry *deviceEntry)
{
    TrustedGroupEntry *groupEntry = GetSelfGroupEntryByPeerCert(osAccountId, certInfo);
    if (groupEntry == NULL) {
        LOGE("Failed to get self group entry!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    const char *groupId = StringGet(&groupEntry->id);
    int32_t ret = GetSelfDeviceEntry(osAccountId, groupId, deviceEntry);
    DestroyGroupEntry(groupEntry);
    return ret;
}

static int32_t VerifyPeerCertInfo(int32_t osAccountId, const char *selfUserId, const char *selfAuthId,
    const CertInfo *certInfo)
{
    uint8_t *keyAliasValue = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (keyAliasValue == NULL) {
        LOGE("Failed to alloc memory for key alias value!");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff keyAlias = { .val = keyAliasValue, .length = SHA256_LEN };
    int32_t ret = GetAccountAuthTokenManager()->generateKeyAlias(selfUserId, selfAuthId, &keyAlias, true);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate server pk alias!");
        HcFree(keyAliasValue);
        return ret;
    }
    KeyParams keyParams = { { keyAlias.val, keyAlias.length, true }, false, osAccountId };
    ret = GetLoaderInstance()->verify(
        &keyParams, &certInfo->pkInfoStr, certInfo->signAlg, &certInfo->pkInfoSignature);
    HcFree(keyAliasValue);
    if (ret != HC_SUCCESS) {
        return HC_ERR_VERIFY_FAILED;
    }
    return HC_SUCCESS;
}

static int32_t GetPeerPubKeyFromCert(const CertInfo *peerCertInfo, Uint8Buff *peerPkBuff)
{
    CJson *pkInfoPeer = CreateJsonFromString((const char *)peerCertInfo->pkInfoStr.val);
    if (pkInfoPeer == NULL) {
        LOGE("Failed to create peer pkInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    const char *devicePk = GetStringFromJson(pkInfoPeer, FIELD_DEVICE_PK);
    if (devicePk == NULL) {
        LOGE("Failed to get peer devicePk!");
        FreeJson(pkInfoPeer);
        return HC_ERR_JSON_GET;
    }
    uint32_t pkSize = HcStrlen(devicePk) / BYTE_TO_HEX_OPER_LENGTH;
    peerPkBuff->val = (uint8_t *)HcMalloc(pkSize, 0);
    if (peerPkBuff->val == NULL) {
        LOGE("Failed to alloc memory for peerPk!");
        FreeJson(pkInfoPeer);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(pkInfoPeer, FIELD_DEVICE_PK, peerPkBuff->val, pkSize) != HC_SUCCESS) {
        LOGE("Failed to get peer public key!");
        HcFree(peerPkBuff->val);
        FreeJson(pkInfoPeer);
        return HC_ERR_JSON_GET;
    }
    FreeJson(pkInfoPeer);
    peerPkBuff->length = pkSize;
    return HC_SUCCESS;
}

static int32_t GetSharedSecretForAccountInPake(int32_t osAccountId, const char *userId, const char *authId,
    const CertInfo *peerCertInfo, Uint8Buff *sharedSecret)
{
    uint8_t *priAliasVal = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (priAliasVal == NULL) {
        LOGE("Failed to alloc memory for self key alias!");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff aliasBuff = { priAliasVal, SHA256_LEN };
    int32_t ret = GetAccountAuthTokenManager()->generateKeyAlias(userId, authId, &aliasBuff, false);
    if (ret != HC_SUCCESS) {
        HcFree(priAliasVal);
        return ret;
    }
    Uint8Buff peerPkBuff = { 0 };
    ret = GetPeerPubKeyFromCert(peerCertInfo, &peerPkBuff);
    if (ret != HC_SUCCESS) {
        HcFree(priAliasVal);
        return ret;
    }

    uint32_t sharedKeyAliasLen = HcStrlen(SHARED_KEY_ALIAS) + 1;
    sharedSecret->val = (uint8_t *)HcMalloc(sharedKeyAliasLen, 0);
    if (sharedSecret->val == NULL) {
        LOGE("Failed to malloc for psk alias.");
        HcFree(priAliasVal);
        ClearFreeUint8Buff(&peerPkBuff);
        return HC_ERR_ALLOC_MEMORY;
    }
    sharedSecret->length = sharedKeyAliasLen;
    (void)memcpy_s(sharedSecret->val, sharedKeyAliasLen, SHARED_KEY_ALIAS, sharedKeyAliasLen);
    KeyParams privKeyParams = { { aliasBuff.val, aliasBuff.length, true }, false, osAccountId };
    KeyBuff pubKeyBuff = { peerPkBuff.val, peerPkBuff.length, false };
    ret = GetLoaderInstance()->agreeSharedSecretWithStorage(
        &privKeyParams, &pubKeyBuff, P256, P256_SHARED_SECRET_KEY_SIZE, sharedSecret);
    HcFree(priAliasVal);
    ClearFreeUint8Buff(&peerPkBuff);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to agree shared secret!");
        FreeBuffData(sharedSecret);
    }
    return ret;
}

int32_t GenerateCertInfo(const Uint8Buff *pkInfoStr, const Uint8Buff *pkInfoSignature, CertInfo *certInfo)
{
    if (!(IsUint8BuffValid(pkInfoStr, pkInfoStr->length) &&
        IsUint8BuffValid(pkInfoSignature, pkInfoSignature->length) &&
        certInfo != NULL)) {
        LOGE("input invailed!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t pkInfoLen = pkInfoStr->length;
    certInfo->pkInfoStr.val = (uint8_t *)HcMalloc(pkInfoLen, 0);
    if (certInfo->pkInfoStr.val == NULL) {
        LOGE("Failed to alloc pkInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(certInfo->pkInfoStr.val, pkInfoLen, pkInfoStr->val, pkInfoLen) != EOK) {
        LOGE("Failed to copy pkInfo!");
        FreeBuffData(&certInfo->pkInfoStr);
        return HC_ERR_MEMORY_COPY;
    }
    certInfo->pkInfoStr.length = pkInfoLen;

    uint32_t signatureLen = pkInfoSignature->length;
    certInfo->pkInfoSignature.val = (uint8_t *)HcMalloc(signatureLen, 0);
    if (certInfo->pkInfoSignature.val == NULL) {
        LOGE("Failed to alloc pkInfoSignature memory!");
        FreeBuffData(&certInfo->pkInfoStr);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(certInfo->pkInfoSignature.val, signatureLen, pkInfoSignature->val, signatureLen) != EOK) {
        LOGE("Failed to copy pkInfoSignature!");
        FreeBuffData(&certInfo->pkInfoStr);
        FreeBuffData(&certInfo->pkInfoSignature);
        return HC_ERR_MEMORY_COPY;
    }
    certInfo->pkInfoSignature.length = signatureLen;

    certInfo->certVersion = CERT_VERSION_V3;
    return HC_SUCCESS;
}

static int32_t GetCertInfo(int32_t osAccountId, const char *userId, const char *authId, CertInfo *certInfo)
{
    AccountToken *token = CreateAccountToken();
    if (token == NULL) {
        LOGE("Failed to create account token.");
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
    certInfo->signAlg = P256;
    return HC_SUCCESS;
}

static int32_t GetAccountAsymIdentityInfo(
    int32_t osAccountId, const char *userId, const char *authId, IdentityInfo *info, bool isNeedGeneratePdid)
{
    int32_t ret = GetCertInfo(osAccountId, userId, authId, &info->proof.certInfo);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate certInfo!");
        return ret;
    }

#ifdef ENABLE_ACCOUNT_AUTH_EC_SPEKE
    ProtocolEntity *ecSpekeEntity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
    if (ecSpekeEntity == NULL) {
        LOGE("Failed to alloc memory for ec speke entity!");
        return HC_ERR_ALLOC_MEMORY;
    }
    ecSpekeEntity->protocolType = ALG_EC_SPEKE;
    ecSpekeEntity->expandProcessCmds = CMD_ADD_TRUST_DEVICE;
#ifdef ENABLE_PSEUDONYM
    if (isNeedGeneratePdid) {
        ecSpekeEntity->expandProcessCmds |= CMD_MK_AGREE;
    }
#else
    (void)isNeedGeneratePdid;
#endif
    if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&ecSpekeEntity) == NULL) {
        LOGE("Failed to push ecSpeke entity!");
        HcFree(ecSpekeEntity);
        return HC_ERR_ALLOC_MEMORY;
    }
#else
    (void)isNeedGeneratePdid;
#endif

    info->proofType = CERTIFICATED;
    return HC_SUCCESS;
}

static int32_t GetLocalDeviceType(int32_t osAccountId, const CJson *in, const char *groupId, int32_t *localDevType)
{
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to alloc memory for deviceEntry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetPeerDeviceEntry(osAccountId, in, groupId, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGI("Peer device not found, set local device type to accessory!");
        *localDevType = DEVICE_TYPE_ACCESSORY;
        DestroyDeviceEntry(deviceEntry);
        return HC_SUCCESS;
    }
    if (deviceEntry->source == SELF_CREATED) {
        LOGI("Peer device is self created, set local device type to accessory!");
        *localDevType = DEVICE_TYPE_ACCESSORY;
    }
    DestroyDeviceEntry(deviceEntry);
    return HC_SUCCESS;
}

static int32_t GenerateAuthTokenForAccessory(int32_t osAccountId, const char *groupId, Uint8Buff *authToken)
{
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetSelfDeviceEntry(osAccountId, groupId, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get self device entry with osAcccountId and groupId!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    const char *userIdSelf = StringGet(&deviceEntry->userId);
    const char *devIdSelf = StringGet(&deviceEntry->authId);
    uint8_t keyAliasVal[SHA256_LEN] = { 0 };
    Uint8Buff keyAlias = { keyAliasVal, SHA256_LEN };
    ret = GetSymTokenManager()->generateKeyAlias(userIdSelf, devIdSelf, &keyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias for authCode!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }

    authToken->val = (uint8_t *)HcMalloc(AUTH_TOKEN_SIZE, 0);
    if (authToken->val == NULL) {
        LOGE("Failed to alloc memory for auth token!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_ALLOC_MEMORY;
    }
    authToken->length = AUTH_TOKEN_SIZE;
    Uint8Buff userIdBuff = { (uint8_t *)userIdSelf, HcStrlen(userIdSelf) };
    Uint8Buff challenge = { (uint8_t *)KEY_INFO_PERSISTENT_TOKEN, HcStrlen(KEY_INFO_PERSISTENT_TOKEN) };
    KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, false, osAccountId };
    ret = GetLoaderInstance()->computeHkdf(&keyAliasParams, &userIdBuff, &challenge, authToken);
    DestroyDeviceEntry(deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to computeHkdf from authCode to authToken!");
        FreeBuffData(authToken);
    }
    return ret;
}

static int32_t GenerateTokenAliasForController(
    int32_t osAccountId, const CJson *in, const char *groupId, Uint8Buff *authTokenAlias)
{
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetPeerDeviceEntry(osAccountId, in, groupId, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Error occurs, failed to get peer device entry!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    authTokenAlias->val = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (authTokenAlias->val == NULL) {
        LOGE("Failed to alloc memory for auth token alias!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_ALLOC_MEMORY;
    }
    authTokenAlias->length = SHA256_LEN;
    const char *userIdPeer = StringGet(&deviceEntry->userId);
    const char *devIdPeer = StringGet(&deviceEntry->authId);
    ret = GetSymTokenManager()->generateKeyAlias(userIdPeer, devIdPeer, authTokenAlias);
    DestroyDeviceEntry(deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias for authToken!");
        FreeBuffData(authTokenAlias);
    }
    return ret;
}

static int32_t GenerateAuthTokenByDevType(
    const CJson *in, const CJson *urlJson, Uint8Buff *authToken, bool *isTokenStored)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(urlJson, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId!");
        return HC_ERR_JSON_GET;
    }
    int32_t localDevType = DEVICE_TYPE_CONTROLLER;
    int32_t ret = GetLocalDeviceType(osAccountId, in, groupId, &localDevType);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get local device type!");
        return ret;
    }
    if (localDevType == DEVICE_TYPE_ACCESSORY) {
        *isTokenStored = false;
        ret = GenerateAuthTokenForAccessory(osAccountId, groupId, authToken);
    } else {
        ret = GenerateTokenAliasForController(osAccountId, in, groupId, authToken);
    }
    return ret;
}

static int32_t GetSelfAccountIdentityInfo(
    int32_t osAccountId, const char *groupId, IdentityInfo *info, bool isNeedGeneratePdid)
{
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetSelfDeviceEntry(osAccountId, groupId, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get self device entry!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    if (deviceEntry->credential == SYMMETRIC_CRED) {
        ret = GetIdentityInfoByType(KEY_TYPE_SYM, TRUST_TYPE_UID, groupId, info);
    } else {
        const char *userId = StringGet(&deviceEntry->userId);
        const char *authId = StringGet(&deviceEntry->authId);
        ret = GetAccountAsymIdentityInfo(osAccountId, userId, authId, info, isNeedGeneratePdid);
    }
    DestroyDeviceEntry(deviceEntry);
    return ret;
}

static bool isNeedGeneratePdidByPeerCert(int32_t osAccountId, const CertInfo *certInfo)
{
#ifdef ENABLE_PSEUDONYM
    CJson *pkInfoJson = CreateJsonFromString((const char *)certInfo->pkInfoStr.val);
    if (pkInfoJson == NULL) {
        LOGE("Failed to create pkInfo json!");
        return false;
    }
    const char *userId = GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId!");
        FreeJson(pkInfoJson);
        return false;
    }
    bool isNeedGenerate = GetPseudonymInstance()->isNeedRefreshPseudonymId(osAccountId, userId);
    FreeJson(pkInfoJson);
    return isNeedGenerate;
#else
    (void)osAccountId;
    (void)certInfo;
    return false;
#endif
}

int32_t GetAccountRelatedCredInfo(
    int32_t osAccountId, const char *groupId, const char *deviceId, bool isUdid, IdentityInfo *info)
{
    if (groupId == NULL || deviceId == NULL || info == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GaGetTrustedDeviceEntryById(osAccountId, deviceId, isUdid, groupId, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGI("peer device not exist, get self identity info.");
        DestroyDeviceEntry(deviceEntry);
        return GetSelfAccountIdentityInfo(osAccountId, groupId, info, true);
    }
    bool isNeedGeneratePdid = false;
#ifdef ENABLE_PSEUDONYM
    const char *peerUserId = StringGet(&deviceEntry->userId);
    isNeedGeneratePdid = GetPseudonymInstance()->isNeedRefreshPseudonymId(osAccountId, peerUserId);
#endif
    if (deviceEntry->source == SELF_CREATED) {
        LOGI("peer device is from self created, get self identity info.");
        DestroyDeviceEntry(deviceEntry);
        return GetSelfAccountIdentityInfo(osAccountId, groupId, info, isNeedGeneratePdid);
    }
    int credType = deviceEntry->credential;
    DestroyDeviceEntry(deviceEntry);
    if (credType == SYMMETRIC_CRED) {
        LOGI("credential type is symmetric, get sym identity info.");
        return GetIdentityInfoByType(KEY_TYPE_SYM, TRUST_TYPE_UID, groupId, info);
    } else {
        LOGI("credential type is asymmetric, get self identity info.");
        return GetSelfAccountIdentityInfo(osAccountId, groupId, info, isNeedGeneratePdid);
    }
}

static int32_t SetSharedKyFromPluginOutput(const CJson *output, Uint8Buff *sharedSecret)
{
    uint32_t sharedKyLen = 0;
    if (GetByteLenFromJson(output, FIELD_SHARED_SECRET, &sharedKyLen) != HC_SUCCESS) {
        LOGE("Get shared ky len failed!");
        return HC_ERR_JSON_GET;
    }
    uint8_t *sharedKy = (uint8_t *)HcMalloc(sharedKyLen, 0);
    if (sharedKy == NULL) {
        LOGE("Failed to alloc memory for shared ky!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(output, FIELD_SHARED_SECRET, sharedKy, sharedKyLen) != HC_SUCCESS) {
        LOGE("Get shared ky failed!");
        HcFree(sharedKy);
        return HC_ERR_JSON_GET;
    }
    sharedSecret->val = sharedKy;
    sharedSecret->length = sharedKyLen;
    return HC_SUCCESS;
}

static int32_t GetSharedSecretByPeerCertFromPlugin(int32_t osAccountId, const char *id, const char *idField,
    const CertInfo *peerCertInfo, Uint8Buff *sharedSecret)
{
    CJson *input = CreateJson();
    if (input == NULL) {
        LOGE("Create input params json failed!");
        return HC_ERR_JSON_CREATE;
    }
    CJson *output = CreateJson();
    if (output == NULL) {
        LOGE("Create output results json failed!");
        FreeJson(input);
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = HC_ERR_JSON_ADD;
    if ((id != NULL) && (idField != NULL) && (AddStringToJson(input, idField, id) != HC_SUCCESS)) {
        LOGE("Across-account cred eixsts, but add cred id to json failed!");
        goto ERR;
    }
    GOTO_ERR_AND_SET_RET(AddCertInfoToJson(peerCertInfo, input), res);
    GOTO_ERR_AND_SET_RET(ExecuteAccountAuthCmd(osAccountId, GET_SHARED_SECRET_BY_PEER_CERT, input, output), res);
    GOTO_ERR_AND_SET_RET(SetSharedKyFromPluginOutput(output, sharedSecret), res);
ERR:
    FreeJson(input);
    FreeJson(output);
    return res;
}

int32_t GetAccountAsymSharedSecret(int32_t osAccountId, const char *id, const char *idField,
    const CertInfo *peerCertInfo, Uint8Buff *sharedSecret)
{
    if ((peerCertInfo == NULL) || (sharedSecret == NULL)) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (HasAccountPlugin()) {
        return GetSharedSecretByPeerCertFromPlugin(osAccountId, id, idField, peerCertInfo, sharedSecret);
    }
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create self device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetSelfDeviceEntryByPeerCert(osAccountId, peerCertInfo, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get self device entry!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    const char *selfUserId = StringGet(&deviceEntry->userId);
    const char *selfAuthId = StringGet(&deviceEntry->authId);
    ret = VerifyPeerCertInfo(osAccountId, selfUserId, selfAuthId, peerCertInfo);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to verify peer cert! [Res]: %" LOG_PUB "d", ret);
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    ret = GetSharedSecretForAccountInPake(osAccountId, selfUserId, selfAuthId, peerCertInfo, sharedSecret);
    DestroyDeviceEntry(deviceEntry);
    return ret;
}

int32_t GetAccountSymSharedSecret(const CJson *in, const CJson *urlJson, Uint8Buff *sharedSecret)
{
    if (in == NULL || urlJson == NULL || sharedSecret == NULL) {
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
    int32_t ret = GenerateAuthTokenByDevType(in, urlJson, &authToken, &isTokenStored);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate auth token by devType!");
        return ret;
    }
    uint8_t seed[SEED_SIZE] = { 0 };
    Uint8Buff seedBuff = { seed, SEED_SIZE };
    ret = GetByteFromJson(in, FIELD_SEED, seed, SEED_SIZE);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get seed form json!");
        FreeBuffData(&authToken);
        return HC_ERR_JSON_GET;
    }
    sharedSecret->val = (uint8_t *)HcMalloc(ISO_PSK_LEN, 0);
    if (sharedSecret->val == NULL) {
        LOGE("Failed to alloc shared secret memory!");
        FreeBuffData(&authToken);
        return HC_ERR_ALLOC_MEMORY;
    }
    sharedSecret->length = ISO_PSK_LEN;
    KeyParams keyParams = { { authToken.val, authToken.length, isTokenStored }, false, osAccountId };
    ret = GetLoaderInstance()->computeHmac(&keyParams, &seedBuff, sharedSecret);
    FreeBuffData(&authToken);
    if (ret != HC_SUCCESS) {
        LOGE("ComputeHmac for psk failed, ret: %" LOG_PUB "d.", ret);
        FreeBuffData(sharedSecret);
    }
    return ret;
}

int32_t GetAccountAsymCredInfo(int32_t osAccountId, const CertInfo *certInfo, IdentityInfo **returnInfo)
{
    if (certInfo == NULL || returnInfo == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create self device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetSelfDeviceEntryByPeerCert(osAccountId, certInfo, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get self device entry!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to create identity info!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_ALLOC_MEMORY;
    }
    const char *selfUserId = StringGet(&deviceEntry->userId);
    const char *selfAuthId = StringGet(&deviceEntry->authId);
    bool isNeedGeneratePdid = isNeedGeneratePdidByPeerCert(osAccountId, certInfo);
    ret = GetAccountAsymIdentityInfo(osAccountId, selfUserId, selfAuthId, info, isNeedGeneratePdid);
    DestroyDeviceEntry(deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get account asym identity info!");
        DestroyIdentityInfo(info);
        return ret;
    }
    *returnInfo = info;
    return HC_SUCCESS;
}

int32_t GetAccountSymCredInfoByPeerUrl(const CJson *in, const CJson *urlJson, IdentityInfo *info)
{
    if (in == NULL || urlJson == NULL || info == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(urlJson, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get group id!");
        return HC_ERR_JSON_GET;
    }
    int32_t ret = CheckGroupExist(osAccountId, groupId);
    if (ret != HC_SUCCESS) {
        LOGE("group not exist!");
        return ret;
    }
    return GetIdentityInfoByType(KEY_TYPE_SYM, TRUST_TYPE_UID, groupId, info);
}