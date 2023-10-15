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

#include "account_auth_plugin_proxy.h"
#include "account_module_defines.h"
#include "account_related_creds_manager.h"
#include "account_related_group_auth.h"
#include "alg_defs.h"
#include "alg_loader.h"
#include "creds_operation_utils.h"
#include "das_task_common.h"
#include "data_manager.h"
#include "group_auth_data_operation.h"
#include "group_operation_common.h"
#include "hc_log.h"
#include "hc_types.h"
#include "securec.h"

static int32_t GetAccountRelatedCandidateGroups(int32_t osAccountId, const CJson *in, bool isDeviceLevel,
    GroupEntryVec *vec)
{
    BaseGroupAuth *groupAuth = GetAccountRelatedGroupAuth();
    if (groupAuth == NULL) {
        return HC_ERR_NULL_PTR;
    }
    QueryGroupParams queryParams = InitQueryGroupParams();
    if (!isDeviceLevel) {
        queryParams.groupVisibility = GROUP_VISIBILITY_PUBLIC;
    }
    ((AccountRelatedGroupAuth *)groupAuth)->getAccountCandidateGroup(osAccountId, in, &queryParams, vec);
    // All return success, only notify the plugin.
    if (HasAccountAuthPlugin() == HC_SUCCESS && vec->size(vec) == 0) {
        CJson *input = CreateJson();
        if (input == NULL) {
            return HC_SUCCESS;
        }
        CJson *output = CreateJson();
        if (output == NULL) {
            FreeJson(input);
            return HC_SUCCESS;
        }
        int32_t ret = ExcuteCredMgrCmd(osAccountId, QUERY_SELF_CREDENTIAL_INFO, input, output);
        if (ret != HC_SUCCESS) {
            LOGE("Account cred is empty.");
        }
        FreeJson(input);
        FreeJson(output);
    }
    return HC_SUCCESS;
}

static int32_t GetAccountUnrelatedCandidateGroups(int32_t osAccountId, bool isDeviceLevel, GroupEntryVec *vec)
{
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupType = PEER_TO_PEER_GROUP;
    if (!isDeviceLevel) {
        queryParams.groupVisibility = GROUP_VISIBILITY_PUBLIC;
    }
    return QueryGroups(osAccountId, &queryParams, vec);
}

static bool IsP2pAuthTokenExist(const TrustedDeviceEntry *deviceEntry)
{
    Uint8Buff pkgNameBuff = { (uint8_t *)GROUP_MANAGER_PACKAGE_NAME, strlen(GROUP_MANAGER_PACKAGE_NAME) };

    const char *serviceType = StringGet(&deviceEntry->serviceType);
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, strlen(serviceType) };

    const char *peerAuthId = StringGet(&deviceEntry->authId);
    Uint8Buff peerAuthIdBuff = { (uint8_t *)peerAuthId, strlen(peerAuthId) };

    uint8_t keyAliasVal[ISO_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAlias = { keyAliasVal, ISO_KEY_ALIAS_LEN };
    int32_t ret = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_AUTH_TOKEN, &peerAuthIdBuff, &keyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias!");
        return false;
    }

    ret = GetLoaderInstance()->checkKeyExist(&keyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("auth token not exist!");
        return false;
    }
    return true;
}

static int32_t GetAccountUnrelatedIdentityInfo(int32_t osAccountId, const char *groupId,
    const char *deviceId, bool isUdid, IdentityInfo *info)
{
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create deviceEntry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GaGetTrustedDeviceEntryById(osAccountId, deviceId, isUdid, groupId, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get device entry!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }

    int32_t keyType = IsP2pAuthTokenExist(deviceEntry) ? KEY_TYPE_SYM : KEY_TYPE_ASYM;
    DestroyDeviceEntry(deviceEntry);
    ret = GetIdentityInfoByType(keyType, TRUST_TYPE_P2P, groupId, info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get p2p identity by key type!");
    }
    return ret;
}

static int32_t GetIdentityInfo(int32_t osAccountId, const TrustedGroupEntry *groupEntry,
    const char *deviceId, bool isUdid, IdentityInfo **returnInfo)
{
    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to create identity info!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret;
    const char *groupId = StringGet(&groupEntry->id);
    if (groupEntry->type == PEER_TO_PEER_GROUP) {
        ret = GetAccountUnrelatedIdentityInfo(osAccountId, groupId, deviceId, isUdid, info);
    } else {
        ret = GetAccountRelatedCredInfo(osAccountId, groupId, deviceId, isUdid, info);
    }
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get identity info!");
        DestroyIdentityInfo(info);
        return ret;
    }
    *returnInfo = info;
    return HC_SUCCESS;
}

static bool IsDeviceInGroup(int32_t osAccountId, int32_t groupType, const char *deviceId, const char *groupId,
    bool isUdid)
{
    if (isUdid) {
        return GaIsDeviceInGroup(groupType, osAccountId, deviceId, NULL, groupId);
    } else {
        return GaIsDeviceInGroup(groupType, osAccountId, NULL, deviceId, groupId);
    }
}

static void AddNoPseudonymIdentityInfo(int32_t osAccountId, const TrustedGroupEntry *groupEntry, const char *deviceId,
    bool isUdid, IdentityInfoVec *identityInfoVec)
{
    IdentityInfo *info = NULL;
    if (GetIdentityInfo(osAccountId, groupEntry, deviceId, isUdid, &info) != HC_SUCCESS) {
        return;
    }
    info->proof.certInfo.isPseudonym = false;
    identityInfoVec->pushBack(identityInfoVec, (const IdentityInfo **)&info);
}

static int32_t GetIdentityInfos(int32_t osAccountId, const CJson *in, const GroupEntryVec *groupEntryVec,
    IdentityInfoVec *identityInfoVec)
{
    const char *pkgName = GetStringFromJson(in, FIELD_SERVICE_PKG_NAME);
    if (pkgName == NULL) {
        LOGE("Failed to get service package name!");
        return HC_ERR_JSON_GET;
    }
    bool isUdid = false;
    const char *deviceId = GetPeerDevIdFromJson(in, &isUdid);
    if (deviceId == NULL) {
        LOGE("Failed to get peer device id!");
        return HC_ERR_JSON_GET;
    }
    uint32_t index;
    TrustedGroupEntry **ptr = NULL;
    FOR_EACH_HC_VECTOR(*groupEntryVec, index, ptr) {
        const TrustedGroupEntry *groupEntry = (TrustedGroupEntry *)(*ptr);
        const char *groupId = StringGet(&(groupEntry->id));
        if (groupId == NULL) {
            continue;
        }
        if (!GaIsGroupAccessible(osAccountId, groupId, pkgName)) {
            continue;
        }
        if (!IsDeviceInGroup(osAccountId, groupEntry->type, deviceId, groupId, isUdid)) {
            continue;
        }
        IdentityInfo *info = NULL;
        if (GetIdentityInfo(osAccountId, groupEntry, deviceId, isUdid, &info) != HC_SUCCESS) {
            continue;
        }
        if (info->proofType == CERTIFICATED) {
            info->proof.certInfo.isPseudonym = true;
        }
        identityInfoVec->pushBack(identityInfoVec, (const IdentityInfo **)&info);
        if (info->proofType == CERTIFICATED) {
            AddNoPseudonymIdentityInfo(osAccountId, groupEntry, deviceId, isUdid, identityInfoVec);
        }
    }
    LOGI("The identity info size is: %u", identityInfoVec->size(identityInfoVec));
    return HC_SUCCESS;
}

static int32_t GetCredInfosForPinType(IdentityInfoVec *identityInfoVec)
{
    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to create identity info!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetIdentityInfoByType(KEY_TYPE_SYM, TRUST_TYPE_PIN, NULL, info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get credential info for pin!");
        DestroyIdentityInfo(info);
        return ret;
    }
    identityInfoVec->pushBack(identityInfoVec, (const IdentityInfo **)&info);
    return HC_SUCCESS;
}

static int32_t CheckAndGetP2pCredInfo(const CJson *in, const CJson *urlJson, IdentityInfo *info)
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
    int32_t ret = CheckGroupExist(osAccountId, groupId);
    if (ret != HC_SUCCESS) {
        LOGE("group not exist!");
        return ret;
    }
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    ret = GetPeerDeviceEntry(osAccountId, in, groupId, deviceEntry);
    DestroyDeviceEntry(deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("peer device not found!");
        return ret;
    }
    int32_t keyType = 0;
    if (GetIntFromJson(urlJson, PRESHARED_URL_KEY_TYPE, &keyType) != HC_SUCCESS) {
        LOGE("Failed to get key type!");
        return HC_ERR_JSON_GET;
    }
    ret = GetIdentityInfoByType(keyType, TRUST_TYPE_P2P, groupId, info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get p2p identity info by key type!");
    }
    return ret;
}

static int32_t GetCredInfoByPeerUrlInner(const CJson *in, const Uint8Buff *presharedUrl, IdentityInfo *info)
{
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
    int32_t ret;
    switch (trustType) {
        case TRUST_TYPE_PIN:
            ret = GetIdentityInfoByType(KEY_TYPE_SYM, TRUST_TYPE_PIN, NULL, info);
            break;
        case TRUST_TYPE_UID:
            ret = GetAccountSymCredInfoByPeerUrl(in, urlJson, info);
            break;
        case TRUST_TYPE_P2P:
            ret = CheckAndGetP2pCredInfo(in, urlJson, info);
            break;
        default:
            LOGE("Invalid trust type!");
            ret = HC_ERR_INVALID_PARAMS;
            break;
    }
    FreeJson(urlJson);
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

static int32_t GenerateKeyAliasInIso(const CJson *in, const char *groupId, uint8_t *keyAlias,
    uint32_t keyAliasLen)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetPeerDeviceEntry(osAccountId, in, groupId, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get peer device entry!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    Uint8Buff pkgNameBuff = { (uint8_t *)GROUP_MANAGER_PACKAGE_NAME, (uint32_t)strlen(GROUP_MANAGER_PACKAGE_NAME) };
    const char *serviceType = StringGet(&deviceEntry->serviceType);
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, (uint32_t)strlen(serviceType) };
    const char *peerAuthId = StringGet(&deviceEntry->authId);
    Uint8Buff peerAuthIdBuff = { (uint8_t *)peerAuthId, (uint32_t)strlen(peerAuthId) };
    Uint8Buff outKeyAlias = { keyAlias, keyAliasLen };
    ret = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_AUTH_TOKEN, &peerAuthIdBuff,
        &outKeyAlias);
    DestroyDeviceEntry(deviceEntry);
    return ret;
}

static int32_t AuthGeneratePsk(const CJson *in, const char *groupId, const Uint8Buff *seed,
    Uint8Buff *sharedSecret)
{
    uint8_t keyAlias[ISO_KEY_ALIAS_LEN] = { 0 };
    int ret = GenerateKeyAliasInIso(in, groupId, keyAlias, sizeof(keyAlias));
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias in iso!");
        return ret;
    }
    Uint8Buff keyAliasBuf = { keyAlias, sizeof(keyAlias) };
    return GetLoaderInstance()->computeHmac(&keyAliasBuf, seed, sharedSecret, true);
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

static int32_t GetSharedSecretForPinInIso(const CJson *in, Uint8Buff *sharedSecret)
{
    const char *pinCode = GetStringFromJson(in, FIELD_PIN_CODE);
    if (pinCode == NULL) {
        LOGE("Failed to get pinCode!");
        return HC_ERR_JSON_GET;
    }
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

static int32_t GetSharedSecretForP2pInIso(const CJson *in, const char *groupId, Uint8Buff *sharedSecret)
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
    ret = AuthGeneratePsk(in, groupId, &seedBuff, sharedSecret);
    HcFree(seedVal);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate psk!");
        FreeBuffData(sharedSecret);
    }
    return ret;
}

static int32_t GetSelfAuthIdAndUserType(int32_t osAccountId, const char *groupId, Uint8Buff *authIdBuff,
    int32_t *userType)
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
    const char *selfAuthId = StringGet(&deviceEntry->authId);
    uint32_t authIdLen = strlen(selfAuthId);
    authIdBuff->val = (uint8_t *)HcMalloc(authIdLen + 1, 0);
    if (authIdBuff->val == NULL) {
        LOGE("Failed to alloc memory for authId!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(authIdBuff->val, authIdLen + 1, selfAuthId, authIdLen) != EOK) {
        LOGE("Failed to copy authId!");
        HcFree(authIdBuff->val);
        authIdBuff->val = NULL;
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_MEMORY_COPY;
    }
    authIdBuff->length = authIdLen;
    *userType = deviceEntry->devType;
    DestroyDeviceEntry(deviceEntry);
    return HC_SUCCESS;
}

static int32_t ComputeAndSavePsk(int32_t osAccountId, const char *groupId, const TrustedDeviceEntry *peerDeviceEntry,
    const Uint8Buff *sharedKeyAlias)
{
    Uint8Buff selfAuthIdBuff = { NULL, 0 };
    int32_t selfUserType = 0;
    int32_t ret = GetSelfAuthIdAndUserType(osAccountId, groupId, &selfAuthIdBuff, &selfUserType);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get self auth id and user type!");
        return ret;
    }

    Uint8Buff pkgNameBuff = { (uint8_t *)GROUP_MANAGER_PACKAGE_NAME, strlen(GROUP_MANAGER_PACKAGE_NAME) };
    const char *serviceType = StringGet(&peerDeviceEntry->serviceType);
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, strlen(serviceType) };
    KeyAliasType keyType = (KeyAliasType)selfUserType;
    uint8_t selfKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff selfKeyAlias = { selfKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    ret = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, keyType, &selfAuthIdBuff, &selfKeyAlias);
    HcFree(selfAuthIdBuff.val);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate self key alias!");
        return ret;
    }

#ifdef DEV_AUTH_FUNC_TEST
    KeyAliasType keyTypePeer = KEY_ALIAS_LT_KEY_PAIR;
#else
    KeyAliasType keyTypePeer = (KeyAliasType)peerDeviceEntry->devType;
#endif
    const char *peerAuthId = StringGet(&peerDeviceEntry->authId);
    Uint8Buff peerAuthIdBuff = { (uint8_t *)peerAuthId, strlen(peerAuthId) };
    uint8_t peerKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff peerKeyAlias = { peerKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    ret = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, keyTypePeer, &peerAuthIdBuff, &peerKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate peer key alias!");
        return ret;
    }

    ret = GetLoaderInstance()->checkKeyExist(&selfKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("self auth keyPair not exist!");
        return ret;
    }
    ret = GetLoaderInstance()->checkKeyExist(&peerKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("peer auth pubKey not exist!");
        return ret;
    }

    KeyBuff selfKeyAliasBuff = { selfKeyAlias.val, selfKeyAlias.length, true };
    KeyBuff peerKeyAliasBuff = { peerKeyAlias.val, peerKeyAlias.length, true };
    return GetLoaderInstance()->agreeSharedSecretWithStorage(&selfKeyAliasBuff, &peerKeyAliasBuff, ED25519,
        PAKE_PSK_LEN, sharedKeyAlias);
}

static int32_t GeneratePskAliasAndCheckExist(const CJson *in, const char *groupId, Uint8Buff *pskKeyAlias)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to create device entry!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret = GetPeerDeviceEntry(osAccountId, in, groupId, deviceEntry);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get peer device entry!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    Uint8Buff pkgNameBuff = { (uint8_t *)GROUP_MANAGER_PACKAGE_NAME, strlen(GROUP_MANAGER_PACKAGE_NAME) };
    const char *serviceType = StringGet(&deviceEntry->serviceType);
    Uint8Buff serviceTypeBuff = { (uint8_t *)serviceType, strlen(serviceType) };
    const char *peerAuthId = StringGet(&deviceEntry->authId);
    Uint8Buff peerAuthIdBuff = { (uint8_t *)peerAuthId, strlen(peerAuthId) };
    ret = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_PSK, &peerAuthIdBuff, pskKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate psk key alias!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    LOGI("psk alias: %x %x %x %x****.", pskKeyAlias->val[DEV_AUTH_ZERO], pskKeyAlias->val[DEV_AUTH_ONE],
        pskKeyAlias->val[DEV_AUTH_TWO], pskKeyAlias->val[DEV_AUTH_THREE]);
    if (GetLoaderInstance()->checkKeyExist(pskKeyAlias) != HC_SUCCESS) {
        ret = ComputeAndSavePsk(osAccountId, groupId, deviceEntry, pskKeyAlias);
    }
    DestroyDeviceEntry(deviceEntry);
    return ret;
}

static void UpperToLowercase(Uint8Buff *hex)
{
    for (uint32_t i = 0; i < hex->length; i++) {
        if (hex->val[i] >= 'A' && hex->val[i] <= 'F') {
            hex->val[i] += ASCII_CASE_DIFFERENCE_VALUE;
        }
    }
}

static int32_t ConvertPsk(const Uint8Buff *srcPsk, Uint8Buff *sharedSecret)
{
    uint32_t len = PAKE_PSK_LEN * BYTE_TO_HEX_OPER_LENGTH;
    sharedSecret->val = (uint8_t *)HcMalloc(len + 1, 0);
    if (sharedSecret->val == NULL) {
        LOGE("Failed to alloc memory for sharedSecret!");
        return HC_ERR_ALLOC_MEMORY;
    }

    if (ByteToHexString(srcPsk->val, srcPsk->length, (char *)sharedSecret->val, len + 1) != HC_SUCCESS) {
        LOGE("Convert psk from byte to hex string failed!");
        HcFree(sharedSecret->val);
        return HC_ERR_CONVERT_FAILED;
    }
    sharedSecret->length = len;
    (void)UpperToLowercase(sharedSecret);
    return HC_SUCCESS;
}

static int32_t GetSharedSecretForP2pInPake(const CJson *in, const char *groupId, Uint8Buff *sharedSecret)
{
    uint8_t pskKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff pskKeyAlias = { pskKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    int32_t ret = GeneratePskAliasAndCheckExist(in, groupId, &pskKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias for psk!");
        return ret;
    }
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
    ret = GetByteFromJson(in, FIELD_NONCE, nonceBuff.val, nonceBuff.length);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get nonce!");
        HcFree(pskVal);
        HcFree(nonceVal);
        return HC_ERR_JSON_GET;
    }
    Uint8Buff keyInfo = { (uint8_t *)TMP_AUTH_KEY_FACTOR, strlen(TMP_AUTH_KEY_FACTOR) };
    ret = GetLoaderInstance()->computeHkdf(&pskKeyAlias, &nonceBuff, &keyInfo, &pskBuff, true);
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

static int32_t GetSharedSecretForPin(const CJson *in, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
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

static int32_t GetSharedSecretForP2p(const CJson *in, const CJson *urlJson, ProtocolAlgType protocolType,
    Uint8Buff *sharedSecret)
{
    const char *groupId = GetStringFromJson(urlJson, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId!");
        return HC_ERR_JSON_GET;
    }
    int32_t ret;
    if (protocolType == ALG_ISO) {
        ret = GetSharedSecretForP2pInIso(in, groupId, sharedSecret);
        LOGI("get shared secret for p2p in iso result: %d", ret);
    } else {
        ret = GetSharedSecretForP2pInPake(in, groupId, sharedSecret);
        LOGI("get shared secret for p2p in pake result: %d", ret);
    }
    return ret;
}

static void GetGroupInfoByGroupId(int32_t osAccountId, const char *groupId, GroupEntryVec *groupEntryVec)
{
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupId = groupId;
    int32_t ret = QueryGroups(osAccountId, &queryParams, groupEntryVec);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to query groups for groupId: %s!", groupId);
    }
}

static void GetCandidateGroups(int32_t osAccountId, const CJson *in, GroupEntryVec *groupEntryVec)
{
    bool isDeviceLevel = false;
    (void)GetBoolFromJson(in, FIELD_IS_DEVICE_LEVEL, &isDeviceLevel);

    int32_t ret = GetAccountRelatedCandidateGroups(osAccountId, in, isDeviceLevel, groupEntryVec);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get account related groups!");
    }

    ret = GetAccountUnrelatedCandidateGroups(osAccountId, isDeviceLevel, groupEntryVec);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get p2p groups!");
    }
}

static int32_t GetCredInfosForGroups(const CJson *in, IdentityInfoVec *identityInfoVec)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(in, FIELD_GROUP_ID);
    if (groupId == NULL) {
        groupId = GetStringFromJson(in, FIELD_SERVICE_TYPE);
    }

    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    if (groupId == NULL) {
        GetCandidateGroups(osAccountId, in, &groupEntryVec);
    } else {
        GetGroupInfoByGroupId(osAccountId, groupId, &groupEntryVec);
    }

    if (groupEntryVec.size(&groupEntryVec) == 0) {
        LOGE("No satisfied candidate group!");
        ClearGroupEntryVec(&groupEntryVec);
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    int32_t ret = GetIdentityInfos(osAccountId, in, &groupEntryVec, identityInfoVec);
    ClearGroupEntryVec(&groupEntryVec);
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

int32_t GetCredInfosByPeerIdentity(const CJson *in, IdentityInfoVec *identityInfoVec)
{
    if (in == NULL || identityInfoVec == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *pinCode = GetStringFromJson(in, FIELD_PIN_CODE);
    if (pinCode != NULL) {
        return GetCredInfosForPinType(identityInfoVec);
    } else {
        return GetCredInfosForGroups(in, identityInfoVec);
    }
}

int32_t GetCredInfoByPeerUrl(const CJson *in, const Uint8Buff *presharedUrl, IdentityInfo **returnInfo)
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
    int32_t ret = GetCredInfoByPeerUrlInner(in, presharedUrl, info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get credential info by peer url!");
        DestroyIdentityInfo(info);
        return ret;
    }
    *returnInfo = info;
    return HC_SUCCESS;
}

int32_t GetSharedSecretByUrl(const CJson *in, const Uint8Buff *presharedUrl, ProtocolAlgType protocolType,
    Uint8Buff *sharedSecret)
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
    int32_t ret;
    switch (trustType) {
        case TRUST_TYPE_PIN:
            ret = GetSharedSecretForPin(in, protocolType, sharedSecret);
            break;
        case TRUST_TYPE_P2P:
            ret = GetSharedSecretForP2p(in, urlJson, protocolType, sharedSecret);
            break;
        case TRUST_TYPE_UID:
            if (protocolType != ALG_ISO) {
                LOGE("protocol type is not iso, not supported!");
                ret = HC_ERR_INVALID_PARAMS;
            } else {
                ret = GetAccountSymSharedSecret(in, urlJson, sharedSecret);
            }
            break;
        default:
            LOGE("Invalid trust type!");
            ret = HC_ERR_INVALID_PARAMS;
            break;
    }
    FreeJson(urlJson);
    return ret;
}

int32_t GetCredInfoByPeerCert(const CJson *in, const CertInfo *certInfo, IdentityInfo **returnInfo)
{
    if (in == NULL || certInfo == NULL || returnInfo == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = GetAccountAsymCredInfo(osAccountId, certInfo, returnInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get account asym cred info!");
        return res;
    }
    if (certInfo->isPseudonym) {
        (*returnInfo)->proof.certInfo.isPseudonym = true;
    } else {
        (*returnInfo)->proof.certInfo.isPseudonym = false;
    }
    return HC_SUCCESS;
}

int32_t GetSharedSecretByPeerCert(const CJson *in, const CertInfo *peerCertInfo, ProtocolAlgType protocolType,
    Uint8Buff *sharedSecret)
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
    return GetAccountAsymSharedSecret(osAccountId, peerCertInfo, sharedSecret);
}