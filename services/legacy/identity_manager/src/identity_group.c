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

#include "account_related_group_auth.h"
#include "account_task_manager.h"
#include "alg_defs.h"
#include "alg_loader.h"
#include "cert_operation.h"
#include "group_auth_data_operation.h"
#include "group_operation_common.h"
#include "hc_log.h"
#include "identity_manager.h"

static int32_t GetAccountRelatedCandidateGroups(
    int32_t osAccountId, const CJson *in, bool isDeviceLevel, GroupEntryVec *vec)
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
    if (HasAccountPlugin() && vec->size(vec) == 0) {
        CJson *input = CreateJson();
        if (input == NULL) {
            return HC_SUCCESS;
        }
        CJson *output = CreateJson();
        if (output == NULL) {
            FreeJson(input);
            return HC_SUCCESS;
        }
        int32_t ret = ExecuteAccountAuthCmd(osAccountId, QUERY_SELF_CREDENTIAL_INFO, input, output);
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

static void GetGroupInfoByGroupId(int32_t osAccountId, const char *groupId, GroupEntryVec *groupEntryVec)
{
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupId = groupId;
    int32_t ret = QueryGroups(osAccountId, &queryParams, groupEntryVec);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to query groups for groupId: %" LOG_PUB "s!", groupId);
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

static bool IsDeviceInGroup(
    int32_t osAccountId, int32_t groupType, const char *deviceId, const char *groupId, bool isUdid)
{
    if (isUdid) {
        return GaIsDeviceInGroup(groupType, osAccountId, deviceId, NULL, groupId);
    } else {
        return GaIsDeviceInGroup(groupType, osAccountId, NULL, deviceId, groupId);
    }
}

static int32_t SetProtocolsToIdentityInfo(int32_t keyType, IdentityInfo *info)
{
    if (keyType == KEY_TYPE_ASYM) {
#ifdef ENABLE_P2P_AUTH_EC_SPEKE
        ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
        if (entity == NULL) {
            LOGE("Failed to alloc memory for entity!");
            return HC_ERR_ALLOC_MEMORY;
        }
        entity->protocolType = ALG_EC_SPEKE;
        if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity) == NULL) {
            LOGE("Failed to push entity!");
            HcFree(entity);
            return HC_ERR_ALLOC_MEMORY;
        }
#else
        (void)info;
#endif
    } else {
#ifdef ENABLE_P2P_AUTH_ISO
        ProtocolEntity *entity = (ProtocolEntity *)HcMalloc(sizeof(ProtocolEntity), 0);
        if (entity == NULL) {
            LOGE("Failed to alloc memory for entity!");
            return HC_ERR_ALLOC_MEMORY;
        }
        entity->protocolType = ALG_ISO;
        if (info->protocolVec.pushBack(&info->protocolVec, (const ProtocolEntity **)&entity) == NULL) {
            LOGE("Failed to push entity!");
            HcFree(entity);
            return HC_ERR_ALLOC_MEMORY;
        }
#else
        (void)info;
#endif
    }

    return HC_SUCCESS;
}

static bool IsP2pAuthTokenExist(int32_t osAccountId, const TrustedDeviceEntry *deviceEntry)
{
    const char *serviceType = StringGet(&deviceEntry->serviceType);
    const char *peerAuthId = StringGet(&deviceEntry->authId);
    uint8_t keyAliasVal[ISO_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAlias = { keyAliasVal, ISO_KEY_ALIAS_LEN };
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)GROUP_MANAGER_PACKAGE_NAME;
    tokenParams.pkgName.length = HcStrlen(GROUP_MANAGER_PACKAGE_NAME);
    tokenParams.serviceType.val = (uint8_t *)serviceType;
    tokenParams.serviceType.length = HcStrlen(serviceType);
    tokenParams.userType = KEY_ALIAS_AUTH_TOKEN;
    tokenParams.authId.val = (uint8_t *)peerAuthId;
    tokenParams.authId.length = HcStrlen(peerAuthId);
    int32_t ret = GenerateKeyAlias(&tokenParams, &keyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias!");
        return false;
    }

    ret = GetLoaderInstance()->checkKeyExist(&keyAlias, false, osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("auth token not exist!");
        return false;
    }
    return true;
}

static int32_t GetAccountUnrelatedIdentityInfo(
    int32_t osAccountId, const char *groupId, const char *deviceId, bool isUdid, IdentityInfo *info)
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

    int32_t keyType = IsP2pAuthTokenExist(osAccountId, deviceEntry) ? KEY_TYPE_SYM : KEY_TYPE_ASYM;
    DestroyDeviceEntry(deviceEntry);
    CJson *urlJson = CreateCredUrlJson(PRE_SHARED, keyType, TRUST_TYPE_P2P);

    if (!urlJson) {
        LOGE("Failed to create CredUrlJson info!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddStringToJson(urlJson, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
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

    ret = SetPreSharedUrlForProof(urlStr, &info->proof.preSharedUrl);
    FreeJsonString(urlStr);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set preSharedUrl of proof!");
        return ret;
    }

    ret = SetProtocolsToIdentityInfo(keyType, info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set protocols!");
        return ret;
    }

    info->proofType = PRE_SHARED;
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get p2p identity by key type!");
    }
    return ret;
}

static int32_t GetIdentityInfo(int32_t osAccountId, const TrustedGroupEntry *groupEntry, const char *deviceId,
    bool isUdid, IdentityInfo **returnInfo)
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

static void AddNoPseudonymIdentityInfo(int32_t osAccountId, const TrustedGroupEntry *groupEntry,
    const char *deviceId, bool isUdid, IdentityInfoVec *identityInfoVec)
{
    IdentityInfo *info = NULL;
    if (GetIdentityInfo(osAccountId, groupEntry, deviceId, isUdid, &info) != HC_SUCCESS) {
        return;
    }
    info->proof.certInfo.isPseudonym = false;
    if (identityInfoVec->pushBack(identityInfoVec, (const IdentityInfo **)&info) == NULL) {
        LOGE("Failed to push info!");
        DestroyIdentityInfo(info);
        return;
    }
}

static int32_t GetIdentityInfos(
    int32_t osAccountId, const CJson *in, const GroupEntryVec *groupEntryVec, IdentityInfoVec *identityInfoVec)
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
    FOR_EACH_HC_VECTOR(*groupEntryVec, index, ptr)
    {
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
        if (identityInfoVec->pushBack(identityInfoVec, (const IdentityInfo **)&info) == NULL) {
            LOGE("Failed to push info!");
            DestroyIdentityInfo(info);
            return HC_ERR_ALLOC_MEMORY;
        }
        if (info->proofType == CERTIFICATED) {
            AddNoPseudonymIdentityInfo(osAccountId, groupEntry, deviceId, isUdid, identityInfoVec);
        }
    }
    LOGI("The identity info size is: %" LOG_PUB "u", identityInfoVec->size(identityInfoVec));
    return HC_SUCCESS;
}

static int32_t GetCredInfosByPeerIdentity(const CJson *in, IdentityInfoVec *identityInfoVec)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    int32_t ret;
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

    bool isDeviceLevel = false;
    (void)GetBoolFromJson(in, FIELD_IS_DEVICE_LEVEL, &isDeviceLevel);
    if (groupEntryVec.size(&groupEntryVec) == 0) {
        if (isDeviceLevel) {
            // device level auth still has the chance to try p2p direct auth
            // so, do not report error here.
            LOGI("No satisfied candidate group!");
        } else {
            LOGE("No satisfied candidate group!");
        }
        ClearGroupEntryVec(&groupEntryVec);
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    ret = GetIdentityInfos(osAccountId, in, &groupEntryVec, identityInfoVec);
    ClearGroupEntryVec(&groupEntryVec);
    return ret;
}

static int32_t SetIdentityInfoByUrl(const CJson *urlJson, IdentityInfo *info)
{
    if (urlJson == NULL || info == NULL) {
        LOGE("Need urlJson and IdentityInfo is not NULL!");
        return HC_ERR_INVALID_PARAMS;
    }

    int32_t keyType = 0;
    if (GetIntFromJson(urlJson, PRESHARED_URL_KEY_TYPE, &keyType) != HC_SUCCESS) {
        LOGE("Failed to get trust type!");
        return HC_ERR_JSON_GET;
    }

    char *urlStr = PackJsonToString(urlJson);
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

    ret = SetProtocolsToIdentityInfo(keyType, info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to set protocols!");
        return ret;
    }

    info->proofType = PRE_SHARED;
    return ret;
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

    ret = SetIdentityInfoByUrl(urlJson, info);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get p2p identity info by key type!");
    }
    return ret;
}

static int32_t GetCredInfoByPeerUrl(const CJson *in, const Uint8Buff *presharedUrl, IdentityInfo **returnInfo)
{
    if (in == NULL || presharedUrl == NULL || returnInfo == NULL) {
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

    IdentityInfo *info = CreateIdentityInfo();
    if (info == NULL) {
        LOGE("Failed to create identity info!");
        FreeJson(urlJson);
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t ret;
    switch (trustType) {
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

    *returnInfo = info;
    return ret;
}

static int32_t GenerateKeyAliasForIso(const TrustedDeviceEntry *deviceEntry, Uint8Buff *keyAliasBuff)
{
    const char *serviceType = StringGet(&deviceEntry->serviceType);
    const char *peerAuthId = StringGet(&deviceEntry->authId);
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)GROUP_MANAGER_PACKAGE_NAME;
    tokenParams.pkgName.length = HcStrlen(GROUP_MANAGER_PACKAGE_NAME);
    tokenParams.serviceType.val = (uint8_t *)serviceType;
    tokenParams.serviceType.length = HcStrlen(serviceType);
    tokenParams.userType = KEY_ALIAS_AUTH_TOKEN;
    if (deviceEntry->upgradeFlag == 1) {
        tokenParams.userType = deviceEntry->devType;
    }
    tokenParams.authId.val = (uint8_t *)peerAuthId;
    tokenParams.authId.length = HcStrlen(peerAuthId);
    int32_t ret = GenerateKeyAlias(&tokenParams, keyAliasBuff);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias for iso!");
        return ret;
    }
    if (deviceEntry->upgradeFlag == 1) {
        ret = ToLowerCase(keyAliasBuff);
        if (ret != HC_SUCCESS) {
            LOGE("Failed to convert psk alias to lower case!");
            return ret;
        }
    }
    return HC_SUCCESS;
}

static int32_t AuthGeneratePsk(const CJson *in, const char *groupId, const Uint8Buff *seed, Uint8Buff *sharedSecret)
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
    uint8_t keyAlias[ISO_KEY_ALIAS_LEN] = { 0 };
    uint8_t upgradeKeyAlias[ISO_UPGRADE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff keyAliasBuf = { keyAlias, ISO_KEY_ALIAS_LEN };
    if (deviceEntry->upgradeFlag == 1) {
        keyAliasBuf.val = upgradeKeyAlias;
        keyAliasBuf.length = ISO_UPGRADE_KEY_ALIAS_LEN;
    }
    ret = GenerateKeyAliasForIso(deviceEntry, &keyAliasBuf);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate key alias in iso!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    if (deviceEntry->upgradeFlag == 1) {
        KeyParams keyAliasParams = { { keyAliasBuf.val, keyAliasBuf.length, true }, true, osAccountId };
        ret = GetLoaderInstance()->computeHmacWithThreeStage(&keyAliasParams, seed, sharedSecret);
    } else {
        KeyParams keyAliasParams = { { keyAliasBuf.val, keyAliasBuf.length, true }, false, osAccountId };
        ret = GetLoaderInstance()->computeHmac(&keyAliasParams, seed, sharedSecret);
    }
    DestroyDeviceEntry(deviceEntry);
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

static int32_t GetSelfAuthIdAndUserType(
    int32_t osAccountId, const char *groupId, Uint8Buff *authIdBuff, int32_t *userType, int32_t *upgradeFlag)
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
    uint32_t authIdLen = HcStrlen(selfAuthId);
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
    *upgradeFlag = deviceEntry->upgradeFlag;
    DestroyDeviceEntry(deviceEntry);
    return HC_SUCCESS;
}

static int32_t GenerateSelfKeyAlias(const char *serviceType, int32_t selfUserType, const Uint8Buff *selfAuthIdBuff,
    bool isSelfFromUpgrade, Uint8Buff *selfKeyAlias)
{
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)GROUP_MANAGER_PACKAGE_NAME;
    tokenParams.pkgName.length = HcStrlen(GROUP_MANAGER_PACKAGE_NAME);
    tokenParams.serviceType.val = (uint8_t *)serviceType;
    tokenParams.serviceType.length = HcStrlen(serviceType);
    tokenParams.userType = selfUserType;
    if (isSelfFromUpgrade) {
        tokenParams.userType = KEY_ALIAS_LT_KEY_PAIR;
    }
    tokenParams.authId = *selfAuthIdBuff;
    int32_t ret = GenerateKeyAlias(&tokenParams, selfKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate self key alias!");
        return ret;
    }
    if (isSelfFromUpgrade) {
        ret = ToLowerCase(selfKeyAlias);
        if (ret != HC_SUCCESS) {
            LOGE("Failed to convert self key alias to lower case!");
            return ret;
        }
    }
    return HC_SUCCESS;
}

static int32_t GeneratePeerKeyAlias(const TrustedDeviceEntry *peerDeviceEntry, Uint8Buff *peerKeyAlias)
{
    const char *serviceType = StringGet(&peerDeviceEntry->serviceType);
    const char *peerAuthId = StringGet(&peerDeviceEntry->authId);
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)GROUP_MANAGER_PACKAGE_NAME;
    tokenParams.pkgName.length = HcStrlen(GROUP_MANAGER_PACKAGE_NAME);
    tokenParams.serviceType.val = (uint8_t *)serviceType;
    tokenParams.serviceType.length = HcStrlen(serviceType);
#ifdef DEV_AUTH_FUNC_TEST
    tokenParams.userType = KEY_ALIAS_LT_KEY_PAIR;
#else
    tokenParams.userType = peerDeviceEntry->devType;
#endif
    tokenParams.authId.val = (uint8_t *)peerAuthId;
    tokenParams.authId.length = HcStrlen(peerAuthId);
    int32_t ret = GenerateKeyAlias(&tokenParams, peerKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate peer key alias!");
        return ret;
    }
    if (peerDeviceEntry->upgradeFlag == 1) {
        ret = ToLowerCase(peerKeyAlias);
        if (ret != HC_SUCCESS) {
            LOGE("Failed to convert peer key alias to lower case!");
            return ret;
        }
    }
    return HC_SUCCESS;
}

static int32_t CheckSelfKeyAlias(const Uint8Buff *selfKeyAlias, bool isSelfFromUpgrade, int32_t osAccountId,
    const char *groupId)
{
    int32_t ret = GetLoaderInstance()->checkKeyExist(selfKeyAlias, isSelfFromUpgrade, osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("self auth keyPair not exist, need to delete group and devices!");
        if (DelGroupFromDb(osAccountId, groupId) != HC_SUCCESS) {
            LOGW("delete group from db failed!");
            return ret;
        }
        LOGI("self auth keyPair not exist, delete group from db successfully!");
    }
    return ret;
}

static int32_t CheckPeerKeyAlias(const Uint8Buff *peerKeyAlias, bool isPeerFromUpgrade, int32_t osAccountId,
    const char *groupId, const TrustedDeviceEntry *peerDeviceEntry)
{
    int32_t ret = GetLoaderInstance()->checkKeyExist(peerKeyAlias, isPeerFromUpgrade, osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("peer auth pubKey not exist, need to delete peer device!");
        if (DelDeviceFromDb(osAccountId, groupId, peerDeviceEntry) != HC_SUCCESS) {
            LOGW("delete peer device from db failed!");
            return ret;
        }
        LOGI("peer auth pubKey not exist, delete peer device from db successfully!");
    }
    return ret;
}

static int32_t ComputeAndSavePsk(int32_t osAccountId, const char *groupId,
    const TrustedDeviceEntry *peerDeviceEntry, const Uint8Buff *sharedKeyAlias)
{
    Uint8Buff selfAuthIdBuff = { NULL, 0 };
    int32_t selfUserType = 0;
    int32_t selfUpgradeFlag = 0;
    int32_t ret = GetSelfAuthIdAndUserType(osAccountId, groupId, &selfAuthIdBuff, &selfUserType, &selfUpgradeFlag);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to get self auth id and user type!");
        return ret;
    }
    const char *serviceType = StringGet(&peerDeviceEntry->serviceType);
    bool isSelfFromUpgrade = selfUpgradeFlag == 1;
    uint8_t selfKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff selfKeyAlias = { selfKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    ret = GenerateSelfKeyAlias(serviceType, selfUserType, &selfAuthIdBuff, isSelfFromUpgrade, &selfKeyAlias);
    HcFree(selfAuthIdBuff.val);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate self key alias!");
        return ret;
    }

    uint8_t peerKeyAliasVal[PAKE_KEY_ALIAS_LEN] = { 0 };
    Uint8Buff peerKeyAlias = { peerKeyAliasVal, PAKE_KEY_ALIAS_LEN };
    ret = GeneratePeerKeyAlias(peerDeviceEntry, &peerKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate peer key alias!");
        return ret;
    }

    ret = CheckSelfKeyAlias(&selfKeyAlias, isSelfFromUpgrade, osAccountId, groupId);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    bool isPeerFromUpgrade = peerDeviceEntry->upgradeFlag == 1;
    ret = CheckPeerKeyAlias(&peerKeyAlias, isPeerFromUpgrade, osAccountId, groupId, peerDeviceEntry);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    uint8_t peerPubKeyVal[PAKE_ED25519_KEY_PAIR_LEN] = { 0 };
    Uint8Buff peerPubKeyBuff = { peerPubKeyVal, PAKE_ED25519_KEY_PAIR_LEN };
    KeyParams peerKeyParams = { { peerKeyAlias.val, peerKeyAlias.length, true }, isPeerFromUpgrade, osAccountId };
    ret = GetLoaderInstance()->exportPublicKey(&peerKeyParams, &peerPubKeyBuff);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to export peer public key!");
        return ret;
    }
    KeyParams selfKeyAliasParams = { { selfKeyAlias.val, selfKeyAlias.length, true }, isSelfFromUpgrade, osAccountId };
    KeyBuff peerKeyBuff = { peerPubKeyBuff.val, peerPubKeyBuff.length, false };
    return GetLoaderInstance()->agreeSharedSecretWithStorage(
        &selfKeyAliasParams, &peerKeyBuff, ED25519, PAKE_PSK_LEN, sharedKeyAlias);
}

static int32_t GeneratePskAliasInner(const char *serviceType, const char *peerAuthId, Uint8Buff *pskKeyAlias)
{
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName.val = (uint8_t *)GROUP_MANAGER_PACKAGE_NAME;
    tokenParams.pkgName.length = HcStrlen(GROUP_MANAGER_PACKAGE_NAME);
    tokenParams.serviceType.val = (uint8_t *)serviceType;
    tokenParams.serviceType.length = HcStrlen(serviceType);
    tokenParams.userType = KEY_ALIAS_PSK;
    tokenParams.authId.val = (uint8_t *)peerAuthId;
    tokenParams.authId.length = HcStrlen(peerAuthId);
    return GenerateKeyAlias(&tokenParams, pskKeyAlias);
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
    const char *serviceType = StringGet(&deviceEntry->serviceType);
    const char *peerAuthId = StringGet(&deviceEntry->authId);
    ret = GeneratePskAliasInner(serviceType, peerAuthId, pskKeyAlias);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate psk key alias!");
        DestroyDeviceEntry(deviceEntry);
        return ret;
    }
    bool isPeerFromUpgrade = deviceEntry->upgradeFlag == 1;
    if (isPeerFromUpgrade) {
        ret = ToLowerCase(pskKeyAlias);
        if (ret != HC_SUCCESS) {
            LOGE("Failed to convert psk alias to lower case!");
            DestroyDeviceEntry(deviceEntry);
            return ret;
        }
    }
    LOGI("psk alias: %" LOG_PUB "x %" LOG_PUB "x %" LOG_PUB "x %" LOG_PUB "x****.", pskKeyAlias->val[DEV_AUTH_ZERO],
        pskKeyAlias->val[DEV_AUTH_ONE], pskKeyAlias->val[DEV_AUTH_TWO], pskKeyAlias->val[DEV_AUTH_THREE]);
    if (GetLoaderInstance()->checkKeyExist(pskKeyAlias, isPeerFromUpgrade, osAccountId) != HC_SUCCESS) {
        ret = ComputeAndSavePsk(osAccountId, groupId, deviceEntry, pskKeyAlias);
    }
    DestroyDeviceEntry(deviceEntry);
    return ret;
}

static int32_t GetSharedSecretForP2pInPake(const CJson *in, const char *groupId, Uint8Buff *sharedSecret)
{
    int32_t osAccountId;
    if (GetIntFromJson(in, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
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
    Uint8Buff keyInfo = { (uint8_t *)TMP_AUTH_KEY_FACTOR, HcStrlen(TMP_AUTH_KEY_FACTOR) };
    KeyParams keyAliasParams = { { pskKeyAlias.val, pskKeyAlias.length, true }, false, osAccountId };
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

static int32_t GetSharedSecretForP2p(
    const CJson *in, const CJson *urlJson, ProtocolAlgType protocolType, Uint8Buff *sharedSecret)
{
    const char *groupId = GetStringFromJson(urlJson, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId!");
        return HC_ERR_JSON_GET;
    }
    int32_t ret;
    if (protocolType == ALG_ISO) {
        ret = GetSharedSecretForP2pInIso(in, groupId, sharedSecret);
        LOGI("get shared secret for p2p in iso result: %" LOG_PUB "d", ret);
    } else {
        ret = GetSharedSecretForP2pInPake(in, groupId, sharedSecret);
        LOGI("get shared secret for p2p in pake result: %" LOG_PUB "d", ret);
    }
    return ret;
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

    int32_t ret;
    switch (trustType) {
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

static int32_t GetCredInfoByPeerCert(const CJson *in, const CertInfo *certInfo, IdentityInfo **returnInfo)
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
    const char *peerUserId = GetStringFromJson(in, FIELD_PEER_USER_ID);
    if (peerUserId != NULL) {
        LOGE("peerUserId exists.");
    }
    return GetAccountAsymSharedSecret(osAccountId, peerUserId, FIELD_PEER_USER_ID, peerCertInfo, sharedSecret);
}

static const AuthIdentity g_authIdentity = {
    .getCredInfosByPeerIdentity = GetCredInfosByPeerIdentity,
    .getCredInfoByPeerUrl = GetCredInfoByPeerUrl,
    .getSharedSecretByUrl = GetSharedSecretByUrl,
    .getCredInfoByPeerCert = GetCredInfoByPeerCert,
    .getSharedSecretByPeerCert = GetSharedSecretByPeerCert,
};

const AuthIdentity *GetGroupAuthIdentity(void)
{
    return &g_authIdentity;
}