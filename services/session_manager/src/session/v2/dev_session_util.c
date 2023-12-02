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

#include "dev_session_util.h"

#include "alg_loader.h"
#include "hc_log.h"
#include "pseudonym_manager.h"

#define AUTH_ID_LEN 32
#define FIELD_AUTH_ID_CLIENT "authIdC"
#define FIELD_AUTH_ID_SERVER "authIdS"

static TrustedDeviceEntry *GetPeerDeviceEntryByContext(int32_t osAccountId, const CJson *context)
{
    const char *groupId = GetStringFromJson(context, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId!");
        return NULL;
    }
    bool isUdid = false;
    const char *peerDeviceId = GetStringFromJson(context, FIELD_PEER_UDID);
    if (peerDeviceId != NULL) {
        isUdid = true;
    } else {
        LOGW("peer udid not found, try to get peer authId!");
        peerDeviceId = GetStringFromJson(context, FIELD_PEER_AUTH_ID);
        if (peerDeviceId == NULL) {
            LOGE("Failed to get peer authId!");
            return NULL;
        }
    }
    return GetDeviceEntryById(osAccountId, peerDeviceId, isUdid, groupId);
}

static int32_t GetPdidByContext(const CJson *context, char **returnPdid)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    TrustedDeviceEntry *deviceEntry = GetPeerDeviceEntryByContext(osAccountId, context);
    if (deviceEntry == NULL) {
        LOGE("Failed to get device entry!");
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    const char *userId = StringGet(&deviceEntry->userId);
    if (userId == NULL) {
        LOGE("userId is null!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_NULL_PTR;
    }
    PseudonymManager *manager = GetPseudonymInstance();
    if (manager == NULL) {
        LOGE("Pseudonym manager is null!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_NULL_PTR;
    }
    char *pdid = NULL;
    int32_t res = manager->getPseudonymId(osAccountId, userId, &pdid);
    DestroyDeviceEntry(deviceEntry);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get pdid!");
        return res;
    }
    if (DeepCopyString(pdid, returnPdid) != HC_SUCCESS) {
        LOGE("Failed to copy pdid!");
        HcFree(pdid);
        return HC_ERR_ALLOC_MEMORY;
    }
    HcFree(pdid);
    return HC_SUCCESS;
}

static int32_t BuildRealPkInfoJson(const CJson *pkInfoJson, const CJson *peerInfoJson, CJson *realPkInfoJson)
{
    const char *devicePk = GetStringFromJson(pkInfoJson, FIELD_DEVICE_PK);
    if (devicePk == NULL) {
        LOGE("Failed to get devicePk!");
        return HC_ERR_JSON_GET;
    }
    const char *version = GetStringFromJson(pkInfoJson, FIELD_VERSION);
    if (version == NULL) {
        LOGE("Failed to get version!");
        return HC_ERR_JSON_GET;
    }
    const char *userId = GetStringFromJson(peerInfoJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId!");
        return HC_ERR_JSON_GET;
    }
    const char *deviceId = GetStringFromJson(peerInfoJson, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(realPkInfoJson, FIELD_DEVICE_PK, devicePk) != HC_SUCCESS) {
        LOGE("Failed to add devicePk!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(realPkInfoJson, FIELD_USER_ID, userId) != HC_SUCCESS) {
        LOGE("Failed to add userId!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(realPkInfoJson, FIELD_DEVICE_ID, deviceId) != HC_SUCCESS) {
        LOGE("Failed to add deviceId!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(realPkInfoJson, FIELD_VERSION, version) != HC_SUCCESS) {
        LOGE("Failed to add version!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GetRealPkInfoJson(int32_t osAccountId, CJson *pkInfoJson, CJson **realPkInfoJson)
{
    const char *pdid = GetStringFromJson(pkInfoJson, FIELD_PSEUDONYM_ID);
    if (pdid == NULL) {
        LOGE("Failed to get pdid!");
        return HC_ERR_JSON_GET;
    }
    PseudonymManager *manager = GetPseudonymInstance();
    if (manager == NULL) {
        LOGE("Pseudonym manager is null!");
        return HC_ERR_NULL_PTR;
    }
    char *peerInfo = NULL;
    int32_t res = manager->getRealInfo(osAccountId, pdid, &peerInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get peerInfo!");
        return res;
    }
    CJson *peerInfoJson = CreateJsonFromString(peerInfo);
    HcFree(peerInfo);
    if (peerInfoJson == NULL) {
        LOGE("Failed to create peerInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    *realPkInfoJson = CreateJson();
    if (*realPkInfoJson == NULL) {
        LOGE("Failed to create real pkInfo json!");
        FreeJson(peerInfoJson);
        return HC_ERR_JSON_CREATE;
    }
    res = BuildRealPkInfoJson(pkInfoJson, peerInfoJson, *realPkInfoJson);
    FreeJson(peerInfoJson);
    if (res != HC_SUCCESS) {
        LOGE("Failed to build real pkInfo json!");
        FreeJson(*realPkInfoJson);
        *realPkInfoJson = NULL;
    }
    return res;
}

static int32_t GeneratePeerInfoJson(const CJson *pkInfoJson, CJson **peerInfoJson)
{
    const char *userId = GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId!");
        return HC_ERR_JSON_GET;
    }
    const char *devId = GetStringFromJson(pkInfoJson, FIELD_DEVICE_ID);
    if (devId == NULL) {
        LOGE("Failed to get devId!");
        return HC_ERR_JSON_GET;
    }
    *peerInfoJson = CreateJson();
    if (*peerInfoJson == NULL) {
        LOGE("Failed to create peerInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    if (AddStringToJson(*peerInfoJson, FIELD_USER_ID, userId) != HC_SUCCESS) {
        LOGE("Failed to add userId!");
        FreeJson(*peerInfoJson);
        *peerInfoJson = NULL;
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(*peerInfoJson, FIELD_DEVICE_ID, devId) != HC_SUCCESS) {
        LOGE("Failed to add devId!");
        FreeJson(*peerInfoJson);
        *peerInfoJson = NULL;
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static bool IsPeerPseudonym(const CJson *inputData)
{
    const char *pkInfoStr = GetStringFromJson(inputData, FIELD_PK_INFO);
    if (pkInfoStr == NULL) {
        LOGE("Failed to get peer pkInfo!");
        return false;
    }
    CJson *pkInfoJson = CreateJsonFromString(pkInfoStr);
    if (pkInfoJson == NULL) {
        LOGE("Failed to create pkInfo json!");
        return false;
    }
    bool res = GetStringFromJson(pkInfoJson, FIELD_PSEUDONYM_ID) != NULL;
    FreeJson(pkInfoJson);
    return res;
}

static int32_t SetPeerAuthIdByDb(CJson *context, const char *groupId)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *peerUdid = GetStringFromJson(context, FIELD_PEER_UDID);
    if (peerUdid == NULL) {
        LOGE("Failed to get peer udid!");
        return HC_ERR_JSON_GET;
    }
    TrustedDeviceEntry *entry = GetDeviceEntryById(osAccountId, peerUdid, true, groupId);
    if (entry == NULL) {
        LOGE("Failed to get device entry!");
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    const char *peerAuthId = StringGet(&entry->authId);
    if (AddStringToJson(context, FIELD_PEER_AUTH_ID, peerAuthId) != HC_SUCCESS) {
        LOGE("Failed to add peer authId to context!");
        DestroyDeviceEntry(entry);
        return HC_ERR_JSON_ADD;
    }
    DestroyDeviceEntry(entry);
    return HC_SUCCESS;
}

int32_t FillPeerAuthIdIfNeeded(bool isClient, const CJson *context, CJson *inputData)
{
    const char *peerAuthId = GetStringFromJson(context, FIELD_PEER_AUTH_ID);
    if (peerAuthId == NULL) {
        LOGI("no peer authId in context, no need to fill!");
        return HC_SUCCESS;
    }
    CJson *authData = GetObjFromJson(inputData, FIELD_AUTH_DATA);
    if (authData == NULL) {
        LOGE("Failed to get authData!");
        return HC_ERR_JSON_GET;
    }
    Uint8Buff authIdBuff = { (uint8_t *)peerAuthId, HcStrlen(peerAuthId) + 1 };
    if (isClient && GetStringFromJson(authData, FIELD_AUTH_ID_SERVER) != NULL) {
        if (AddByteToJson(authData, FIELD_AUTH_ID_SERVER, authIdBuff.val, authIdBuff.length) != HC_SUCCESS) {
            LOGE("Failed to fill server authId!");
            return HC_ERR_JSON_ADD;
        }
        return HC_SUCCESS;
    }
    if (!isClient && GetStringFromJson(authData, FIELD_AUTH_ID_CLIENT) != NULL) {
        if (AddByteToJson(authData, FIELD_AUTH_ID_CLIENT, authIdBuff.val, authIdBuff.length) != HC_SUCCESS) {
            LOGE("Failed to fill client authId!");
            return HC_ERR_JSON_ADD;
        }
        return HC_SUCCESS;
    }
    return HC_SUCCESS;
}

bool IsP2pAuth(const IdentityInfo *info)
{
    if (info->proofType == CERTIFICATED) {
        return false;
    }
    CJson *urlJson = CreateJsonFromString((const char *)info->proof.preSharedUrl.val);
    if (urlJson == NULL) {
        LOGE("Failed to create urlJson!");
        return false;
    }
    int32_t trustType = 0;
    if (GetIntFromJson(urlJson, PRESHARED_URL_TRUST_TYPE, &trustType) != HC_SUCCESS) {
        LOGE("Failed to get trust type!");
        FreeJson(urlJson);
        return false;
    }
    FreeJson(urlJson);
    return trustType == TRUST_TYPE_P2P;
}

int32_t SetPeerAuthIdToContextIfNeeded(CJson *context, const IdentityInfo *info)
{
    if (!IsP2pAuth(info)) {
        LOGI("Not p2p auth, no need to set peer authId!");
        return HC_SUCCESS;
    }
    /* auth with credentials directly no need set peer auth id here */
    bool isDirectAuth = false;
    (void)GetBoolFromJson(context, FIELD_IS_DIRECT_AUTH, &isDirectAuth);
    if (isDirectAuth) {
        return HC_SUCCESS;
    }
    CJson *urlJson = CreateJsonFromString((const char *)info->proof.preSharedUrl.val);
    if (urlJson == NULL) {
        LOGE("Failed to create urlJson!");
        return HC_ERR_JSON_CREATE;
    }
    const char *groupId = GetStringFromJson(urlJson, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId!");
        FreeJson(urlJson);
        return HC_ERR_JSON_GET;
    }
    int32_t res = SetPeerAuthIdByDb(context, groupId);
    FreeJson(urlJson);
    return res;
}

int32_t SetPeerInfoToContext(CJson *context, const CJson *inputData)
{
    if (IsPeerPseudonym(inputData)) {
        LOGI("Peer is pseudonym, no need to set peerInfo!");
        return HC_SUCCESS;
    }
    const char *pkInfoStr = GetStringFromJson(inputData, FIELD_PK_INFO);
    if (pkInfoStr == NULL) {
        LOGE("Failed to get peer pkInfo!");
        return HC_ERR_JSON_GET;
    }
    CJson *pkInfoJson = CreateJsonFromString(pkInfoStr);
    if (pkInfoJson == NULL) {
        LOGE("Failed to create pkInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    const char *userId = GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId!");
        FreeJson(pkInfoJson);
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_INDEX_KEY, userId) != HC_SUCCESS) {
        LOGE("Failed to add pdidIndex!");
        FreeJson(pkInfoJson);
        return HC_ERR_JSON_ADD;
    }
    CJson *peerInfoJson = NULL;
    int32_t res = GeneratePeerInfoJson(pkInfoJson, &peerInfoJson);
    FreeJson(pkInfoJson);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate peerInfo json!");
        return res;
    }
    char *peerInfoStr = PackJsonToString(peerInfoJson);
    FreeJson(peerInfoJson);
    if (peerInfoStr == NULL) {
        LOGE("Failed to convert peerInfo from json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    if (AddStringToJson(context, FIELD_REAL_INFO, peerInfoStr) != HC_SUCCESS) {
        LOGE("Failed to add peerInfo to context!");
        FreeJsonString(peerInfoStr);
        return HC_ERR_JSON_ADD;
    }
    FreeJsonString(peerInfoStr);
    return HC_SUCCESS;
}

int32_t ReplaceAuthIdWithRandom(CJson *authData)
{
    uint8_t authId[AUTH_ID_LEN] = { 0 };
    Uint8Buff authIdBuff = { authId, AUTH_ID_LEN };
    int32_t res = GetLoaderInstance()->generateRandom(&authIdBuff);
    if (res != HC_SUCCESS) {
        LOGI("Failed to generate random authId!");
        return res;
    }
    if (GetStringFromJson(authData, FIELD_AUTH_ID_CLIENT) != NULL &&
        AddByteToJson(authData, FIELD_AUTH_ID_CLIENT, authIdBuff.val, authIdBuff.length) != HC_SUCCESS) {
        LOGE("Failed to replace client authId with random!");
        return HC_ERR_JSON_ADD;
    }
    if (GetStringFromJson(authData, FIELD_AUTH_ID_SERVER) != NULL &&
        AddByteToJson(authData, FIELD_AUTH_ID_SERVER, authIdBuff.val, authIdBuff.length) != HC_SUCCESS) {
        LOGE("Failed to replace server authId with random!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

int32_t CheckPeerPkInfoForPdid(const CJson *context, const CJson *inputData)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *pkInfo = GetStringFromJson(inputData, FIELD_PK_INFO);
    if (pkInfo == NULL) {
        LOGE("Failed to get pkInfo!");
        return HC_ERR_JSON_GET;
    }
    CJson *pkInfoJson = CreateJsonFromString(pkInfo);
    if (pkInfoJson == NULL) {
        LOGE("Failed to create pkInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    const char *pdid = GetStringFromJson(pkInfoJson, FIELD_PSEUDONYM_ID);
    if (pdid == NULL) {
        LOGI("No pdid in peer pkInfo, check success!");
        FreeJson(pkInfoJson);
        return HC_SUCCESS;
    }
    PseudonymManager *manager = GetPseudonymInstance();
    if (manager == NULL) {
        LOGE("Pseudonym manager is null!");
        FreeJson(pkInfoJson);
        return HC_ERR_NULL_PTR;
    }
    char *peerInfo = NULL;
    int32_t res = manager->getRealInfo(osAccountId, pdid, &peerInfo);
    FreeJson(pkInfoJson);
    if (res != HC_SUCCESS) {
        LOGE("Can not get peerInfo with pdid, check fail!");
        return res;
    }
    HcFree(peerInfo);
    return HC_SUCCESS;
}

int32_t GetRealPkInfoStr(int32_t osAccountId, const CJson *credInfo, char **returnPkInfoStr, bool *isPseudonym)
{
    const char *pkInfoStr = GetStringFromJson(credInfo, FIELD_PK_INFO);
    if (pkInfoStr == NULL) {
        LOGE("Failed to get pkInfo!");
        return HC_ERR_JSON_GET;
    }
    CJson *pkInfoJson = CreateJsonFromString(pkInfoStr);
    if (pkInfoJson == NULL) {
        LOGE("Failed to create pkInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    CJson *realPkInfoJson = NULL;
    int32_t res = GetRealPkInfoJson(osAccountId, pkInfoJson, &realPkInfoJson);
    FreeJson(pkInfoJson);
    if (res != HC_SUCCESS) {
        LOGW("Failed to get real pkInfo json!");
        if (DeepCopyString(pkInfoStr, returnPkInfoStr) != HC_SUCCESS) {
            LOGE("Failed to copy pkInfoStr!");
            return HC_ERR_ALLOC_MEMORY;
        }
        *isPseudonym = false;
        return HC_SUCCESS;
    } else {
        LOGI("Get real pkInfo json successfully!");
        char *realPkInfoStr = PackJsonToString(realPkInfoJson);
        FreeJson(realPkInfoJson);
        if (realPkInfoStr == NULL) {
            LOGE("Failed to convert pkInfo from json to string!");
            return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
        }
        res = DeepCopyString(realPkInfoStr, returnPkInfoStr);
        FreeJsonString(realPkInfoStr);
        if (res != HC_SUCCESS) {
            LOGE("Failed to copy realPkInfoStr!");
            return HC_ERR_ALLOC_MEMORY;
        }
        *isPseudonym = true;
        return HC_SUCCESS;
    }
}

int32_t AddPkInfoWithPdid(const CJson *context, CJson *credInfo, const char *realPkInfoStr)
{
    if (context == NULL || credInfo == NULL || realPkInfoStr == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    char *pdid = NULL;
    int32_t res = GetPdidByContext(context, &pdid);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get pdid by context!");
        return res;
    }
    CJson *pkInfoJson = CreateJsonFromString(realPkInfoStr);
    if (pkInfoJson == NULL) {
        LOGE("Failed to create pkInfo json!");
        HcFree(pdid);
        return HC_ERR_JSON_CREATE;
    }
    DeleteItemFromJson(pkInfoJson, FIELD_USER_ID);
    DeleteItemFromJson(pkInfoJson, FIELD_DEVICE_ID);
    if (AddStringToJson(pkInfoJson, FIELD_PSEUDONYM_ID, pdid) != HC_SUCCESS) {
        LOGE("Failed to add pdid to pkInfo!");
        HcFree(pdid);
        FreeJson(pkInfoJson);
        return HC_ERR_JSON_ADD;
    }
    HcFree(pdid);
    char *pkInfoWithPdid = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    if (pkInfoWithPdid == NULL) {
        LOGE("Failed to convert pkInfo from json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    if (AddStringToJson(credInfo, FIELD_PK_INFO, pkInfoWithPdid) != HC_SUCCESS) {
        LOGE("Failed to add pkInfo with pdid!");
        FreeJsonString(pkInfoWithPdid);
        return HC_ERR_JSON_ADD;
    }
    FreeJsonString(pkInfoWithPdid);
    return HC_SUCCESS;
}

TrustedDeviceEntry *GetDeviceEntryById(int32_t osAccountId, const char *deviceId, bool isUdid,
    const char *groupId)
{
    DeviceEntryVec deviceEntryVec = CreateDeviceEntryVec();
    QueryDeviceParams params = InitQueryDeviceParams();
    params.groupId = groupId;
    if (isUdid) {
        params.udid = deviceId;
    } else {
        params.authId = deviceId;
    }
    if (QueryDevices(osAccountId, &params, &deviceEntryVec) != HC_SUCCESS) {
        LOGE("Failed to query trusted devices!");
        ClearDeviceEntryVec(&deviceEntryVec);
        return NULL;
    }
    uint32_t index;
    TrustedDeviceEntry **deviceEntry;
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, deviceEntry) {
        TrustedDeviceEntry *returnEntry = DeepCopyDeviceEntry(*deviceEntry);
        ClearDeviceEntryVec(&deviceEntryVec);
        return returnEntry;
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return NULL;
}