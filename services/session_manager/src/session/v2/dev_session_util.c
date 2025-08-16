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

#include <time.h>
#include "alg_loader.h"
#include "hc_log.h"
#include "pseudonym_manager.h"

#include "dev_session_def.h"
#include "string_util.h"

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

static int32_t GetPdidIndexByGroup(const CJson *context, int32_t osAccountId, char **returnPdidIndex)
{
    TrustedDeviceEntry *deviceEntry = GetPeerDeviceEntryByContext(osAccountId, context);
    if (deviceEntry == NULL) {
        LOGE("Failed to get device entry!");
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    const char *pdidIndex = StringGet(&deviceEntry->userId);
    if (pdidIndex == NULL) {
        LOGE("pdidIndex is null!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_NULL_PTR;
    }
    if (DeepCopyString(pdidIndex, returnPdidIndex) != HC_SUCCESS) {
        LOGE("Failed to copy pdidIndex!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_ALLOC_MEMORY;
    }
    DestroyDeviceEntry(deviceEntry);
    return HC_SUCCESS;
}

static int32_t GetPdidIndexByISInfo(const CJson *context, char **returnPdidIndex)
{
    const char *pdidIndex = GetStringFromJson(context, FIELD_CRED_ID);
    if (pdidIndex == NULL) {
        LOGE("Failed to get cred ID!");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyString(pdidIndex, returnPdidIndex) != HC_SUCCESS) {
        LOGE("Failed to copy pdidIndex!");
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t GetPdidByContext(const CJson *context, bool isCredAuth, char **returnPdid)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    char *pdidIndex = NULL;
    int32_t res = isCredAuth? GetPdidIndexByISInfo(context, &pdidIndex)
        : GetPdidIndexByGroup(context, osAccountId, &pdidIndex);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get pdidIndex!");
        return res;
    }
    PseudonymManager *manager = GetPseudonymInstance();
    if (manager == NULL) {
        LOGE("Pseudonym manager is null!");
        HcFree(pdidIndex);
        return HC_ERR_NULL_PTR;
    }
    char *pdid = NULL;
    res = manager->getPseudonymId(osAccountId, pdidIndex, &pdid);
    HcFree(pdidIndex);
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

static int32_t SetPeerAuthIdByCredAuthInfo(CJson *context)
{
    CJson *credAuthInfo = GetObjFromJson(context, FIELD_CREDENTIAL_OBJ);
    if (credAuthInfo == NULL) {
        LOGE("Get self credAuthInfo fail.");
        return HC_ERR_JSON_GET;
    }
    const char *peerAuthId = GetStringFromJson(credAuthInfo, FIELD_DEVICE_ID);
    if (peerAuthId == NULL) {
        LOGE("Get peer authId fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_PEER_AUTH_ID, peerAuthId) != HC_SUCCESS) {
        LOGE("Failed to add peer authId to context!");
        return HC_ERR_JSON_ADD;
    }
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

int32_t SetPeerAuthIdToContextIfNeeded(CJson *context, bool isCredAuth, const IdentityInfo *info)
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
    if (isCredAuth) {
        return SetPeerAuthIdByCredAuthInfo(context);
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

int32_t SetPeerInfoToContext(CJson *context, bool isCredAuth, const CJson *inputData)
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
    const char *pdidIndex = isCredAuth ? GetStringFromJson(context, FIELD_CRED_ID)
        : GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (pdidIndex == NULL) {
        LOGE("Failed to get pdidIndex!");
        FreeJson(pkInfoJson);
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_INDEX_KEY, pdidIndex) != HC_SUCCESS) {
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

int32_t AddPkInfoWithPdid(const CJson *context, CJson *credInfo, bool isCredAuth,
    const char *realPkInfoStr)
{
    if (context == NULL || credInfo == NULL || realPkInfoStr == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    char *pdid = NULL;
    int32_t res = GetPdidByContext(context, isCredAuth, &pdid);
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

int32_t BuildPeerCertInfo(const char *pkInfoStr, const char *pkInfoSignHexStr, int32_t signAlg,
    CertInfo *peerCert)
{
    if ((pkInfoStr == NULL) || (pkInfoSignHexStr == NULL) || (peerCert == NULL)) {
        LOGE("The input contains null ptr!");
        return HC_ERR_NULL_PTR;
    }
    Uint8Buff pkInfoStrBuff = { (uint8_t *)pkInfoStr, HcStrlen(pkInfoStr) + 1 };
    uint32_t pkInfoSignatureLen = HcStrlen(pkInfoSignHexStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (DeepCopyUint8Buff(&pkInfoStrBuff, &peerCert->pkInfoStr) != HC_SUCCESS) {
        LOGE("copy pkInfoStr fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (InitUint8Buff(&peerCert->pkInfoSignature, pkInfoSignatureLen) != HC_SUCCESS) {
        LOGE("allocate pkInfoSignature memory fail.");
        ClearFreeUint8Buff(&peerCert->pkInfoStr);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (HexStringToByte(pkInfoSignHexStr, peerCert->pkInfoSignature.val,
        peerCert->pkInfoSignature.length) != HC_SUCCESS) {
        LOGE("get pkInfoSignature from json fail.");
        ClearFreeUint8Buff(&peerCert->pkInfoStr);
        ClearFreeUint8Buff(&peerCert->pkInfoSignature);
        return HC_ERR_JSON_ADD;
    }
    peerCert->signAlg = (Algorithm)signAlg;
    return HC_SUCCESS;
}

void DestroyCertInfo(CertInfo *certInfo)
{
    ClearFreeUint8Buff(&certInfo->pkInfoSignature);
    ClearFreeUint8Buff(&certInfo->pkInfoStr);
}

int32_t GetPeerCertInfo(CJson *context, const CJson *credInfo, CertInfo *peerCert)
{
    if ((context == NULL) || (credInfo == NULL) || (peerCert == NULL)) {
        LOGE("The input contains null ptr!");
        return HC_ERR_NULL_PTR;
    }
    int32_t osAccountId = 0;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    int32_t signAlg;
    if (GetIntFromJson(credInfo, FIELD_SIGN_ALG, &signAlg) != HC_SUCCESS) {
        LOGE("get signAlg from json fail.");
        return HC_ERR_JSON_GET;
    }
    char *pkInfoStr = NULL;
    int32_t res = GetRealPkInfoStr(osAccountId, credInfo, &pkInfoStr, &peerCert->isPseudonym);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get real pkInfo string!");
        return res;
    }
    const char *pkInfoSignHexStr = GetStringFromJson(credInfo, FIELD_PK_INFO_SIGNATURE);
    if (pkInfoSignHexStr == NULL) {
        LOGE("get pkInfoSignature from json fail.");
        HcFree(pkInfoStr);
        return HC_ERR_JSON_GET;
    }
    res = BuildPeerCertInfo(pkInfoStr, pkInfoSignHexStr, signAlg, peerCert);
    HcFree(pkInfoStr);
    return res;
}

static int32_t GetSaltMsg(Uint8Buff *saltMsg)
{
    uint8_t randomVal[DEV_SESSION_SALT_LEN] = { 0 };
    Uint8Buff random = { randomVal, DEV_SESSION_SALT_LEN };
    int32_t res = GetLoaderInstance()->generateRandom(&random);
    if (res != HC_SUCCESS) {
        LOGE("generate random failed, res: %" LOG_PUB "d", res);
        return res;
    }
    clock_t times = 0;
    if (memcpy_s(saltMsg->val, saltMsg->length, random.val, random.length) != EOK) {
        LOGE("memcpy random failed.");
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(saltMsg->val + random.length, saltMsg->length - random.length, &times, sizeof(clock_t)) != EOK) {
        LOGE("memcpy times failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t CalSalt(Uint8Buff *salt)
{
    if ((salt == NULL) || (salt->val == NULL)) {
        LOGE("The input contains null ptr!");
        return HC_ERR_NULL_PTR;
    }
    uint32_t saltMsgLen = DEV_SESSION_SALT_LEN + sizeof(clock_t);
    Uint8Buff saltMsg = { NULL, 0 };
    if (InitUint8Buff(&saltMsg, saltMsgLen) != HC_SUCCESS) {
        LOGE("allocate saltMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GetSaltMsg(&saltMsg);
    if (res != HC_SUCCESS) {
        FreeUint8Buff(&saltMsg);
        return res;
    }
    res = GetLoaderInstance()->sha256(&saltMsg, salt);
    FreeUint8Buff(&saltMsg);
    if (res != HC_SUCCESS) {
        LOGE("sha256 for session salt failed.");
        return res;
    }
    return HC_SUCCESS;
}

int32_t GetSelfUserId(int32_t osAccountId, char *userId, uint32_t userIdLen)
{
    if (userId == NULL) {
        LOGE("The input is null ptr!");
        return HC_ERR_NULL_PTR;
    }
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
                LOGE("copy fail");
                ClearGroupEntryVec(&accountVec);
                return HC_ERROR;
            }
            index++;
        }
    } while (0);
    ClearGroupEntryVec(&accountVec);
    return HC_SUCCESS;
}

int32_t AddMsgToSessionMsg(int32_t eventType, const CJson *msg, CJson *sessionMsg)
{
    if ((msg == NULL) || (sessionMsg == NULL)) {
        LOGE("The input contains null ptr!");
        return HC_ERR_NULL_PTR;
    }
    CJson *event = CreateJson();
    if (event == NULL) {
        LOGE("allocate event memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddIntToJson(event, FIELD_TYPE, eventType) != HC_SUCCESS) {
        LOGE("add eventType to event fail.");
        FreeJson(event);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToJson(event, FIELD_DATA, msg) != HC_SUCCESS) {
        LOGE("add msg to event fail.");
        FreeJson(event);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToArray(sessionMsg, event) != HC_SUCCESS) {
        LOGE("add event to sessionMsg fail.");
        FreeJson(event);
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

bool IsPeerSameUserId(int32_t osAccountId, const char *peerUserId)
{
    if (peerUserId == NULL) {
        LOGE("The input is null ptr!");
        return false;
    }
    GroupEntryVec groupVec = CreateGroupEntryVec();
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupType = IDENTICAL_ACCOUNT_GROUP;
    if (QueryGroups(osAccountId, &queryParams, &groupVec) != HC_SUCCESS || groupVec.size(&groupVec) <= 0) {
        LOGE("get identical account group from db fail.");
        ClearGroupEntryVec(&groupVec);
        return false;
    }
    TrustedGroupEntry *groupEntry = groupVec.get(&groupVec, 0);
    bool isSame = (HcStrcmp(StringGet(&(groupEntry->userId)), peerUserId) == 0);
    ClearGroupEntryVec(&groupVec);
    return isSame;
}