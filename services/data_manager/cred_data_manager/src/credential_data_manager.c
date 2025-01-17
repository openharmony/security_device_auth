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

#include "credential_data_manager.h"

#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"
#include "securec.h"
#include "hidump_adapter.h"
#include "os_account_adapter.h"
#include "security_label_adapter.h"
#include "account_task_manager.h"
#include "cred_listener.h"

typedef struct {
    DECLARE_TLV_STRUCT(17)
    TlvString credId;
    TlvString deviceId;
    TlvString peerUserSpaceId;
    TlvUint8 subject;
    TlvString userId;
    TlvUint8 issuer;
    TlvUint8 credType;
    TlvUint8 keyFormat;
    TlvUint8 algorithmType;
    TlvUint8 proofType;
    TlvBuffer authorizedAccountList;
    TlvBuffer authorizedAppList;
    TlvBuffer authorizedDeviceList;
    TlvUint8 authorizedScope;
    TlvString credOwner;
    TlvInt32 ownerUid;
    TlvString extendInfo;
} TlvCredentialElement;
DECLEAR_INIT_FUNC(TlvCredentialElement)
DECLARE_TLV_VECTOR(TlvCredentialVec, TlvCredentialElement)

typedef struct {
    DECLARE_TLV_STRUCT(2)
    TlvInt32 version;
    TlvCredentialVec credentials;
} HCCredDataBaseV1;
DECLEAR_INIT_FUNC(HCCredDataBaseV1)

BEGIN_TLV_STRUCT_DEFINE(TlvCredentialElement, 0x0001)
    TLV_MEMBER(TlvString, credId, 0x4001)
    TLV_MEMBER(TlvString, deviceId, 0x4002)
    TLV_MEMBER(TlvString, peerUserSpaceId, 0x4003)
    TLV_MEMBER(TlvUint8, subject, 0x4004)
    TLV_MEMBER(TlvString, userId, 0x4005)
    TLV_MEMBER(TlvUint8, issuer, 0x4006)
    TLV_MEMBER(TlvUint8, credType, 0x4007)
    TLV_MEMBER(TlvUint8, keyFormat, 0x4008)
    TLV_MEMBER(TlvUint8, algorithmType, 0x4009)
    TLV_MEMBER(TlvUint8, proofType, 0x400A)
    TLV_MEMBER(TlvBuffer, authorizedAccountList, 0x400B)
    TLV_MEMBER(TlvBuffer, authorizedAppList, 0x400C)
    TLV_MEMBER(TlvBuffer, authorizedDeviceList, 0x400D)
    TLV_MEMBER(TlvUint8, authorizedScope, 0x400E)
    TLV_MEMBER(TlvString, credOwner, 0x400F)
    TLV_MEMBER(TlvInt32, ownerUid, 0x4010)
    TLV_MEMBER(TlvString, extendInfo, 0x4011)
END_TLV_STRUCT_DEFINE()
IMPLEMENT_TLV_VECTOR(TlvCredentialVec, TlvCredentialElement, 1)

BEGIN_TLV_STRUCT_DEFINE(HCCredDataBaseV1, 0x0001)
    TLV_MEMBER(TlvInt32, version, 0x6001)
    TLV_MEMBER(TlvCredentialVec, credentials, 0x6002)
END_TLV_STRUCT_DEFINE()

IMPLEMENT_HC_VECTOR(CredentialVec, Credential*, 1)

typedef struct {
    int32_t osAccountId;
    CredentialVec credentials;
} OsAccountCredInfo;

DECLARE_HC_VECTOR(DevAuthCredDb, OsAccountCredInfo)
IMPLEMENT_HC_VECTOR(DevAuthCredDb, OsAccountCredInfo, 1)

#define MAX_DB_PATH_LEN 256

static HcMutex *g_credMutex = NULL;
static DevAuthCredDb g_devauthCredDb;
const uint8_t DEFAULT_CRED_PARAM_VAL = 0;

static bool EndWithZero(HcParcel *parcel)
{
    const char *p = GetParcelLastChar(parcel);
    if (p == NULL) {
        return false;
    }
    return (*p == '\0');
}

static bool LoadStringVectorFromParcel(StringVector *vec, HcParcel *parcel)
{
    uint32_t strLen = 0;
    do {
        if (!ParcelReadUint32(parcel, &strLen)) {
            return true;
        }
        if ((strLen == 0) || (strLen > MAX_STRING_LEN)) {
            return false;
        }
        HcString str = CreateString();
        ClearParcel(&str.parcel);
        if (!ParcelReadParcel(parcel, &str.parcel, strLen, false) ||
            !EndWithZero(&str.parcel)) {
            DeleteString(&str);
            return false;
        } else {
            if (vec->pushBack(vec, &str) == NULL) {
                DeleteString(&str);
                return false;
            }
        }
    } while (1);
}

static bool SaveStringVectorToParcel(const StringVector *vec, HcParcel *parcel)
{
    uint32_t index;
    HcString *str = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, str) {
        uint32_t len = StringLength(str) + sizeof(char);
        if (!ParcelWriteUint32(parcel, len)) {
            return false;
        }
        if (!ParcelWrite(parcel, GetParcelData(&str->parcel), GetParcelDataSize(&str->parcel))) {
            return false;
        }
    }
    return true;
}

static bool GetOsAccountCredInfoPathCe(int32_t osAccountId, char *infoPath, uint32_t pathBufferLen)
{
    const char *beginPath = GetStorageDirPathCe();
    if (beginPath == NULL) {
        LOGE("[CRED#DB]: Failed to get the storage path!");
        return false;
    }
    if (sprintf_s(infoPath, pathBufferLen, "%s/%d/deviceauth/hccredential.dat", beginPath, osAccountId) <= 0) {
        LOGE("[CRED#DB]: Failed to generate db file path!");
        return false;
    }
    return true;
}

static bool GetOsAccountCredInfoPathDe(int32_t osAccountId, char *infoPath, uint32_t pathBufferLen)
{
    const char *beginPath = GetStorageDirPath();
    if (beginPath == NULL) {
        LOGE("[CRED#DB]: Failed to get the storage path dir!");
        return false;
    }
    int32_t writeByteNum;
    if (osAccountId == DEFAULT_OS_ACCOUNT) {
        writeByteNum = sprintf_s(infoPath, pathBufferLen, "%s/hccredential.dat", beginPath);
    } else {
        writeByteNum = sprintf_s(infoPath, pathBufferLen, "%s/hccredential%d.dat", beginPath, osAccountId);
    }
    if (writeByteNum <= 0) {
        LOGE("[CRED#DB]: sprintf_s fail!");
        return false;
    }
    return true;
}

static bool GetOsAccountCredInfoPath(int32_t osAccountId, char *infoPath, uint32_t pathBufferLen)
{
    if (IsOsAccountSupported())  {
        return GetOsAccountCredInfoPathCe(osAccountId, infoPath, pathBufferLen);
    } else {
        return GetOsAccountCredInfoPathDe(osAccountId, infoPath, pathBufferLen);
    }
}

static bool GenerateAuthorizedAccountList(const Credential *entry, Credential *returnEntry)
{
    uint32_t index = 0;
    HcString *authorizedAccount = NULL;
    FOR_EACH_HC_VECTOR(entry->authorizedAccountList, index, authorizedAccount) {
        if (authorizedAccount == NULL) {
            continue;
        }
        HcString returnAuthorizedAccount = CreateString();
        if (!StringSet(&returnAuthorizedAccount, *authorizedAccount)) {
            DeleteString(&returnAuthorizedAccount);
            LOGE("[CRED#DB]: Failed to copy authorizedAccount!");
            return false;
        }
        if (returnEntry->authorizedAccountList.pushBack(&returnEntry->authorizedAccountList, &returnAuthorizedAccount)
            == NULL) {
            LOGE("[CRED#DB]: Failed to push authorizedAccount to list!");
            DeleteString(&returnAuthorizedAccount);
            return false;
        }
    }
    return true;
}

bool GenerateCredFromCred(const Credential *entry, Credential *returnEntry)
{
    if (!StringSet(&returnEntry->credId, entry->credId)) {
        LOGE("[CRED#DB]: Failed to copy credId!");
        return false;
    }
    if (!StringSet(&returnEntry->deviceId, entry->deviceId)) {
        LOGE("[CRED#DB]: Failed to copy deviceId!");
        return false;
    }
    if (!StringSet(&returnEntry->peerUserSpaceId, entry->peerUserSpaceId)) {
        LOGE("[CRED#DB]: Failed to copy peerUserSpaceId!");
        return false;
    }
    if (!StringSet(&returnEntry->userId, entry->userId)) {
        LOGE("[CRED#DB]: Failed to copy userId!");
        return false;
    }
    if (!StringSet(&returnEntry->credOwner, entry->credOwner)) {
        LOGE("[CRED#DB]: Failed to copy credOwner!");
        return false;
    }
    if (!GenerateAuthorizedAccountList(entry, returnEntry)) {
        return false;
    }
    if (!StringSet(&returnEntry->extendInfo, entry->extendInfo)) {
        LOGE("[CRED#DB]: Failed to copy extendInfo!");
        return false;
    }
    returnEntry->subject = entry->subject;
    returnEntry->authorizedScope = entry->authorizedScope;
    returnEntry->credType = entry->credType;
    returnEntry->issuer = entry->issuer;
    returnEntry->keyFormat = entry->keyFormat;
    returnEntry->algorithmType = entry->algorithmType;
    returnEntry->proofType = entry->proofType;
    returnEntry->ownerUid = entry->ownerUid;
    return true;
}

static bool GenerateCredentialFromTlv(TlvCredentialElement *credential, Credential *entry)
{
    if (!StringSet(&entry->credId, credential->credId.data)) {
        LOGE("[CRED#DB]: Failed to load credId from tlv!");
        return false;
    }
    if (!StringSet(&entry->deviceId, credential->deviceId.data)) {
        LOGE("[CRED#DB]: Failed to load deviceId from tlv!");
        return false;
    }
    if (!StringSet(&entry->peerUserSpaceId, credential->peerUserSpaceId.data)) {
        LOGE("[CRED#DB]: Failed to load peerUserSpaceId from tlv!");
        return false;
    }
    if (!StringSet(&entry->userId, credential->userId.data)) {
        LOGE("[CRED#DB]: Failed to load userId from tlv!");
        return false;
    }
    if (!StringSet(&entry->credOwner, credential->credOwner.data)) {
        LOGE("[CRED#DB]: Failed to load credOwner from tlv!");
        return false;
    }
    if (!LoadStringVectorFromParcel(&entry->authorizedAccountList, &credential->authorizedAccountList.data)) {
        LOGE("[CRED#DB]: Failed to load authorizedAccountList from tlv!");
        return false;
    }
    if (!StringSet(&entry->extendInfo, credential->extendInfo.data)) {
        LOGE("[CRED#DB]: Failed to load extendInfo from tlv!");
        return false;
    }
    entry->subject = credential->subject.data;
    entry->authorizedScope = credential->authorizedScope.data;
    entry->issuer = credential->issuer.data;
    entry->credType = credential->credType.data;
    entry->keyFormat = credential->keyFormat.data;
    entry->algorithmType = credential->algorithmType.data;
    entry->proofType = credential->proofType.data;
    entry->ownerUid = credential->ownerUid.data;
    return true;
}

static bool LoadCredentials(HCCredDataBaseV1 *db, CredentialVec *vec)
{
    uint32_t index;
    TlvCredentialElement *credentialTlv = NULL;
    FOR_EACH_HC_VECTOR(db->credentials.data, index, credentialTlv) {
        if (credentialTlv == NULL) {
            continue;
        }
        Credential *entry = CreateCredential();
        if (entry == NULL) {
            LOGE("[CRED#DB]: Failed to allocate entry memory!");
            ClearCredentialVec(vec);
            return false;
        }
        if (!GenerateCredentialFromTlv(credentialTlv, entry)) {
            DestroyCredential(entry);
            ClearCredentialVec(vec);
            return false;
        }
        if (vec->pushBackT(vec, entry) == NULL) {
            LOGE("[CRED#DB]: Failed to push entry to vec!");
            DestroyCredential(entry);
            ClearCredentialVec(vec);
            return false;
        }
    }
    return true;
}

static bool ReadCredInfoFromParcel(HcParcel *parcel, OsAccountCredInfo *info)
{
    bool ret = false;
    HCCredDataBaseV1 dbv1;
    TLV_INIT(HCCredDataBaseV1, &dbv1)
    if (DecodeTlvMessage((TlvBase *)&dbv1, parcel, false)) {
        if (!LoadCredentials(&dbv1, &info->credentials)) {
            TLV_DEINIT(dbv1)
            return false;
        }
        ret = true;
    } else {
        LOGE("[CRED#DB]: Decode Tlv Message Failed!");
    }
    TLV_DEINIT(dbv1)
    return ret;
}

static bool ReadParcelFromFile(const char *filePath, HcParcel *parcel)
{
    FileHandle file;
    int ret = HcFileOpen(filePath, MODE_FILE_READ, &file);
    if (ret != 0) {
        LOGE("[CRED#DB]: Failed to open database file!");
        return false;
    }
    SetSecurityLabel(filePath, SECURITY_LABEL_S2);
    int fileSize = HcFileSize(file);
    if (fileSize <= 0) {
        LOGE("[CRED#DB]: The database file size is invalid!");
        HcFileClose(file);
        return false;
    }
    char *fileData = (char *)HcMalloc(fileSize, 0);
    if (fileData == NULL) {
        LOGE("[CRED#DB]: Failed to allocate fileData memory!");
        HcFileClose(file);
        return false;
    }
    if (HcFileRead(file, fileData, fileSize) != fileSize) {
        LOGE("[CRED#DB]: Read file error!");
        HcFileClose(file);
        HcFree(fileData);
        return false;
    }
    HcFileClose(file);
    if (!ParcelWrite(parcel, fileData, fileSize)) {
        LOGE("[CRED#DB]: parcel write error!");
        HcFree(fileData);
        return false;
    }
    HcFree(fileData);
    return true;
}

static bool SaveParcelToFile(const char *filePath, HcParcel *parcel)
{
    FileHandle file;
    int ret = HcFileOpen(filePath, MODE_FILE_WRITE, &file);
    if (ret != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to open database file!");
        return false;
    }
    SetSecurityLabel(filePath, SECURITY_LABEL_S2);
    int fileSize = (int)GetParcelDataSize(parcel);
    const char *fileData = GetParcelData(parcel);
    int writeSize = HcFileWrite(file, fileData, fileSize);
    HcFileClose(file);
    if (writeSize == fileSize) {
        return true;
    } else {
        LOGE("[CRED#DB]: write file error!");
        return false;
    }
}

static void LoadOsAccountCredDb(int32_t osAccountId)
{
    char filePath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetOsAccountCredInfoPath(osAccountId, filePath, MAX_DB_PATH_LEN)) {
        LOGE("[CRED#DB]: Failed to get os account info path!");
        return;
    }
    HcParcel parcel = CreateParcel(0, 0);
    if (!ReadParcelFromFile(filePath, &parcel)) {
        DeleteParcel(&parcel);
        return;
    }
    OsAccountCredInfo info;
    info.osAccountId = osAccountId;
    info.credentials = CreateCredentialVec();
    if (!ReadCredInfoFromParcel(&parcel, &info)) {
        DestroyCredentialVec(&info.credentials);
        DeleteParcel(&parcel);
        return;
    }
    DeleteParcel(&parcel);
    if (g_devauthCredDb.pushBackT(&g_devauthCredDb, info) == NULL) {
        LOGE("[CRED#DB]: Failed to push osAccountCredInfo to cred database!");
        ClearCredentialVec(&info.credentials);
        return;
    }
    LOGI("[CRED#DB]: Load os account cred db successfully! [Id]: %d", osAccountId);
}

static void RemoveOsAccountCredInfo(int32_t osAccountId)
{
    uint32_t index = 0;
    OsAccountCredInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_devauthCredDb, index, info) {
        if (info != NULL && info->osAccountId == osAccountId) {
            OsAccountCredInfo deleteInfo;
            HC_VECTOR_POPELEMENT(&g_devauthCredDb, &deleteInfo, index);
            ClearCredentialVec(&deleteInfo.credentials);
            return;
        }
    }
}

static void OnOsAccountUnlocked(int32_t osAccountId)
{
    (void)LockHcMutex(g_credMutex);
    RemoveOsAccountCredInfo(osAccountId);
    LoadOsAccountCredDb(osAccountId);
    UnlockHcMutex(g_credMutex);
}

static void OnOsAccountRemoved(int32_t osAccountId)
{
    LOGI("[CRED#DB]: os account is removed, osAccountId: %d", osAccountId);
    (void)LockHcMutex(g_credMutex);
    RemoveOsAccountCredInfo(osAccountId);
    UnlockHcMutex(g_credMutex);
}

static bool IsOsAccountDataLoaded(int32_t osAccountId)
{
    uint32_t index = 0;
    OsAccountCredInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_devauthCredDb, index, info) {
        if (info != NULL && info->osAccountId == osAccountId) {
            return true;
        }
    }
    return false;
}

static void LoadDataIfNotLoaded(int32_t osAccountId)
{
    if (IsOsAccountDataLoaded(osAccountId)) {
        return;
    }
    LOGI("[CRED#DB]: data has not been loaded, load it, osAccountId: %d", osAccountId);
    LoadOsAccountCredDb(osAccountId);
}

static OsAccountCredInfo *GetCredInfoByOsAccountId(int32_t osAccountId)
{
    if (IsOsAccountSupported()) {
        LoadDataIfNotLoaded(osAccountId);
    }
    uint32_t index = 0;
    OsAccountCredInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_devauthCredDb, index, info) {
        if (info != NULL && info->osAccountId == osAccountId) {
            return info;
        }
    }
    LOGI("[CRED#DB]: Create a new os account database cache! [Id]: %d", osAccountId);
    OsAccountCredInfo newInfo;
    newInfo.osAccountId = osAccountId;
    newInfo.credentials = CreateCredentialVec();
    OsAccountCredInfo *returnInfo = g_devauthCredDb.pushBackT(&g_devauthCredDb, newInfo);
    if (returnInfo == NULL) {
        LOGE("[CRED#DB]: Failed to push osAccountInfo to database!");
        DestroyCredentialVec(&newInfo.credentials);
    }
    return returnInfo;
}

static void LoadDevAuthCredDb(void)
{
    if (IsOsAccountSupported()) {
        return;
    }
    (void)LockHcMutex(g_credMutex);
    StringVector osAccountDbNameVec = CreateStrVector();
    HcFileGetSubFileName(GetStorageDirPath(), &osAccountDbNameVec);
    uint32_t index;
    HcString *dbName;
    FOR_EACH_HC_VECTOR(osAccountDbNameVec, index, dbName) {
        int32_t osAccountId;
        const char *osAccountIdStr = StringGet(dbName);
        if (osAccountIdStr == NULL) {
            continue;
        }
        if (strcmp(osAccountIdStr, "hccredential.dat") == 0) {
            LoadOsAccountCredDb(DEFAULT_OS_ACCOUNT);
        } else if (sscanf_s(osAccountIdStr, "hccredential%d.dat", &osAccountId) == 1) {
            LoadOsAccountCredDb(osAccountId);
        }
    }
    DestroyStrVector(&osAccountDbNameVec);
    UnlockHcMutex(g_credMutex);
}

static bool SetCredentialElement(TlvCredentialElement *element, Credential *entry)
{
    if (!StringSet(&element->credId.data, entry->credId)) {
        LOGE("[CRED#DB]: Failed to copy credId!");
        return false;
    }
    if (!StringSet(&element->deviceId.data, entry->deviceId)) {
        LOGE("[CRED#DB]: Failed to copy deviceId!");
        return false;
    }
    if (!StringSet(&element->peerUserSpaceId.data, entry->peerUserSpaceId)) {
        LOGE("[CRED#DB]: Failed to copy peerUserSpaceId!");
        return false;
    }
    if (!StringSet(&element->userId.data, entry->userId)) {
        LOGE("[CRED#DB]: Failed to copy userId!");
        return false;
    }
    if (!StringSet(&element->credOwner.data, entry->credOwner)) {
        LOGE("[CRED#DB]: Failed to copy credOwner!");
        return false;
    }
    if (!SaveStringVectorToParcel(&entry->authorizedAccountList, &element->authorizedAccountList.data)) {
        LOGE("[CRED#DB]: Failed to copy authorizedAccountList!");
        return false;
    }
    if (!StringSet(&element->extendInfo.data, entry->extendInfo)) {
        LOGE("[CRED#DB]: Failed to copy extendInfo!");
        return false;
    }
    element->subject.data = entry->subject;
    element->authorizedScope.data = entry->authorizedScope;
    element->issuer.data = entry->issuer;
    element->credType.data = entry->credType;
    element->keyFormat.data = entry->keyFormat;
    element->algorithmType.data = entry->algorithmType;
    element->proofType.data = entry->proofType;
    element->ownerUid.data = entry->ownerUid;
    return true;
}

static bool SaveCredentials(const CredentialVec *vec, HCCredDataBaseV1 *db)
{
    uint32_t index;
    Credential **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if (entry == NULL || *entry == NULL) {
            continue;
        }
        TlvCredentialElement tmp;
        TlvCredentialElement *element = db->credentials.data.pushBack(&db->credentials.data, &tmp);
        if (element == NULL) {
            return false;
        }
        TLV_INIT(TlvCredentialElement, element);
        if (!SetCredentialElement(element, *entry)) {
            TLV_DEINIT((*element));
            return false;
        }
    }
    return true;
}

static bool SaveCredInfoToParcel(const OsAccountCredInfo *info, HcParcel *parcel)
{
    int32_t ret = false;
    HCCredDataBaseV1 dbv1;
    TLV_INIT(HCCredDataBaseV1, &dbv1)
    dbv1.version.data = 1;
    do {
        if (!SaveCredentials(&info->credentials, &dbv1)) {
            break;
        }
        if (!EncodeTlvMessage((TlvBase *)&dbv1, parcel)) {
            LOGE("[CRED#DB]: Encode Tlv Message failed!");
            break;
        }
        ret = true;
    } while (0);
    TLV_DEINIT(dbv1)
    return ret;
}

static bool CompareQueryCredentialParams(const QueryCredentialParams *params, const Credential *entry)
{
    if ((params->deviceId != NULL) && (strcmp(params->deviceId, StringGet(&entry->deviceId)) != 0)) {
        return false;
    }
    if ((params->credOwner != NULL) && (strcmp(params->credOwner, StringGet(&entry->credOwner)) != 0)) {
        return false;
    }
    if ((params->userId != NULL) && (strcmp(params->userId, StringGet(&entry->userId)) != 0)) {
        return false;
    }
    if ((params->credId != NULL) && (strcmp(params->credId, StringGet(&entry->credId)) != 0)) {
        return false;
    }
    if ((params->credType != DEFAULT_CRED_PARAM_VAL) && (params->credType != entry->credType)) {
        return false;
    }
    if ((params->subject != DEFAULT_CRED_PARAM_VAL) && (params->subject != entry->subject)) {
        return false;
    }
    if ((params->issuer != DEFAULT_CRED_PARAM_VAL) && (params->issuer != entry->issuer)) {
        return false;
    }
    if ((params->ownerUid != DEFAULT_CRED_PARAM_VAL) && (params->ownerUid != entry->ownerUid)) {
        return false;
    }
    return true;
}

static Credential **QueryCredentialPtrIfMatch(const CredentialVec *vec, const QueryCredentialParams *params)
{
    uint32_t index;
    Credential **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if (entry != NULL && *entry != NULL && CompareQueryCredentialParams(params, *entry)) {
            return entry;
        }
    }
    return NULL;
}

static void PostCredAddMsg(const Credential *entry)
{
    if (!IsCredListenerSupported()) {
        return;
    }
    OnCredAdd(StringGet(&entry->credId), NULL);
}

static void PostCredUpdateMsg(const Credential *entry)
{
    if (!IsCredListenerSupported()) {
        return;
    }
    OnCredUpdate(StringGet(&entry->credId), NULL);
}

static void PostCredDeleteMsg(const Credential *entry)
{
    if (!IsCredListenerSupported()) {
        return;
    }
    OnCredDelete(StringGet(&entry->credId), NULL);
}

QueryCredentialParams InitQueryCredentialParams(void)
{
    QueryCredentialParams params = {
        .deviceId = NULL,
        .credOwner = NULL,
        .credId = NULL,
        .userId = NULL,
        .credType = DEFAULT_CRED_PARAM_VAL,
        .ownerUid = DEFAULT_CRED_PARAM_VAL,
        .subject = DEFAULT_CRED_PARAM_VAL,
        .issuer = DEFAULT_CRED_PARAM_VAL,
    };
    return params;
}

Credential *CreateCredential(void)
{
    Credential *ptr = (Credential *)HcMalloc(sizeof(Credential), 0);
    if (ptr == NULL) {
        LOGE("[CRED#DB]: Failed to allocate Credential memory!");
        return NULL;
    }
    ptr->credId = CreateString();
    ptr->deviceId = CreateString();
    ptr->peerUserSpaceId = CreateString();
    ptr->userId = CreateString();
    ptr->credOwner = CreateString();
    ptr->authorizedAccountList = CreateStrVector();
    ptr->authorizedAppList = CreateStrVector();
    ptr->authorizedDeviceList = CreateStrVector();
    ptr->extendInfo = CreateString();
    return ptr;
}

void DestroyCredential(Credential *credential)
{
    if (credential == NULL) {
        return;
    }
    DeleteString(&credential->credId);
    DeleteString(&credential->deviceId);
    DeleteString(&credential->peerUserSpaceId);
    DeleteString(&credential->userId);
    DeleteString(&credential->credOwner);
    DestroyStrVector(&credential->authorizedAccountList);
    DestroyStrVector(&credential->authorizedAppList);
    DestroyStrVector(&credential->authorizedDeviceList);
    DeleteString(&credential->extendInfo);
    HcFree(credential);
}

Credential *DeepCopyCredential(const Credential *entry)
{
    Credential *returnEntry = CreateCredential();
    if (returnEntry == NULL) {
        return NULL;
    }
    if (!GenerateCredFromCred(entry, returnEntry)) {
        DestroyCredential(returnEntry);
        return NULL;
    }
    return returnEntry;
}

void ClearCredentialVec(CredentialVec *vec)
{
    uint32_t index;
    Credential **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if (entry == NULL || *entry == NULL) {
            continue;
        }
        DestroyCredential(*entry);
    }
    DESTROY_HC_VECTOR(CredentialVec, vec);
}

static int32_t AddCredIdToReturn(const Credential *credInfo, CJson *json)
{
    const char *credId = StringGet(&credInfo->credId);
    if (credId == NULL) {
        LOGE("[CRED#DB]: Failed to get credId from credInfo!");
        return IS_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_CRED_ID, credId) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add credId to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddCredTypeToReturn(const Credential *credInfo, CJson *json)
{
    uint8_t credType = credInfo->credType;
    if (AddIntToJson(json, FIELD_CRED_TYPE, credType) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add credType to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddUserIdToReturn(const Credential *credInfo, CJson *json)
{
    const char *userId = StringGet(&credInfo->userId);
    if (userId == NULL) {
        LOGE("[CRED#DB]: Failed to get userId from credInfo!");
        return IS_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_USER_ID, userId) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add userId to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddSubjectToReturn(const Credential *credInfo, CJson *json)
{
    uint8_t subject = credInfo->subject;
    if (AddIntToJson(json, FIELD_SUBJECT, subject) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add subject to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddIssuerToReturn(const Credential *credInfo, CJson *json)
{
    uint8_t issuer = credInfo->issuer;
    if (AddIntToJson(json, FIELD_ISSUER, issuer) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add issuer to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddKeyFormatToReturn(const Credential *credInfo, CJson *json)
{
    uint8_t keyFormat = credInfo->keyFormat;
    if (AddIntToJson(json, FIELD_KEY_FORMAT, keyFormat) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add keyFormat to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddProofTypeToReturn(const Credential *credInfo, CJson *json)
{
    uint8_t proofType = credInfo->proofType;
    if (AddIntToJson(json, FIELD_PROOF_TYPE, proofType) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add proofType to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddAlgorithmTypeToReturn(const Credential *credInfo, CJson *json)
{
    uint8_t algorithmType = credInfo->algorithmType;
    if (AddIntToJson(json, FIELD_ALGORITHM_TYPE, algorithmType) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add algorithmType to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddDeviceIdToReturn(const Credential *credInfo, CJson *json)
{
    const char *deviceId = StringGet(&credInfo->deviceId);
    if (deviceId == NULL) {
        LOGE("[CRED#DB]: Failed to get deviceId from credInfo!");
        return IS_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_DEVICE_ID, deviceId) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add deviceId to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddCredOwnerToReturn(const Credential *credInfo, CJson *json)
{
    const char *credOwner = StringGet(&credInfo->credOwner);
    if (credOwner == NULL) {
        LOGE("[CRED#DB]: Failed to get credOwner from credInfo!");
        return IS_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_CRED_OWNER, credOwner) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add credOwner to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddExtendInfoToReturn(const Credential *credInfo, CJson *json)
{
    const char *extendInfo = StringGet(&credInfo->extendInfo);
    if (extendInfo == NULL) {
        LOGE("[CRED#DB]: Failed to get extendInfo from credInfo!");
        return IS_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_EXTEND_INFO, extendInfo) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add extendInfo to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddPeerUserSpaceIdToReturn(const Credential *credInfo, CJson *json)
{
    const char *peerUserSpaceId = StringGet(&credInfo->peerUserSpaceId);
    if (peerUserSpaceId == NULL) {
        LOGE("[CRED#DB]: Failed to get peerUserSpaceId from credInfo!");
        return IS_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_PEER_USER_SPACE_ID, peerUserSpaceId) != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to add peerUserSpaceId to json!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

static int32_t AddAuthorizedAccountListToReturn(const Credential *credInfo, CJson *json)
{
    CJson *arr = CreateJsonArray();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return IS_ERR_JSON_CREATE;
    }
    uint32_t index = 0;
    HcString *authorizedAccount = NULL;
    FOR_EACH_HC_VECTOR(credInfo->authorizedAccountList, index, authorizedAccount) {
        if (authorizedAccount == NULL) {
            continue;
        }
        if (AddStringToArray(arr, StringGet(authorizedAccount)) != IS_SUCCESS) {
            FreeJson(arr);
            LOGE("[CRED#DB]: Failed to add authorizedAccount to json!");
            return IS_ERR_JSON_ADD;
        }
    }
    if (AddObjToJson(json, FIELD_AUTHORIZED_ACCOUNT_LIST, arr) != IS_SUCCESS) {
        FreeJson(arr);
        LOGE("[CRED#DB]: Failed to add authorizedAccountList to json!");
        return IS_ERR_JSON_ADD;
    }
    FreeJson(arr);
    return IS_SUCCESS;
}

int32_t GenerateReturnCredInfo(const Credential *credential, CJson *returnJson)
{
    int32_t result;
    if (((result = AddCredIdToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddDeviceIdToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddPeerUserSpaceIdToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddSubjectToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddUserIdToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddIssuerToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddCredTypeToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddKeyFormatToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddAlgorithmTypeToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddProofTypeToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddCredOwnerToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddAuthorizedAccountListToReturn(credential, returnJson)) != IS_SUCCESS) ||
        ((result = AddExtendInfoToReturn(credential, returnJson)) != IS_SUCCESS)) {
        return result;
    }
    return IS_SUCCESS;
}

int32_t AddCredToDb(int32_t osAccountId, const Credential *entry)
{
    LOGI("[CRED#DB]: Start to add a cred to database! [OsAccountId]: %d", osAccountId);
    if (entry == NULL) {
        LOGE("[CRED#DB]: The input entry is NULL!");
        return IS_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_credMutex);
    OsAccountCredInfo *info = GetCredInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_credMutex);
        return IS_ERR_INVALID_PARAMS;
    }
    Credential *newEntry = DeepCopyCredential(entry);
    if (newEntry == NULL) {
        UnlockHcMutex(g_credMutex);
        return IS_ERR_MEMORY_COPY;
    }
    QueryCredentialParams params = InitQueryCredentialParams();
    params.credId = StringGet(&entry->credId);
    Credential **oldEntryPtr = QueryCredentialPtrIfMatch(&info->credentials, &params);
    if (oldEntryPtr != NULL) {
        DestroyCredential(*oldEntryPtr);
        *oldEntryPtr = newEntry;
        PostCredUpdateMsg(newEntry);
        UnlockHcMutex(g_credMutex);
        LOGI("[CRED#DB]: Update an old credential successfully! [credType]: %u", entry->credType);
        return IS_SUCCESS;
    }
    if (info->credentials.pushBackT(&info->credentials, newEntry) == NULL) {
        DestroyCredential(newEntry);
        UnlockHcMutex(g_credMutex);
        LOGE("[CRED#DB]: Failed to push credential to vec!");
        return IS_ERR_MEMORY_COPY;
    }
    PostCredAddMsg(newEntry);
    UnlockHcMutex(g_credMutex);
    LOGI("[CRED#DB]: Add a credential to database successfully! [credType]: %u", entry->credType);
    return IS_SUCCESS;
}

int32_t DelCredential(int32_t osAccountId, const QueryCredentialParams *params)
{
    LOGI("[CRED#DB]: Start to delete credential from database! [OsAccountId]: %d", osAccountId);
    if (params == NULL) {
        LOGE("[CRED#DB]: The input params is NULL!");
        return IS_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_credMutex);
    OsAccountCredInfo *info = GetCredInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_credMutex);
        return IS_ERR_INVALID_PARAMS;
    }
    int32_t count = 0;
    uint32_t index = 0;
    Credential **entry = NULL;
    while (index < HC_VECTOR_SIZE(&info->credentials)) {
        entry = info->credentials.getp(&info->credentials, index);
        if ((entry == NULL) || (*entry == NULL) || (!CompareQueryCredentialParams(params, *entry))) {
            index++;
            continue;
        }
        Credential *popEntry;
        HC_VECTOR_POPELEMENT(&info->credentials, &popEntry, index);
        PostCredDeleteMsg(popEntry);
        LOGI("[CRED#DB]: Delete a credential from database successfully! [credType]: %u", popEntry->credType);
        DestroyCredential(popEntry);
        count++;
    }
    UnlockHcMutex(g_credMutex);
    LOGI("[CRED#DB]: Number of credentials deleted: %d", count);
    return IS_SUCCESS;
}

int32_t QueryCredentials(int32_t osAccountId, const QueryCredentialParams *params, CredentialVec *vec)
{
    if ((params == NULL) || (vec == NULL)) {
        LOGE("[CRED#DB]: The input params or vec is NULL!");
        return IS_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_credMutex);
    OsAccountCredInfo *info = GetCredInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_credMutex);
        return IS_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    Credential **entry;
    FOR_EACH_HC_VECTOR(info->credentials, index, entry) {
        if (entry != NULL && *entry != NULL && !CompareQueryCredentialParams(params, *entry)) {
            continue;
        }
        Credential *newEntry = DeepCopyCredential(*entry);
        if (newEntry == NULL) {
            continue;
        }
        if (vec->pushBackT(vec, newEntry) == NULL) {
            LOGE("[CRED#DB]: Failed to push entry to vec!");
            DestroyCredential(newEntry);
        }
    }
    UnlockHcMutex(g_credMutex);
    return IS_SUCCESS;
}

int32_t SaveOsAccountCredDb(int32_t osAccountId)
{
    (void)LockHcMutex(g_credMutex);
    OsAccountCredInfo *info = GetCredInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_credMutex);
        return IS_ERR_INVALID_PARAMS;
    }
    HcParcel parcel = CreateParcel(0, 0);
    if (!SaveCredInfoToParcel(info, &parcel)) {
        DeleteParcel(&parcel);
        UnlockHcMutex(g_credMutex);
        return IS_ERR_MEMORY_COPY;
    }
    char filePath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetOsAccountCredInfoPath(osAccountId, filePath, MAX_DB_PATH_LEN)) {
        DeleteParcel(&parcel);
        UnlockHcMutex(g_credMutex);
        return IS_ERR_CONVERT_FAILED;
    }
    if (!SaveParcelToFile(filePath, &parcel)) {
        DeleteParcel(&parcel);
        UnlockHcMutex(g_credMutex);
        return IS_ERR_MEMORY_COPY;
    }
    DeleteParcel(&parcel);
    UnlockHcMutex(g_credMutex);
    LOGI("[CRED#DB]: Save an os account cred database successfully! [Id]: %d", osAccountId);
    return IS_SUCCESS;
}

#ifdef DEV_AUTH_HIVIEW_ENABLE
static void DumpCredential(int fd, const Credential *credential)
{
    dprintf(fd, "||--------------------------Credential--------------------------|                  |\n");
    dprintf(fd, "||%-16s = %-46.8s|                  |\n", "credId", StringGet(&credential->credId));
    dprintf(fd, "||%-16s = %-46.8s|                  |\n", "deviceId", StringGet(&credential->deviceId));
    dprintf(fd, "||%-16s = %-46.8s|                  |\n", "peerUserSpaceId", StringGet(&credential->peerUserSpaceId));
    dprintf(fd, "||%-16s = %-46d|                  |\n", "subject", credential->subject);
    dprintf(fd, "||%-16s = %-46.8s|                  |\n", "userId", StringGet(&credential->userId));
    dprintf(fd, "||%-16s = %-46d|                  |\n", "issuer", credential->issuer);
    dprintf(fd, "||%-16s = %-46d|                  |\n", "credType", credential->credType);
    dprintf(fd, "||%-16s = %-46d|                  |\n", "keyFormat", credential->keyFormat);
    dprintf(fd, "||%-16s = %-46d|                  |\n", "algorithmType", credential->algorithmType);
    dprintf(fd, "||%-16s = %-46d|                  |\n", "proofType", credential->proofType);
    uint32_t index = 0;
    HcString *authorizedAccount = NULL;
    FOR_EACH_HC_VECTOR(credential->authorizedAccountList, index, authorizedAccount) {
        if (authorizedAccount == NULL) {
            continue;
        }
        dprintf(fd, "||%-16s %d = %-46.8s|                  |\n", "account", index, StringGet(authorizedAccount));
    }
    dprintf(fd, "||%-16s = %-46d|                  |\n", "authorizedScope", credential->authorizedScope);
    dprintf(fd, "||%-16s = %-46.8s|                  |\n", "credOwner", StringGet(&credential->credOwner));
    dprintf(fd, "||%-16s = %-46.8s|                  |\n", "extendInfo", StringGet(&credential->extendInfo));
    dprintf(fd, "||--------------------------Credential--------------------------|                  |\n");
}

static void DumpDb(int fd, const OsAccountCredInfo *db)
{
    const CredentialVec *credentials = &db->credentials;
    dprintf(fd, "|------------------------------------CRED-DataBase-------------------------------------|\n");
    dprintf(fd, "|%-12s = %-67d|\n", "osAccountId", db->osAccountId);
    dprintf(fd, "|%-12s = %-67d|\n", "credentialNum", credentials->size(credentials));
    uint32_t index;
    Credential **credential;
    FOR_EACH_HC_VECTOR(*credentials, index, credential) {
        if (credential == NULL || *credential == NULL) {
            continue;
        }
        DumpCredential(fd, *credential);
    }
    dprintf(fd, "|------------------------------------CRED-DataBase-------------------------------------|\n");
}

static void LoadAllAccountsData(void)
{
    int32_t *accountIds = NULL;
    uint32_t size = 0;
    int32_t ret = GetAllOsAccountIds(&accountIds, &size);
    if (ret != IS_SUCCESS) {
        LOGE("[CRED#DB]: Failed to get all os account ids, [res]: %d", ret);
        return;
    }
    for (uint32_t index = 0; index < size; index++) {
        LoadDataIfNotLoaded(accountIds[index]);
    }
    HcFree(accountIds);
}

static void DevAuthDataBaseDump(int fd)
{
    if (g_credMutex == NULL) {
        LOGE("[CRED#DB]: Init mutex failed");
        return;
    }
    (void)LockHcMutex(g_credMutex);
    if (IsOsAccountSupported()) {
        LoadAllAccountsData();
    }
    uint32_t index;
    OsAccountCredInfo *info;
    FOR_EACH_HC_VECTOR(g_devauthCredDb, index, info) {
        if (info == NULL) {
            continue;
        }
        DumpDb(fd, info);
    }
    UnlockHcMutex(g_credMutex);
}
#endif

int32_t InitCredDatabase(void)
{
    if (g_credMutex == NULL) {
        g_credMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_credMutex == NULL) {
            LOGE("[CRED#DB]: Alloc cred databaseMutex failed");
            return IS_ERR_ALLOC_MEMORY;
        }
        if (InitHcMutex(g_credMutex, false) != IS_SUCCESS) {
            LOGE("[CRED#DB]: Init mutex failed");
            HcFree(g_credMutex);
            g_credMutex = NULL;
            return IS_ERR_INIT_FAILED;
        }
    }
    g_devauthCredDb = CREATE_HC_VECTOR(DevAuthCredDb);
    AddOsAccountEventCallback(CRED_DATA_CALLBACK, OnOsAccountUnlocked, OnOsAccountRemoved);
    LoadDevAuthCredDb();
    DEV_AUTH_REG_CRED_DUMP_FUNC(DevAuthDataBaseDump);
    return IS_SUCCESS;
}

void DestroyCredDatabase(void)
{
    RemoveOsAccountEventCallback(CRED_DATA_CALLBACK);
    (void)LockHcMutex(g_credMutex);
    uint32_t index;
    OsAccountCredInfo *info;
    FOR_EACH_HC_VECTOR(g_devauthCredDb, index, info) {
        if (info == NULL) {
            continue;
        }
        ClearCredentialVec(&info->credentials);
    }
    DESTROY_HC_VECTOR(DevAuthCredDb, &g_devauthCredDb);
    UnlockHcMutex(g_credMutex);
    DestroyHcMutex(g_credMutex);
    HcFree(g_credMutex);
    g_credMutex = NULL;
}