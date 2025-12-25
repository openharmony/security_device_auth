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

#include "operation_data_manager.h"

#include "broadcast_manager.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_time.h"
#include "hc_string_vector.h"
#include "hc_types.h"
#include "key_manager.h"
#include "hidump_adapter.h"
#include "os_account_adapter.h"
#include "pseudonym_manager.h"
#include "security_label_adapter.h"
#include "account_task_manager.h"
#include "string_util.h"

typedef struct {
    DECLARE_TLV_STRUCT(5)
    TlvString caller;
    TlvString function;
    TlvString operationInfo;
    TlvUint32 operationType;
    TlvInt64 operationTime;
} TlvOperation;
DECLEAR_INIT_FUNC(TlvOperation)
DECLARE_TLV_VECTOR(TlvOperationVec, TlvOperation)

typedef struct {
    DECLARE_TLV_STRUCT(2)
    TlvInt32 version;
    TlvOperationVec operations;
} HcOperationDataBaseV1;
DECLEAR_INIT_FUNC(HcOperationDataBaseV1)

BEGIN_TLV_STRUCT_DEFINE(TlvOperation, 0x0001)
    TLV_MEMBER(TlvString, caller, 0x4001)
    TLV_MEMBER(TlvString, function, 0x4002)
    TLV_MEMBER(TlvString, operationInfo, 0x4003)
    TLV_MEMBER(TlvUint32, operationType, 0x4004)
    TLV_MEMBER(TlvInt64, operationTime, 0x4005)
END_TLV_STRUCT_DEFINE()
IMPLEMENT_TLV_VECTOR(TlvOperationVec, TlvOperation, 1)

BEGIN_TLV_STRUCT_DEFINE(HcOperationDataBaseV1, 0x0001)
    TLV_MEMBER(TlvInt32, version, 0x6001)
    TLV_MEMBER(TlvOperationVec, operations, 0x6002)
END_TLV_STRUCT_DEFINE()

IMPLEMENT_HC_VECTOR(OperationVec, Operation*, 1)

typedef struct {
    int32_t osAccountId;
    bool isTained;
    OperationVec operations;
} OsAccountOperationInfo;

DECLARE_HC_VECTOR(OperationDb, OsAccountOperationInfo)
IMPLEMENT_HC_VECTOR(OperationDb, OsAccountOperationInfo, 1)

#define MAX_DB_PATH_LEN 256
#define TAINED_OPERATION "tained operation record!"
#define TIME_LEN 20

static HcMutex *g_operationMutex = NULL;
static OperationDb g_operationDb;

static bool IsOsAccountOperationInfoLoaded(int32_t osAccountId)
{
    uint32_t index = 0;
    OsAccountOperationInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_operationDb, index, info) {
        if (info != NULL && info->osAccountId == osAccountId) {
            return true;
        }
    }
    return false;
}

static bool SetOperationElement(TlvOperation *element, Operation *entry)
{
    if (!StringSet(&element->caller.data, entry->caller)) {
        LOGE("[Operation]: Failed to copy caller!");
        return false;
    }
    if (!StringSet(&element->function.data, entry->function)) {
        LOGE("[Operation]: Failed to copy function!");
        return false;
    }
    if (!StringSet(&element->operationInfo.data, entry->operationInfo)) {
        LOGE("[Operation]: Failed to copy operationInfo!");
        return false;
    }
    element->operationType.data = entry->operationType;
    element->operationTime.data = entry->operationTime;
    return true;
}

static bool SaveOperations(const OperationVec *vec, HcOperationDataBaseV1 *db)
{
    uint32_t index = 0;
    Operation **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        TlvOperation tmp;
        TlvOperation *element = db->operations.data.pushBack(&db->operations.data, &tmp);
        if (element == NULL) {
            return false;
        }
        TLV_INIT(TlvOperation, element);
        if (!SetOperationElement(element, *entry)) {
            TLV_DEINIT((*element));
            return false;
        }
    }
    return true;
}

static bool SaveOperationInfoToParcel(const OsAccountOperationInfo *info, HcParcel *parcel)
{
    int32_t ret = false;
    HcOperationDataBaseV1 dbv1;
    TLV_INIT(HcOperationDataBaseV1, &dbv1)
    dbv1.version.data = 1;
    do {
        if (!SaveOperations(&info->operations, &dbv1)) {
            break;
        }
        if (!EncodeTlvMessage((TlvBase *)&dbv1, parcel)) {
            LOGE("[Operation]: Encode Tlv Message failed!");
            break;
        }
        ret = true;
    } while (0);
    TLV_DEINIT(dbv1)
    return ret;
}

static bool GetOsAccountOperationInfoPathCe(int32_t osAccountId, char *infoPath, uint32_t pathBufferLen)
{
    const char *beginPath = GetStorageDirPathCe();
    if (beginPath == NULL) {
        LOGE("[Operation]: Failed to get the storage path!");
        return false;
    }
    if (sprintf_s(infoPath, pathBufferLen, "%s/%d/deviceauth/hcoperation.dat", beginPath, osAccountId) <= 0) {
        LOGE("[Operation]: Failed to generate db file path!");
        return false;
    }
    return true;
}

static bool SaveParcelToFile(const char *filePath, HcParcel *parcel)
{
    FileHandle file;
    int ret = HcFileOpen(filePath, MODE_FILE_WRITE, &file);
    if (ret != HC_SUCCESS) {
        LOGE("[Operation]: Failed to open database file!");
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
        LOGE("[Operation]: write file error!");
        return false;
    }
}

static int32_t SaveOperationInfo(const OsAccountOperationInfo *info)
{
    if (info == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    if (!info->isTained) {
        return HC_SUCCESS;
    }
    HcParcel parcel = CreateParcel(0, 0);
    if (!SaveOperationInfoToParcel(info, &parcel)) {
        DeleteParcel(&parcel);
        return HC_ERR_MEMORY_COPY;
    }
    char filePath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetOsAccountOperationInfoPathCe(info->osAccountId, filePath, MAX_DB_PATH_LEN)) {
        DeleteParcel(&parcel);
        return HC_ERROR;
    }
    if (!SaveParcelToFile(filePath, &parcel)) {
        DeleteParcel(&parcel);
        return HC_ERR_MEMORY_COPY;
    }
    DeleteParcel(&parcel);
    return HC_SUCCESS;
}

static bool SaveTainedOperation(int32_t osAccountId)
{
    Operation *tainedOperation = CreateOperationRecord();
    if (tainedOperation == NULL) {
        LOGE("failed to create tained operation!");
        return false;
    }
    tainedOperation->operationTime = HcGetRealTime();
    if (StringAppendPointer(&(tainedOperation->operationInfo), TAINED_OPERATION) == HC_FALSE) {
        LOGE("failed to append tained operation info!");
    }
    OsAccountOperationInfo tainedInfo;
    tainedInfo.osAccountId = osAccountId;
    tainedInfo.operations = CreateOperationVec();
    tainedInfo.isTained = true;
    if (tainedInfo.operations.pushBackT(&tainedInfo.operations, tainedOperation) == NULL) {
        DestroyOperationRecord(tainedOperation);
        DestroyOperationVec(&tainedInfo.operations);
        LOGE("push tained operation info failed!");
        return false;
    }
    bool res = (SaveOperationInfo(&tainedInfo) == HC_SUCCESS);
    ClearOperationVec(&tainedInfo.operations);
    return res;
}

static bool ReadParcelFromFile(const char *filePath, HcParcel *parcel)
{
    FileHandle file;
    int ret = HcFileOpen(filePath, MODE_FILE_READ, &file);
    if (ret != 0) {
        LOGE("[Operation]: Failed to open database file!");
        return false;
    }
    SetSecurityLabel(filePath, SECURITY_LABEL_S2);
    int fileSize = HcFileSize(file);
    if (fileSize <= 0) {
        LOGE("[Operation]: The database file size is invalid!");
        HcFileClose(file);
        return false;
    }
    char *fileData = (char*)HcMalloc(fileSize, 0);
    if (fileData == NULL) {
        LOGE("[Operation]: Failed to allocate fileData memory!");
        HcFileClose(file);
        return false;
    }
    if (HcFileRead(file, fileData, fileSize) != fileSize) {
        LOGE("[Operation]: Read file error!");
        HcFileClose(file);
        HcFree(fileData);
        return false;
    }
    HcFileClose(file);
    if (!ParcelWrite(parcel, fileData, fileSize)) {
        HcFree(fileData);
        LOGE("[Operation]: parcel write error!");
        return false;
    }
    HcFree(fileData);
    return true;
}

static bool GenerateOperationFromTlv(TlvOperation *operation, Operation *entry)
{
    if (!StringSet(&entry->caller, operation->caller.data)) {
        LOGE("[Operation]: Failed to load caller from tlv!");
        return false;
    }
    if (!StringSet(&entry->function, operation->function.data)) {
        LOGE("[Operation]: Failed to load function from tlv!");
        return false;
    }
    if (!StringSet(&entry->operationInfo, operation->operationInfo.data)) {
        LOGE("[Operation]: Failed to load operationInfo from tlv!");
        return false;
    }
    entry->operationType = operation->operationType.data;
    entry->operationTime = operation->operationTime.data;
    return true;
}

static bool LoadOperations(HcOperationDataBaseV1 *db, OperationVec *vec)
{
    uint32_t index;
    TlvOperation *operation = NULL;
    FOR_EACH_HC_VECTOR(db->operations.data, index, operation) {
        if (operation == NULL) {
            continue;
        }
        Operation *entry = CreateOperationRecord();
        if (entry == NULL) {
            LOGE("[Operation]: Failed to allocate entry memory!");
            ClearOperationVec(vec);
            return false;
        }
        if (!GenerateOperationFromTlv(operation, entry)) {
            DestroyOperationRecord(entry);
            ClearOperationVec(vec);
            return false;
        }
        if (vec->pushBackT(vec, entry) == NULL) {
            LOGE("[Operation]: Failed to push entry to vec!");
            DestroyOperationRecord(entry);
            ClearOperationVec(vec);
            return false;
        }
    }
    return true;
}

static bool ReadInfoFromParcel(HcParcel *parcel, OsAccountOperationInfo *info)
{
    bool ret = false;
    HcOperationDataBaseV1 dbv1;
    TLV_INIT(HcOperationDataBaseV1, &dbv1)
    if (DecodeTlvMessage((TlvBase *)&dbv1, parcel, false)) {
        if (!LoadOperations(&dbv1, &info->operations)) {
            TLV_DEINIT(dbv1)
            return false;
        }
        ret = true;
    } else {
        LOGE("[Operation]: Decode Tlv Message Failed!");
    }
    TLV_DEINIT(dbv1)
    return ret;
}

static void LoadOsAccountDb(int32_t osAccountId)
{
    char filePath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetOsAccountOperationInfoPathCe(osAccountId, filePath, MAX_DB_PATH_LEN)) {
        LOGE("[Operation]: Failed to get os account info path!");
        return;
    }
    HcParcel parcel = CreateParcel(0, 0);
    if (!ReadParcelFromFile(filePath, &parcel)) {
        DeleteParcel(&parcel);
        return;
    }
    OsAccountOperationInfo info;
    info.osAccountId = osAccountId;
    info.isTained = false;
    info.operations = CreateOperationVec();
    if (!ReadInfoFromParcel(&parcel, &info)) {
        DestroyOperationVec(&info.operations);
        DeleteParcel(&parcel);
        return;
    }
    DeleteParcel(&parcel);
    if (g_operationDb.pushBackT(&g_operationDb, info) == NULL) {
        LOGE("[Operation]: Failed to push osAccountInfo to database!");
        DestroyOperationVec(&info.operations);
        return;
    }
    LOGI("[Operation]: Load os account db successfully! [Id]: %" LOG_PUB "d", osAccountId);
}

static void LoadDataIfNotLoaded(int32_t osAccountId)
{
    if (IsOsAccountOperationInfoLoaded(osAccountId)) {
        return;
    }
    LOGI("[Operation]: data has not been loaded, load it, osAccountId: %" LOG_PUB "d", osAccountId);
    LoadOsAccountDb(osAccountId);
}

static OsAccountOperationInfo *GetOperationInfoByOsAccountId(int32_t osAccountId)
{
    if (IsOsAccountSupported()) {
        LoadDataIfNotLoaded(osAccountId);
    }
    uint32_t index = 0;
    OsAccountOperationInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_operationDb, index, info) {
        if (info != NULL && (osAccountId == ANY_OS_ACCOUNT || info->osAccountId == osAccountId)) {
            return info;
        }
    }
    LOGI("[Operation]: Create a new os account database cache! [Id]: %" LOG_PUB "d", osAccountId);
    OsAccountOperationInfo newInfo;
    newInfo.osAccountId = osAccountId;
    newInfo.operations = CreateOperationVec();
    newInfo.isTained = false;
    OsAccountOperationInfo *returnInfo = g_operationDb.pushBackT(&g_operationDb, newInfo);
    if (returnInfo == NULL) {
        LOGE("[Operation]: Failed to push osAccountInfo to database!");
        DestroyOperationVec(&newInfo.operations);
    }
    return returnInfo;
}

static bool GenerateOperationFromOperation(const Operation *entry, Operation *returnEntry)
{
    if (!StringSet(&returnEntry->caller, entry->caller)) {
        LOGE("[Operation]: Failed to copy caller!");
        return false;
    }
    if (!StringSet(&returnEntry->function, entry->function)) {
        LOGE("[Operation]: Failed to copy function!");
        return false;
    }
    if (!StringSet(&returnEntry->operationInfo, entry->operationInfo)) {
        LOGE("[Operation]: Failed to copy operationInfo!");
        return false;
    }
    returnEntry->operationType = entry->operationType;
    returnEntry->operationTime = entry->operationTime;
    return true;
}

Operation *CreateOperationRecord(void)
{
    Operation *ptr = (Operation *)HcMalloc(sizeof(Operation), 0);
    if (ptr == NULL) {
        LOGE("[Operation]: Failed to allocate operation memory!");
        return NULL;
    }
    ptr->caller = CreateString();
    ptr->function = CreateString();
    ptr->operationInfo = CreateString();
    return ptr;
}

void DestroyOperationRecord(Operation *operation)
{
    if (operation == NULL) {
        return;
    }
    DeleteString(&operation->caller);
    DeleteString(&operation->function);
    DeleteString(&operation->operationInfo);
    HcFree(operation);
}

Operation *DeepCopyOperationRecord(const Operation *entry)
{
    if (entry == NULL) {
        return NULL;
    }
    Operation *returnEntry = CreateOperationRecord();
    if (returnEntry == NULL) {
        return NULL;
    }
    if (!GenerateOperationFromOperation(entry, returnEntry)) {
        DestroyOperationRecord(returnEntry);
        return NULL;
    }
    return returnEntry;
}

void ClearOperationVec(OperationVec *vec)
{
    if (vec == NULL) {
        return;
    }
    uint32_t index;
    Operation **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if (entry == NULL || *entry == NULL) {
            continue;
        }
        DestroyOperationRecord(*entry);
    }
    DESTROY_HC_VECTOR(OperationVec, vec);
}

static void SaveAllOperationInfo(void)
{
    uint32_t index = 0;
    OsAccountOperationInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_operationDb, index, info) {
        if (info == NULL) {
            continue;
        }
        int32_t res = SaveOperationInfo(info);
        LOGI("[Operation]: Save an os account database [Id]: %" LOG_PUB "d, ret = %" LOG_PUB "d",
            info->osAccountId, res);
    }
}

static void RemoveRedundantRecord(OsAccountOperationInfo *info, uint32_t maxRecord)
{
    uint32_t operationSize = HC_VECTOR_SIZE(&info->operations);
    if (operationSize <= maxRecord) {
        return;
    }
    int32_t needRemoveCnt = operationSize - maxRecord;
    uint32_t index = 0;
    Operation **entry = NULL;
    while (index < HC_VECTOR_SIZE(&info->operations) && needRemoveCnt > 0) {
        entry = info->operations.getp(&info->operations, index);
        if ((entry == NULL) || (*entry == NULL)) {
            index++;
            continue;
        }
        Operation *popEntry;
        HC_VECTOR_POPELEMENT(&info->operations, &popEntry, index);
        DestroyOperationRecord(popEntry);
        needRemoveCnt--;
    }
    return;
}

int32_t RecordOperationData(int32_t osAccountId, const Operation *entry)
{
    LOGI("[Operation]: Start to add a operation to database! [OsAccountId]: %" LOG_PUB "d", osAccountId);
    if (entry == NULL) {
        LOGE("[Operation]: The input entry is NULL!");
        return HC_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_operationMutex);
    OsAccountOperationInfo *info = GetOperationInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_operationMutex);
        return HC_ERR_INVALID_PARAMS;
    }
    Operation *newEntry = DeepCopyOperationRecord(entry);
    if (newEntry == NULL) {
        UnlockHcMutex(g_operationMutex);
        return HC_ERR_MEMORY_COPY;
    }
    newEntry->operationTime = HcGetRealTime();
    if (info->operations.pushBackT(&info->operations, newEntry) == NULL) {
        DestroyOperationRecord(newEntry);
        UnlockHcMutex(g_operationMutex);
        LOGE("[Operation]: Failed to push operation to vec!");
        return HC_ERR_MEMORY_COPY;
    }
    if ((!info->isTained) && (!SaveTainedOperation(osAccountId))) {
        LOGE("record tained opearation info failed!");
    }
    info->isTained = true;
    RemoveRedundantRecord(info, MAX_RECENT_OPERATION_CNT);
    LOGI("[Operation]: Add a operation to database successfully! [caller]: %" LOG_PUB "s", StringGet(&entry->caller));
    UnlockHcMutex(g_operationMutex);
    return HC_SUCCESS;
}

int32_t GetOperationDataRecently(int32_t osAccountId, DevAuthOperationType type, char *record,
    uint32_t recordSize, uint32_t maxOperationCnt)
{
    (void)LockHcMutex(g_operationMutex);
    if (record == NULL) {
        UnlockHcMutex(g_operationMutex);
        return -1;
    }
    OsAccountOperationInfo *info = GetOperationInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_operationMutex);
        return -1;
    }
    uint32_t cnt = 0;
    int32_t offset = 0;
    Operation **entry;
    memset_s(record, recordSize, 0, recordSize);
    int64_t index = ((int64_t)HC_VECTOR_SIZE(&info->operations)) - 1;
    while (index >= 0 && cnt < maxOperationCnt) {
        entry = info->operations.getp(&info->operations, index);
        if ((entry == NULL) || (*entry == NULL) ||
            ((type != OPERATION_ANY) && ((*entry)->operationType != type))) {
            index--;
            continue;
        }
        int32_t incOffset = sprintf_s(record + offset, recordSize - offset - 1,
            "[caller: %s, function: %s, operationInfo: %s, type:%u opTime: %ld]",
            StringGet(&(*entry)->caller), StringGet(&(*entry)->function),
            StringGet(&(*entry)->operationInfo), (*entry)->operationType,
            (*entry)->operationTime);
        if (incOffset <= 0) {
            break;
        }
        offset += incOffset;
        index--;
        cnt++;
    }
    UnlockHcMutex(g_operationMutex);
    LOGI("[Operation]: get operation record success!");
    return offset;
}

static void LoadDeviceAuthDb(void)
{
    if (IsOsAccountSupported()) {
        return;
    }
    (void)LockHcMutex(g_operationMutex);
    StringVector osAccountDbNameVec = CreateStrVector();
    HcFileGetSubFileName(GetStorageDirPath(), &osAccountDbNameVec);
    HcString *dbName;
    uint32_t index;
    FOR_EACH_HC_VECTOR(osAccountDbNameVec, index, dbName) {
        int32_t osAccountId;
        const char *osAccountIdStr = StringGet(dbName);
        if (osAccountIdStr == NULL) {
            LOGW("[Operation]: Invalid osAccountIdStr!");
            continue;
        }
        if (IsStrEqual(osAccountIdStr, "hcoperation.dat")) {
            LoadOsAccountDb(DEFAULT_OS_ACCOUNT);
        } else if (sscanf_s(osAccountIdStr, "hcoperation%d.dat", &osAccountId) == 1) {
            LoadOsAccountDb(osAccountId);
        }
    }
    DestroyStrVector(&osAccountDbNameVec);
    UnlockHcMutex(g_operationMutex);
}


#ifdef DEV_AUTH_HIVIEW_ENABLE
static char *HcFormatTime(int64_t timestamp)
{
    char *curTime = (char*)HcMalloc(TIME_LEN, 0);
    if (curTime != NULL) {
        struct tm *tm_info = localtime((time_t*)&timestamp);
        strftime(curTime, TIME_LEN, "%Y-%m-%d %H:%M:%S", tm_info);
        return curTime;
    }
    return NULL;
}
static void DumpOperation(int fd, const Operation *operation)
{
    dprintf(fd, "||---------------------------Operation---------------------------|                  |\n");
    dprintf(fd, "||%-12s = %47s|                  |\n", "caller", StringGet(&operation->caller));
    dprintf(fd, "||%-12s = %47s|                  |\n", "function", StringGet(&operation->function));
    dprintf(fd, "||%-12s = %47s|                  |\n", "operationInfo", StringGet(&operation->operationInfo));
    dprintf(fd, "||%-12s = %47d|                  |\n", "operationType", operation->operationType);
    char *curTime = HcFormatTime(operation->operationTime);
    dprintf(fd, "||%-12s = %47d                   \n", "operationTime", operation->operationTime);
    dprintf(fd, "||---------------------------Operation---------------------------|                  |\n");
    HcFree(curTime);
}

static void DumpDb(int fd, const OsAccountOperationInfo *db)
{
    const OperationVec *operations = &db->operations;
    dprintf(fd, "|------------------------------------OperationDB------------------------------------|\n");
    dprintf(fd, "|%-12s = %-68d|\n", "osAccountId", db->osAccountId);
    dprintf(fd, "|%-12s = %-68d|\n", "operationNum", operations->size(operations));
    uint32_t index;
    Operation **operation;
    FOR_EACH_HC_VECTOR(*operations, index, operation) {
        DumpOperation(fd, *operation);
    }
    dprintf(fd, "|------------------------------------OperationDB------------------------------------|\n");
}

static void LoadAllAccountsData(void)
{
    int32_t *accountIds = NULL;
    uint32_t size = 0;
    int32_t ret = GetAllOsAccountIds(&accountIds, &size);
    if (ret != HC_SUCCESS) {
        LOGE("[Operation]: Failed to get all os account ids, [res]: %" LOG_PUB "d", ret);
        return;
    }
    for (uint32_t index = 0; index < size; index++) {
        LoadDataIfNotLoaded(accountIds[index]);
    }
    HcFree(accountIds);
}

static void DevAuthDataBaseDump(int fd)
{
    if (g_operationMutex == NULL) {
        LOGE("[Operation]: Init mutex failed");
        return;
    }
    (void)LockHcMutex(g_operationMutex);
    if (IsOsAccountSupported()) {
        LoadAllAccountsData();
    }
    uint32_t index;
    OsAccountOperationInfo *info;
    FOR_EACH_HC_VECTOR(g_operationDb, index, info) {
        DumpDb(fd, info);
    }
    UnlockHcMutex(g_operationMutex);
}
#endif

int32_t InitOperationDataManager(void)
{
    if (g_operationMutex == NULL) {
        g_operationMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_operationMutex == NULL) {
            LOGE("[Operation]: Alloc operation mutex failed.");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (InitHcMutex(g_operationMutex, false) != HC_SUCCESS) {
            LOGE("[Operation]: Init mutex failed");
            HcFree(g_operationMutex);
            g_operationMutex = NULL;
            return HC_ERR_INIT_FAILED;
        }
    }
    g_operationDb = CREATE_HC_VECTOR(OperationDb);
    LoadDeviceAuthDb();
    DEV_AUTH_REG_OPERATION_DUMP_FUNC(DevAuthDataBaseDump);
    return HC_SUCCESS;
}

void DestroyOperationDataManager(void)
{
    (void)LockHcMutex(g_operationMutex);
    SaveAllOperationInfo();
    uint32_t index;
    OsAccountOperationInfo *info;
    FOR_EACH_HC_VECTOR(g_operationDb, index, info) {
        if (info == NULL) {
            continue;
        }
        ClearOperationVec(&info->operations);
    }
    DESTROY_HC_VECTOR(OperationDb, &g_operationDb);
    UnlockHcMutex(g_operationMutex);
    DestroyHcMutex(g_operationMutex);
    HcFree(g_operationMutex);
    g_operationMutex = NULL;
}