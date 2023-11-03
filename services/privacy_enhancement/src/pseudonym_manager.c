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

#include "pseudonym_manager.h"

#include "string_util.h"
#include "hc_dev_info.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_time.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "os_account_adapter.h"
#include "security_label_adapter.h"

#define MAX_REFRESH_COUNT 1000
#define MAX_REFRESH_TIME 86400
#define MAX_DB_PATH_LEN 256
typedef struct {
    char *pseudonymId;
    char *indexKey;
    char *realInfo;
    char *deviceId;
    int32_t refreshCount;
    int64_t startTime;
} PseudonymInfo;

DECLARE_HC_VECTOR(PseudonymInfoVec, PseudonymInfo*);
IMPLEMENT_HC_VECTOR(PseudonymInfoVec, PseudonymInfo*, 1);

typedef struct {
    int32_t osAccountId;
    PseudonymInfoVec pseudonymInfoVec;
} OsAccountPseudonymInfo;

DECLARE_HC_VECTOR(PseudonymDb, OsAccountPseudonymInfo)
IMPLEMENT_HC_VECTOR(PseudonymDb, OsAccountPseudonymInfo, 1)

static PseudonymDb g_pseudonymDb;
static HcMutex *g_mutex = NULL;
static bool g_isInitial = false;

void DestroyPseudonymInfo(PseudonymInfo *pseudonymInfo)
{
    if (pseudonymInfo == NULL) {
        LOGE("Input pseudonymInfo is null");
        return;
    }
    HcFree(pseudonymInfo->pseudonymId);
    HcFree(pseudonymInfo->realInfo);
    HcFree(pseudonymInfo->deviceId);
    HcFree(pseudonymInfo->indexKey);
    HcFree(pseudonymInfo);
}

void ClearPseudonymInfoVec(PseudonymInfoVec *vec)
{
    uint32_t index;
    PseudonymInfo **pseudonymInfoEntry;
    FOR_EACH_HC_VECTOR(*vec, index, pseudonymInfoEntry) {
        DestroyPseudonymInfo(*pseudonymInfoEntry);
    }
    DestroyPseudonymInfoVec(vec);
}

static PseudonymInfo **QueryPseudonymInfoPtrIfMatch(const PseudonymInfoVec *vec, const char *realInfo)
{
    if (realInfo == NULL) {
        LOGE("Invalid input realInfo.");
        return NULL;
    }
    uint32_t index;
    PseudonymInfo **pseudonymInfo;
    FOR_EACH_HC_VECTOR(*vec, index, pseudonymInfo) {
        if (strcmp(realInfo, (*pseudonymInfo)->realInfo) == 0) {
            return pseudonymInfo;
        }
    }
    return NULL;
}

PseudonymInfo *CreatePseudonymInfo(void)
{
    PseudonymInfo *pseudonymInfo = (PseudonymInfo *)HcMalloc(sizeof(PseudonymInfo), 0);
    if (pseudonymInfo == NULL) {
        LOGE("Failed to allocate pseudonymInfo memory!");
        return NULL;
    }
    pseudonymInfo->pseudonymId = NULL;
    pseudonymInfo->indexKey = NULL;
    pseudonymInfo->realInfo = NULL;
    pseudonymInfo->deviceId = NULL;
    pseudonymInfo->refreshCount = MAX_REFRESH_COUNT;
    pseudonymInfo->startTime = HcGetCurTime();
    return pseudonymInfo;
}

static int32_t GeneratePseudonymInfoFromJson(const CJson *pseudonymJson, PseudonymInfo *pseudonymInfoEntry)
{
    const char *pseudonymId = GetStringFromJson(pseudonymJson, FIELD_PSEUDONYM_ID);
    if (pseudonymId == NULL) {
        LOGE("Failed to get pseudonymId");
        return HC_ERR_JSON_GET;
    }
    GOTO_IF_ERR(DeepCopyString(pseudonymId, &pseudonymInfoEntry->pseudonymId));

    const char *indexKey = GetStringFromJson(pseudonymJson, FIELD_INDEX_KEY);
    if (indexKey == NULL) {
        LOGE("Failed to get indexKey");
        return HC_ERR_JSON_GET;
    }
    GOTO_IF_ERR(DeepCopyString(indexKey, &pseudonymInfoEntry->indexKey));

    const char *realInfo = GetStringFromJson(pseudonymJson, FIELD_REAL_INFO);
    if (realInfo == NULL) {
        LOGE("Failed to get realInfo");
        return HC_ERR_JSON_GET;
    }
    GOTO_IF_ERR(DeepCopyString(realInfo, &pseudonymInfoEntry->realInfo));

    const char *deviceId = GetStringFromJson(pseudonymJson, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId");
        return HC_ERR_JSON_GET;
    }
    GOTO_IF_ERR(DeepCopyString(deviceId, &pseudonymInfoEntry->deviceId));

    pseudonymInfoEntry->refreshCount = 0;
    pseudonymInfoEntry->startTime = 0;
    return HC_SUCCESS;
ERR:
    LOGE("Failed to copy string");
    return HC_ERR_MEMORY_COPY;
}

static int32_t CreatePseudonymFromJson(CJson *pseudonymJson, PseudonymInfoVec *vec)
{
    int32_t num = GetItemNum(pseudonymJson);
    if (num <= 0) {
        LOGE("No pseudonym info found.");
        return HC_ERR_JSON_GET;
    }
    int32_t ret;
    for (int32_t i = 0; i < num; i++) {
        CJson *pseudonymEntryJson = GetItemFromArray(pseudonymJson, i);
        if (pseudonymEntryJson == NULL) {
            LOGE("pseudonym entry json is null");
            return HC_ERR_JSON_GET;
        }
        PseudonymInfo *pseudonymInfo = CreatePseudonymInfo();
        if (pseudonymInfo == NULL) {
            LOGE("Failed to create pseudonymInfo");
            return HC_ERR_ALLOC_MEMORY;
        }
        ret = GeneratePseudonymInfoFromJson(pseudonymEntryJson, pseudonymInfo);
        if (ret != HC_SUCCESS) {
            LOGE("Generate pseudonymInfo failed");
            DestroyPseudonymInfo(pseudonymInfo);
            return ret;
        }
        if (vec->pushBackT(vec, pseudonymInfo) == NULL) {
            LOGE("Failed to push pseudonymInfo to vec");
            DestroyPseudonymInfo(pseudonymInfo);
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static bool GetPseudonymPathCe(int32_t osAccountId, char *path, uint32_t pathBufferLen)
{
    const char *beginPath = GetStorageDirPathCe();
    if (beginPath == NULL) {
        LOGE("Failed to get the storage path!");
        return false;
    }
    if (sprintf_s(path, pathBufferLen, "%s/%d/deviceauth/pseudonym/pseudonym_data.dat", beginPath, osAccountId) <= 0) {
        LOGE("Failed to generate pseudonym path!");
        return false;
    }
    return true;
}

static bool GetPseudonymPathDe(int32_t osAccountId, char *path, uint32_t pathBufferLen)
{
    const char *beginPath = GetPseudonymStoragePath();
    if (beginPath == NULL) {
        LOGE("Failed to get the pseudonym storage path!");
        return false;
    }
    int32_t writeByteNum;
    if (osAccountId == DEFAULT_OS_ACCOUNT) {
        writeByteNum = sprintf_s(path, pathBufferLen, "%s/pseudonym_data.dat", beginPath);
    } else {
        writeByteNum = sprintf_s(path, pathBufferLen, "%s/pseudonym_data%d.dat", beginPath, osAccountId);
    }
    if (writeByteNum <= 0) {
        LOGE("sprintf_s fail!");
        return false;
    }
    return true;
}

static bool GetPseudonymPath(int32_t osAccountId, char *path, uint32_t pathBufferLen)
{
    if (IsOsAccountSupported()) {
        return GetPseudonymPathCe(osAccountId, path, pathBufferLen);
    } else {
        return GetPseudonymPathDe(osAccountId, path, pathBufferLen);
    }
}

static int32_t OpenPseudonymFile(int32_t osAccountId, FileHandle *file, int32_t mode)
{
    char *pseudonymPath = (char *)HcMalloc(MAX_DB_PATH_LEN, 0);
    if (pseudonymPath == NULL) {
        LOGE("Malloc pseudonym Path failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (!GetPseudonymPath(osAccountId, pseudonymPath, MAX_DB_PATH_LEN)) {
        LOGE("Get pseudonym path failed");
        HcFree(pseudonymPath);
        return HC_ERROR;
    }
    int32_t ret = HcFileOpen(pseudonymPath, mode, file);
    if (ret == HC_SUCCESS) {
        SetSecurityLabel(pseudonymPath, SECURITY_LABEL_S2);
    }
    HcFree(pseudonymPath);
    return ret;
}

static int32_t LoadPseudonymDataFromFile(int32_t osAccountId, PseudonymInfoVec *vec)
{
    if (vec == NULL) {
        LOGE("Input PseudonymInfo vec is null.");
        return HC_ERR_NULL_PTR;
    }
    FileHandle file = { 0 };
    int32_t ret = OpenPseudonymFile(osAccountId, &file, MODE_FILE_READ);
    if (ret != HC_SUCCESS) {
        LOGE("Open pseudonym data file failed, ret:%d", ret);
        return ret;
    }
    int32_t fileSize = HcFileSize(file);
    if (fileSize <= 0) {
        LOGE("file size stat failed");
        HcFileClose(file);
        return HC_ERROR;
    }
    char *fileData = (char *)HcMalloc(fileSize, 0);
    if (fileData == NULL) {
        LOGE("Malloc file data failed");
        HcFileClose(file);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (HcFileRead(file, fileData, fileSize) != fileSize) {
        LOGE("fileData read failed");
        HcFileClose(file);
        HcFree(fileData);
        return HC_ERROR;
    }
    HcFileClose(file);
    CJson *readJsonFile = CreateJsonFromString(fileData);
    HcFree(fileData);
    if (readJsonFile == NULL) {
        LOGE("fileData parse failed");
        return HC_ERR_JSON_CREATE;
    }
    ret = CreatePseudonymFromJson(readJsonFile, vec);
    FreeJson(readJsonFile);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to read pseudonym data from json");
    }

    return ret;
}

static bool IsNeedRefresh(PseudonymInfo *pseudonymInfo)
{
    if (pseudonymInfo->refreshCount <= 0) {
        LOGI("count is 0, need refresh pseudonymId");
        return true;
    }
    int64_t curTime = HcGetCurTime();
    if (curTime > (pseudonymInfo->startTime + MAX_REFRESH_TIME)) {
        LOGI("time is overdue, need refresh pseudonymId");
        return true;
    }
    return false;
}

static int32_t GenerateJsonFromPseudonymInfo(PseudonymInfo *pseudonymInfo, CJson *pseudonymJson)
{
    if (AddStringToJson(pseudonymJson, FIELD_PSEUDONYM_ID, pseudonymInfo->pseudonymId) != HC_SUCCESS) {
        LOGE("Add pseudonymId to json failed");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(pseudonymJson, FIELD_INDEX_KEY, pseudonymInfo->indexKey) != HC_SUCCESS) {
        LOGE("Add indexKey to json failed");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(pseudonymJson, FIELD_REAL_INFO, pseudonymInfo->realInfo) != HC_SUCCESS) {
        LOGE("Add realInfo to json failed");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(pseudonymJson, FIELD_DEVICE_ID, pseudonymInfo->deviceId) != HC_SUCCESS) {
        LOGE("Add deviceId to json failed");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t WritePseudonymJsonToFile(int32_t osAccountId, CJson *Json)
{
    char *storeJsonString = PackJsonToString(Json);
    if (storeJsonString == NULL) {
        LOGE("Pack stored json to string failed.");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    FileHandle file = { 0 };
    int32_t ret = OpenPseudonymFile(osAccountId, &file, MODE_FILE_WRITE);
    if (ret != HC_SUCCESS) {
        LOGE("Open pseudonym file failed.");
        FreeJsonString(storeJsonString);
        return ret;
    }
    int32_t fileSize = (int32_t)(HcStrlen(storeJsonString) + 1);
    if (HcFileWrite(file, storeJsonString, fileSize) != fileSize) {
        LOGE("Failed to write Pseudonym array to file.");
        ret = HC_ERR_FILE;
    }
    FreeJsonString(storeJsonString);
    HcFileClose(file);
    return ret;
}

static int32_t SavePseudonymInfoToFile(int32_t osAccountId, const PseudonymInfoVec *vec)
{
    CJson *storeJson = CreateJsonArray();
    if (storeJson == NULL) {
        LOGE("Create json failed when save Pseudonym data to file.");
        return HC_ERR_JSON_CREATE;
    }
    int32_t ret;
    uint32_t index;
    PseudonymInfo **pseudonymInfoEntry;
    FOR_EACH_HC_VECTOR(*vec, index, pseudonymInfoEntry) {
        CJson *entryJson = CreateJson();
        if (entryJson == NULL) {
            LOGE("Create json failed.");
            FreeJson(storeJson);
            return HC_ERR_JSON_CREATE;
        }
        ret = GenerateJsonFromPseudonymInfo(*pseudonymInfoEntry, entryJson);
        if (ret != HC_SUCCESS) {
            LOGE("Generate json from pseudonymInfo failed");
            FreeJson(entryJson);
            FreeJson(storeJson);
            return ret;
        }
        if (AddObjToArray(storeJson, entryJson) != HC_SUCCESS) {
            LOGE("Add pseudonymInfoEntry json to array failed");
            FreeJson(entryJson);
            FreeJson(storeJson);
            return HC_ERR_JSON_ADD;
        }
    }
    ret = WritePseudonymJsonToFile(osAccountId, storeJson);
    FreeJson(storeJson);
    return ret;
}

static const char *GetParamByFieldName(const char *fieldName, PseudonymInfo *pseudonymInfoEntry)
{
    if (strcmp(fieldName, FIELD_DEVICE_ID) == 0) {
        return pseudonymInfoEntry->deviceId;
    } else if (strcmp(fieldName, FIELD_INDEX_KEY) == 0) {
        return pseudonymInfoEntry->indexKey;
    } else {
        LOGE("Not support this field!");
        return NULL;
    }
}

static void LoadOsAccountPseudonymDb(int32_t osAccountId)
{
    OsAccountPseudonymInfo info;
    info.osAccountId = osAccountId;
    info.pseudonymInfoVec = CreatePseudonymInfoVec();
    if (LoadPseudonymDataFromFile(osAccountId, &info.pseudonymInfoVec) != HC_SUCCESS) {
        ClearPseudonymInfoVec(&info.pseudonymInfoVec);
        return;
    }
    if (g_pseudonymDb.pushBackT(&g_pseudonymDb, info) == NULL) {
        LOGE("Failed to push osAccountInfo to database!");
        ClearPseudonymInfoVec(&info.pseudonymInfoVec);
    }
    LOGI("Load pseudonym os account db successfully! [Id]: %d", osAccountId);
}

static void OnOsAccountUnlocked(int32_t osAccountId)
{
    LOGI("Os account is unlocked, osAccountId: %d", osAccountId);
    g_mutex->lock(g_mutex);
    LoadOsAccountPseudonymDb(osAccountId);
    g_mutex->unlock(g_mutex);
}

static void RemoveOsAccountPseudonymInfo(int32_t osAccountId)
{
    uint32_t index = 0;
    OsAccountPseudonymInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_pseudonymDb, index, info) {
        if (info->osAccountId == osAccountId) {
            OsAccountPseudonymInfo deleteInfo;
            HC_VECTOR_POPELEMENT(&g_pseudonymDb, &deleteInfo, index);
            ClearPseudonymInfoVec(&deleteInfo.pseudonymInfoVec);
            return;
        }
    }
}

static void OnOsAccountRemoved(int32_t osAccountId)
{
    LOGI("Os account is removed, osAccountId: %d", osAccountId);
    g_mutex->lock(g_mutex);
    RemoveOsAccountPseudonymInfo(osAccountId);
    g_mutex->unlock(g_mutex);
}

static bool IsOsAccountDataLoaded(int32_t osAccountId)
{
    uint32_t index = 0;
    OsAccountPseudonymInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_pseudonymDb, index, info) {
        if (info->osAccountId == osAccountId) {
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
    LOGI("Data has not been loaded, load it, osAccountId: %d", osAccountId);
    LoadOsAccountPseudonymDb(osAccountId);
}

static OsAccountPseudonymInfo *GetPseudonymInfoByOsAccountId(int32_t osAccountId)
{
    if (IsOsAccountSupported()) {
        LoadDataIfNotLoaded(osAccountId);
    }
    uint32_t index = 0;
    OsAccountPseudonymInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_pseudonymDb, index, info) {
        if (info->osAccountId == osAccountId) {
            return info;
        }
    }
    LOGI("Create a new os account database cache! [Id]: %d", osAccountId);
    OsAccountPseudonymInfo newInfo;
    newInfo.osAccountId = osAccountId;
    newInfo.pseudonymInfoVec = CreatePseudonymInfoVec();
    OsAccountPseudonymInfo *returnInfo = g_pseudonymDb.pushBackT(&g_pseudonymDb, newInfo);
    if (returnInfo == NULL) {
        LOGE("Failed to push OsAccountPseudonymInfo to database!");
        DestroyPseudonymInfoVec(&newInfo.pseudonymInfoVec);
    }
    return returnInfo;
}

static int32_t SaveOsAccountPseudonymDb(int32_t osAccountId)
{
    g_mutex->lock(g_mutex);
    OsAccountPseudonymInfo *info = GetPseudonymInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Get pseudonym info by os account id failed");
        g_mutex->unlock(g_mutex);
        return HC_ERROR;
    }
    int32_t ret = SavePseudonymInfoToFile(osAccountId, &info->pseudonymInfoVec);
    if (ret != HC_SUCCESS) {
        LOGE("Save pseudonym info to file failed");
        g_mutex->unlock(g_mutex);
        return ret;
    }
    g_mutex->unlock(g_mutex);
    LOGI("Save an os account database successfully! [Id]: %d", osAccountId);
    return HC_SUCCESS;
}

static int32_t DeletePseudonymInner(int32_t osAccountId, const char *dataTodelete, PseudonymInfoVec *deleteVec,
    const char *fieldName)
{
    LOGI("Start to delete Pseudonym from database!");
    g_mutex->lock(g_mutex);
    OsAccountPseudonymInfo *info = GetPseudonymInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Get pseudonym info by os account id failed");
        g_mutex->unlock(g_mutex);
        return HC_ERROR;
    }
    int32_t count = 0;
    uint32_t index = 0;
    PseudonymInfo **pseudonymInfoEntry = NULL;
    while (index < HC_VECTOR_SIZE(&info->pseudonymInfoVec)) {
        pseudonymInfoEntry = info->pseudonymInfoVec.getp(&info->pseudonymInfoVec, index);
        if ((pseudonymInfoEntry == NULL) || (*pseudonymInfoEntry == NULL) ||
            (strcmp(dataTodelete, GetParamByFieldName(fieldName, *pseudonymInfoEntry))) != 0) {
            index++;
            continue;
        }
        PseudonymInfo *deletepseudonymInfoEntry = NULL;
        HC_VECTOR_POPELEMENT(&info->pseudonymInfoVec, &deletepseudonymInfoEntry, index);
        count++;
        LOGI("Delete pseudonymInfoEntry from database successfully!");
        if (deleteVec->pushBackT(deleteVec, deletepseudonymInfoEntry) == NULL) {
            LOGE("Failed to push deleted pseudonymInfoEntry to vec");
            DestroyPseudonymInfo(deletepseudonymInfoEntry);
        }
    }
    g_mutex->unlock(g_mutex);
    if (count == 0) {
        LOGE("No pseudonym info deleted");
        return HC_ERROR;
    }
    LOGI("Number of pseudonym info deleted: %d", count);
    return HC_SUCCESS;
}

static void InitPseudonymManger(void)
{
    if (g_mutex == NULL) {
        g_mutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_mutex == NULL) {
            LOGE("Alloc sessionMutex failed");
            return;
        }
        if (InitHcMutex(g_mutex) != HC_SUCCESS) {
            LOGE("Init mutex failed");
            HcFree(g_mutex);
            g_mutex = NULL;
            return;
        }
    }
    g_mutex->lock(g_mutex);
    if (!g_isInitial) {
        g_pseudonymDb = CREATE_HC_VECTOR(PseudonymDb);
        AddOsAccountEventCallback(PSEUDONYM_DATA_CALLBACK, OnOsAccountUnlocked, OnOsAccountRemoved);
        g_isInitial = true;
    }
    g_mutex->unlock(g_mutex);
}

static void LoadPseudonymData(void)
{
    InitPseudonymManger();
    if (IsOsAccountSupported()) {
        return;
    }
    g_mutex->lock(g_mutex);
    StringVector dbNameVec = CreateStrVector();
    HcFileGetSubFileName(GetPseudonymStoragePath(), &dbNameVec);
    uint32_t index;
    HcString *dbName = NULL;
    FOR_EACH_HC_VECTOR(dbNameVec, index, dbName) {
        int32_t osAccountId;
        const char *name = StringGet(dbName);
        if (name == NULL) {
            continue;
        }
        if (strcmp(name, "pseudonym_data.dat") == 0) {
            LoadOsAccountPseudonymDb(DEFAULT_OS_ACCOUNT);
        } else if (sscanf_s(name, "pseudonym_data%d.dat", &osAccountId) == 1) {
            LoadOsAccountPseudonymDb(osAccountId);
        }
    }
    DestroyStrVector(&dbNameVec);
    g_mutex->unlock(g_mutex);
}

static int32_t GetRealInfo(int32_t osAccountId, const char *pseudonymId, char **realInfo)
{
    if (pseudonymId == NULL || realInfo == NULL) {
        LOGE("pseudonymId is null!");
        return HC_ERR_INVALID_PARAMS;
    }
    InitPseudonymManger();
    g_mutex->lock(g_mutex);
    OsAccountPseudonymInfo *info = GetPseudonymInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get Pseudonym by os account id");
        g_mutex->unlock(g_mutex);
        return HC_ERROR;
    }
    uint32_t index;
    PseudonymInfo **pseudonymInfoEntry = NULL;
    FOR_EACH_HC_VECTOR(info->pseudonymInfoVec, index, pseudonymInfoEntry) {
        if ((pseudonymInfoEntry != NULL) && (*pseudonymInfoEntry != NULL) &&
            (strcmp((*pseudonymInfoEntry)->pseudonymId, pseudonymId) == 0)) {
            if (DeepCopyString((*pseudonymInfoEntry)->realInfo, realInfo) != HC_SUCCESS) {
                LOGE("Failed to deep copy realInfo!");
                g_mutex->unlock(g_mutex);
                return HC_ERR_MEMORY_COPY;
            }
            g_mutex->unlock(g_mutex);
            return HC_SUCCESS;
        }
    }
    g_mutex->unlock(g_mutex);
    return HC_SUCCESS;
}

static int32_t GetPseudonymId(int32_t osAccountId, const char *indexKey, char **pseudonymId)
{
    if (indexKey == NULL || pseudonymId == NULL) {
        LOGE("input params is null!");
        return HC_ERR_INVALID_PARAMS;
    }
    InitPseudonymManger();
    g_mutex->lock(g_mutex);
    OsAccountPseudonymInfo *info = GetPseudonymInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get Pseudonym by os account id");
        g_mutex->unlock(g_mutex);
        return HC_ERROR;
    }
    uint32_t index;
    PseudonymInfo **pseudonymInfoEntry = NULL;
    FOR_EACH_HC_VECTOR(info->pseudonymInfoVec, index, pseudonymInfoEntry) {
        if ((pseudonymInfoEntry != NULL) && (*pseudonymInfoEntry != NULL) &&
            (strcmp((*pseudonymInfoEntry)->indexKey, indexKey) == 0)) {
            if (DeepCopyString((*pseudonymInfoEntry)->pseudonymId, pseudonymId) != HC_SUCCESS) {
                LOGE("Failed to deep copy pseudonymId!");
                g_mutex->unlock(g_mutex);
                return HC_ERR_MEMORY_COPY;
            }
            g_mutex->unlock(g_mutex);
            return HC_SUCCESS;
        }
    }
    g_mutex->unlock(g_mutex);
    return HC_SUCCESS;
}

static int32_t AddPseudonymIdInfoToMemory(int32_t osAccountId, PseudonymInfo *pseudonymInfo)
{
    LOGI("Start to add a pseudonymInfo to memory!");
    g_mutex->lock(g_mutex);
    OsAccountPseudonymInfo *info = GetPseudonymInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get Pseudonym by os account id");
        g_mutex->unlock(g_mutex);
        return HC_ERROR;
    }
    PseudonymInfo **oldPtr = QueryPseudonymInfoPtrIfMatch(&info->pseudonymInfoVec,
        pseudonymInfo->realInfo);
    if (oldPtr != NULL) {
        DestroyPseudonymInfo(*oldPtr);
        *oldPtr = pseudonymInfo;
        g_mutex->unlock(g_mutex);
        LOGI("Replace an old pseudonymInfo successfully!");
        return HC_SUCCESS;
    }
    if (info->pseudonymInfoVec.pushBackT(&info->pseudonymInfoVec, pseudonymInfo) == NULL) {
        g_mutex->unlock(g_mutex);
        LOGE("Failed to push pseudonymInfo to vec!");
        return HC_ERR_MEMORY_COPY;
    }
    g_mutex->unlock(g_mutex);
    LOGI("Add pseudonymInfo to memory successfully!");
    return HC_SUCCESS;
}

static PseudonymInfo *BuildPseudonymInfoEntry(const char *realInfo, const char *pseudonymId, const char *deviceId,
    const char *indexKey)
{
    PseudonymInfo *pseudonymInfoEntry = CreatePseudonymInfo();
    if (pseudonymInfoEntry == NULL) {
        LOGE("Failed to create pseudonymInfoEntry");
        return NULL;
    }
    GOTO_IF_ERR(DeepCopyString(pseudonymId, &pseudonymInfoEntry->pseudonymId));
    GOTO_IF_ERR(DeepCopyString(realInfo, &pseudonymInfoEntry->realInfo));
    GOTO_IF_ERR(DeepCopyString(deviceId, &pseudonymInfoEntry->deviceId));
    GOTO_IF_ERR(DeepCopyString(indexKey, &pseudonymInfoEntry->indexKey));
    return pseudonymInfoEntry;
ERR:
    DestroyPseudonymInfo(pseudonymInfoEntry);
    return NULL;
}

static int32_t SavePseudonymId(int32_t osAccountId, const char *pseudonymId, const char *realInfo, const char *deviceId,
    const char *indexKey)
{
    if (realInfo == NULL || pseudonymId == NULL || deviceId == NULL || indexKey == NULL) {
        LOGE("params is null!");
        return HC_ERR_INVALID_PARAMS;
    }
    InitPseudonymManger();
    PseudonymInfo *pseudonymInfo = BuildPseudonymInfoEntry(realInfo, pseudonymId, deviceId, indexKey);
    if (pseudonymInfo == NULL) {
        LOGE("Failed to build pseudonymInfoEntry");
        return HC_ERROR;
    }
    int ret = AddPseudonymIdInfoToMemory(osAccountId, pseudonymInfo);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to add pseudonymId info to memory");
        DestroyPseudonymInfo(pseudonymInfo);
        return ret;
    }
    ret = SaveOsAccountPseudonymDb(osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to add Save Pseudonym info to Database");
        DestroyPseudonymInfo(pseudonymInfo);
        return ret;
    }
    return HC_SUCCESS;
}

static int32_t DeleteAllPseudonymId(int32_t osAccountId, const char *deviceId)
{
    if (deviceId == NULL) {
        LOGE("deviceId is null!");
        return HC_ERR_INVALID_PARAMS;
    }
    InitPseudonymManger();
    PseudonymInfoVec deletePseudonymIdVec = CreatePseudonymInfoVec();
    int32_t ret = DeletePseudonymInner(osAccountId, deviceId, &deletePseudonymIdVec, FIELD_DEVICE_ID);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to delete pseudonym inner, account id is: %d", osAccountId);
        DestroyPseudonymInfoVec(&deletePseudonymIdVec);
        return ret;
    }
    ret = SaveOsAccountPseudonymDb(osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to save pseudonym data to db, account id is: %d", osAccountId);
        ClearPseudonymInfoVec(&deletePseudonymIdVec);
        return ret;
    }
    ClearPseudonymInfoVec(&deletePseudonymIdVec);
    return HC_SUCCESS;
}

static int32_t DeletePseudonymId(int32_t osAccountId, const char *indexKey)
{
    if (indexKey == NULL) {
        LOGE("indexKey is null!");
        return HC_ERR_INVALID_PARAMS;
    }
    InitPseudonymManger();
    PseudonymInfoVec deletePseudonymIdVec = CreatePseudonymInfoVec();
    int32_t ret = DeletePseudonymInner(osAccountId, indexKey, &deletePseudonymIdVec, FIELD_INDEX_KEY);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to delete pseudonym inner, account id is: %d", osAccountId);
        DestroyPseudonymInfoVec(&deletePseudonymIdVec);
        return ret;
    }
    ret = SaveOsAccountPseudonymDb(osAccountId);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to save pseudonym data to db, account id is: %d", osAccountId);
        ClearPseudonymInfoVec(&deletePseudonymIdVec);
        return ret;
    }
    ClearPseudonymInfoVec(&deletePseudonymIdVec);
    return HC_SUCCESS;
}

static bool IsNeedRefreshPseudonymId(int32_t osAccountId, const char *indexKey)
{
    if (indexKey == NULL) {
        LOGE("indexKey is null");
        return true;
    }
    InitPseudonymManger();
    g_mutex->lock(g_mutex);
    OsAccountPseudonymInfo *info = GetPseudonymInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get Pseudonym by os account id");
        g_mutex->unlock(g_mutex);
        return true;
    }
    uint32_t index;
    PseudonymInfo **pseudonymInfoEntry = NULL;
    FOR_EACH_HC_VECTOR(info->pseudonymInfoVec, index, pseudonymInfoEntry) {
        if ((pseudonymInfoEntry != NULL) && (*pseudonymInfoEntry != NULL) &&
            (strcmp((*pseudonymInfoEntry)->indexKey, indexKey) == 0)) {
            if (IsNeedRefresh(*pseudonymInfoEntry)) {
                g_mutex->unlock(g_mutex);
                return true;
            }
            (*pseudonymInfoEntry)->refreshCount--;
            g_mutex->unlock(g_mutex);
            return false;
        }
    }
    g_mutex->unlock(g_mutex);
    return true;
}

static PseudonymManager g_pseudonymManager = {
    .loadPseudonymData = LoadPseudonymData,
    .getRealInfo = GetRealInfo,
    .getPseudonymId = GetPseudonymId,
    .savePseudonymId = SavePseudonymId,
    .deleteAllPseudonymId = DeleteAllPseudonymId,
    .deletePseudonymId = DeletePseudonymId,
    .isNeedRefreshPseudonymId = IsNeedRefreshPseudonymId
};

PseudonymManager *GetPseudonymInstance(void)
{
    return &g_pseudonymManager;
}

void DestroyPseudonymManager(void)
{
    g_mutex->lock(g_mutex);
    RemoveOsAccountEventCallback(PSEUDONYM_DATA_CALLBACK);
    uint32_t index;
    OsAccountPseudonymInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_pseudonymDb, index, info) {
        ClearPseudonymInfoVec(&info->pseudonymInfoVec);
    }
    DESTROY_HC_VECTOR(PseudonymDb, &g_pseudonymDb);
    g_mutex->unlock(g_mutex);
    DestroyHcMutex(g_mutex);
    HcFree(g_mutex);
    g_mutex = NULL;
}