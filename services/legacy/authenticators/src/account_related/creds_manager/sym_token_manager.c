/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "sym_token_manager.h"

#include "alg_defs.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "hc_dev_info.h"
#include "hal_error.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"
#include "os_account_adapter.h"
#include "security_label_adapter.h"
#include "string_util.h"

IMPLEMENT_HC_VECTOR(SymTokenVec, SymToken*, 1)

typedef struct {
    int32_t osAccountId;
    SymTokenVec tokens;
} OsSymTokensInfo;

DECLARE_HC_VECTOR(SymTokensDb, OsSymTokensInfo)
IMPLEMENT_HC_VECTOR(SymTokensDb, OsSymTokensInfo, 1)

#define FIELD_SYM_TOKENS "symTokens"

#define MAX_DB_PATH_LEN 256

SymTokenManager g_symTokenManager;

static SymTokensDb g_symTokensDb;
static HcMutex *g_dataMutex;

static bool IsTokenMatch(const SymToken *token, const char *userId, const char *deviceId)
{
    return (strcmp(userId, token->userId) == 0) && (strcmp(deviceId, token->deviceId) == 0);
}

static bool GetTokensFilePathCe(int32_t osAccountId, char *tokenPath, uint32_t pathBufferLen)
{
    const char *beginPath = GetStorageDirPathCe();
    if (beginPath == NULL) {
        LOGE("Failed to get the storage path!");
        return false;
    }
    if (sprintf_s(tokenPath, pathBufferLen, "%s/%d/deviceauth/account/account_data_sym.dat",
        beginPath, osAccountId) <= 0) {
        LOGE("Failed to generate token path!");
        return false;
    }
    return true;
}

static bool GetTokensFilePathDe(int32_t osAccountId, char *tokenPath, uint32_t pathBufferLen)
{
    const char *beginPath = GetAccountStoragePath();
    if (beginPath == NULL) {
        LOGE("Failed to get the account storage path!");
        return false;
    }
    int32_t writeByteNum;
    if (osAccountId == DEFAULT_OS_ACCOUNT) {
        writeByteNum = sprintf_s(tokenPath, pathBufferLen, "%s/account_data_sym.dat", beginPath);
    } else {
        writeByteNum = sprintf_s(tokenPath, pathBufferLen, "%s/account_data_sym%d.dat", beginPath, osAccountId);
    }
    if (writeByteNum <= 0) {
        LOGE("sprintf_s fail!");
        return false;
    }
    return true;
}

static bool GetTokensFilePath(int32_t osAccountId, char *tokenPath, uint32_t pathBufferLen)
{
    if (IsOsAccountSupported()) {
        return GetTokensFilePathCe(osAccountId, tokenPath, pathBufferLen);
    } else {
        return GetTokensFilePathDe(osAccountId, tokenPath, pathBufferLen);
    }
}

static SymToken *CreateSymTokenByJson(const CJson *tokenJson)
{
    SymToken *token = (SymToken *)HcMalloc(sizeof(SymToken), 0);
    if (token == NULL) {
        LOGE("Failed to allocate token memory!");
        return NULL;
    }
    const char *userId = GetStringFromJson(tokenJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId from json!");
        HcFree(token);
        return NULL;
    }
    const char *deviceId = GetStringFromJson(tokenJson, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGE("Failed to get deviceId from json!");
        HcFree(token);
        return NULL;
    }
    if (strcpy_s(token->userId, DEV_AUTH_USER_ID_SIZE, userId) != EOK) {
        LOGE("Failed to copy userId!");
        HcFree(token);
        return NULL;
    }
    if (strcpy_s(token->deviceId, DEV_AUTH_DEVICE_ID_SIZE, deviceId) != EOK) {
        LOGE("Failed to copy deviceId!");
        HcFree(token);
        return NULL;
    }
    return token;
}

static int32_t CreateTokensFromJson(CJson *tokensJson, SymTokenVec *vec)
{
    CJson *symTokensJson = GetObjFromJson(tokensJson, FIELD_SYM_TOKENS);
    if (symTokensJson == NULL) {
        LOGE("Failed to get symTokensJson from json!");
        return HC_ERR_JSON_GET;
    }
    int32_t tokenNum = GetItemNum(symTokensJson);
    if (tokenNum <= 0) {
        LOGE("No token found.");
        return HC_ERR_JSON_GET;
    }
    for (int32_t i = 0; i < tokenNum; i++) {
        CJson *tokenJson = GetItemFromArray(symTokensJson, i);
        if (tokenJson == NULL) {
            LOGE("Token json is null");
            ClearSymTokenVec(vec);
            return HC_ERR_JSON_GET;
        }
        SymToken *symToken = CreateSymTokenByJson(tokenJson);
        if (symToken == NULL) {
            LOGE("Failed to create symToken from json!");
            ClearSymTokenVec(vec);
            return HC_ERR_ALLOC_MEMORY;
        }
        if (vec->pushBackT(vec, symToken) == NULL) {
            LOGE("Failed to push symToken to vec");
            HcFree(symToken);
            ClearSymTokenVec(vec);
            return HC_ERR_MEMORY_COPY;
        }
    }
    return HC_SUCCESS;
}

static int32_t ReadTokensFromFile(SymTokenVec *vec, const char *tokenPath)
{
    if (vec == NULL) {
        LOGE("Input token vec is null.");
        return HC_ERR_NULL_PTR;
    }
    FileHandle file = { 0 };
    int32_t ret = HcFileOpen(tokenPath, MODE_FILE_READ, &file);
    if (ret != HC_SUCCESS) {
        LOGE("Open token file failed");
        return ret;
    }
    SetSecurityLabel(tokenPath, SECURITY_LABEL_S2);
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
    ret = CreateTokensFromJson(readJsonFile, vec);
    FreeJson(readJsonFile);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to create tokens from json");
    }
    return ret;
}

static int32_t WriteTokensJsonToFile(CJson *tokensJson, const char *tokenPath)
{
    char *storeJsonString = PackJsonToString(tokensJson);
    if (storeJsonString == NULL) {
        LOGE("Pack stored json to string failed.");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    FileHandle file = { 0 };
    int32_t ret = HcFileOpen(tokenPath, MODE_FILE_WRITE, &file);
    if (ret != HC_SUCCESS) {
        LOGE("Open token file failed.");
        FreeJsonString(storeJsonString);
        return ret;
    }
    SetSecurityLabel(tokenPath, SECURITY_LABEL_S2);
    int32_t fileSize = (int32_t)(HcStrlen(storeJsonString) + 1);
    if (HcFileWrite(file, storeJsonString, fileSize) != fileSize) {
        LOGE("Failed to write token array to file.");
        ret = HC_ERR_FILE;
    }
    FreeJsonString(storeJsonString);
    HcFileClose(file);
    return ret;
}

static int32_t GenerateJsonFromToken(const SymToken *token, CJson *tokenJson)
{
    if (AddStringToJson(tokenJson, FIELD_USER_ID, token->userId) != HC_SUCCESS) {
        LOGE("Failed to add userId to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(tokenJson, FIELD_DEVICE_ID, token->deviceId) != HC_SUCCESS) {
        LOGE("Failed to add deviceId to json!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t SaveTokensToFile(const SymTokenVec *vec, const char *tokenPath)
{
    CJson *symTokensJson = CreateJsonArray();
    if (symTokensJson == NULL) {
        LOGE("Create json failed when save tokens to file.");
        return HC_ERR_JSON_CREATE;
    }
    int32_t ret;
    uint32_t index;
    SymToken **token;
    FOR_EACH_HC_VECTOR(*vec, index, token) {
        CJson *tokenJson = CreateJson();
        if (tokenJson == NULL) {
            LOGE("Create token json failed.");
            FreeJson(symTokensJson);
            return HC_ERR_JSON_CREATE;
        }
        ret = GenerateJsonFromToken(*token, tokenJson);
        if (ret != HC_SUCCESS) {
            LOGE("Generate json from token failed");
            FreeJson(tokenJson);
            FreeJson(symTokensJson);
            return ret;
        }
        if (AddObjToArray(symTokensJson, tokenJson) != HC_SUCCESS) {
            LOGE("Add token json to array failed");
            FreeJson(tokenJson);
            FreeJson(symTokensJson);
            return HC_ERR_JSON_ADD;
        }
    }
    CJson *allTokensJson = CreateJson();
    if (allTokensJson == NULL) {
        LOGE("Failed to allocate tokensJson memory!");
        FreeJson(symTokensJson);
        return HC_ERR_JSON_CREATE;
    }
    if (AddObjToJson(allTokensJson, FIELD_SYM_TOKENS, symTokensJson) != HC_SUCCESS) {
        LOGE("Failed to add symTokensJson to json!");
        FreeJson(symTokensJson);
        FreeJson(allTokensJson);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(symTokensJson);
    ret = WriteTokensJsonToFile(allTokensJson, tokenPath);
    FreeJson(allTokensJson);
    return ret;
}

static SymToken **QueryTokenPtrIfMatch(const SymTokenVec *vec, const char *userId, const char *deviceId)
{
    uint32_t index;
    SymToken **token;
    FOR_EACH_HC_VECTOR(*vec, index, token) {
        if (IsTokenMatch(*token, userId, deviceId)) {
            return token;
        }
    }
    return NULL;
}

static int32_t GenerateKeyAlias(const char *userId, const char *deviceId, Uint8Buff *keyAlias)
{
    if ((userId == NULL) || (deviceId == NULL) || (keyAlias == NULL)) {
        LOGE("Invalid input params");
        return HC_ERR_NULL_PTR;
    }
    /* KeyAlias = sha256(userId + deviceId + tag). */
    const char *authCodeTag = "authCode";
    uint32_t authCodeTagLen = HcStrlen(authCodeTag);
    uint32_t userIdLen = HcStrlen(userId);
    uint32_t deviceIdLen = HcStrlen(deviceId);
    uint32_t aliasLen = authCodeTagLen + userIdLen + deviceIdLen;
    uint8_t *aliasVal = (uint8_t *)HcMalloc(aliasLen, 0);
    if (aliasVal == NULL) {
        LOGE("Failed to malloc for self key aliasStr.");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff oriAliasBuff = {
        aliasVal,
        aliasLen
    };
    if (memcpy_s(oriAliasBuff.val, oriAliasBuff.length, userId, userIdLen) != EOK) {
        LOGE("Failed to copy userId.");
        HcFree(aliasVal);
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(oriAliasBuff.val + userIdLen, oriAliasBuff.length - userIdLen, deviceId, deviceIdLen) != EOK) {
        LOGE("Failed to copy deviceId.");
        HcFree(aliasVal);
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(oriAliasBuff.val + userIdLen + deviceIdLen,
        oriAliasBuff.length - userIdLen - deviceIdLen, authCodeTag, authCodeTagLen) != EOK) {
        LOGE("Failed to copy authCodeTag.");
        HcFree(aliasVal);
        return HC_ERR_MEMORY_COPY;
    }
    int32_t res = GetLoaderInstance()->sha256(&oriAliasBuff, keyAlias);
    HcFree(aliasVal);
    if (res != HAL_SUCCESS) {
        LOGE("Compute authCode alias hash failed");
    }
    return res;
}

static int32_t ImportSymTokenToKeyManager(const SymToken *token, CJson *in, int32_t opCode)
{
    uint8_t authCode[DEV_AUTH_AUTH_CODE_SIZE] = { 0 };
    if (GetByteFromJson(in, FIELD_AUTH_CODE, authCode, DEV_AUTH_AUTH_CODE_SIZE) != HC_SUCCESS) {
        LOGE("Failed to get authCode from json!");
        return HC_ERR_JSON_GET;
    }
    uint8_t *keyAliasVal = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (keyAliasVal == NULL) {
        LOGE("Failed to allocate keyAliasVal memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff keyAlias = {
        .val = keyAliasVal,
        .length = SHA256_LEN
    };
    Uint8Buff authCodeBuff = {
        .val = authCode,
        .length = DEV_AUTH_AUTH_CODE_SIZE
    };
    int32_t res = GenerateKeyAlias(token->userId, token->deviceId, &keyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate authCode key alias!");
        HcFree(keyAliasVal);
        return res;
    }
    KeyPurpose purpose = KEY_PURPOSE_DERIVE;
    if (opCode == IMPORT_TRUSTED_CREDENTIALS) {
        purpose = KEY_PURPOSE_MAC;
    }
    res = GetLoaderInstance()->importSymmetricKey(&keyAlias, &authCodeBuff, purpose, NULL);
    HcFree(keyAliasVal);
    if (res != HC_SUCCESS) {
        LOGE("Failed to import sym token! res: %d", res);
    } else {
        LOGI("Import sym token success!");
    }
    /* Clear sensitive data: authCode. */
    (void)memset_s(authCode, DEV_AUTH_AUTH_CODE_SIZE, 0, DEV_AUTH_AUTH_CODE_SIZE);
    ClearSensitiveStringInJson(in, FIELD_AUTH_CODE);
    return res;
}

static int32_t DeleteSymTokenFromKeyManager(const SymToken *token)
{
    uint8_t *keyAliasVal = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (keyAliasVal == NULL) {
        LOGE("Failed to allocate keyAliasVal memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff keyAlias = {
        .val = keyAliasVal,
        .length = SHA256_LEN
    };
    int32_t res = GenerateKeyAlias(token->userId, token->deviceId, &keyAlias);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate authCode key alias!");
        HcFree(keyAliasVal);
        return res;
    }
    res = GetLoaderInstance()->deleteKey(&keyAlias);
    HcFree(keyAliasVal);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete sym token! res: %d", res);
    } else {
        LOGI("Delete sym token success!");
    }
    return res;
}

static void LoadOsSymTokensDb(int32_t osAccountId)
{
    char tokenPath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetTokensFilePath(osAccountId, tokenPath, MAX_DB_PATH_LEN)) {
        LOGE("Failed to get token path!");
        return;
    }
    OsSymTokensInfo info;
    info.osAccountId = osAccountId;
    info.tokens = CreateSymTokenVec();
    if (ReadTokensFromFile(&info.tokens, tokenPath) != HC_SUCCESS) {
        DestroySymTokenVec(&info.tokens);
        return;
    }
    if (g_symTokensDb.pushBackT(&g_symTokensDb, info) == NULL) {
        LOGE("Failed to push osAccountInfo to database!");
        ClearSymTokenVec(&info.tokens);
    }
    LOGI("Load os account db successfully! [Id]: %d", osAccountId);
}

static void TryMoveDeDataToCe(int32_t osAccountId)
{
    char tokenPathDe[MAX_DB_PATH_LEN] = { 0 };
    if (!GetTokensFilePathDe(osAccountId, tokenPathDe, MAX_DB_PATH_LEN)) {
        LOGE("Failed to get de token path!");
        return;
    }
    char tokenPathCe[MAX_DB_PATH_LEN] = { 0 };
    if (!GetTokensFilePathCe(osAccountId, tokenPathCe, MAX_DB_PATH_LEN)) {
        LOGE("Failed to get ce token path!");
        return;
    }
    OsSymTokensInfo info;
    info.osAccountId = osAccountId;
    info.tokens = CreateSymTokenVec();
    if (ReadTokensFromFile(&info.tokens, tokenPathCe) == HC_SUCCESS) {
        LOGI("Ce data exists, no need to move!");
        ClearSymTokenVec(&info.tokens);
        return;
    }
    ClearSymTokenVec(&info.tokens);
    info.tokens = CreateSymTokenVec();
    if (ReadTokensFromFile(&info.tokens, tokenPathDe) != HC_SUCCESS) {
        LOGI("De data not exists, no need to move!");
        ClearSymTokenVec(&info.tokens);
        return;
    }
    if (SaveTokensToFile(&info.tokens, tokenPathCe) != HC_SUCCESS) {
        LOGE("Failed to save tokens to ce file!");
        ClearSymTokenVec(&info.tokens);
        return;
    }
    ClearSymTokenVec(&info.tokens);
    info.tokens = CreateSymTokenVec();
    if (ReadTokensFromFile(&info.tokens, tokenPathCe) != HC_SUCCESS) {
        LOGE("Failed to read ce file data!");
        ClearSymTokenVec(&info.tokens);
        return;
    }
    ClearSymTokenVec(&info.tokens);
    LOGI("Move de data to ce successfully, remove the de file!");
    HcFileRemove(tokenPathDe);
}

static void RemoveOsSymTokensInfo(int32_t osAccountId)
{
    uint32_t index = 0;
    OsSymTokensInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_symTokensDb, index, info) {
        if (info->osAccountId == osAccountId) {
            OsSymTokensInfo deleteInfo;
            HC_VECTOR_POPELEMENT(&g_symTokensDb, &deleteInfo, index);
            ClearSymTokenVec(&deleteInfo.tokens);
            return;
        }
    }
}

static void LoadOsSymTokensDbCe(int32_t osAccountId)
{
    TryMoveDeDataToCe(osAccountId);
    RemoveOsSymTokensInfo(osAccountId);
    LoadOsSymTokensDb(osAccountId);
}

static void OnOsAccountUnlocked(int32_t osAccountId)
{
    LOGI("Os account is unlocked, osAccountId: %d", osAccountId);
    g_dataMutex->lock(g_dataMutex);
    LoadOsSymTokensDbCe(osAccountId);
    g_dataMutex->unlock(g_dataMutex);
}

static void OnOsAccountRemoved(int32_t osAccountId)
{
    LOGI("Os account is removed, osAccountId: %d", osAccountId);
    g_dataMutex->lock(g_dataMutex);
    RemoveOsSymTokensInfo(osAccountId);
    g_dataMutex->unlock(g_dataMutex);
}

static bool IsOsAccountDataLoaded(int32_t osAccountId)
{
    uint32_t index = 0;
    OsSymTokensInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_symTokensDb, index, info) {
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
    LoadOsSymTokensDbCe(osAccountId);
}

static OsSymTokensInfo *GetTokensInfoByOsAccountId(int32_t osAccountId)
{
    if (IsOsAccountSupported()) {
        LoadDataIfNotLoaded(osAccountId);
    }
    uint32_t index = 0;
    OsSymTokensInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_symTokensDb, index, info) {
        if (info->osAccountId == osAccountId) {
            return info;
        }
    }
    LOGI("Create a new os account database cache! [Id]: %d", osAccountId);
    OsSymTokensInfo newInfo;
    newInfo.osAccountId = osAccountId;
    newInfo.tokens = CreateSymTokenVec();
    OsSymTokensInfo *returnInfo = g_symTokensDb.pushBackT(&g_symTokensDb, newInfo);
    if (returnInfo == NULL) {
        LOGE("Failed to push OsSymTokensInfo to database!");
        DestroySymTokenVec(&newInfo.tokens);
    }
    return returnInfo;
}

static int32_t SaveOsSymTokensDb(int32_t osAccountId)
{
    char tokenPath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetTokensFilePath(osAccountId, tokenPath, MAX_DB_PATH_LEN)) {
        LOGE("Failed to get token path!");
        return HC_ERROR;
    }
    OsSymTokensInfo *info = GetTokensInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get tokens by os account id. [OsAccountId]: %d", osAccountId);
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = SaveTokensToFile(&info->tokens, tokenPath);
    if (ret != HC_SUCCESS) {
        LOGE("Save tokens to file failed");
        return ret;
    }
    LOGI("Save an os account database successfully! [Id]: %d", osAccountId);
    return HC_SUCCESS;
}

static int32_t AddSymTokenToVec(int32_t osAccountId, SymToken *token)
{
    LOGI("Start to add a token to database!");
    OsSymTokensInfo *info = GetTokensInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get tokens by os account id. [OsAccountId]: %d", osAccountId);
        return HC_ERR_INVALID_PARAMS;
    }
    SymToken **oldTokenPtr = QueryTokenPtrIfMatch(&info->tokens, token->userId, token->deviceId);
    if (oldTokenPtr != NULL) {
        LOGI("Replace an old token successfully!");
        HcFree(*oldTokenPtr);
        *oldTokenPtr = token;
        return HC_SUCCESS;
    }
    if (info->tokens.pushBackT(&info->tokens, token) == NULL) {
        LOGE("Failed to push token to vec!");
        return HC_ERR_MEMORY_COPY;
    }
    LOGI("Add a token to database successfully!");
    return HC_SUCCESS;
}

static SymToken *PopSymTokenFromVec(int32_t osAccountId, const char *userId, const char *deviceId)
{
    LOGI("Start to pop token from database!");
    OsSymTokensInfo *info = GetTokensInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        LOGE("Failed to get tokens by os account id. [OsAccountId]: %d", osAccountId);
        return NULL;
    }
    uint32_t index = 0;
    SymToken **token = NULL;
    while (index < HC_VECTOR_SIZE(&info->tokens)) {
        token = info->tokens.getp(&info->tokens, index);
        if ((token == NULL) || (*token == NULL) || (!IsTokenMatch(*token, userId, deviceId))) {
            index++;
            continue;
        }
        SymToken *deleteToken = NULL;
        HC_VECTOR_POPELEMENT(&info->tokens, &deleteToken, index);
        LOGI("Pop a token from database successfully!");
        return deleteToken;
    }
    LOGE("The token is not found!");
    return NULL;
}

static int32_t AddToken(int32_t osAccountId, int32_t opCode, CJson *in)
{
    LOGI("[Token]: Add sym token starting ...");
    if (in == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_NULL_PTR;
    }
    SymToken *symToken = CreateSymTokenByJson(in);
    if (symToken == NULL) {
        LOGE("Failed to create symToken from json!");
        return HC_ERR_ALLOC_MEMORY;
    }
    g_dataMutex->lock(g_dataMutex);
    int32_t res = AddSymTokenToVec(osAccountId, symToken);
    if (res != HC_SUCCESS) {
        g_dataMutex->unlock(g_dataMutex);
        LOGE("Failed to add sym token to vec");
        HcFree(symToken);
        return res;
    }
    res = ImportSymTokenToKeyManager(symToken, in, opCode);
    if (res != HC_SUCCESS) {
        g_dataMutex->unlock(g_dataMutex);
        LOGE("Failed to import sym token!");
        return res;
    }
    res = SaveOsSymTokensDb(osAccountId);
    g_dataMutex->unlock(g_dataMutex);
    if (res != HC_SUCCESS) {
        LOGE("Failed to save token to db");
        return res;
    }
    LOGI("[Token]: Add sym token success");
    return HC_SUCCESS;
}

static int32_t DeleteToken(int32_t osAccountId, const char *userId, const char *deviceId)
{
    LOGI("[Token]: Delete sym token starting ...");
    if ((userId == NULL) || (deviceId == NULL)) {
        LOGE("Invalid params");
        return HC_ERR_NULL_PTR;
    }
    g_dataMutex->lock(g_dataMutex);
    SymToken *symToken = PopSymTokenFromVec(osAccountId, userId, deviceId);
    if (symToken == NULL) {
        g_dataMutex->unlock(g_dataMutex);
        return HC_ERR_NULL_PTR;
    }
    int32_t res = DeleteSymTokenFromKeyManager(symToken);
    HcFree(symToken);
    if (res != HC_SUCCESS) {
        g_dataMutex->unlock(g_dataMutex);
        LOGE("Failed to delete sym token!");
        return res;
    }
    res = SaveOsSymTokensDb(osAccountId);
    g_dataMutex->unlock(g_dataMutex);
    if (res != HC_SUCCESS) {
        LOGE("Failed to save token to db, account id is: %d", osAccountId);
        return res;
    }
    LOGI("[Token]: Delete sym token success");
    return HC_SUCCESS;
}

static void LoadTokenDb(void)
{
    if (IsOsAccountSupported()) {
        return;
    }
    StringVector dbNameVec = CreateStrVector();
    HcFileGetSubFileName(GetAccountStoragePath(), &dbNameVec);
    uint32_t index;
    HcString *dbName = NULL;
    FOR_EACH_HC_VECTOR(dbNameVec, index, dbName) {
        int32_t osAccountId;
        const char *name = StringGet(dbName);
        if (name == NULL) {
            continue;
        }
        if (strcmp(name, "account_data_sym.dat") == 0) {
            LoadOsSymTokensDb(DEFAULT_OS_ACCOUNT);
        } else if (sscanf_s(name, "account_data_sym%d.dat", &osAccountId) == 1) {
            LoadOsSymTokensDb(osAccountId);
        }
    }
    DestroyStrVector(&dbNameVec);
}

void ClearSymTokenVec(SymTokenVec *vec)
{
    uint32_t index;
    SymToken **token;
    FOR_EACH_HC_VECTOR(*vec, index, token) {
        HcFree(*token);
    }
    DESTROY_HC_VECTOR(SymTokenVec, vec);
}

SymTokenManager *GetSymTokenManager(void)
{
    return &g_symTokenManager;
}

void InitSymTokenManager(void)
{
    if (g_dataMutex == NULL) {
        g_dataMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_dataMutex == NULL) {
            LOGE("Alloc account database mutex failed.");
            return;
        }
        if (InitHcMutex(g_dataMutex) != HC_SUCCESS) {
            LOGE("Init account mutex failed.");
            HcFree(g_dataMutex);
            g_dataMutex = NULL;
            return;
        }
    }
    g_dataMutex->lock(g_dataMutex);
    (void)memset_s(&g_symTokenManager, sizeof(SymTokenManager), 0, sizeof(SymTokenManager));
    g_symTokenManager.addToken = AddToken;
    g_symTokenManager.deleteToken = DeleteToken;
    g_symTokenManager.generateKeyAlias = GenerateKeyAlias;
    g_symTokensDb = CREATE_HC_VECTOR(SymTokensDb);
    AddOsAccountEventCallback(SYM_TOKEN_DATA_CALLBACK, OnOsAccountUnlocked, OnOsAccountRemoved);
    LoadTokenDb();
    g_dataMutex->unlock(g_dataMutex);
}

void DestroySymTokenManager(void)
{
    g_dataMutex->lock(g_dataMutex);
    RemoveOsAccountEventCallback(SYM_TOKEN_DATA_CALLBACK);
    (void)memset_s(&g_symTokenManager, sizeof(SymTokenManager), 0, sizeof(SymTokenManager));
    uint32_t index;
    OsSymTokensInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_symTokensDb, index, info) {
        ClearSymTokenVec(&info->tokens);
    }
    DESTROY_HC_VECTOR(SymTokensDb, &g_symTokensDb);
    g_dataMutex->unlock(g_dataMutex);
    DestroyHcMutex(g_dataMutex);
    HcFree(g_dataMutex);
    g_dataMutex = NULL;
}
