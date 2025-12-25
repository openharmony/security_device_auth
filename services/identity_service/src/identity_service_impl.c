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

#include "identity_service_impl.h"

#include "alg_defs.h"
#include "alg_loader.h"
#include "clib_error.h"
#include "common_defs.h"
#include "operation_data_manager.h"
#include "credential_data_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hal_error.h"
#include "hc_log.h"

#include "identity_operation.h"
#include "identity_service_defines.h"
#include "permission_adapter.h"
#include "hisysevent_adapter.h"

static void SetStringForcely(HcString *self, const char *str)
{
    if (StringAppendPointer(self, str) != HC_TRUE) {
        DeleteString(self);
        *self = CreateString();
    }
}

static void ISRecordAndReport(int32_t osAccountId, const Credential *credential,
    const char *funcName, int32_t processCode, int32_t ret)
{
    if (ret != IS_SUCCESS) {
        return;
    }
    CJson *operationInfo = CreateJson();
    if (operationInfo == NULL) {
        return;
    }
    Operation *operation = CreateOperationRecord();
    if (operation == NULL) {
        FreeJson(operationInfo);
        return;
    }
    const char *appId = StringGet(&(credential->credOwner));
    char anonymous[DEFAULT_ANONYMOUS_LEN + 1] = { 0 };
    if (GetAnonymousString(StringGet(&(credential->credId)), anonymous, DEFAULT_ANONYMOUS_LEN, false) != HC_SUCCESS) {
        (void)memset_s(anonymous, DEFAULT_ANONYMOUS_LEN + 1, 0, DEFAULT_ANONYMOUS_LEN + 1);
    }
    (void)AddIntToJson(operationInfo, FIELD_CRED_TYPE, (int32_t)(credential->credType));
    (void)AddStringToJson(operationInfo, FIELD_CRED_ID, anonymous);
    char *operationInfoString = PackJsonToString(operationInfo);
    if (operationInfoString != NULL) {
        SetStringForcely(&operation->operationInfo, operationInfoString);
        FreeJsonString(operationInfoString);
    }
    SetStringForcely(&operation->caller, appId);
    SetStringForcely(&operation->function, funcName);
    operation->operationType = OPERATION_IDENTITY_SERVICE;
    RecordOperationData(osAccountId, operation);
#ifdef DEV_AUTH_HIVIEW_ENABLE
    DevAuthCallEvent eventData;
    eventData.funcName = funcName;
    eventData.osAccountId = osAccountId;
    eventData.callResult = ret;
    eventData.processCode = processCode;
    eventData.appId = appId;
    eventData.credType = credential->credType;
    eventData.groupType = DEFAULT_GROUP_TYPE;
    eventData.executionTime = DEFAULT_EXECUTION_TIME;
    eventData.extInfo = StringGet(&(operation->operationInfo));
    DEV_AUTH_REPORT_CALL_EVENT(eventData);
#else
    (void)processCode;
#endif
    DestroyOperationRecord(operation);
    FreeJson(operationInfo);
}

static int32_t AddCredentialImplInner(int32_t osAccountId, CJson *reqJson, Credential *credential,
    char **returnData)
{
    uint8_t method = DEFAULT_VAL;
    Uint8Buff keyValue = { NULL, 0 };
    int32_t ret = CheckAndSetCredInfo(osAccountId, credential, reqJson, &method, &keyValue);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    Uint8Buff credIdByte = { NULL, 0 };
    if ((ret = GenerateCredId(osAccountId, credential, &credIdByte)) != IS_SUCCESS) {
        HcFree(keyValue.val);
        return ret;
    }
    if ((ret = AddKeyValueToHuks(osAccountId, &credIdByte, credential, method, &keyValue)) != IS_SUCCESS) {
        HcFree(keyValue.val);
        HcFree(credIdByte.val);
        return ret;
    }
    HcFree(keyValue.val);
    if ((ret = AddCredAndSaveDb(osAccountId, credential)) != IS_SUCCESS) {
        if (GetLoaderInstance()->deleteKey(&credIdByte, false, osAccountId) != IS_SUCCESS) {
            LOGE("Failed to delete key from HUKS");
        }
        HcFree(credIdByte.val);
        return ret;
    }
    HcFree(credIdByte.val);
    if (DeepCopyString(StringGet(&credential->credId), returnData) != EOK) {
        LOGE("Failed to return credId");
        return IS_ERR_MEMORY_COPY;
    }
    return IS_SUCCESS;
}

int32_t AddCredentialImpl(int32_t osAccountId, const char *requestParams, char **returnData)
{
    CJson *reqJson = CreateJsonFromString(requestParams);
    if (reqJson == NULL) {
        LOGE("Failed to create reqJson from string!");
        return IS_ERR_JSON_CREATE;
    }
    Credential *credential = CreateCredential();
    if (credential == NULL) {
        LOGE("Failed to malloc Credential");
        FreeJson(reqJson);
        return IS_ERR_ALLOC_MEMORY;
    }
    int32_t ret = AddCredentialImplInner(osAccountId, reqJson, credential, returnData);
    ISRecordAndReport(osAccountId, credential, ADD_CREDENTIAL_EVENT, PROCESS_ADD_CREDENTIAL, ret);
    FreeJson(reqJson);
    DestroyCredential(credential);
    return ret;
}

int32_t ExportCredentialImpl(int32_t osAccountId, const char *credId, char **returnData)
{
    Credential *credential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credId, &credential);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    ret = CheckOwnerUidPermission(credential);
    DestroyCredential(credential);
    if (ret != IS_SUCCESS) {
        LOGE("Check Uid failed when export credential.");
        return ret;
    }
    Uint8Buff credIdByte = { NULL, 0 };

    ret = GetValidKeyAlias(osAccountId, credId, &credIdByte);
    if (ret == HAL_ERR_KEY_NOT_EXIST) {
        LOGE("Huks key not exist!");
        DelCredById(osAccountId, credId);
        return IS_ERR_HUKS_KEY_NOT_EXIST;
    }
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks check key exist failed");
        return IS_ERR_HUKS_CHECK_KEY_EXIST_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to check key exist in HUKS");
        return ret;
    }

    KeyParams keyParams = { { credIdByte.val, credIdByte.length, true }, false, osAccountId };
    uint8_t pubKeyVal[KEY_VALUE_MAX_LENGTH] = { 0 };
    Uint8Buff keyValue = { pubKeyVal, KEY_VALUE_MAX_LENGTH };
    ret = GetLoaderInstance()->exportPublicKey(&keyParams, &keyValue);
    HcFree(credIdByte.val);
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks export key failed!");
        return IS_ERR_HUKS_EXPORT_KEY_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to export key");
        return ret;
    }

    ret = AddKeyValueToReturn(keyValue, returnData);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    return IS_SUCCESS;
}

int32_t QueryCredentialByParamsImpl(int32_t osAccountId, const char *requestParams, char **returnData)
{
    CJson *reqJson = CreateJsonFromString(requestParams);
    if (reqJson == NULL) {
        LOGE("Failed to create reqJson from string!");
        return IS_ERR_JSON_CREATE;
    }

    QueryCredentialParams queryParams = InitQueryCredentialParams();
    SetQueryParamsFromJson(&queryParams, reqJson);
    if (CheckInterfacePermission(CRED_PRIVILEGE_PERMISSION) != HC_SUCCESS) {
        LOGI("no privilege permission, need to check ownerUid.");
        queryParams.ownerUid = GetCallingUid();
    }

    CredentialVec credentialVec = CreateCredentialVec();
    int32_t ret = QueryCredentials(osAccountId, &queryParams, &credentialVec);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to query credentials");
        FreeJson(reqJson);
        ClearCredentialVec(&credentialVec);
        return ret;
    }
    if (credentialVec.size(&credentialVec) == 0) {
        LOGW("No credential found");
        FreeJson(reqJson);
        ClearCredentialVec(&credentialVec);
        return GenerateReturnEmptyArrayStr(returnData);
    }

    CJson *credIdJson = CreateJsonArray();
    if (credIdJson == NULL) {
        LOGE("Failed to create credIdJson object");
        FreeJson(reqJson);
        ClearCredentialVec(&credentialVec);
        return IS_ERR_JSON_CREATE;
    }

    ret = GetCredIdsFromCredVec(osAccountId, reqJson, &credentialVec, credIdJson);
    FreeJson(reqJson);
    ClearCredentialVec(&credentialVec);
    if (ret != IS_SUCCESS) {
        FreeJson(credIdJson);
        return ret;
    }
    
    *returnData = PackJsonToString(credIdJson);
    FreeJson(credIdJson);
    if (*returnData == NULL) {
        LOGE("Failed to pack json to string");
        return IS_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }

    return IS_SUCCESS;
}

static int32_t CheckQueryPermission(Credential *credential, int32_t uid)
{
    if (uid == DEV_AUTH_UID) {
        return IS_SUCCESS;
    }
    if (CheckInterfacePermission(CRED_PRIVILEGE_PERMISSION) == IS_SUCCESS) {
        return IS_SUCCESS;
    }
    int32_t ret = CheckOwnerUidPermission(credential);
    if (ret != IS_SUCCESS) {
        LOGE("don't have privilege or owner uid permission to query cred info");
        return ret;
    }
    return IS_SUCCESS;
}

static int32_t CheckDeletePermission(Credential *credential)
{
    if (CheckInterfacePermission(CRED_PRIVILEGE_PERMISSION) == IS_SUCCESS) {
        LOGI("delete credential with privilege permission!");
        return IS_SUCCESS;
    }
    return CheckOwnerUidPermission(credential);
}

int32_t QueryCredInfoByCredIdImpl(int32_t osAccountId, int32_t uid, const char *credId, char **returnData)
{
    Credential *credential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credId, &credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get credential by credId, ret = %" LOG_PUB "d", ret);
        return ret;
    }
    ret = CheckQueryPermission(credential, uid);
    if (ret != IS_SUCCESS) {
        DestroyCredential(credential);
        return ret;
    }
    CJson *credInfoJson = CreateJson();
    if (credInfoJson == NULL) {
        LOGE("Failed to create credInfoJson object");
        DestroyCredential(credential);
        return IS_ERR_JSON_CREATE;
    }

    ret = GenerateReturnCredInfo(credential, credInfoJson);
    DestroyCredential(credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to generate return credential info");
        FreeJson(credInfoJson);
        return ret;
    }

    *returnData = PackJsonToString(credInfoJson);
    FreeJson(credInfoJson);
    if (*returnData == NULL) {
        LOGE("Failed to pack json to string");
        return IS_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }

    return IS_SUCCESS;
}

int32_t DeleteCredentialImpl(int32_t osAccountId, const char *credId)
{
    Credential *credential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credId, &credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get credential by credId, ret = %" LOG_PUB "d", ret);
        return ret;
    }
    ret = CheckDeletePermission(credential);
    int32_t currentUid = GetCallingUid();
    do {
        if (ret != IS_SUCCESS) {
            LOGE("Check Uid failed when delete credential.");
            break;
        }

        uint32_t credIdByteLen = HcStrlen(credId) / BYTE_TO_HEX_OPER_LENGTH;
        Uint8Buff credIdByte = { NULL, credIdByteLen };
        credIdByte.val = (uint8_t *)HcMalloc(credIdByteLen, 0);
        if (credIdByte.val == NULL) {
            LOGE("Failed to malloc credIdByte");
            ret = IS_ERR_ALLOC_MEMORY;
            break;
        }

        ret = HexStringToByte(credId, credIdByte.val, credIdByte.length);
        if (ret != IS_SUCCESS) {
            LOGE("Failed to convert credId to byte, invalid credId, ret: %" LOG_PUB "d", ret);
            HcFree(credIdByte.val);
            ret = IS_ERR_INVALID_HEX_STRING;
            break;
        }

        if (currentUid != DEV_AUTH_UID) {
            ret = GetLoaderInstance()->deleteKey(&credIdByte, false, osAccountId);
        }
        HcFree(credIdByte.val);
        if (ret == HAL_ERR_HUKS) {
            LOGW("Huks delete key failed, error: %" LOG_PUB "d," \
                "continue to delete local cred", IS_ERR_HUKS_DELETE_FAILED);
        }

        ret = DelCredById(osAccountId, credId);
    } while (0);
    ISRecordAndReport(osAccountId, credential, DELETE_CREDENTIAL_EVENT, PROCESS_DELETE_CREDENTIAL, ret);
    DestroyCredential(credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to delete local credential");
        return ret;
    }
    LOGI("Delete credential success");
    return IS_SUCCESS;
}

static int32_t DelCredsWithHash(int32_t osAccountId, CJson *reqJson, CredentialVec *credentialVec, CJson *credIdJson)
{
    Credential **ptr;
    uint32_t index;
    int32_t ret = IS_SUCCESS;
    FOR_EACH_HC_VECTOR(*credentialVec, index, ptr) {
        if (*ptr == NULL) {
            continue;
        }
        Credential *credential = (Credential *)(*ptr);
        const char *credId = StringGet(&credential->credId);
        if (credId == NULL) {
            LOGE("Failed to get credId");
            continue;
        }

        if (!IsCredHashMatch(credential, reqJson)) {
            continue;
        }

        ret = AddStringToArray(credIdJson, credId);
        if (ret != IS_SUCCESS) {
            LOGE("Failed to add credId to json");
            return IS_ERR_JSON_ADD;
        }
        ret = DeleteCredentialImpl(osAccountId, credId);
    }
    return ret;
}

int32_t DeleteCredByParamsImpl(int32_t osAccountId, const char *requestParams, char **returnData)
{
    CJson *reqJson = CreateJsonFromString(requestParams);
    if (reqJson == NULL) {
        LOGE("Failed to create reqJson from string!");
        return IS_ERR_JSON_CREATE;
    }
    QueryCredentialParams delParams = InitQueryCredentialParams();
    SetQueryParamsFromJson(&delParams, reqJson);
    delParams.ownerUid = GetCallingUid();

    CredentialVec credentialVec = CreateCredentialVec();
    int32_t ret = QueryCredentials(osAccountId, &delParams, &credentialVec);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to query credentials");
        FreeJson(reqJson);
        ClearCredentialVec(&credentialVec);
        return ret;
    }
    CJson *credIdJson = CreateJsonArray();
    if (credIdJson == NULL) {
        LOGE("Failed to create credIdJson");
        FreeJson(reqJson);
        ClearCredentialVec(&credentialVec);
        return IS_ERR_JSON_CREATE;
    }
    ret = DelCredsWithHash(osAccountId, reqJson, &credentialVec, credIdJson);
    FreeJson(reqJson);
    ClearCredentialVec(&credentialVec);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get and delete credential in vec");
        FreeJson(credIdJson);
        return ret;
    }
    *returnData = PackJsonToString(credIdJson);
    FreeJson(credIdJson);
    if (*returnData == NULL) {
        LOGE("Failed to pack json to string");
        return IS_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    return ret;
}

int32_t UpdateCredInfoImpl(int32_t osAccountId, const char *credId, const char *requestParams)
{
    Credential *credential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credId, &credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get credential by credId, ret: %" LOG_PUB "d", ret);
        return ret;
    }

    ret = CheckOwnerUidPermission(credential);
    if (ret != IS_SUCCESS) {
        LOGE("Check Uid failed when update credinfo.");
        DestroyCredential(credential);
        return ret;
    }

    CJson *reqJson = CreateJsonFromString(requestParams);
    if (reqJson == NULL) {
        LOGE("Failed to create reqJson from string!");
        DestroyCredential(credential);
        return IS_ERR_JSON_CREATE;
    }
    ret = UpdateInfoFromJson(credential, reqJson);
    FreeJson(reqJson);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to set update info");
        DestroyCredential(credential);
        return ret;
    }

    ret = AddCredAndSaveDb(osAccountId, credential);
    ISRecordAndReport(osAccountId, credential, UPDATE_CREDENTIAL_INFO_EVENT, PROCESS_UPDATE_CREDENTIAL_INFO, ret);
    DestroyCredential(credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to add credential to db");
        return ret;
    }

    return IS_SUCCESS;
}

static int32_t AddUpdateCred(int32_t osAccountId, CJson *baseInfoJson, QueryCredentialParams *queryParams)
{
    int32_t ret = AddUpdateInfoToJson(queryParams, baseInfoJson);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to add update info to json");
        return ret;
    }
    char *addCredReq = PackJsonToString(baseInfoJson);
    if (addCredReq == NULL) {
        LOGE("Failed to pack baseInfoJson to addCredReq");
        return IS_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    char *addRetStr = NULL;
    ret = AddCredentialImpl(osAccountId, addCredReq, &addRetStr);
    FreeJsonString(addCredReq);
    HcFree(addRetStr);
    return ret;
}

static int32_t DelCredInVec(int32_t osAccountId, CredentialVec *credVec)
{
    uint32_t index;
    Credential **ptr;
    int32_t ret = IS_SUCCESS;
    FOR_EACH_HC_VECTOR(*credVec, index, ptr) {
        if (*ptr == NULL) {
            continue;
        }
        Credential *credential = (Credential *)(*ptr);
        const char *credId = StringGet(&credential->credId);
        if (credId == NULL) {
            continue;
        }
        ret = DeleteCredentialImpl(osAccountId, credId);
        if (ret != IS_SUCCESS) {
            LOGE("Failed to delete credential, ret = %" LOG_PUB "d", ret);
            return ret;
        }
    }
    return IS_SUCCESS;
}

static int32_t ProcessAbnormalCreds(int32_t osAccountId, CJson *baseInfoJson, QueryCredentialParams *queryParams)
{
    int32_t ret = DelCredential(osAccountId, queryParams);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to delete abnormal credentials, ret = %" LOG_PUB "d", ret);
        return ret;
    }
    return AddUpdateCred(osAccountId, baseInfoJson, queryParams);
}

static int32_t HandleUpdateCredsBySize(int32_t osAccountId, CJson *baseInfoJson,
    QueryCredentialParams *queryParams, CredentialVec *updateCredVec, CredentialVec *selfCredVec)
{
    int32_t ret = IS_ERROR;
    uint32_t updateMatchSize = updateCredVec->size(updateCredVec);
    switch (updateMatchSize) {
        case UPDATE_MATCHED_NUM_ZERO:
            ret = AddUpdateCred(osAccountId, baseInfoJson, queryParams); // == 0 need add
            break;
        case UPDATE_MATCHED_NUM_ONE:
            ret = EraseUpdateCredIdInSelfVec(updateCredVec, selfCredVec); // update info exists in self vec
            break;
        default:
            ret = ProcessAbnormalCreds(osAccountId, baseInfoJson, queryParams); // > 1 need del old
            break;
    }
    return ret;
}

static int32_t ProcessUpdateInfo(int32_t osAccountId, CJson *updateInfoList,
    CJson *baseInfoJson, QueryCredentialParams *queryParams, CredentialVec *selfCredVec)
{
    int32_t ret = IS_SUCCESS;
    int32_t updateInfoNum = GetItemNum(updateInfoList);
    for (int32_t i = 0; i < updateInfoNum; i++) {
        CJson *item = GetItemFromArray(updateInfoList, i); // shallow copy
        if (item == NULL) {
            LOGE("updateInfoList item is NULL");
            return IS_ERR_JSON_GET;
        }
        CredentialVec updateCredVec = CreateCredentialVec();
        ret = GetUpdateCredVec(osAccountId, item, queryParams, &updateCredVec);
        if (ret != IS_SUCCESS) {
            ClearCredentialVec(&updateCredVec);
            return ret;
        }
        ret = HandleUpdateCredsBySize(osAccountId, baseInfoJson, queryParams, &updateCredVec, selfCredVec);
        ClearCredentialVec(&updateCredVec);
        if (ret != IS_SUCCESS) {
            return ret;
        }
    }
    return ret;
}

static int32_t GetCurrentCredIds(int32_t osAccountId, CJson *baseInfoJson, char **returnData)
{
    char *queryStr = NULL;
    int32_t ret = GetQueryJsonStr(baseInfoJson, &queryStr);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    ret = QueryCredentialByParamsImpl(osAccountId, queryStr, returnData);
    FreeJsonString(queryStr);
    return ret;
}

static int32_t BatchUpdateCredsImplInner(int32_t osAccountId,
    CJson *baseInfoJson, CJson *updateInfoList, char **returnData)
{
    QueryCredentialParams queryParams = InitQueryCredentialParams();
    int32_t ret = SetRequiredParamsFromJson(&queryParams, baseInfoJson);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    queryParams.ownerUid = GetCallingUid();

    CredentialVec selfCredVec = CreateCredentialVec();
    ret = QueryCredentials(osAccountId, &queryParams, &selfCredVec);
    if (ret != IS_SUCCESS) {
        ClearCredentialVec(&selfCredVec);
        return ret;
    }

    ret = ProcessUpdateInfo(osAccountId, updateInfoList, baseInfoJson, &queryParams, &selfCredVec);
    if (ret != IS_SUCCESS) {
        ClearCredentialVec(&selfCredVec);
        return ret;
    }

    ret = DelCredInVec(osAccountId, &selfCredVec);
    ClearCredentialVec(&selfCredVec);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    return GetCurrentCredIds(osAccountId, baseInfoJson, returnData);
}

int32_t BatchUpdateCredsImpl(int32_t osAccountId, const char *requestParams, char **returnData)
{
    CJson *reqJson = CreateJsonFromString(requestParams);
    if (reqJson == NULL) {
        LOGE("Failed to create reqJson from string!");
        return IS_ERR_JSON_CREATE;
    }
    CJson *baseInfoJson = GetObjFromJson(reqJson, FIELD_BASE_INFO);
    CJson *updateInfoList = GetObjFromJson(reqJson, FIELD_UPDATE_LISTS);
    if (baseInfoJson == NULL || updateInfoList == NULL) {
        LOGE("baseInfoJson or updateLists is NULL");
        FreeJson(reqJson);
        return IS_ERR_INVALID_PARAMS;
    }
    int32_t ret = BatchUpdateCredsImplInner(osAccountId, baseInfoJson, updateInfoList, returnData);
    FreeJson(reqJson);
    return ret;
}

static int32_t AgreeCredentialImplInner(int32_t osAccountId, const char *selfCredId,
    CJson *reqJson, Credential *agreeCredential, char **returnData)
{
    Uint8Buff keyValue = { NULL, 0 };
    Uint8Buff agreeCredIdByte = { NULL, 0 };
    int32_t ret = SetAgreeCredInfo(osAccountId, reqJson, agreeCredential, &keyValue, &agreeCredIdByte);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    uint8_t peerKeyAliasVal[SHA256_LEN] = { 0 };
    Uint8Buff peerKeyAlias = { peerKeyAliasVal, SHA256_LEN };
    ret = ImportAgreeKeyValue(osAccountId, agreeCredential, &keyValue, &peerKeyAlias);
    if (ret != IS_SUCCESS) {
        HcFree(keyValue.val);
        HcFree(agreeCredIdByte.val);
        return ret;
    }

    Uint8Buff selfCredIdByte = { NULL, 0 };
    ret = CheckAndDelInvalidCred(osAccountId, selfCredId, &selfCredIdByte);
    if (ret != IS_SUCCESS) {
        HcFree(keyValue.val);
        HcFree(agreeCredIdByte.val);
        return ret;
    }

    ret = ComputePskAndDelInvalidKey(osAccountId,
        agreeCredential->algorithmType, &selfCredIdByte, &peerKeyAlias, &agreeCredIdByte);
    HcFree(keyValue.val);
    HcFree(selfCredIdByte.val);
    HcFree(agreeCredIdByte.val);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    ret = AddCredAndSaveDb(osAccountId, agreeCredential);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    if (DeepCopyString(StringGet(&agreeCredential->credId), returnData) != EOK) {
        LOGE("Failed to return credId");
        return IS_ERR_MEMORY_COPY;
    }
    return IS_SUCCESS;
}

int32_t AgreeCredentialImpl(int32_t osAccountId, const char *selfCredId, const char *requestParams, char **returnData)
{
    CJson *reqJson = CreateJsonFromString(requestParams);
    if (reqJson == NULL) {
        LOGE("Failed to create reqJson from string!");
        return IS_ERR_JSON_CREATE;
    }
    Credential *agreeCredential = CreateCredential();
    if (agreeCredential == NULL) {
        LOGE("Failed to malloc agreeCredential");
        FreeJson(reqJson);
        return IS_ERR_ALLOC_MEMORY;
    }
    int32_t ret = AgreeCredentialImplInner(osAccountId, selfCredId, reqJson, agreeCredential, returnData);
    ISRecordAndReport(osAccountId, agreeCredential, AGREE_CREDENTIAL_EVENT, PROCESS_AGREE_CREDENTIAL, ret);
    FreeJson(reqJson);
    DestroyCredential(agreeCredential);
    return ret;
}

int32_t RegCredListener(const char *appId, const CredChangeListener *listener)
{
    if ((appId == NULL) || (listener == NULL)) {
        LOGE("The input parameter contains NULL value!");
        return IS_ERR_INVALID_PARAMS;
    }
    if (!IsCredListenerSupported()) {
        LOGE("Broadcast is not supported!");
        return IS_ERR_NOT_SUPPORT;
    }
    return AddCredListener(appId, listener);
}

int32_t UnRegCredListener(const char *appId)
{
    if (appId == NULL) {
        LOGE("The input parameter contains NULL value!");
        return IS_ERR_INVALID_PARAMS;
    }
    if (!IsCredListenerSupported()) {
        LOGE("Broadcast is not supported!");
        return IS_ERR_NOT_SUPPORT;
    }
    return RemoveCredListener(appId);
}
