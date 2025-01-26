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

#include "identity_service.h"

#include "alg_defs.h"
#include "alg_loader.h"
#include "clib_error.h"
#include "common_defs.h"
#include "credential_data_manager.h"
#include "cred_listener.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hal_error.h"
#include "hc_log.h"

#include "identity_operation.h"

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
    if ((ret = AddKeyValueToHuks(osAccountId, credIdByte, credential, method, keyValue)) != IS_SUCCESS) {
        HcFree(keyValue.val);
        HcFree(credIdByte.val);
        return ret;
    }
    HcFree(keyValue.val);
    HcFree(credIdByte.val);
    if ((ret = AddCredAndSaveDb(osAccountId, credential)) != IS_SUCCESS) {
        if (GetLoaderInstance()->deleteKey(&credIdByte, false, osAccountId) != IS_SUCCESS) {
            LOGE("Failed to delete key from HUKS");
        }
        return ret;
    }
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
    DestroyCredential(credential);

    uint32_t credIdByteLen = HcStrlen(credId) / BYTE_TO_HEX_OPER_LENGTH;
    Uint8Buff credIdByte = { NULL, credIdByteLen };
    credIdByte.val = (uint8_t *)HcMalloc(credIdByteLen, 0);
    if (credIdByte.val == NULL) {
        LOGE("Failed to malloc credIdByte");
        return IS_ERR_ALLOC_MEMORY;
    }

    ret = CheckCredIdExistInHuks(osAccountId, credId, &credIdByte);
    if (ret == HAL_ERR_KEY_NOT_EXIST) {
        LOGE("Huks key not exist!");
        DelCredById(osAccountId, credId);
        HcFree(credIdByte.val);
        return IS_ERR_HUKS_KEY_NOT_EXIST;
    }
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks check key exist failed");
        HcFree(credIdByte.val);
        return IS_ERR_HUKS_CHECK_KEY_EXIST_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to check key exist in HUKS");
        HcFree(credIdByte.val);
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

    CredentialVec credentialVec = CreateCredentialVec();

    int32_t ret = QueryCredentials(osAccountId, &queryParams, &credentialVec);
    FreeJson(reqJson);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to query credentials");
        ClearCredentialVec(&credentialVec);
        return ret;
    }
    if (credentialVec.size(&credentialVec) == 0) {
        LOGW("No credential found");
        ClearCredentialVec(&credentialVec);
        return GenerateReturnEmptyArrayStr(returnData);
    }

    CJson *credIdJson = CreateJsonArray();
    if (credIdJson == NULL) {
        LOGE("Failed to create credIdJson object");
        ClearCredentialVec(&credentialVec);
        return IS_ERR_JSON_CREATE;
    }

    ret = GetCredIdsFromCredVec(credentialVec, credIdJson, osAccountId);
    ClearCredentialVec(&credentialVec);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get credIds from credentials");
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

int32_t QueryCredInfoByCredIdImpl(int32_t osAccountId, const char *credId, char **returnData)
{
    Credential *credential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credId, &credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get credential by credId, ret = %d", ret);
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

int32_t DeleteCredentialImpl(int32_t osAccountId, const char *appId, const char *credId)
{
    Credential *credential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credId, &credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get credential by credId, ret = %d", ret);
        return ret;
    }

    if (strcmp(StringGet(&credential->credOwner), appId) != 0) {
        LOGE("appId is not the same as the appId of the credential");
        DestroyCredential(credential);
        return IS_ERR_INVALID_PARAMS;
    }
    DestroyCredential(credential);

    uint32_t credIdByteLen = HcStrlen(credId) / BYTE_TO_HEX_OPER_LENGTH;
    Uint8Buff credIdByte = { NULL, credIdByteLen };
    credIdByte.val = (uint8_t *)HcMalloc(credIdByteLen, 0);
    if (credIdByte.val == NULL) {
        LOGE("Failed to malloc credIdByte");
        return IS_ERR_ALLOC_MEMORY;
    }

    ret = HexStringToByte(credId, credIdByte.val, credIdByte.length);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credId to byte, invalid credId, ret: %d", ret);
        HcFree(credIdByte.val);
        return IS_ERR_INVALID_HEX_STRING;
    }

    ret = GetLoaderInstance()->deleteKey(&credIdByte, false, osAccountId);
    HcFree(credIdByte.val);
    if (ret == HAL_ERR_HUKS) {
        LOGW("Huks delete key failed, error: %d, continue to delete local cred", IS_ERR_HUKS_DELETE_FAILED);
    }

    ret = DelCredById(osAccountId, credId);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to delete local credential");
        return ret;
    }
    LOGI("Delete credential success");
    return IS_SUCCESS;
}

int32_t UpdateCredInfoImpl(int32_t osAccountId, const char *appId, const char *credId, const char *requestParams)
{
    Credential *credential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credId, &credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get credential by credId, ret: %d", ret);
        return ret;
    }

    if (strcmp(StringGet(&credential->credOwner), appId) != 0) {
        LOGE("appId is not the same as the appId of the credential");
        DestroyCredential(credential);
        return IS_ERR_INVALID_PARAMS;
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
    DestroyCredential(credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to add credential to db");
        return ret;
    }

    return IS_SUCCESS;
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
