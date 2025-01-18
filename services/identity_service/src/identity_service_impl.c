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
    uint8_t method = DEFAULT_VAL;
    Uint8Buff keyValue = { NULL, 0 };
    char *credIdStr = NULL;
    int32_t ret = CheckAndSetCredInfo(credential, reqJson, osAccountId, &method, &keyValue);
    FreeJson(reqJson);
    if (ret != IS_SUCCESS) {
        DestroyCredential(credential);
        return ret;
    }
    uint8_t credIdByteVal[SHA256_LEN] = { 0 };
    Uint8Buff credIdByte = { credIdByteVal, sizeof(credIdByteVal) };
    if ((ret = GenerateCredId(credential, osAccountId, &credIdByte, &credIdStr)) != IS_SUCCESS) {
        HcFree(keyValue.val);
        DestroyCredential(credential);
        return ret;
    }
    if ((ret = AddKeyValueToHuks(credIdByte, credential, osAccountId, method, &keyValue)) != IS_SUCCESS) {
        HcFree(keyValue.val);
        HcFree(credIdStr);
        DestroyCredential(credential);
        return ret;
    }
    HcFree(keyValue.val);
    if ((ret = AddCredAndSaveDb(osAccountId, credential)) != IS_SUCCESS) {
        HcFree(credIdStr);
        DestroyCredential(credential);
        if (GetLoaderInstance()->deleteKey(&credIdByte, false, osAccountId) != IS_SUCCESS) {
            LOGE("Failed to delete key from HUKS");
        }
        return ret;
    }
    DestroyCredential(credential);
    if (DeepCopyString(credIdStr, returnData) != EOK) {
        LOGE("Failed to return credId");
        HcFree(credIdStr);
        return IS_ERR_MEMORY_COPY;
    }
    HcFree(credIdStr);
    return IS_SUCCESS;
}

int32_t ExportCredentialImpl(int32_t osAccountId, const char *credId, char **returnData)
{
    Credential *credential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credId, &credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to get credential by credId, ret = %d", ret);
        return ret;
    }
    DestroyCredential(credential);

    uint8_t credIdVal[SHA256_LEN] = { 0 };
    Uint8Buff credIdHashBuff = { credIdVal, SHA256_LEN };
    ret = CheckCredIdExistInHuks(osAccountId, credId, &credIdHashBuff);
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

    KeyParams keyParams = { { credIdHashBuff.val, credIdHashBuff.length, true }, false, osAccountId };
    uint8_t pubKeyVal[PUB_KEY_LENGTH] = { 0 };
    Uint8Buff keyValue = { pubKeyVal, PUB_KEY_LENGTH };
    ret = GetLoaderInstance()->exportPublicKey(&keyParams, &keyValue);
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
        LOGE("Failed to add pub key to return");
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
    FreeJson(reqJson);

    CredentialVec credentialVec = CreateCredentialVec();

    int32_t ret = QueryCredentials(osAccountId, &queryParams, &credentialVec);
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

    uint8_t credIdVal[SHA256_LEN] = { 0 };
    Uint8Buff credIdHashBuff = { credIdVal, SHA256_LEN };
    ret = HexStringToByte(credId, credIdHashBuff.val, credIdHashBuff.length);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credId to byte, error: %d", ret);
        return ret;
    }

    ret = GetLoaderInstance()->deleteKey(&credIdHashBuff, false, osAccountId);
    if (ret == HAL_ERR_HUKS) {
        LOGW("Huks delete key failed, error: %d, continue to delete local cred", IS_ERR_HUKS_DELETE_FAILED);
    }

    ret = DelCredById(osAccountId, credId);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to delete local credential");
        return ret;
    }

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
