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

#include "cred_session_util.h"

#include "hc_log.h"
#include "identity_service.h"
#include "device_auth.h"
#include "common_defs.h"
#include "device_auth_common.h"
#include "hc_types.h"
#include "hc_dev_info.h"
#include "json_utils.h"
#include "alg_defs.h"
#include "alg_loader.h"
#include "string_util.h"
#include "os_account_adapter.h"
#include "identity_service_defines.h"

static int32_t AddCredIdToContextIfNeeded(CJson *context)
{
    CJson *credJson = GetObjFromJson(context, FIELD_CREDENTIAL_OBJ);
    if (credJson == NULL) {
        LOGE("Get self credential fail.");
        return HC_ERR_JSON_GET;
    }
    uint8_t credType = ACCOUNT_RELATED;
    if (GetUint8FromJson(context, FIELD_CRED_TYPE, &credType) != HC_SUCCESS) {
        LOGE("Get credential type fail.");
        return HC_ERR_JSON_GET;
    }
    if (credType != ACCOUNT_SHARED) {
        LOGI("No need to add across account credential id to context");
        return HC_SUCCESS;
    }
    const char *credId = GetStringFromJson(context, FIELD_CRED_ID);
    if (AddStringToJson(context, FIELD_ACROSS_ACCOUNT_CRED_ID, credId) != HC_SUCCESS) {
        LOGE("add across account credential id to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static const char *GetAppIdByContext(const CJson *context)
{
    const char *pinCode = GetStringFromJson(context, FIELD_PIN_CODE);
    if (pinCode == NULL) {
        const CJson *json = GetObjFromJson(context, FIELD_CREDENTIAL_OBJ);
        if (json == NULL) {
            LOGE("get self credential info from json fail.");
            return NULL;
        }
        const char *appId = GetStringFromJson(json, FIELD_CRED_OWNER);
        if (appId == NULL) {
            LOGE("get appId from json fail.");
            return NULL;
        }
        return appId;
    }
    const char *appId = GetStringFromJson(context, FIELD_SERVICE_PKG_NAME);
    if (appId == NULL) {
        LOGE("get servicePkgName from json fail.");
        return NULL;
    }
    return appId;
}

static int32_t AddUserIdHashHexStringToContext(CJson *context, CJson *credAuthInfo)
{
    uint8_t credType = ACCOUNT_UNRELATED;
    if (GetUint8FromJson(credAuthInfo, FIELD_CRED_TYPE, &credType) != HC_SUCCESS) {
        LOGE("get int from json failed!");
        return HC_ERR_JSON_GET;
    }
    if (credType == ACCOUNT_UNRELATED) {
        return HC_SUCCESS;
    }
    const char *userId = GetStringFromJson(credAuthInfo, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get user ID!");
        return HC_ERR_JSON_GET;
    }
    Uint8Buff userIdBuf = { (uint8_t *)userId, (uint32_t)HcStrlen(userId) };
    uint8_t userIdHashByte[SHA256_LEN] = { 0 };
    Uint8Buff userIdHashBuf = { userIdHashByte, sizeof(userIdHashByte) };
    int32_t res = GetLoaderInstance()->sha256(&userIdBuf, &userIdHashBuf);
    if (res != HC_SUCCESS) {
        LOGE("sha256 failed, res:%" LOG_PUB "d", res);
        return res;
    }
    uint32_t userIdHashLen = SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *userIdHash = (char *)HcMalloc(userIdHashLen, 0);
    if (userIdHash == NULL) {
        LOGE("malloc userIdHash string failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    res = ByteToHexString(userIdHashByte, SHA256_LEN, userIdHash, userIdHashLen);
    if (res != HC_SUCCESS) {
        LOGE("Byte to hexString failed, res:%" LOG_PUB "d", res);
        HcFree(userIdHash);
        return res;
    }
    //replace userId plain to hash hex string
    if (AddStringToJson(context, FIELD_USER_ID, userIdHash) != HC_SUCCESS) {
        LOGE("Failed to add userIdHash");
        HcFree(userIdHash);
        return HC_ERR_JSON_ADD;
    }
    HcFree(userIdHash);
    return res;
}

static int32_t QueryAndAddSelfCredToContext(int32_t osAccountId, CJson *context)
{
    const char *credId = GetStringFromJson(context, FIELD_CRED_ID);
    if (credId == NULL) {
        LOGE("get self credential id from json fail.");
        return HC_ERR_JSON_GET;
    }
    PRINT_SENSITIVE_DATA("credId", credId);
    char *credDataStr = NULL;
    int32_t ret = QueryCredInfoByCredId(osAccountId, credId, &credDataStr);
    if (ret != HC_SUCCESS) {
        LOGE("No credential found.");
        return ret;
    }
    CJson *credDataJson = CreateJsonFromString(credDataStr);
    FreeJsonString(credDataStr);
    if (credDataJson == NULL) {
        LOGE("Faild to create json from string");
        return HC_ERR_JSON_FAIL;
    }
    int32_t res = AddUserIdHashHexStringToContext(context, credDataJson);
    if (res != HC_SUCCESS) {
        FreeJson(credDataJson);
        LOGE("Failed to replace userId plain to hash hex string!");
        return res;
    }
    if (AddObjToJson(context, FIELD_CREDENTIAL_OBJ, credDataJson) != HC_SUCCESS) {
        LOGE("add local credential object to context fail.");
        FreeJson(credDataJson);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(credDataJson);
    return HC_SUCCESS;
}

static bool CheckIsCredBind(CJson *context)
{
    const char *pinCode = GetStringFromJson(context, FIELD_PIN_CODE);
    bool isBind = true;
    if (pinCode == NULL || HcStrlen(pinCode) == 0) {
        isBind = false;
    }
    return isBind;
}

static int32_t AddAuthIdToCredContext(CJson *context)
{
    const char *authId = GetStringFromJson(context, FIELD_DEVICE_ID);
    char udid[INPUT_UDID_LEN] = { 0 };
    if (authId == NULL) {
        LOGD("No authId is found. The default value is udid!");
        int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
            return HC_ERR_DB;
        }
        authId = udid;
    }
    if (AddStringToJson(context, FIELD_AUTH_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t BuildClientCredBindContext(int32_t osAccountId, int64_t requestId,
    CJson *context, const char **returnAppId)
{
    const char *appId = GetAppIdByContext(context);
    if (appId == NULL) {
        LOGE("get appId fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, true) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, true) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CRED_AUTH, true) != HC_SUCCESS) {
        LOGE("add isCredAuth to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add osAccountId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, AUTH_FORM_ACCOUNT_UNRELATED) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddAuthIdToCredContext(context)) {
        return HC_ERR_JSON_ADD;
    }
    *returnAppId = appId;
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

static int32_t SetContextOpCode(CJson *context)
{
    uint8_t credType = ACCOUNT_UNRELATED;
    if (GetUint8FromJson(context, FIELD_CRED_TYPE, &credType) != HC_SUCCESS) {
        LOGE("get int from json failed!");
        return HC_ERR_JSON_GET;
    }
    switch (credType) {
        case ACCOUNT_RELATED:
            if (AddIntToJson(context, FIELD_OPERATION_CODE, AUTH_FORM_IDENTICAL_ACCOUNT) != HC_SUCCESS) {
                LOGE("add identical account code to context fail.");
                return HC_ERR_JSON_ADD;
            }
            break;
        case ACCOUNT_UNRELATED:
            if (AddIntToJson(context, FIELD_OPERATION_CODE, AUTH_FORM_ACCOUNT_UNRELATED) != HC_SUCCESS) {
                LOGE("add account unrelated code to context fail.");
                return HC_ERR_JSON_ADD;
            }
            break;
        case ACCOUNT_SHARED:
            if (AddIntToJson(context, FIELD_OPERATION_CODE, AUTH_FORM_ACROSS_ACCOUNT) != HC_SUCCESS) {
                LOGE("add across account code to context fail.");
                return HC_ERR_JSON_ADD;
            }
            break;
        default:
            LOGE("unsupport cred type.");
            return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return HC_SUCCESS;
}

static int32_t BuildClientCredAuthContext(int32_t osAccountId, int64_t requestId,
    CJson *context, const char **returnAppId)
{
    int32_t res = QueryAndAddSelfCredToContext(osAccountId, context);
    if (res != HC_SUCCESS) {
        return res;
    }
    const char *appId = GetAppIdByContext(context);
    if (appId == NULL) {
        LOGE("get appId fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, false) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, true) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CRED_AUTH, true) != HC_SUCCESS) {
        LOGE("add isCredAuth to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add osAccountId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (SetContextOpCode(context) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddCredIdToContextIfNeeded(context) != HC_SUCCESS) {
        LOGE("add across account credential id to context fail.");
        return HC_ERR_JSON_ADD;
    }
    *returnAppId = appId;
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

int32_t BuildClientCredContext(int32_t osAccountId, int64_t requestId, CJson *context, const char **returnAppId)
{
    if (context == NULL) {
        LOGE("input context is null ptr!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (CheckIsCredBind(context)) {
        return BuildClientCredBindContext(osAccountId, requestId, context, returnAppId);
    }
    return BuildClientCredAuthContext(osAccountId, requestId, context, returnAppId);
}

static int32_t BuildServerCredBindContext(int64_t requestId, CJson *context,
    char **returnPeerUdid, const char **returnAppId)
{
    (void)returnPeerUdid;
    int32_t res = CheckConfirmationExist(context);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddOsAccountIdToContextIfValid(context);
    if (res != HC_SUCCESS) {
        return res;
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, true) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, false) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    const char *appId = GetAppIdByContext(context);
    if (appId == NULL) {
        LOGE("get appId Fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CRED_AUTH, true) != HC_SUCCESS) {
        LOGE("add isCredAuth to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddAuthIdToCredContext(context)) {
        return HC_ERR_JSON_ADD;
    }
    *returnAppId = appId;
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

static int32_t BuildServerCredAuthContext(int64_t requestId, CJson *context,
    char **returnPeerUdid, const char **returnAppId)
{
    (void) returnPeerUdid;
    int32_t res = CheckConfirmationExist(context);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddOsAccountIdToContextIfValid(context);
    if (res != HC_SUCCESS) {
        return res;
    }
    int32_t osAccountId = ANY_OS_ACCOUNT;
    (void)GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId);
    if (AddBoolToJson(context, FIELD_IS_BIND, false) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, false) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if ((res = QueryAndAddSelfCredToContext(osAccountId, context)) != HC_SUCCESS ||
       ((res = AddCredIdToContextIfNeeded(context)) != HC_SUCCESS)) {
        return res;
    }
    const char *appId = GetAppIdByContext(context);
    if (appId == NULL) {
        LOGE("get appId Fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddBoolToJson(context, FIELD_IS_CRED_AUTH, true) != HC_SUCCESS) {
        LOGE("add isCredAuth to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    *returnAppId = appId;
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

int32_t BuildServerCredContext(int64_t requestId, CJson *context, char **returnPeerUdid, const char **returnAppId)
{
    if (context == NULL) {
        LOGE("input context is null ptr!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (CheckIsCredBind(context)) {
        return BuildServerCredBindContext(requestId, context, returnPeerUdid, returnAppId);
    }
    return BuildServerCredAuthContext(requestId, context, returnPeerUdid, returnAppId);
}
