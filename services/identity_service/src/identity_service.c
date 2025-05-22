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

#include "common_defs.h"
#include "credential_data_manager.h"
#include "hc_log.h"
#include "identity_service_impl.h"
#include "os_account_adapter.h"
#include "permission_adapter.h"
#include "hisysevent_adapter.h"

int32_t AddCredential(int32_t osAccountId, const char *requestParams, char **returnData)
{
    SET_LOG_MODE(TRACE_MODE);

    if (requestParams == NULL || returnData == NULL) {
        LOGE("Failed to add credential, NULL params!");
        return IS_ERR_INVALID_PARAMS;
    }

    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }

    int32_t ret = AddCredentialImpl(osAccountId, requestParams, returnData);
    if (ret != IS_SUCCESS) {
        LOGE("Add credential failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(ADD_CREDENTIAL_EVENT, PROCESS_ADD_CREDENTIAL, ret);
    }
    return ret;
}

int32_t ExportCredential(int32_t osAccountId, const char *credId, char **returnData)
{
    SET_LOG_MODE(TRACE_MODE);

    if (credId == NULL || returnData == NULL) {
        LOGE("Failed to export credential, NULL params!");
        return IS_ERR_INVALID_PARAMS;
    }

    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }

    int32_t ret = ExportCredentialImpl(osAccountId, credId, returnData);
    if (ret != IS_SUCCESS) {
        LOGE("Export credential failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(EXPORT_CREDENTIAL_EVENT, PROCESS_EXPORT_CREDENTIAL, ret);
    }
    return ret;
}

int32_t QueryCredentialByParams(int32_t osAccountId, const char *requestParams, char **returnData)
{
    SET_LOG_MODE(TRACE_MODE);

    if (requestParams == NULL || returnData == NULL) {
        LOGE("Failed to query credential by params, NULL params!");
        return IS_ERR_INVALID_PARAMS;
    }

    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }

    int32_t ret = QueryCredentialByParamsImpl(osAccountId, requestParams, returnData);
    if (ret != IS_SUCCESS) {
        LOGE("Query credential by params failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(QUERY_CREDENTIAL_BY_PARAMS_EVENT,
            PROCESS_QUERY_CREDENTIAL_BY_PARAMS, ret);
    }
    return ret;
}

int32_t QueryCredInfoByCredIdAndUid(int32_t osAccountId, int32_t uid, const char *credId,
    char **returnData)
{
    return QueryCredInfoByCredIdImpl(osAccountId, uid, credId, returnData);
}

int32_t QueryCredInfoByCredId(int32_t osAccountId, const char *credId, char **returnData)
{
    SET_LOG_MODE(TRACE_MODE);

    if (credId == NULL || returnData == NULL) {
        LOGE("Failed to query credential info by credId, NULL params!");
        return IS_ERR_INVALID_PARAMS;
    }

    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }

    int32_t ret = QueryCredInfoByCredIdAndUid(osAccountId, GetCallingUid(), credId, returnData);
    if (ret != IS_SUCCESS) {
        LOGE("Query credential by credId failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(QUERY_CRED_INFO_BY_CRED_ID_EVENT,
            PROCESS_QUERY_CRED_INFO_BY_CRED_ID, ret);
    }
    return ret;
}

int32_t DeleteCredential(int32_t osAccountId, const char *credId)
{
    SET_LOG_MODE(TRACE_MODE);

    if (credId == NULL) {
        LOGE("Failed to delete credential, NULL credId!");
        return IS_ERR_INVALID_PARAMS;
    }

    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }

    int32_t ret = DeleteCredentialImpl(osAccountId, credId);
    if (ret != IS_SUCCESS) {
        LOGE("Delete credential failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(DELETE_CREDENTIAL_EVENT,
            PROCESS_DELETE_CREDENTIAL, ret);
    }
    return ret;
}

int32_t DeleteCredByParams(int32_t osAccountId, const char *requestParams, char **returnData)
{
    SET_LOG_MODE(TRACE_MODE);

    if (requestParams == NULL || returnData == NULL) {
        LOGE("Failed to batch delete credential, NULL params!");
        return IS_ERR_INVALID_PARAMS;
    }

    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    int32_t ret = DeleteCredByParamsImpl(osAccountId, requestParams, returnData);
    if (ret != IS_SUCCESS) {
        LOGE("Delete cred by params failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(DELETE_CREDENTIAL_BY_PARAMS_EVENT,
            PROCESS_DELETE_CREDENTIAL_BY_PARAMS, ret);
    }
    return ret;
}

int32_t UpdateCredInfo(int32_t osAccountId, const char *credId, const char *requestParams)
{
    SET_LOG_MODE(TRACE_MODE);

    if (credId == NULL || requestParams == NULL) {
        LOGE("Failed to update credential, NULL params!");
        return IS_ERR_INVALID_PARAMS;
    }

    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }

    int32_t ret = UpdateCredInfoImpl(osAccountId, credId, requestParams);
    if (ret != IS_SUCCESS) {
        LOGE("Update credInfo failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(UPDATE_CREDENTIAL_INFO_EVENT,
            PROCESS_UPDATE_CREDENTIAL_INFO, ret);
    }
    return ret;
}

int32_t BatchUpdateCredentials(int32_t osAccountId, const char *requestParams, char **returnData)
{
    SET_LOG_MODE(TRACE_MODE);

    if (requestParams == NULL || returnData == NULL) {
        LOGE("Failed to batch update credential, NULL params!");
        return IS_ERR_INVALID_PARAMS;
    }

    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    int32_t ret = BatchUpdateCredsImpl(osAccountId, requestParams, returnData);
    if (ret != IS_SUCCESS) {
        LOGE("Batch update creds failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(BATCH_UPDATE_CREDENTIALS_EVENT,
            PROCESS_BATCH_UPDATE_CREDENTIALS, ret);
    }
    return ret;
}

int32_t AgreeCredential(int32_t osAccountId, const char *selfCredId, const char *requestParams, char **returnData)
{
    SET_LOG_MODE(TRACE_MODE);

    if (selfCredId == NULL || requestParams == NULL || returnData == NULL) {
        LOGE("Failed to agree credential, NULL params!");
        return IS_ERR_INVALID_PARAMS;
    }
    
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return IS_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }

    int32_t ret = AgreeCredentialImpl(osAccountId, selfCredId, requestParams, returnData);
    if (ret != IS_SUCCESS) {
        LOGE("Agree credential failed, ret: %" LOG_PUB "d.", ret);
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(AGREE_CREDENTIAL_EVENT,
            PROCESS_AGREE_CREDENTIAL, ret);
    }
    return ret;
}

int32_t RegisterChangeListener(const char *appId, CredChangeListener *listener)
{
    SET_LOG_MODE(TRACE_MODE);

    return IsCredListenerSupported() ? RegCredListener(appId, listener) : HC_ERR_NOT_SUPPORT;
}

int32_t UnregisterChangeListener(const char *appId)
{
    SET_LOG_MODE(TRACE_MODE);
    
    return IsCredListenerSupported() ? UnRegCredListener(appId) : HC_ERR_NOT_SUPPORT;
}

static bool IsJsonString(const char *str)
{
    CJson *json = CreateJsonFromString(str);
    if (json == NULL) {
        return false;
    }
    FreeJson(json);
    return true;
}

void DestroyInfo(char **returnData)
{
    if (returnData == NULL || *returnData == NULL) {
        LOGE("Invalid params!");
        return;
    }
    if (IsJsonString(*returnData)) {
        FreeJsonString(*returnData);
    } else {
        HcFree(*returnData);
    }
    *returnData = NULL;
}

int32_t InitIdentityService(void)
{
    if (InitCredDatabase() != HC_SUCCESS) {
        return IS_ERR_SERVICE_NEED_RESTART;
    }
    return IsCredListenerSupported() ? InitCredListener() : HC_SUCCESS;
}

void DestroyIdentityService(void)
{
    if (IsCredListenerSupported()) {
        DestroyCredListener();
    }
    DestroyCredDatabase();
}