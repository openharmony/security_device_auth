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

    return AddCredentialImpl(osAccountId, requestParams, returnData);
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

    return ExportCredentialImpl(osAccountId, credId, returnData);
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

    return QueryCredentialByParamsImpl(osAccountId, requestParams, returnData);
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

    return QueryCredInfoByCredIdImpl(osAccountId, credId, returnData);
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

    return DeleteCredentialImpl(osAccountId, credId);
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

    return UpdateCredInfoImpl(osAccountId, credId, requestParams);
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

void DestroyInfo(char **returnData)
{
    if (returnData == NULL || *returnData == NULL) {
        return;
    }
    FreeJsonString(*returnData);
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