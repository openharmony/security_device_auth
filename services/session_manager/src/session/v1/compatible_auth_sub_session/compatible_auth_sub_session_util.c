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

#include "compatible_auth_sub_session_util.h"

#include "account_unrelated_group_auth.h"
#include "account_related_group_auth.h"
#include "hc_log.h"
#include "hc_types.h"
#include "os_account_adapter.h"

static int32_t AuthFormToModuleType(int32_t authForm)
{
    int moduleType = INVALID_MODULE_TYPE;
    if (authForm == AUTH_FORM_ACCOUNT_UNRELATED) {
        moduleType = DAS_MODULE;
    } else if ((authForm == AUTH_FORM_IDENTICAL_ACCOUNT) || (authForm == AUTH_FORM_ACROSS_ACCOUNT)) {
        moduleType = ACCOUNT_MODULE;
    } else {
        LOGE("Invalid auth form!");
    }
    return moduleType;
}

int32_t GetAuthModuleType(const CJson *in)
{
    int32_t authForm = AUTH_FORM_INVALID_TYPE;
    if (GetIntFromJson(in, FIELD_AUTH_FORM, &authForm) != HC_SUCCESS) {
        LOGE("Failed to get auth form!");
        return INVALID_MODULE_TYPE;
    }
    return AuthFormToModuleType(authForm);
}

char *GetDuplicatePkgName(const CJson *params)
{
    const char *pkgName = GetStringFromJson(params, FIELD_SERVICE_PKG_NAME);
    if (pkgName == NULL) {
        LOGE("Failed to get servicePkgName from json!");
        return NULL;
    }
    uint32_t pkgNameLen = HcStrlen(pkgName) + 1;
    char *returnPkgName = (char *)HcMalloc(pkgNameLen, 0);
    if (returnPkgName == NULL) {
        LOGE("Failed to allocate returnPkgName memory!");
        return NULL;
    }
    if (memcpy_s(returnPkgName, pkgNameLen, pkgName, pkgNameLen) != EOK) {
        LOGE("Failed to copy pkgName!");
        HcFree(returnPkgName);
        return NULL;
    }
    return returnPkgName;
}

int32_t CombineAuthConfirmData(const CJson *confirmationJson, CJson *dataFromClient)
{
    int32_t osAccountId = ANY_OS_ACCOUNT;
    (void)GetIntFromJson(confirmationJson, FIELD_OS_ACCOUNT_ID, &osAccountId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (osAccountId == INVALID_OS_ACCOUNT) {
        LOGE("Invalid os account!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (AddIntToJson(dataFromClient, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("Failed to add os accountId!");
        return HC_ERR_JSON_ADD;
    }
    int32_t authForm = AUTH_FORM_INVALID_TYPE;
    if (GetIntFromJson(dataFromClient, FIELD_AUTH_FORM, &authForm) != HC_SUCCESS) {
        LOGE("Failed to get auth form!");
        return HC_ERR_JSON_GET;
    }
    int32_t groupAuthType = GetAuthType(authForm);
    BaseGroupAuth *groupAuthHandle = GetGroupAuth(groupAuthType);
    if (groupAuthHandle == NULL) {
        LOGE("Failed to get group auth handle!");
        return HC_ERR_NOT_SUPPORT;
    }
    int32_t res = groupAuthHandle->combineServerConfirmParams(confirmationJson, dataFromClient);
    if (res != HC_SUCCESS) {
        LOGE("Failed to combine server confirm params!");
    }
    return res;
}

int32_t GetAuthType(int32_t authForm)
{
    switch (authForm) {
        case AUTH_FORM_ACCOUNT_UNRELATED:
            return ACCOUNT_UNRELATED_GROUP_AUTH_TYPE;
        case AUTH_FORM_IDENTICAL_ACCOUNT:
            return ACCOUNT_RELATED_GROUP_AUTH_TYPE;
        case AUTH_FORM_ACROSS_ACCOUNT:
            return ACCOUNT_RELATED_GROUP_AUTH_TYPE;
        default:
            LOGE("Invalid authForm!");
            return INVALID_GROUP_AUTH_TYPE;
    }
}

BaseGroupAuth *GetGroupAuth(int32_t groupAuthType)
{
    switch (groupAuthType) {
        case ACCOUNT_UNRELATED_GROUP_AUTH_TYPE:
            LOGI("Non-account auth type.");
            return GetAccountUnrelatedGroupAuth();
        case ACCOUNT_RELATED_GROUP_AUTH_TYPE:
            LOGI("Account-related auth type.");
            return GetAccountRelatedGroupAuth();
        default:
            LOGE("Invalid auth type!");
    }
    return NULL;
}
