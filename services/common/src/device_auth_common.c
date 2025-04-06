/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "os_account_adapter.h"
#include "device_auth_common.h"
#include "hc_log.h"

int32_t AddOsAccountIdToContextIfValid(CJson *context)
{
    int32_t osAccountId = ANY_OS_ACCOUNT;
    (void)GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    LOGI("[OsAccountId]: %" LOG_PUB "d", osAccountId);
    if (osAccountId == INVALID_OS_ACCOUNT) {
        return HC_ERR_INVALID_PARAMS;
    }
    if (!CheckIsForegroundOsAccountId(osAccountId)) {
        LOGE("This access is not from the foreground user, rejected it.");
        return HC_ERR_CROSS_USER_ACCESS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add operationCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

int32_t CheckConfirmationExist(const CJson *context)
{
    uint32_t confirmation = REQUEST_REJECTED;
    if (GetUnsignedIntFromJson(context, FIELD_CONFIRMATION, &confirmation) != HC_SUCCESS) {
        LOGE("Failed to get confimation from json!");
        return HC_ERR_JSON_GET;
    }
    if (confirmation == REQUEST_ACCEPTED) {
        LOGI("The service accepts this request!");
    } else {
        LOGW("The service rejects this request!");
    }
    return HC_SUCCESS;
}

int32_t AddChannelInfoToContext(int32_t channelType, int64_t channelId, CJson *context)
{
    if (AddIntToJson(context, FIELD_CHANNEL_TYPE, channelType) != HC_SUCCESS) {
        LOGE("add channelType to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(context, FIELD_CHANNEL_ID, (uint8_t *)&channelId, sizeof(int64_t)) != HC_SUCCESS) {
        LOGE("add channelId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}