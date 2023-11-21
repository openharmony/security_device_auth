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

#include "compatible_bind_sub_session_util.h"

#include "channel_manager.h"
#include "dev_auth_module_manager.h"
#include "group_operation_common.h"
#include "hc_log.h"
#include "hc_time.h"
#include "hitrace_adapter.h"
#include "performance_dumper.h"

static int32_t AddPinCode(const CJson *returnData, CJson *jsonParams)
{
    const char *pinCode = GetStringFromJson(returnData, FIELD_PIN_CODE);
    if (pinCode == NULL) {
        LOGE("Failed to get pinCode from returnData!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(jsonParams, FIELD_PIN_CODE, pinCode) != HC_SUCCESS) {
        LOGE("Failed to add pinCode to jsonParams!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddAuthIdIfExist(const CJson *returnData, CJson *jsonParams)
{
    const char *authId = GetStringFromJson(returnData, FIELD_DEVICE_ID);
    if (authId != NULL && AddStringToJson(jsonParams, FIELD_DEVICE_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add authId to jsonParams!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddUserTypeIfExistAndValid(const CJson *returnData, CJson *jsonParams)
{
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    if (GetIntFromJson(returnData, FIELD_USER_TYPE, &userType) == HC_SUCCESS) {
        if (!IsUserTypeValid(userType)) {
            LOGE("The input userType is invalid!");
            return HC_ERR_INVALID_PARAMS;
        }
        if (AddIntToJson(jsonParams, FIELD_USER_TYPE, userType) != HC_SUCCESS) {
            LOGE("Failed to add userType to jsonParams!");
            return HC_ERR_JSON_ADD;
        }
    }
    return HC_SUCCESS;
}

static int32_t AddGroupVisibilityIfExistAndValid(const CJson *returnData, CJson *jsonParams)
{
    int32_t groupVisibility = GROUP_VISIBILITY_PUBLIC;
    if (GetIntFromJson(returnData, FIELD_GROUP_VISIBILITY, &groupVisibility) == HC_SUCCESS) {
        if (!IsGroupVisibilityValid(groupVisibility)) {
            LOGE("The input groupVisibility invalid!");
            return HC_ERR_INVALID_PARAMS;
        }
        if (AddIntToJson(jsonParams, FIELD_GROUP_VISIBILITY, groupVisibility) != HC_SUCCESS) {
            LOGE("Failed to add groupVisibility to jsonParams!");
            return HC_ERR_JSON_ADD;
        }
    }
    return HC_SUCCESS;
}

static int32_t AddExpireTimeIfExistAndValid(const CJson *returnData, CJson *jsonParams)
{
    int32_t expireTime = DEFAULT_EXPIRE_TIME;
    if (GetIntFromJson(returnData, FIELD_EXPIRE_TIME, &expireTime) == HC_SUCCESS) {
        if (!IsExpireTimeValid(expireTime)) {
            LOGE("The input expireTime invalid!");
            return HC_ERR_INVALID_PARAMS;
        }
        if (AddIntToJson(jsonParams, FIELD_EXPIRE_TIME, expireTime) != HC_SUCCESS) {
            LOGE("Failed to add expireTime to jsonParams!");
            return HC_ERR_JSON_ADD;
        }
    }
    return HC_SUCCESS;
}

static int32_t CombineInfoWhenInvite(const CJson *returnData, CJson *jsonParams)
{
    int32_t result;
    if (((result = AddPinCode(returnData, jsonParams)) != HC_SUCCESS) ||
        ((result = AddAuthIdIfExist(returnData, jsonParams)) != HC_SUCCESS) ||
        ((result = AddUserTypeIfExistAndValid(returnData, jsonParams)) != HC_SUCCESS) ||
        ((result = AddGroupVisibilityIfExistAndValid(returnData, jsonParams)) != HC_SUCCESS) ||
        ((result = AddExpireTimeIfExistAndValid(returnData, jsonParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupErrorInfo(int32_t errorCode, const CompatibleBindSubSession *session,
    CJson *errorData)
{
    if (AddIntToJson(errorData, FIELD_GROUP_ERROR_MSG, errorCode) != HC_SUCCESS) {
        LOGE("Failed to add errorCode to errorData!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(errorData, FIELD_APP_ID, session->base.appId) != HC_SUCCESS) {
        LOGE("Failed to add appId to errorData!");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(errorData, FIELD_REQUEST_ID, session->reqId) != HC_SUCCESS) {
        LOGE("Failed to add requestId to errorData!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupErrorMsg(int32_t errorCode, int64_t requestId, const CJson *jsonParams, CJson **errorData)
{
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    *errorData = CreateJson();
    if (*errorData == NULL) {
        LOGE("Failed to allocate errorData memory!");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(*errorData, FIELD_GROUP_ERROR_MSG, errorCode) != HC_SUCCESS) {
        LOGE("Failed to add errorCode to errorData!");
        FreeJson(*errorData);
        *errorData = NULL;
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(*errorData, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("Failed to add appId to errorData!");
        FreeJson(*errorData);
        *errorData = NULL;
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(*errorData, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("Failed to add requestId to errorData!");
        FreeJson(*errorData);
        *errorData = NULL;
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

int32_t CreateAndProcessBindTask(CompatibleBindSubSession *session, const CJson *in, CJson *out, int32_t *status)
{
    LOGI("Start to create and process module task! [ModuleType]: %d", session->moduleType);
    DEV_AUTH_START_TRACE(TRACE_TAG_CREATE_AUTH_TASK);
    int32_t res = CreateTask(&(session->base.curTaskId), in, out, session->moduleType);
    DEV_AUTH_FINISH_TRACE();
    if (res != HC_SUCCESS) {
        LOGE("Failed to create module task! res: %d", res);
        return res;
    }
    DEV_AUTH_START_TRACE(TRACE_TAG_PROCESS_AUTH_TASK);
    res = ProcessTask(session->base.curTaskId, in, out, status, session->moduleType);
    DEV_AUTH_FINISH_TRACE();
    if (res != HC_SUCCESS) {
        LOGE("Failed to process module task! res: %d", res);
        return res;
    }
    LOGI("Create and process module task successfully!");
    return HC_SUCCESS;
}

int32_t TransmitBindSessionData(const CompatibleBindSubSession *session, const CJson *sendData)
{
    char *sendDataStr = PackJsonToString(sendData);
    if (sendDataStr == NULL) {
        LOGE("An error occurred when converting json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    DEV_AUTH_START_TRACE(TRACE_TAG_SEND_DATA);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(session->reqId, HcGetCurTimeInMillis());
    int32_t res = HcSendMsg(session->channelType, session->reqId, session->channelId,
        session->base.callback, sendDataStr);
    DEV_AUTH_FINISH_TRACE();
    FreeJsonString(sendDataStr);
    if (res != HC_SUCCESS) {
        LOGE("Failed to send msg to peer device! res: %d", res);
        return res;
    }
    return HC_SUCCESS;
}

int32_t CombineConfirmData(int operationCode, const CJson *returnData, CJson *jsonParams)
{
    if (operationCode == MEMBER_JOIN) {
        return AddPinCode(returnData, jsonParams);
    } else {
        return CombineInfoWhenInvite(returnData, jsonParams);
    }
}

void InformPeerGroupErrorIfNeeded(bool isNeedInform, int32_t errorCode, const CompatibleBindSubSession *session)
{
    if (!isNeedInform) {
        return;
    }
    CJson *errorData = CreateJson();
    if (errorData == NULL) {
        LOGE("Failed to allocate errorData memory!");
        return;
    }
    int32_t res = AddGroupErrorInfo(errorCode, session, errorData);
    if (res != HC_SUCCESS) {
        FreeJson(errorData);
        return;
    }
    res = TransmitBindSessionData(session, errorData);
    FreeJson(errorData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to transmit group error to peer!");
        return;
    }
    LOGI("Notify the peer device that an error occurred at the local end successfully!");
}

void InformPeerProcessError(int64_t requestId, const CJson *jsonParams, const DeviceAuthCallback *callback,
    int32_t errorCode)
{
    int64_t channelId = DEFAULT_CHANNEL_ID;
    ChannelType channelType = SOFT_BUS;
    if (GetByteFromJson(jsonParams, FIELD_CHANNEL_ID, (uint8_t *)&channelId, sizeof(int64_t)) != HC_SUCCESS) {
        channelType = SERVICE_CHANNEL;
    }
    CJson *errorData = NULL;
    int32_t res = GenerateGroupErrorMsg(errorCode, requestId, jsonParams, &errorData);
    if (res != HC_SUCCESS) {
        return;
    }
    char *errorDataStr = PackJsonToString(errorData);
    FreeJson(errorData);
    if (errorDataStr == NULL) {
        LOGE("An error occurred when converting json to string!");
        return;
    }
    (void)HcSendMsg(channelType, requestId, channelId, callback, errorDataStr);
    FreeJsonString(errorDataStr);
}