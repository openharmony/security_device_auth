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

#include "compatible_bind_sub_session_common.h"

#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_log.h"

static int32_t AddPinCode(const CJson *jsonParams, CompatibleBindSubSession *session)
{
    const char *pinCode = GetStringFromJson(jsonParams, FIELD_PIN_CODE);
    if (pinCode == NULL) {
        LOGE("Failed to get pinCode from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(session->params, FIELD_PIN_CODE, pinCode) != HC_SUCCESS) {
        LOGE("Failed to add pinCode to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddProtocolExpandVal(const CJson *jsonParams, CompatibleBindSubSession *session)
{
    int32_t protocolExpandVal = INVALID_PROTOCOL_EXPAND_VALUE;
    (void)GetIntFromJson(jsonParams, FIELD_PROTOCOL_EXPAND, &protocolExpandVal);
    if (AddIntToJson(session->params, FIELD_PROTOCOL_EXPAND, protocolExpandVal) != HC_SUCCESS) {
        LOGE("Failed to add protocol expand val to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupId(const char *groupId, CJson *params)
{
    if (AddStringToJson(params, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupName(const CJson *jsonParams, CJson *params)
{
    const char *groupName = GetStringFromJson(jsonParams, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(params, FIELD_GROUP_NAME, groupName) != HC_SUCCESS) {
        LOGE("Failed to add groupName to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupOwnerIfExist(const CJson *jsonParams, CJson *params)
{
    const char *groupOwner = GetStringFromJson(jsonParams, FIELD_GROUP_OWNER);
    if ((groupOwner != NULL) && (AddStringToJson(params, FIELD_GROUP_OWNER, groupOwner) != HC_SUCCESS)) {
        LOGE("Failed to add groupOwner to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupTypeIfValid(const CJson *jsonParams, CJson *params)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetIntFromJson(jsonParams, FIELD_GROUP_TYPE, &groupType) != HC_SUCCESS) {
        LOGE("Failed to get groupType from json params!");
        return HC_ERR_JSON_GET;
    }
    if (groupType != PEER_TO_PEER_GROUP) {
        LOGE("The input groupType is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (AddIntToJson(params, FIELD_GROUP_TYPE, groupType) != HC_SUCCESS) {
        LOGE("Failed to add groupType to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupVisibilityIfValidOrDefault(const CJson *jsonParams, CJson *params)
{
    int32_t groupVisibility = GROUP_VISIBILITY_PUBLIC;
    (void)GetIntFromJson(jsonParams, FIELD_GROUP_VISIBILITY, &groupVisibility);
    if (!IsGroupVisibilityValid(groupVisibility)) {
        LOGE("The input groupVisibility is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (AddIntToJson(params, FIELD_GROUP_VISIBILITY, groupVisibility) != HC_SUCCESS) {
        LOGE("Failed to add groupVisibility to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddExpireTimeIfValidOrDefault(const CJson *jsonParams, CJson *params)
{
    int32_t expireTime = DEFAULT_EXPIRE_TIME;
    (void)GetIntFromJson(jsonParams, FIELD_EXPIRE_TIME, &expireTime);
    if (!IsExpireTimeValid(expireTime)) {
        LOGE("The input expireTime is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (AddIntToJson(params, FIELD_EXPIRE_TIME, expireTime) != HC_SUCCESS) {
        LOGE("Failed to add expireTime to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupInfoToSessionParams(const char *groupId, const CJson *jsonParams, CJson *params)
{
    int32_t result;
    if (((result = AddGroupId(groupId, params)) != HC_SUCCESS) ||
        ((result = AddGroupName(jsonParams, params)) != HC_SUCCESS) ||
        ((result = AddGroupOwnerIfExist(jsonParams, params)) != HC_SUCCESS) ||
        ((result = AddGroupTypeIfValid(jsonParams, params)) != HC_SUCCESS) ||
        ((result = AddGroupVisibilityIfValidOrDefault(jsonParams, params)) != HC_SUCCESS) ||
        ((result = AddExpireTimeIfValidOrDefault(jsonParams, params)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CheckAuthIdAndUserTypeValid(int32_t osAccountId, int userType, const char *groupId, const char *authId)
{
    if (!IsGroupExistByGroupId(osAccountId, groupId)) {
        return HC_SUCCESS;
    }
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return res;
    }
    TrustedDeviceEntry *deviceInfo = CreateDeviceEntry();
    if (deviceInfo == NULL) {
        LOGE("Failed to allocate deviceInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GetTrustedDevInfoById(osAccountId, udid, true, groupId, deviceInfo);
    if (result != HC_SUCCESS) {
        LOGE("Failed to obtain the local device information from the database!");
        DestroyDeviceEntry(deviceInfo);
        return result;
    }
    const char *oriAuthId = StringGet(&deviceInfo->authId);
    if ((deviceInfo->devType != userType) || ((oriAuthId != NULL) && (strcmp(oriAuthId, authId) != 0))) {
        LOGE("Once a group is created, the service cannot change the local authId and userType used in the group!");
        DestroyDeviceEntry(deviceInfo);
        return HC_ERR_INVALID_PARAMS;
    }
    DestroyDeviceEntry(deviceInfo);
    return HC_SUCCESS;
}

static int32_t AddAuthIdAndUserTypeIfValidOrDefault(int32_t osAccountId, const char *groupId, const CJson *jsonParams,
    CJson *params)
{
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(jsonParams, FIELD_USER_TYPE, &userType);
    if (!IsUserTypeValid(userType)) {
        LOGE("The input userType is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *authId = GetStringFromJson(jsonParams, FIELD_DEVICE_ID);
    char udid[INPUT_UDID_LEN] = { 0 };
    if (authId == NULL) {
        LOGI("authId is not found, use udid by default!");
        int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get local udid! res: %d", res);
            return res;
        }
        authId = udid;
    }
    int32_t result = CheckAuthIdAndUserTypeValid(osAccountId, userType, groupId, authId);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (AddIntToJson(params, FIELD_USER_TYPE, userType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(params, FIELD_AUTH_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddUdid(CJson *params)
{
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return res;
    }
    if (AddStringToJson(params, FIELD_CONN_DEVICE_ID, udid) != HC_SUCCESS) {
        LOGE("Failed to add udid to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddUserTypeIfValidOrDefault(const CJson *jsonParams, CJson *params)
{
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(jsonParams, FIELD_USER_TYPE, &userType);
    if (!IsUserTypeValid(userType)) {
        LOGE("The input userType is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (AddIntToJson(params, FIELD_USER_TYPE, userType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddDevInfoToSessionParams(int32_t osAccountId, const char *groupId, const CJson *jsonParams,
    CJson *params)
{
    int32_t result;
    if (((result = AddAuthIdAndUserTypeIfValidOrDefault(osAccountId, groupId, jsonParams, params)) != HC_SUCCESS) ||
        ((result = AddUdid(params)) != HC_SUCCESS) ||
        ((result = AddUserTypeIfValidOrDefault(jsonParams, params)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateParamsByInput(int32_t osAccountId, const char *groupId, const CJson *jsonParams, CJson *params)
{
    int32_t result = AddGroupInfoToSessionParams(groupId, jsonParams, params);
    if (result != HC_SUCCESS) {
        return result;
    }
    return AddDevInfoToSessionParams(osAccountId, groupId, jsonParams, params);
}

static int32_t AddGroupInfoToParams(const TrustedGroupEntry *entry, CJson *params)
{
    if (AddStringToJson(params, FIELD_GROUP_ID, StringGet(&entry->id)) != HC_SUCCESS) {
        LOGE("Failed to add groupId to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(params, FIELD_GROUP_TYPE, entry->type) != HC_SUCCESS) {
        LOGE("Failed to add groupType to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(params, FIELD_GROUP_NAME, StringGet(&entry->name)) != HC_SUCCESS) {
        LOGE("Failed to add groupName to json!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupInfoByDatabase(int32_t osAccountId, const char *groupId, CJson *params)
{
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        LOGE("Failed to get groupEntry from db!");
        return HC_ERR_DB;
    }
    int32_t res = AddGroupInfoToParams(entry, params);
    if (res != HC_SUCCESS) {
        DestroyGroupEntry(entry);
        return res;
    }
    DestroyGroupEntry(entry);
    return HC_SUCCESS;
}

static int32_t AddDevInfoToParams(const TrustedDeviceEntry *devAuthParams, CJson *params)
{
    if (AddStringToJson(params, FIELD_AUTH_ID, StringGet(&devAuthParams->authId)) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(params, FIELD_CONN_DEVICE_ID, StringGet(&devAuthParams->udid)) != HC_SUCCESS) {
        LOGE("Failed to add udid to params!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(params, FIELD_USER_TYPE, devAuthParams->devType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddDevInfoByDatabase(int32_t osAccountId, const char *groupId, CJson *params)
{
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return res;
    }
    TrustedDeviceEntry *devAuthParams = CreateDeviceEntry();
    if (devAuthParams == NULL) {
        LOGE("Failed to allocate devEntry memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    res = GetTrustedDevInfoById(osAccountId, udid, true, groupId, devAuthParams);
    if (res != HC_SUCCESS) {
        LOGE("Failed to obtain the device information from the database!");
        DestroyDeviceEntry(devAuthParams);
        return res;
    }
    res = AddDevInfoToParams(devAuthParams, params);
    if (res != HC_SUCCESS) {
        DestroyDeviceEntry(devAuthParams);
        return res;
    }
    DestroyDeviceEntry(devAuthParams);
    return HC_SUCCESS;
}

static int32_t GenerateParamsByDatabase(int32_t osAccountId, const char *groupId, CJson *params)
{
    int32_t result = AddGroupInfoByDatabase(osAccountId, groupId, params);
    if (result != HC_SUCCESS) {
        return result;
    }
    return AddDevInfoByDatabase(osAccountId, groupId, params);
}

static int32_t AddGroupAndDevInfo(int32_t osAccountId, int isClient, const CJson *jsonParams,
    CompatibleBindSubSession *session)
{
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    if (IsCreateGroupNeeded(isClient, session->opCode)) {
        return GenerateParamsByInput(osAccountId, groupId, jsonParams, session->params);
    } else {
        return GenerateParamsByDatabase(osAccountId, groupId, session->params);
    }
}

static int32_t AddPeerAuthIdAndUdidIfExist(const CJson *jsonParams, CompatibleBindSubSession *session)
{
    const char *peerAuthId = GetStringFromJson(jsonParams, FIELD_PEER_DEVICE_ID);
    if (peerAuthId != NULL && AddStringToJson(session->params, FIELD_PEER_AUTH_ID, peerAuthId) != HC_SUCCESS) {
        LOGE("Failed to add peerAuthId to params!");
        return HC_ERR_JSON_ADD;
    }
    const char *peerUdid = GetStringFromJson(jsonParams, FIELD_PEER_UDID);
    if (peerUdid != NULL && AddStringToJson(session->params, FIELD_PEER_UDID, peerUdid) != HC_SUCCESS) {
        LOGE("Failed to add peerUdid to params!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupAndDevInfoToParams(const CompatibleBindSubSession *session, CJson *moduleParams)
{
    const char *groupId = GetStringFromJson(session->params, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from params!");
        return HC_ERR_JSON_GET;
    }
    const char *authId = GetStringFromJson(session->params, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGE("Failed to get authId from params!");
        return HC_ERR_JSON_GET;
    }
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    if (GetIntFromJson(session->params, FIELD_USER_TYPE, &userType) != HC_SUCCESS) {
        LOGE("Failed to get userType from params!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(moduleParams, FIELD_SERVICE_TYPE, groupId) != HC_SUCCESS) {
        LOGE("Failed to add serviceType to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(moduleParams, FIELD_SELF_AUTH_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add serviceType to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(moduleParams, FIELD_SELF_TYPE, userType) != HC_SUCCESS) {
        LOGE("Failed to add userType to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddRequestInfoToParams(bool isClient, const CompatibleBindSubSession *session, CJson *moduleParams)
{
    if (AddInt64StringToJson(moduleParams, FIELD_REQUEST_ID, session->reqId) != HC_SUCCESS) {
        LOGE("Failed to add requestId to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(moduleParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH) != HC_SUCCESS) {
        LOGE("Failed to add sessionKeyLength to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(moduleParams, FIELD_IS_CLIENT, isClient) != HC_SUCCESS) {
        LOGE("Failed to add isClient to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    /* Use the GroupManager package name. */
    if (AddStringToJson(moduleParams, FIELD_PKG_NAME, GROUP_MANAGER_PACKAGE_NAME) != HC_SUCCESS) {
        LOGE("Failed to add pkgName to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddPinCodeToParams(CompatibleBindSubSession *session, CJson *moduleParams)
{
    const char *pinCode = GetStringFromJson(session->params, FIELD_PIN_CODE);
    if (pinCode == NULL) {
        LOGE("Failed to get pinCode from params!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(moduleParams, FIELD_PIN_CODE, pinCode) != HC_SUCCESS) {
        LOGE("Failed to add pinCode to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    /* Release the memory in advance to reduce the memory usage. */
    (void)DeleteItemFromJson(session->params, FIELD_PIN_CODE);
    return HC_SUCCESS;
}

static int32_t AddProtocolExpandValToParams(CompatibleBindSubSession *session, CJson *moduleParams)
{
    int32_t protocolExpandVal = INVALID_PROTOCOL_EXPAND_VALUE;
    (void)GetIntFromJson(session->params, FIELD_PROTOCOL_EXPAND, &protocolExpandVal);
    if (AddIntToJson(moduleParams, FIELD_PROTOCOL_EXPAND, protocolExpandVal) != HC_SUCCESS) {
        LOGE("Failed to add protocol expand val to moduleParams!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupInfoToSendData(const CompatibleBindSubSession *session, CJson *data)
{
    const char *groupId = GetStringFromJson(session->params, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from params!");
        return HC_ERR_JSON_GET;
    }
    const char *groupName = GetStringFromJson(session->params, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from params!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(data, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to data!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(data, FIELD_GROUP_NAME, groupName) != HC_SUCCESS) {
        LOGE("Failed to add groupName to data!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(data, FIELD_GROUP_OP, session->opCode) != HC_SUCCESS) {
        LOGE("Failed to add groupOp to data!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(data, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP) != HC_SUCCESS) {
        LOGE("Failed to add groupType to data!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddDevInfoToSendData(const CompatibleBindSubSession *session, CJson *data)
{
    const char *authId = GetStringFromJson(session->params, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGE("Failed to get authId from params!");
        return HC_ERR_JSON_GET;
    }
    const char *udid = GetStringFromJson(session->params, FIELD_CONN_DEVICE_ID);
    if (udid == NULL) {
        LOGE("Failed to get udid from params!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(data, FIELD_PEER_DEVICE_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add peerDeviceId to data!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(data, FIELD_CONN_DEVICE_ID, udid) != HC_SUCCESS) {
        LOGE("Failed to add connDeviceId to data!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddRequestInfoToSendData(const CompatibleBindSubSession *session, CJson *data)
{
    if (AddStringToJson(data, FIELD_APP_ID, session->base.appId) != HC_SUCCESS) {
        LOGE("Failed to add appId to data!");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(data, FIELD_REQUEST_ID, session->reqId) != HC_SUCCESS) {
        LOGE("Failed to add requestId to data!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(data, FIELD_OWNER_NAME, "") != HC_SUCCESS) {
        LOGE("Failed to add ownerName to data!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GenerateCompatibleInfo(CJson *groupInfo)
{
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return res;
    }
    if (AddStringToJson(groupInfo, FIELD_DEVICE_ID, udid) != HC_SUCCESS) {
        LOGE("Failed to add deviceId to groupInfo!");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(groupInfo, FIELD_IS_UUID, true) != HC_SUCCESS) {
        LOGE("Failed to add uuIdAsDeviceId to groupInfo!");
        return HC_ERR_JSON_ADD;
    }
    /* To be compatible with packets of earlier versions. */
    CJson *managers = CreateJsonArray();
    if (managers == NULL) {
        LOGE("Failed to allocate managers memory!");
        return HC_ERR_JSON_CREATE;
    }
    if (AddObjToJson(groupInfo, FIELD_GROUP_MANAGERS, managers) != HC_SUCCESS) {
        LOGE("Failed to add groupManagers to groupInfo!");
        FreeJson(managers);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(managers);
    /* Currently, only the public group can be created. */
    if (AddIntToJson(groupInfo, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC) != HC_SUCCESS) {
        LOGE("Failed to add groupVisibility to groupInfo!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddCompatibleInfoToSendData(bool isNeedCompatibleInfo, CJson *data)
{
    if (!isNeedCompatibleInfo) {
        return HC_SUCCESS;
    }
    CJson *groupInfo = CreateJson();
    if (groupInfo == NULL) {
        LOGE("Failed to allocate groupInfo memory!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = GenerateCompatibleInfo(groupInfo);
    if (res != HC_SUCCESS) {
        FreeJson(groupInfo);
        return res;
    }
    if (AddObjToJson(data, FIELD_GROUP_INFO, groupInfo) != HC_SUCCESS) {
        LOGE("Failed to add groupInfo to sendData!");
        FreeJson(groupInfo);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(groupInfo);
    return HC_SUCCESS;
}

bool IsCreateGroupNeeded(int isClient, int operationCode)
{
    return ((isClient == CLIENT) && (operationCode == MEMBER_JOIN)) ||
           ((isClient == SERVER) && (operationCode == MEMBER_INVITE));
}

int32_t GenerateBaseBindParams(int32_t osAccountId, int isClient, const CJson *jsonParams,
    CompatibleBindSubSession *session)
{
    if (session->params == NULL) {
        session->params = CreateJson();
        if (session->params == NULL) {
            LOGE("Failed to allocate session params memory!");
            return HC_ERR_JSON_CREATE;
        }
    }

    int32_t result;
    if (((result = AddPinCode(jsonParams, session)) != HC_SUCCESS) ||
        ((result = AddProtocolExpandVal(jsonParams, session)) != HC_SUCCESS) ||
        ((result = AddGroupAndDevInfo(osAccountId, isClient, jsonParams, session)) != HC_SUCCESS) ||
        ((result = AddPeerAuthIdAndUdidIfExist(jsonParams, session)) != HC_SUCCESS)) {
        return result;
    }

    return HC_SUCCESS;
}

int32_t GenerateBaseModuleParams(bool isClient, CompatibleBindSubSession *session, CJson *moduleParams)
{
    int32_t result;
    if (((result = AddGroupAndDevInfoToParams(session, moduleParams)) != HC_SUCCESS) ||
        ((result = AddRequestInfoToParams(isClient, session, moduleParams)) != HC_SUCCESS) ||
        ((result = AddPinCodeToParams(session, moduleParams)) != HC_SUCCESS) ||
        ((result = AddProtocolExpandValToParams(session, moduleParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

int32_t AddInfoToBindData(bool isNeedCompatibleInfo, const CompatibleBindSubSession *session, CJson *data)
{
    int32_t result;
    if (((result = AddGroupInfoToSendData(session, data)) != HC_SUCCESS) ||
        ((result = AddDevInfoToSendData(session, data)) != HC_SUCCESS) ||
        ((result = AddRequestInfoToSendData(session, data)) != HC_SUCCESS) ||
        ((result = AddCompatibleInfoToSendData(isNeedCompatibleInfo, data)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}