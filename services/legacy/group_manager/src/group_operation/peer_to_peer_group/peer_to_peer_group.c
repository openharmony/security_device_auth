/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "peer_to_peer_group.h"

#include "alg_defs.h"
#include "callback_manager.h"
#include "channel_manager.h"
#include "data_manager.h"
#include "dev_auth_module_manager.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "string_util.h"

static bool IsSameNameGroupExist(int32_t osAccountId, const char *ownerName, const char *groupName)
{
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.ownerName = ownerName;
    queryParams.groupName = groupName;
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    int32_t result = QueryGroups(osAccountId, &queryParams, &groupEntryVec);
    if (result != HC_SUCCESS) {
        ClearGroupEntryVec(&groupEntryVec);
        return result;
    }
    if (HC_VECTOR_SIZE(&groupEntryVec) > 0) {
        ClearGroupEntryVec(&groupEntryVec);
        return true;
    }
    ClearGroupEntryVec(&groupEntryVec);
    return false;
}

static int32_t CheckGroupName(int32_t osAccountId, const char *appId, const CJson *jsonParams)
{
    const char *groupName = GetStringFromJson(jsonParams, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }

    if (IsSameNameGroupExist(osAccountId, appId, groupName)) {
        LOGE("A group with the same group name has been created! [AppId]: %s, [GroupName]: %s", appId, groupName);
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupId(const char *groupName, const char *appId, char **returnGroupId)
{
    /* peer to peer group: groupId = sha256(groupName | appId) */
    uint8_t *hashMessage = NULL;
    uint32_t messageSize = 0;
    Uint8Buff groupNameBuff = {(uint8_t *)groupName, HcStrlen(groupName)};
    Uint8Buff appIdBuff = {(uint8_t *)appId, HcStrlen(appId)};
    int32_t result = GetHashMessage(&groupNameBuff, &appIdBuff, &hashMessage, &messageSize);
    if (result != HC_SUCCESS) {
        return result;
    }
    int hashStrLen = SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1;
    *returnGroupId = (char *)HcMalloc(hashStrLen, 0);
    if (*returnGroupId == NULL) {
        LOGE("Failed to allocate returnGroupId memory!");
        HcFree(hashMessage);
        return HC_ERR_ALLOC_MEMORY;
    }
    result = GetHashResult(hashMessage, messageSize, *returnGroupId, hashStrLen);
    HcFree(hashMessage);
    if (result != HC_SUCCESS) {
        LOGE("Failed to get hash for groupId! [AppId]: %s, [GroupName]: %s", appId, groupName);
        HcFree(*returnGroupId);
        *returnGroupId = NULL;
        return HC_ERR_HASH_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GeneratePeerToPeerGroupId(const CJson *jsonParams, char **returnGroupId)
{
    const char *groupName = GetStringFromJson(jsonParams, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result = GenerateGroupId(groupName, appId, returnGroupId);
    if (result != HC_SUCCESS) {
        LOGE("Failed to generate groupId! [GroupName]: %s, [AppId]: %s", groupName, appId);
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CheckCreateParams(int32_t osAccountId, const CJson *jsonParams)
{
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result;
    if (((result = CheckGroupName(osAccountId, appId, jsonParams)) != HC_SUCCESS) ||
        ((result = CheckUserTypeIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckGroupVisibilityIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckExpireTimeIfExist(jsonParams)) != HC_SUCCESS) ||
        ((result = CheckGroupNumLimit(osAccountId, PEER_TO_PEER_GROUP, appId)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateGroupParams(const CJson *jsonParams, const char *groupId, TrustedGroupEntry *groupParams)
{
    const char *groupName = GetStringFromJson(jsonParams, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t result;
    if (((result = AddGroupTypeToParams(PEER_TO_PEER_GROUP, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupNameToParams(groupName, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupIdToParams(groupId, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupOwnerToParams(appId, groupParams)) != HC_SUCCESS) ||
        ((result = AddGroupVisibilityOrDefault(jsonParams, groupParams)) != HC_SUCCESS) ||
        ((result = AddExpireTimeOrDefault(jsonParams, groupParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t GenerateDevParams(const CJson *jsonParams, const char *groupId, TrustedDeviceEntry *devParams)
{
    int32_t result;
    if (((result = AddSelfUdidToParams(devParams)) != HC_SUCCESS) ||
        ((result = AddAuthIdToParamsOrDefault(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddSourceToParams(SELF_CREATED, devParams)) != HC_SUCCESS) ||
        ((result = AddUserTypeToParamsOrDefault(jsonParams, devParams)) != HC_SUCCESS) ||
        ((result = AddGroupIdToDevParams(groupId, devParams)) != HC_SUCCESS) ||
        ((result = AddServiceTypeToParams(groupId, devParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static int32_t CreateGroupInner(int32_t osAccountId, const CJson *jsonParams, char **returnGroupId)
{
    char *groupId = NULL;
    int32_t result;
    if (((result = CheckCreateParams(osAccountId, jsonParams)) != HC_SUCCESS) ||
        ((result = GeneratePeerToPeerGroupId(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = ProcessKeyPair(CREATE_KEY_PAIR, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = AddGroupToDatabaseByJson(osAccountId, GenerateGroupParams, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = AddDeviceToDatabaseByJson(osAccountId, GenerateDevParams, jsonParams, groupId)) != HC_SUCCESS) ||
        ((result = SaveOsAccountDb(osAccountId)) != HC_SUCCESS)) {
        HcFree(groupId);
        return result;
    }
    *returnGroupId = groupId;
    return HC_SUCCESS;
}

static int32_t GetPeerDevUserTypeFromDb(int32_t osAccountId, const char *groupId, const char *peerAuthId)
{
    int peerUserType = DEVICE_TYPE_ACCESSORY;
    TrustedDeviceEntry *devAuthParams = CreateDeviceEntry();
    if (devAuthParams == NULL) {
        LOGE("Failed to allocate devEntry memory!");
        return peerUserType;
    }
    if (GetTrustedDevInfoById(osAccountId, peerAuthId, false, groupId, devAuthParams) != HC_SUCCESS) {
        LOGE("Failed to obtain the device information from the database!");
        DestroyDeviceEntry(devAuthParams);
        return peerUserType;
    }
    peerUserType = devAuthParams->devType;
    DestroyDeviceEntry(devAuthParams);
    return peerUserType;
}

static int32_t DelPeerDevAndKeyInfo(int32_t osAccountId, const char *groupId, const char *peerAuthId)
{
    int32_t peerUserType = GetPeerDevUserTypeFromDb(osAccountId, groupId, peerAuthId);
    QueryDeviceParams queryDeviceParams = InitQueryDeviceParams();
    queryDeviceParams.groupId = groupId;
    queryDeviceParams.authId = peerAuthId;
    int32_t result = DelTrustedDevice(osAccountId, &queryDeviceParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to delete peer device from database!");
        return result;
    }
    /* Use the DeviceGroupManager package name. */
    const char *appId = GROUP_MANAGER_PACKAGE_NAME;
    Uint8Buff peerAuthIdBuff = {
        .val = (uint8_t *)peerAuthId,
        .length = HcStrlen(peerAuthId)
    };
    /*
     * If the trusted device has been deleted from the database but the peer key fails to be deleted,
     * the forcible unbinding is still considered successful. Only logs need to be printed.
     */
    result = DeletePeerAuthInfo(appId, groupId, &peerAuthIdBuff, peerUserType, DAS_MODULE);
    if (result != HC_SUCCESS) {
        LOGD("delete peer key fail! res: %d", result);
    } else {
        LOGD("delete peer key success!");
    }
    return HC_SUCCESS;
}

static int32_t DelAllPeerDevAndKeyInfo(int32_t osAccountId, const char *groupId)
{
    QueryDeviceParams queryParams = InitQueryDeviceParams();
    queryParams.groupId = groupId;
    DeviceEntryVec deviceEntryVec = CreateDeviceEntryVec();
    int32_t result = QueryDevices(osAccountId, &queryParams, &deviceEntryVec);
    if (result != HC_SUCCESS) {
        ClearDeviceEntryVec(&deviceEntryVec);
        return result;
    }
    uint32_t index;
    TrustedDeviceEntry **entryPtr = NULL;
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, entryPtr) {
        TrustedDeviceEntry *entry = (TrustedDeviceEntry *)(*entryPtr);
        if (IsLocalDevice(StringGet(&entry->udid))) {
            continue;
        }
        result = DelPeerDevAndKeyInfo(osAccountId, groupId, StringGet(&entry->authId));
        if (result != HC_SUCCESS) {
            ClearDeviceEntryVec(&deviceEntryVec);
            return result;
        }
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return HC_SUCCESS;
}

static int32_t AddAuthIdAndUserTypeToParams(int32_t osAccountId, const char *groupId, CJson *jsonParams)
{
    TrustedDeviceEntry *deviceInfo = CreateDeviceEntry();
    if (deviceInfo == NULL) {
        LOGE("Failed to allocate deviceInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }

    char localUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)localUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        DestroyDeviceEntry(deviceInfo);
        return HC_ERR_DB;
    }

    if (GetTrustedDevInfoById(osAccountId, localUdid, true, groupId, deviceInfo) != HC_SUCCESS) {
        LOGE("No local device information found in the group, udid changed.");
        DestroyDeviceEntry(deviceInfo);
        return HC_ERR_DB;
    }

    if (AddStringToJson(jsonParams, FIELD_DEVICE_ID, StringGet(&deviceInfo->authId)) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        DestroyDeviceEntry(deviceInfo);
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(jsonParams, FIELD_USER_TYPE, deviceInfo->devType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        DestroyDeviceEntry(deviceInfo);
        return HC_ERR_JSON_FAIL;
    }
    DestroyDeviceEntry(deviceInfo);
    return HC_SUCCESS;
}

static int32_t DelGroupAndSelfKeyInfo(int32_t osAccountId, const char *groupId, CJson *jsonParams)
{
    int32_t result = DelGroupFromDb(osAccountId, groupId);
    if (result != HC_SUCCESS) {
        return result;
    }
    /*
     * If the group has been disbanded from the database but the key pair fails to be deleted,
     * we still believe we succeeded in disbanding the group. Only logs need to be printed.
     */
    result = AddAuthIdAndUserTypeToParams(osAccountId, groupId, jsonParams);
    if (result == HC_SUCCESS) {
        result = ProcessKeyPair(DELETE_KEY_PAIR, jsonParams, groupId);
    }
    if (result != HC_SUCCESS) {
        LOGW("delete self key fail! res: %d", result);
    } else {
        LOGI("delete self key success!");
    }
    return HC_SUCCESS;
}

static int32_t HandleLocalUnbind(int64_t requestId, const CJson *jsonParams,
    const DeviceAuthCallback *callback)
{
    const char *peerAuthId = GetStringFromJson(jsonParams, FIELD_DELETE_ID);
    if (peerAuthId == NULL) {
        LOGE("Failed to get peerAuthId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t osAccountId;
    if (GetIntFromJson(jsonParams, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int result = DelPeerDevAndKeyInfo(osAccountId, groupId, peerAuthId);
    if (result != HC_SUCCESS) {
        return result;
    }
    result = SaveOsAccountDb(osAccountId);
    if (result != HC_SUCCESS) {
        LOGE("Failed to save osAccountDb!");
        return result;
    }
    char *returnDataStr = NULL;
    result = GenerateUnbindSuccessData(peerAuthId, groupId, &returnDataStr);
    if (result != HC_SUCCESS) {
        return result;
    }
    ProcessFinishCallback(requestId, MEMBER_DELETE, returnDataStr, callback);
    FreeJsonString(returnDataStr);
    return HC_SUCCESS;
}

static int32_t CheckPeerDeviceStatus(int32_t osAccountId, const char *groupId, const CJson *jsonParams)
{
    const char *peerAuthId = GetStringFromJson(jsonParams, FIELD_DELETE_ID);
    if (peerAuthId == NULL) {
        LOGE("Failed to get peerAuthId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    PRINT_SENSITIVE_DATA("PeerAuthId", peerAuthId);
    TrustedDeviceEntry *deviceInfo = CreateDeviceEntry();
    if (deviceInfo == NULL) {
        LOGE("Failed to allocate deviceInfo memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GetTrustedDevInfoById(osAccountId, peerAuthId, false, groupId, deviceInfo);
    if (result != HC_SUCCESS) {
        LOGE("Failed to obtain the peer device information from the database!");
        DestroyDeviceEntry(deviceInfo);
        return result;
    }
    result = AssertPeerDeviceNotSelf(StringGet(&deviceInfo->udid));
    DestroyDeviceEntry(deviceInfo);
    return result;
}

static int32_t CheckDeletePeerStatus(const CJson *jsonParams)
{
    const char *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    int32_t osAccountId;
    if (GetIntFromJson(jsonParams, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from jsonParams!");
        return HC_ERR_JSON_GET;
    }

    int32_t groupType = PEER_TO_PEER_GROUP;
    int32_t result;
    if (((result = CheckGroupExist(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = GetGroupTypeFromDb(osAccountId, groupId, &groupType)) != HC_SUCCESS) ||
        ((result = AssertGroupTypeMatch(groupType, PEER_TO_PEER_GROUP)) != HC_SUCCESS) ||
        ((result = CheckPermForGroup(osAccountId, MEMBER_DELETE, appId, groupId)) != HC_SUCCESS) ||
        ((result = CheckPeerDeviceStatus(osAccountId, groupId, jsonParams)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

static bool IsLocalForceUnbind(const CJson *jsonParams)
{
    bool isForceDelete = false;
    (void)GetBoolFromJson(jsonParams, FIELD_IS_FORCE_DELETE, &isForceDelete);
    bool isIgnoreChannel = false;
    (void)GetBoolFromJson(jsonParams, FIELD_IS_IGNORE_CHANNEL, &isIgnoreChannel);
    return (isForceDelete && isIgnoreChannel);
}

static int32_t CreateGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to create a peer to peer group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    char *groupId = NULL;
    int32_t result = CreateGroupInner(osAccountId, jsonParams, &groupId);
    if (result != HC_SUCCESS) {
        return result;
    }
    result = ConvertGroupIdToJsonStr(groupId, returnJsonStr);
    HcFree(groupId);
    if (result != HC_SUCCESS) {
        return result;
    }
    LOGI("[End]: Create a peer to peer group successfully!");
    return HC_SUCCESS;
}

static int32_t DeleteGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    LOGI("[Start]: Start to delete a peer to peer group!");
    if ((jsonParams == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t result;
    const char *groupId = NULL;
    if (((result = GetGroupIdFromJson(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = DelAllPeerDevAndKeyInfo(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = DelGroupAndSelfKeyInfo(osAccountId, groupId, jsonParams)) != HC_SUCCESS) ||
        ((result = ConvertGroupIdToJsonStr(groupId, returnJsonStr)) != HC_SUCCESS)) {
        return result;
    }
    LOGI("[End]: Delete a peer to peer group successfully!");
    return HC_SUCCESS;
}

static int32_t DeleteMemberFromGroup(int32_t osAccountId, int64_t requestId, CJson *jsonParams,
    const DeviceAuthCallback *callback)
{
    LOGI("[Start]: Start to delete member from a peer to peer group!");
    if ((jsonParams == NULL) || (callback == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, osAccountId);
    int32_t result = CheckDeletePeerStatus(jsonParams);
    if (result != HC_SUCCESS) {
        ProcessErrorCallback(requestId, MEMBER_DELETE, result, NULL, callback);
        return result;
    }
    if (!IsLocalForceUnbind(jsonParams)) {
        ProcessErrorCallback(requestId, MEMBER_DELETE, HC_ERR_INVALID_PARAMS, NULL, callback);
        return HC_ERR_INVALID_PARAMS;
    }
    result = HandleLocalUnbind(requestId, jsonParams, callback);
    if (result != HC_SUCCESS) {
        ProcessErrorCallback(requestId, MEMBER_DELETE, result, NULL, callback);
    }
    return result;
}

static PeerToPeerGroup g_peerToPeerGroup = {
    .base.type = PEER_TO_PEER_GROUP,
    .base.createGroup = CreateGroup,
    .base.deleteGroup = DeleteGroup,
    .deleteMember = DeleteMemberFromGroup,
};

BaseGroup *GetPeerToPeerGroupInstance(void)
{
    return (BaseGroup *)&g_peerToPeerGroup;
}

bool IsPeerToPeerGroupSupported(void)
{
    return true;
}
