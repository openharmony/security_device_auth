/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "group_data_manager_util.h"

#include <stdio.h>
#include "account_task_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hisysevent_adapter.h"
#include "operation_data_manager.h"
#include "string_util.h"

static int32_t AddGroupNameToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    const char *groupName = StringGet(&groupInfo->name);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_GROUP_NAME, groupName) != HC_SUCCESS) {
        LOGE("Failed to add groupName to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupIdToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    const char *groupId = StringGet(&groupInfo->id);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupOwnerToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    HcString entryManager = HC_VECTOR_GET(&groupInfo->managers, 0);
    const char *groupOwner = StringGet(&entryManager);
    if (groupOwner == NULL) {
        LOGE("Failed to get groupOwner from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_GROUP_OWNER, groupOwner) != HC_SUCCESS) {
        LOGE("Failed to add groupOwner to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupTypeToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    int32_t groupType = groupInfo->type;
    if (AddIntToJson(json, FIELD_GROUP_TYPE, groupType) != HC_SUCCESS) {
        LOGE("Failed to add groupType to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupVisibilityToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    int groupVisibility = groupInfo->visibility;
    if (AddIntToJson(json, FIELD_GROUP_VISIBILITY, groupVisibility) != HC_SUCCESS) {
        LOGE("Failed to add groupVisibility to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddUserIdToReturnIfAccountGroup(const TrustedGroupEntry *groupInfo, CJson *json)
{
    if ((groupInfo->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) && (groupInfo->type != IDENTICAL_ACCOUNT_GROUP)) {
        return HC_SUCCESS;
    }
    const char *userId = StringGet(&groupInfo->userId);
    if (userId == NULL) {
        LOGE("Failed to get userId from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_USER_ID, userId) != HC_SUCCESS) {
        LOGE("Failed to add userId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddSharedUserIdToReturnIfAcrossAccountGroup(const TrustedGroupEntry *groupInfo, CJson *json)
{
    if (groupInfo->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        return HC_SUCCESS;
    }
    const char *sharedUserId = StringGet(&groupInfo->sharedUserId);
    if (sharedUserId == NULL) {
        LOGE("Failed to get sharedUserId from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_SHARED_USER_ID, sharedUserId) != HC_SUCCESS) {
        LOGE("Failed to add sharedUserId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddAuthIdToReturn(const TrustedDeviceEntry *deviceInfo, CJson *json)
{
    const char *authId = StringGet(&deviceInfo->authId);
    if (authId == NULL) {
        LOGE("Failed to get authId from deviceInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_AUTH_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add authId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddCredentialTypeToReturn(const TrustedDeviceEntry *deviceInfo, CJson *json)
{
    int credentialType = deviceInfo->credential;
    if (AddIntToJson(json, FIELD_CREDENTIAL_TYPE, credentialType) != HC_SUCCESS) {
        LOGE("Failed to add credentialType to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddUserTypeToReturn(const TrustedDeviceEntry *deviceInfo, CJson *json)
{
    int userType = deviceInfo->devType;
    if (AddIntToJson(json, FIELD_USER_TYPE, userType) != HC_SUCCESS) {
        LOGE("Failed to add userType to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

typedef int32_t (*GroupInfoAddFunc)(const TrustedGroupEntry *, CJson *);

int32_t GenerateReturnGroupInfo(const TrustedGroupEntry *groupEntry, CJson *returnJson)
{
    if (groupEntry == NULL || returnJson == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    static GroupInfoAddFunc addGroupInfoFuncs[] = {
        AddGroupNameToReturn,
        AddGroupIdToReturn,
        AddGroupOwnerToReturn,
        AddGroupTypeToReturn,
        AddGroupVisibilityToReturn,
        AddUserIdToReturnIfAccountGroup,
        AddSharedUserIdToReturnIfAcrossAccountGroup
    };
    for (int32_t i = 0; i < (int32_t)(sizeof(addGroupInfoFuncs) / sizeof(addGroupInfoFuncs[0])); i++) {
        int32_t result = addGroupInfoFuncs[i](groupEntry, returnJson);
        if (result != HC_SUCCESS) {
            return result;
        }
    }
    return HC_SUCCESS;
}

typedef int32_t (*DevInfoAddFunc)(const TrustedDeviceEntry *, CJson *);

int32_t GenerateReturnDevInfo(const TrustedDeviceEntry *deviceEntry, CJson *returnJson)
{
    if (deviceEntry == NULL || returnJson == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    static DevInfoAddFunc addDevInfoFuncs[] = {
        AddAuthIdToReturn,
        AddCredentialTypeToReturn,
        AddUserTypeToReturn
    };
    for (int32_t i = 0; i < (int32_t)(sizeof(addDevInfoFuncs) / sizeof(addDevInfoFuncs[0])); i++) {
        int32_t result = addDevInfoFuncs[i](deviceEntry, returnJson);
        if (result != HC_SUCCESS) {
            return result;
        }
    }
    return HC_SUCCESS;
}

bool IsSelfDeviceEntry(const TrustedDeviceEntry *deviceEntry)
{
    if (deviceEntry == NULL) {
        LOGE("Invalid input params!");
        return false;
    }
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return false;
    }
    const char *entryUdid = StringGet(&deviceEntry->udid);
    if (entryUdid == NULL) {
        LOGE("The entryUdid is NULL!");
        return false;
    }
    return IsStrEqual(selfUdid, entryUdid);
}

void RecordAddTrustDeviceEvent(int32_t osAccountId, const TrustedDeviceEntry *deviceEntry)
{
    if (deviceEntry == NULL) {
        return;
    }
    CJson *operationInfo = CreateJson();
    if (operationInfo == NULL) {
        return;
    }
    SetAnonymousField(StringGet(&(deviceEntry->groupId)), FIELD_GROUP_ID, operationInfo);
    SetAnonymousField(StringGet(&(deviceEntry->udid)), FIELD_UDID, operationInfo);
    if (deviceEntry->groupEntry != NULL) {
        (void)AddStringToJson(operationInfo, FIELD_GROUP_NAME, StringGet(&(deviceEntry->groupEntry->name)));
    }
    OperationRecord *operation = CreateOperationRecord();
    if (operation == NULL) {
        FreeJson(operationInfo);
        return;
    }
    char *operationInfoString = PackJsonToString(operationInfo);
    FreeJson(operationInfo);
    if (operationInfoString != NULL) {
        CopyHcStringForcibly(&operation->operationInfo, operationInfoString);
        FreeJsonString(operationInfoString);
    }
    CopyHcStringForcibly(&operation->function, ADD_MEMBER_EVENT);
    CopyHcStringForcibly(&operation->caller, DEFAULT_APPID);
    operation->operationType = OPERATION_GROUP;
    RecordOperationData(osAccountId, operation);
    DestroyOperationRecord(operation);
}

#ifdef DEV_AUTH_HIVIEW_ENABLE
static void DumpGroup(int fd, const TrustedGroupEntry *group)
{
    dprintf(fd, "||----------------------------Group----------------------------|                   |\n");
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "name", StringGet(&group->name));
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "id", StringGet(&group->id));
    dprintf(fd, "||%-12s = %-46d|                   |\n", "type", group->type);
    dprintf(fd, "||%-12s = %-46d|                   |\n", "visibility", group->visibility);
    dprintf(fd, "||%-12s = %-46d|                   |\n", "upgradeFlag", group->upgradeFlag);
    dprintf(fd, "||%-12s = %-46d|                   |\n", "expireTime", group->expireTime);
    HcString entryOwner = HC_VECTOR_GET(&group->managers, 0);
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "ownerName", StringGet(&entryOwner));
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "userId", StringGet(&group->userId));
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "sharedUserId", StringGet(&group->sharedUserId));
    dprintf(fd, "||----------------------------Group----------------------------|                   |\n");
}

static void DumpDevice(int fd, const TrustedDeviceEntry *device)
{
    dprintf(fd, "|||--------------------DEV--------------------|                                    |\n");
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "groupId", StringGet(&device->groupId));
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "udid", StringGet(&device->udid));
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "authId", StringGet(&device->authId));
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "userId", StringGet(&device->userId));
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "serviceType",
        StringGet(&device->serviceType));
    dprintf(fd, "|||%-12s = %-28d|                                    |\n", "credential", device->credential);
    dprintf(fd, "|||%-12s = %-28d|                                    |\n", "devType", device->devType);
    dprintf(fd, "|||%-12s = %-28d|                                    |\n", "upgradeFlag", device->upgradeFlag);
    dprintf(fd, "|||%-12s = %-28d|                                    |\n", "credSource", device->source);
    dprintf(fd, "|||--------------------DEV--------------------|                                    |\n");
}

void DumpGroupsAndDevices(int fd, int32_t osAccountId, const GroupEntryVec *groups, const DeviceEntryVec *devices)
{
    if (groups == NULL || devices == NULL) {
        return;
    }
    dprintf(fd, "|-------------------------------------DataBase-------------------------------------|\n");
    dprintf(fd, "|%-12s = %-67d|\n", "osAccountId", osAccountId);
    dprintf(fd, "|%-12s = %-67d|\n", "groupNum", groups->size(groups));
    dprintf(fd, "|%-12s = %-67d|\n", "deviceNum", devices->size(devices));
    uint32_t index;
    TrustedGroupEntry **groupEntry;
    FOR_EACH_HC_VECTOR(*groups, index, groupEntry) {
        DumpGroup(fd, *groupEntry);
    }
    TrustedDeviceEntry **deviceEntry;
    FOR_EACH_HC_VECTOR(*devices, index, deviceEntry) {
        DumpDevice(fd, *deviceEntry);
    }
    dprintf(fd, "|-------------------------------------DataBase-------------------------------------|\n");
}
#endif

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
bool IsSelfDeviceExistInGroup(int32_t osAccountId, const char *groupId)
{
    if (groupId == NULL) {
        return false;
    }
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return false;
    }
    return IsDeviceExistInGroup(osAccountId, groupId, selfUdid);
}

bool IsSelfDeviceExistInGroupForUser(int32_t osAccountId, const char *subProfileIdStr, const char *groupId)
{
    if (subProfileIdStr == NULL || groupId == NULL) {
        return false;
    }
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return false;
    }
    return IsDeviceExistInGroupForUser(osAccountId, subProfileIdStr, groupId, selfUdid);
}
#endif

static int32_t GenerateReturnGroupInfoInner(int32_t osAccountId, const char *subProfileIdStr,
    const TrustedGroupEntry *groupEntry, CJson *returnJson)
{
    int32_t res = GenerateReturnGroupInfo(groupEntry, returnJson);
    if (res != HC_SUCCESS) {
        return res;
    }
    if (AddIntToJson(returnJson, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("Failed to add osAccountId!");
        return HC_ERR_JSON_ADD;
    }
#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
    if (AddStringToJson(returnJson, FIELD_SUB_PROFILE_ID, subProfileIdStr) != HC_SUCCESS) {
        LOGE("Failed to add foreground uid!");
        return HC_ERR_JSON_ADD;
    }
#else
    (void)subProfileIdStr;
#endif
    return HC_SUCCESS;
}

int32_t GenerateMessage(int32_t osAccountId, const char *subProfileIdStr, const TrustedGroupEntry *groupEntry,
    char **returnMessage)
{
    if (subProfileIdStr == NULL || groupEntry == NULL || returnMessage == NULL) {
        LOGE("Invalid input params!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *message = CreateJson();
    if (message == NULL) {
        LOGE("Failed to allocate message memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GenerateReturnGroupInfoInner(osAccountId, subProfileIdStr, groupEntry, message);
    if (result != HC_SUCCESS) {
        FreeJson(message);
        return result;
    }
    char *messageStr = PackJsonToString(message);
    FreeJson(message);
    if (messageStr == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    *returnMessage = messageStr;
    return HC_SUCCESS;
}