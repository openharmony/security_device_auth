/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "group_auth_data_operation.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_string.h"
#include "hc_types.h"
#include "hc_vector.h"

static bool GaDeepCopyDeviceEntry(const TrustedDeviceEntry *entry, TrustedDeviceEntry *returnEntry)
{
    returnEntry->groupEntry = NULL;
    if (!StringSet(&returnEntry->groupId, entry->groupId)) {
        LOGE("[GA]: Failed to copy udid!");
        return false;
    }
    if (!StringSet(&returnEntry->udid, entry->udid)) {
        LOGE("[GA]: Failed to copy udid!");
        return false;
    }
    if (!StringSet(&returnEntry->authId, entry->authId)) {
        LOGE("[GA]: Failed to copy authId!");
        return false;
    }
    if (!StringSet(&returnEntry->serviceType, entry->serviceType)) {
        LOGE("[GA]: Failed to copy serviceType!");
        return false;
    }
    if (!StringSet(&returnEntry->userId, entry->userId)) {
        LOGE("[GA]: Failed to copy userId!");
        return false;
    }
    returnEntry->credential = entry->credential;
    returnEntry->devType = entry->devType;
    returnEntry->lastTm = entry->lastTm;
    returnEntry->source = entry->source;
    return true;
}

static bool GaDeepCopyGroupEntry(const TrustedGroupEntry *entry, TrustedGroupEntry *returnEntry)
{
    if (HC_VECTOR_SIZE(&entry->managers) <= 0) {
        LOGE("[GA]: The group owner is lost!");
        return false;
    }
    HcString entryOwner = HC_VECTOR_GET(&entry->managers, 0);
    if (!StringSet(&returnEntry->name, entry->name)) {
        LOGE("[GA]: Failed to copy groupName!");
        return false;
    }
    if (!StringSet(&returnEntry->id, entry->id)) {
        LOGE("[GA]: Failed to copy groupId!");
        return false;
    }
    if (!StringSet(&returnEntry->userId, entry->userId)) {
        LOGE("[GA]: Failed to copy userId!");
        return false;
    }
    returnEntry->type = entry->type;
    returnEntry->visibility = entry->visibility;
    returnEntry->expireTime = entry->expireTime;
    HcString ownerName = CreateString();
    if (!StringSet(&ownerName, entryOwner)) {
        LOGE("[GA]: Failed to copy groupOwner!");
        DeleteString(&ownerName);
        return false;
    }
    if (returnEntry->managers.pushBack(&returnEntry->managers, &ownerName) == NULL) {
        LOGE("[GA]: Failed to push groupOwner to managers!");
        DeleteString(&ownerName);
        return false;
    }
    return true;
}

static int32_t GetGroupEntryById(int32_t osAccountId, const char *groupId, TrustedGroupEntry *returnEntry)
{
    if (returnEntry == NULL) {
        LOGE("The input returnEntry is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t groupIndex;
    TrustedGroupEntry **entry = NULL;
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    QueryGroupParams groupParams = InitQueryGroupParams();
    groupParams.groupId = groupId;
    if (QueryGroups(osAccountId, &groupParams, &groupEntryVec) != HC_SUCCESS) {
        LOGE("query groups failed!");
        ClearGroupEntryVec(&groupEntryVec);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    FOR_EACH_HC_VECTOR(groupEntryVec, groupIndex, entry) {
        if (!GaDeepCopyGroupEntry(*entry, returnEntry)) {
            ClearGroupEntryVec(&groupEntryVec);
            return HC_ERR_GROUP_NOT_EXIST;
        }
        ClearGroupEntryVec(&groupEntryVec);
        return HC_SUCCESS;
    }
    ClearGroupEntryVec(&groupEntryVec);
    return HC_ERR_GROUP_NOT_EXIST;
}

bool GaIsGroupAccessible(int32_t osAccountId, const char *groupId, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("The input groupId or appId is NULL!");
        return false;
    }
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == NULL) {
        LOGE("Failed to create group entry!");
        return false;
    }
    int32_t res = GetGroupEntryById(osAccountId, groupId, entry);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get group entry by groupId!");
        DestroyGroupEntry(entry);
        return false;
    }
    DestroyGroupEntry(entry);
    return true;
}

int32_t GaGetTrustedDeviceEntryById(int32_t osAccountId, const char *deviceId,
    bool isUdid, const char *groupId, TrustedDeviceEntry *returnDeviceEntry)
{
    if (returnDeviceEntry == NULL) {
        LOGE("The input returnEntry is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    TrustedDeviceEntry **deviceEntry = NULL;
    DeviceEntryVec deviceEntryVec = CREATE_HC_VECTOR(DeviceEntryVec);
    QueryDeviceParams params = InitQueryDeviceParams();
    params.groupId = groupId;
    if (isUdid) {
        params.udid = deviceId;
    } else {
        params.authId = deviceId;
    }
    if (QueryDevices(osAccountId, &params, &deviceEntryVec) != HC_SUCCESS) {
        LOGE("query trusted devices failed!");
        ClearDeviceEntryVec(&deviceEntryVec);
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, deviceEntry) {
        if (!GaDeepCopyDeviceEntry(*deviceEntry, returnDeviceEntry)) {
            ClearDeviceEntryVec(&deviceEntryVec);
            return HC_ERR_GROUP_NOT_EXIST;
        }
        ClearDeviceEntryVec(&deviceEntryVec);
        return HC_SUCCESS;
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return HC_ERR_DEVICE_NOT_EXIST;
}

bool GaIsDeviceInGroup(int32_t groupType, int32_t osAccountId, const char *peerUdid, const char *peerAuthId,
    const char *groupId)
{
    int32_t res;
    int32_t authForm = GroupTypeToAuthForm(groupType);
    if ((authForm == AUTH_FORM_ACROSS_ACCOUNT) || (authForm == AUTH_FORM_IDENTICAL_ACCOUNT)) {
        LOGD("Auth for account related type.");
        return true; /* Do not check  whether account related devices is in account. */
    }
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to allocate memory for deviceEntry!");
        return false;
    }
    if (peerUdid != NULL) {
        res = GaGetTrustedDeviceEntryById(osAccountId, peerUdid, true, groupId, deviceEntry);
    } else if (peerAuthId != NULL) {
        res = GaGetTrustedDeviceEntryById(osAccountId, peerAuthId, false, groupId, deviceEntry);
    } else {
        LOGE("Both the input udid and authId is null!");
        res = HC_ERROR;
    }
    DestroyDeviceEntry(deviceEntry);
    if (res != HC_SUCCESS) {
        return false;
    }
    return true;
}

int32_t GaGetLocalDeviceInfo(int32_t osAccountId, const char *groupId, TrustedDeviceEntry *localAuthInfo)
{
    char *localUdid = (char *)HcMalloc(INPUT_UDID_LEN, 0);
    if (localUdid == NULL) {
        LOGE("Failed to malloc for local udid!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HcGetUdid((uint8_t *)localUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid!");
        HcFree(localUdid);
        return res;
    }
    PRINT_SENSITIVE_DATA("SelfUdid", localUdid);
    res = GaGetTrustedDeviceEntryById(osAccountId, localUdid, true, groupId, localAuthInfo);
    HcFree(localUdid);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local device info from database!");
    }
    return res;
}

int32_t AuthFormToGroupType(int32_t authForm)
{
    int32_t groupType;
    switch (authForm) {
        case AUTH_FORM_ACCOUNT_UNRELATED:
            groupType = PEER_TO_PEER_GROUP;
            break;
        case AUTH_FORM_IDENTICAL_ACCOUNT:
            groupType = IDENTICAL_ACCOUNT_GROUP;
            break;
        case AUTH_FORM_ACROSS_ACCOUNT:
            groupType = ACROSS_ACCOUNT_AUTHORIZE_GROUP;
            break;
        default:
            LOGE("Invalid auth form!");
            groupType = GROUP_TYPE_INVALID;
            break;
    }
    return groupType;
}

int32_t GroupTypeToAuthForm(int32_t groupType)
{
    int32_t authForm;
    switch (groupType) {
        case PEER_TO_PEER_GROUP:
            authForm = AUTH_FORM_ACCOUNT_UNRELATED;
            break;
        case IDENTICAL_ACCOUNT_GROUP:
            authForm = AUTH_FORM_IDENTICAL_ACCOUNT;
            break;
        case ACROSS_ACCOUNT_AUTHORIZE_GROUP:
            authForm = AUTH_FORM_ACROSS_ACCOUNT;
            break;
        default:
            LOGE("Invalid group type!");
            authForm = AUTH_FORM_INVALID_TYPE;
            break;
    }
    return authForm;
}
