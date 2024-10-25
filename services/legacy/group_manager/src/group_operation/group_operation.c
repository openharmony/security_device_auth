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

#include "group_operation.h"

#include "alg_defs.h"
#include "broadcast_manager.h"
#include "callback_manager.h"
#include "common_defs.h"
#include "cred_manager.h"
#include "data_manager.h"
#include "dev_auth_module_manager.h"
#include "device_auth_defines.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "os_account_adapter.h"
#include "task_manager.h"

#include "across_account_group.h"
#include "identical_account_group.h"
#include "peer_to_peer_group.h"
#include "hc_time.h"

static bool IsGroupTypeSupported(int groupType)
{
    if (((groupType == PEER_TO_PEER_GROUP) && (IsPeerToPeerGroupSupported())) ||
        ((groupType == IDENTICAL_ACCOUNT_GROUP) && (IsIdenticalAccountGroupSupported())) ||
        ((groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP) && (IsAcrossAccountGroupSupported()))) {
        return true;
    }
    LOGE("The group type is not supported! [GroupType]: %d", groupType);
    return false;
}

static void RemoveNoPermissionGroup(int32_t osAccountId, GroupEntryVec *groupEntryVec, const char *appId)
{
    uint32_t index = 0;
    TrustedGroupEntry **groupEntryPtr = NULL;
    while (index < groupEntryVec->size(groupEntryVec)) {
        groupEntryPtr = groupEntryVec->getp(groupEntryVec, index);
        if (groupEntryPtr == NULL) {
            LOGW("groupEntryPtr is NULL!");
            index++;
            continue;
        }
        if (CheckGroupAccessible(osAccountId, StringGet(&(*groupEntryPtr)->id), appId) == HC_SUCCESS) {
            index++;
            continue;
        }
        LOGI("Remove a group without permission!");
        TrustedGroupEntry *tempEntry = NULL;
        HC_VECTOR_POPELEMENT(groupEntryVec, &tempEntry, index);
        DestroyGroupEntry(tempEntry);
    }
}

static int32_t GenerateReturnEmptyArrayStr(char **returnVec)
{
    CJson *json = CreateJsonArray();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return HC_ERR_JSON_FAIL;
    }
    *returnVec = PackJsonToString(json);
    FreeJson(json);
    if (*returnVec == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GenerateReturnGroupVec(GroupEntryVec *groupInfoVec, char **returnGroupVec, uint32_t *groupNum)
{
    if (HC_VECTOR_SIZE(groupInfoVec) == 0) {
        *groupNum = 0;
        return GenerateReturnEmptyArrayStr(returnGroupVec);
    }

    CJson *json = CreateJsonArray();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return HC_ERR_JSON_FAIL;
    }
    uint32_t groupCount = 0;
    uint32_t index;
    TrustedGroupEntry **groupInfoPtr = NULL;
    FOR_EACH_HC_VECTOR(*groupInfoVec, index, groupInfoPtr) {
        TrustedGroupEntry *groupInfo = *groupInfoPtr;
        CJson *groupInfoJson = CreateJson();
        if (groupInfoJson == NULL) {
            LOGE("Failed to allocate groupInfoJson memory!");
            FreeJson(json);
            return HC_ERR_ALLOC_MEMORY;
        }
        int32_t result = GenerateReturnGroupInfo(groupInfo, groupInfoJson);
        if (result != HC_SUCCESS) {
            FreeJson(groupInfoJson);
            FreeJson(json);
            return result;
        }
        if (AddObjToArray(json, groupInfoJson) != HC_SUCCESS) {
            LOGE("Failed to add groupInfoStr to returnGroupVec!");
            FreeJson(groupInfoJson);
            FreeJson(json);
            return HC_ERR_JSON_FAIL;
        }
        ++groupCount;
    }
    *returnGroupVec = PackJsonToString(json);
    FreeJson(json);
    if ((*returnGroupVec) == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    *groupNum = groupCount;
    return HC_SUCCESS;
}

static int32_t GenerateReturnDeviceVec(DeviceEntryVec *devInfoVec, char **returnDevInfoVec, uint32_t *deviceNum)
{
    CJson *json = CreateJsonArray();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return HC_ERR_JSON_FAIL;
    }
    uint32_t devCount = 0;
    uint32_t index;
    TrustedDeviceEntry **devInfoPtr = NULL;
    FOR_EACH_HC_VECTOR(*devInfoVec, index, devInfoPtr) {
        TrustedDeviceEntry *devInfo = (TrustedDeviceEntry*)(*devInfoPtr);
        CJson *devInfoJson = CreateJson();
        if (devInfoJson == NULL) {
            LOGE("Failed to allocate devInfoJson memory!");
            FreeJson(json);
            return HC_ERR_ALLOC_MEMORY;
        }
        int32_t result = GenerateReturnDevInfo(devInfo, devInfoJson);
        if (result != HC_SUCCESS) {
            FreeJson(devInfoJson);
            FreeJson(json);
            return result;
        }
        if (AddObjToArray(json, devInfoJson) != HC_SUCCESS) {
            LOGE("Failed to add devInfoStr to returnGroupVec!");
            FreeJson(devInfoJson);
            FreeJson(json);
            return HC_ERR_JSON_FAIL;
        }
        ++devCount;
    }
    *returnDevInfoVec = PackJsonToString(json);
    FreeJson(json);
    if ((*returnDevInfoVec) == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    *deviceNum = devCount;
    return HC_SUCCESS;
}

static bool IsQueryParamsValid(int groupType, const char *groupId, const char *groupName, const char *groupOwner)
{
    if ((groupType == ALL_GROUP) && (groupId == NULL) && (groupName == NULL) && (groupOwner == NULL)) {
        return false;
    } else {
        return true;
    }
}

static int32_t QueryRelatedGroupsForGetPk(int32_t osAccountId, const char *udid, GroupEntryVec *returnGroupEntryVec)
{
    DeviceEntryVec deviceEntryVec = CreateDeviceEntryVec();
    QueryDeviceParams params = InitQueryDeviceParams();
    params.udid = udid;
    int32_t result = QueryDevices(osAccountId, &params, &deviceEntryVec);
    if (result != HC_SUCCESS) {
        LOGE("Failed to query trusted devices!");
        ClearDeviceEntryVec(&deviceEntryVec);
        return result;
    }
    uint32_t index;
    TrustedDeviceEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, entry) {
        /* In order to improve availability, even if there is an error, it does not terminate. */
        TrustedGroupEntry *groupEntry = GetGroupEntryById(osAccountId, StringGet(&(*entry)->groupId));
        if (groupEntry == NULL) {
            LOGW("An exception occurred! Device found, but group not found. There may be dirty data.");
            continue;
        }
        if (groupEntry->visibility != GROUP_VISIBILITY_PUBLIC) {
            DestroyGroupEntry(groupEntry);
            continue;
        }
        if (returnGroupEntryVec->pushBackT(returnGroupEntryVec, groupEntry) == NULL) {
            LOGW("An exception occurred! Failed to push groupEntry to returnGroupEntryVec!");
            DestroyGroupEntry(groupEntry);
        }
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return HC_SUCCESS;
}

static int32_t GetPkByParams(int32_t osAccountId, const char *groupId, const TrustedDeviceEntry *deviceEntry,
    char *returnPkHexStr, int32_t returnPkHexStrLen)
{
    /* Use the DeviceGroupManager package name. */
    const char *appId = GROUP_MANAGER_PACKAGE_NAME;
    int userType = deviceEntry->devType;
    const char *authId = StringGet(&deviceEntry->authId);
    Uint8Buff authIdBuff = { 0, 0 };
    authIdBuff.length = HcStrlen(authId);
    authIdBuff.val = (uint8_t *)HcMalloc(authIdBuff.length, 0);
    if (authIdBuff.val == NULL) {
        LOGE("Failed to allocate authIdBuff memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(authIdBuff.val, authIdBuff.length, authId, authIdBuff.length) != HC_SUCCESS) {
        LOGE("Failed to copy authId!");
        HcFree(authIdBuff.val);
        return HC_ERR_MEMORY_COPY;
    }
    uint8_t returnPkBytes[PUBLIC_KEY_MAX_LENGTH] = { 0 };
    Uint8Buff returnPkBuff = { 0, 0 };
    returnPkBuff.length = PUBLIC_KEY_MAX_LENGTH;
    returnPkBuff.val = returnPkBytes;
    AuthModuleParams authParams = {
        .osAccountId = osAccountId,
        .pkgName = appId,
        .serviceType = groupId,
        .authId = &authIdBuff,
        .userType = userType
    };
    int32_t res = GetPublicKey(DAS_MODULE, &authParams, &returnPkBuff);
    HcFree(authIdBuff.val);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = GetHashResult(returnPkBuff.val, returnPkBuff.length, returnPkHexStr, returnPkHexStrLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get hash for pk!");
        return HC_ERR_HASH_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GeneratePkInfo(int32_t osAccountId, const char *queryUdid, const char *groupId, CJson *pkInfo)
{
    TrustedDeviceEntry *deviceEntry = GetTrustedDeviceEntryById(osAccountId, queryUdid, true, groupId);
    if (deviceEntry == NULL) {
        LOGE("The trusted device is not found!");
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    char returnPkHexStr[SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1] = { 0 };
    int32_t result = GetPkByParams(osAccountId, groupId, deviceEntry, returnPkHexStr, sizeof(returnPkHexStr));
    DestroyDeviceEntry(deviceEntry);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (AddStringToJson(pkInfo, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to pkInfo!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(pkInfo, FIELD_PUBLIC_KEY, returnPkHexStr) != HC_SUCCESS) {
        LOGE("Failed to add publicKey to pkInfo!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static void AddAllPkInfoToList(int32_t osAccountId, const char *queryUdid, const GroupEntryVec *groupEntryVec,
    CJson *pkInfoList)
{
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(*groupEntryVec, index, entry) {
        /* Account related group cannot export public key. */
        if (IsAccountRelatedGroup((*entry)->type)) {
            continue;
        }
        const char *groupId = StringGet(&((*entry)->id));
        CJson *pkInfo = CreateJson();
        if (pkInfo == NULL) {
            LOGE("Failed to create json!");
            continue;
        }
        int32_t res = GeneratePkInfo(osAccountId, queryUdid, groupId, pkInfo);
        if (res != HC_SUCCESS) {
            FreeJson(pkInfo);
            continue;
        }
        if (AddObjToArray(pkInfoList, pkInfo) != HC_SUCCESS) {
            LOGE("Failed to add pkInfo to pkInfoList!");
            FreeJson(pkInfo);
        }
    }
}

static bool IsOnlyAccountRelatedGroups(const GroupEntryVec *groupEntryVec)
{
    if (groupEntryVec->size(groupEntryVec) == 0) {
        LOGW("No groups available.");
        return false;
    }
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    FOR_EACH_HC_VECTOR(*groupEntryVec, index, entry) {
        if (!IsAccountRelatedGroup((*entry)->type)) {
            return false;
        }
    }
    return true;
}

static int32_t GeneratePkInfoList(int32_t osAccountId, const CJson *params, CJson *pkInfoList)
{
    const char *udid = GetStringFromJson(params, FIELD_UDID);
    if (udid == NULL) {
        LOGE("Failed to get udid from params!");
        return HC_ERR_JSON_GET;
    }
    bool isSelfPk = false;
    if (GetBoolFromJson(params, FIELD_IS_SELF_PK, &isSelfPk) != HC_SUCCESS) {
        LOGE("Failed to get isSelfPk from json!");
        return HC_ERR_JSON_GET;
    }
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    int32_t res = QueryRelatedGroupsForGetPk(osAccountId, udid, &groupEntryVec);
    if (res != HC_SUCCESS) {
        ClearGroupEntryVec(&groupEntryVec);
        return res;
    }
    /**
     * Specification requirements:
     * when there are only account related groups in the group list of public key information to be queried,
     * a special error code needs to be returned.
     */
    if (IsOnlyAccountRelatedGroups(&groupEntryVec)) {
        LOGE("There are only account related groups in the group list.");
        ClearGroupEntryVec(&groupEntryVec);
        return HC_ERR_ONLY_ACCOUNT_RELATED;
    }
    const char *queryUdid = NULL;
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    if (isSelfPk) {
        res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get local udid! res: %d", res);
            ClearGroupEntryVec(&groupEntryVec);
            return HC_ERR_DB;
        }
        queryUdid = selfUdid;
    } else {
        queryUdid = udid;
    }
    AddAllPkInfoToList(osAccountId, queryUdid, &groupEntryVec, pkInfoList);
    ClearGroupEntryVec(&groupEntryVec);
    return HC_SUCCESS;
}

static BaseGroup *GetGroupInstance(int32_t groupType)
{
    if (!IsGroupTypeSupported(groupType)) {
        return NULL;
    }
    BaseGroup *instance = NULL;
    if (groupType == PEER_TO_PEER_GROUP) {
        instance = GetPeerToPeerGroupInstance();
    } else if (groupType == IDENTICAL_ACCOUNT_GROUP) {
        instance = GetIdenticalAccountGroupInstance();
    } else if (groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        instance = GetAcrossAccountGroupInstance();
    }
    return instance;
}

static int32_t CreateGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    int32_t groupType = PEER_TO_PEER_GROUP;
    if (GetIntFromJson(jsonParams, FIELD_GROUP_TYPE, &groupType) != HC_SUCCESS) {
        LOGE("Failed to get groupType from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    BaseGroup *instance = GetGroupInstance(groupType);
    if (instance == NULL) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->createGroup(osAccountId, jsonParams, returnJsonStr);
}

static int32_t DeleteGroup(int32_t osAccountId, CJson *jsonParams, char **returnJsonStr)
{
    int32_t result;
    const char *groupId = NULL;
    const char *appId = NULL;
    uint32_t groupType = PEER_TO_PEER_GROUP;
    if (((result = GetGroupIdFromJson(jsonParams, &groupId)) != HC_SUCCESS) ||
        ((result = GetAppIdFromJson(jsonParams, &appId)) != HC_SUCCESS) ||
        ((result = CheckGroupExist(osAccountId, groupId)) != HC_SUCCESS) ||
        ((result = GetGroupTypeFromDb(osAccountId, groupId, &groupType)) != HC_SUCCESS) ||
        ((result = CheckPermForGroup(osAccountId, GROUP_DISBAND, appId, groupId)) != HC_SUCCESS)) {
        return result;
    }
    BaseGroup *instance = GetGroupInstance(groupType);
    if (instance == NULL) {
        LOGE("The group instance is NULL or its function ptr is NULL!");
        return HC_ERR_NULL_PTR;
    }
    return instance->deleteGroup(osAccountId, jsonParams, returnJsonStr);
}

static int32_t DeleteMemberFromPeerToPeerGroup(int32_t osAccountId, int64_t requestId, CJson *jsonParams,
    const DeviceAuthCallback *callback)
{
    if (!IsPeerToPeerGroupSupported()) {
        LOGE("Peer to peer group is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    PeerToPeerGroup *instance = (PeerToPeerGroup *)GetPeerToPeerGroupInstance();
    return instance->deleteMember(osAccountId, requestId, jsonParams, callback);
}

static void DoCreateGroup(HcTaskBase *baseTask)
{
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(task->reqId);
    LOGI("[Start]: DoCreateGroup! [ReqId]: %" PRId64, task->reqId);
    char *returnJsonStr = NULL;
    int32_t result = CreateGroup(task->osAccountId, task->params, &returnJsonStr);
    if (result != HC_SUCCESS) {
        ProcessErrorCallback(task->reqId, GROUP_CREATE, result, NULL, task->cb);
    } else {
        ProcessFinishCallback(task->reqId, GROUP_CREATE, returnJsonStr, task->cb);
        FreeJsonString(returnJsonStr);
    }
}

static void DoDeleteGroup(HcTaskBase *baseTask)
{
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(task->reqId);
    LOGI("[Start]: DoDeleteGroup! [ReqId]: %" PRId64, task->reqId);
    char *returnJsonStr = NULL;
    int32_t result = DeleteGroup(task->osAccountId, task->params, &returnJsonStr);
    if (result != HC_SUCCESS) {
        ProcessErrorCallback(task->reqId, GROUP_DISBAND, result, NULL, task->cb);
    } else {
        ProcessFinishCallback(task->reqId, GROUP_DISBAND, returnJsonStr, task->cb);
        FreeJsonString(returnJsonStr);
    }
}

static void DoDeleteMember(HcTaskBase *baseTask)
{
    GroupManagerTask *task = (GroupManagerTask *)baseTask;
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(task->reqId);
    LOGI("[Start]: DoDeleteMember! [ReqId]: %" PRId64, task->reqId);
    (void)DeleteMemberFromPeerToPeerGroup(task->osAccountId, task->reqId, task->params, task->cb);
}

static int32_t CreateGroupInner(int32_t osAccountId, int64_t requestId, const char *appId, const char *createParams)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (createParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    LOGI("[Start]: [AppId]: %s, [ReqId]: %" PRId64, appId, requestId);
    CJson *params = CreateJsonFromString(createParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = AddBindParamsToJson(GROUP_CREATE, requestId, appId, params);
    if (result != HC_SUCCESS) {
        FreeJson(params);
        return result;
    }
    if (InitAndPushGMTask(osAccountId, GROUP_CREATE, requestId, params, DoCreateGroup) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: create group successfully!");
    return HC_SUCCESS;
}

#ifdef DEV_AUTH_HIVIEW_ENABLE
static DevAuthCallEvent BuildCallEventData(const char *appId, const char *funcName, const int32_t osAccountId,
    const int32_t callResult, const int32_t processCode)
{
    DevAuthCallEvent eventData;
    eventData.appId = appId;
    eventData.funcName = funcName;
    eventData.osAccountId = osAccountId;
    eventData.callResult = callResult;
    eventData.processCode = processCode;
    eventData.credType = DEFAULT_CRED_TYPE;
    eventData.groupType = DEFAULT_GROUP_TYPE;
    eventData.executionTime = DEFAULT_EXECUTION_TIME;
    eventData.extInfo = DEFAULT_EXT_INFO;
    return eventData;
}
#endif

static int32_t RequestCreateGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *createParams)
{
    int64_t startTime = HcGetCurTimeInMillis();
    int32_t res = CreateGroupInner(osAccountId, requestId, appId, createParams);
    int64_t endTime = HcGetCurTimeInMillis();
    int64_t elapsedTime = endTime - startTime;
    LOGI("CreateGroup elapsed time:  %" PRId64 " milliseconds, [OsAccountId]: %d", elapsedTime, osAccountId);
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, createParams, appId, CREATE_GROUP_EVENT);
#ifdef DEV_AUTH_HIVIEW_ENABLE
    DevAuthCallEvent eventData = BuildCallEventData(appId, CREATE_GROUP_EVENT, osAccountId,
        res, PROCESS_CREATE_GROUP);
    eventData.executionTime = elapsedTime;
    DEV_AUTH_REPORT_CALL_EVENT(eventData);
#endif
    return res;
}

static int32_t DeleteGroupInner(int32_t osAccountId, int64_t requestId, const char *appId, const char *disbandParams)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (disbandParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    LOGI("[Start]: [AppId]: %s, [ReqId]: %" PRId64, appId, requestId);
    CJson *params = CreateJsonFromString(disbandParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = AddBindParamsToJson(GROUP_DISBAND, requestId, appId, params);
    if (result != HC_SUCCESS) {
        FreeJson(params);
        return result;
    }
    if (InitAndPushGMTask(osAccountId, GROUP_DISBAND, requestId, params, DoDeleteGroup) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: delete group successfully!");
    return HC_SUCCESS;
}

static int32_t RequestDeleteGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *disbandParams)
{
    int64_t startTime = HcGetCurTimeInMillis();
    int32_t res = DeleteGroupInner(osAccountId, requestId, appId, disbandParams);
    int64_t endTime = HcGetCurTimeInMillis();
    int64_t elapsedTime = endTime - startTime;
    LOGI("DeleteGroup elapsed time:  %" PRId64 " milliseconds", elapsedTime);
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, disbandParams, appId, DELETE_GROUP_EVENT);
#ifdef DEV_AUTH_HIVIEW_ENABLE
    DevAuthCallEvent eventData = BuildCallEventData(appId, DELETE_GROUP_EVENT, osAccountId,
        res, PROCESS_DELETE_GROUP);
    eventData.executionTime = elapsedTime;
    DEV_AUTH_REPORT_CALL_EVENT(eventData);
#endif
    return res;
}

static int32_t DeleteMemberFromGroupInner(int32_t osAccountId, int64_t requestId, const char *appId,
    const char *deleteParams)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (deleteParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    LOGI("[Start]: [AppId]: %s, [ReqId]: %" PRId64, appId, requestId);
    CJson *params = CreateJsonFromString(deleteParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = AddBindParamsToJson(MEMBER_DELETE, requestId, appId, params);
    if (result != HC_SUCCESS) {
        FreeJson(params);
        return result;
    }
    if (InitAndPushGMTask(osAccountId, MEMBER_DELETE, requestId, params, DoDeleteMember) != HC_SUCCESS) {
        FreeJson(params);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("[End]: delete member from group successully!");
    return HC_SUCCESS;
}

static int32_t RequestDeleteMemberFromGroup(int32_t osAccountId, int64_t requestId, const char *appId,
    const char *deleteParams)
{
    int64_t startTime = HcGetCurTimeInMillis();
    int32_t res = DeleteMemberFromGroupInner(osAccountId, requestId, appId, deleteParams);
    int64_t endTime = HcGetCurTimeInMillis();
    int64_t elapsedTime = endTime - startTime;
    LOGI("DeleteMemberFromGroup elapsed time:  %" PRId64 " milliseconds", elapsedTime);
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, deleteParams, appId, DEL_MEMBER_EVENT);
#ifdef DEV_AUTH_HIVIEW_ENABLE
    DevAuthCallEvent eventData = BuildCallEventData(appId, DEL_MEMBER_EVENT, osAccountId,
        res, PROCESS_DELETE_MEMBER_FROM_GROUP);
    eventData.executionTime = elapsedTime;
    DEV_AUTH_REPORT_CALL_EVENT(eventData);
#endif
    return res;
}

static int32_t AddMultiMembersToGroupInner(int32_t osAccountId, const char *appId, const char *addParams)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (addParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    LOGI("[Start]: [AppId]: %s", appId);
    CJson *params = CreateJsonFromString(addParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t groupType = GROUP_TYPE_INVALID;
    if (GetIntFromJson(params, FIELD_GROUP_TYPE, &groupType) != HC_SUCCESS) {
        LOGE("Failed to get groupType from json!");
        FreeJson(params);
        return HC_ERR_JSON_GET;
    }
    if (!IsGroupTypeSupported(groupType)) {
        FreeJson(params);
        return HC_ERR_NOT_SUPPORT;
    }
    int32_t res;
    if (groupType == IDENTICAL_ACCOUNT_GROUP) {
        IdenticalAccountGroup *instance = (IdenticalAccountGroup *)GetIdenticalAccountGroupInstance();
        res = instance->addMultiMembersToGroup(osAccountId, appId, params);
    } else if (groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        AcrossAccountGroup *instance = (AcrossAccountGroup *)GetAcrossAccountGroupInstance();
        res = instance->addMultiMembersToGroup(osAccountId, appId, params);
    } else {
        LOGE("The input groupType is invalid! [GroupType]: %d", groupType);
        res = HC_ERR_INVALID_PARAMS;
    }
    FreeJson(params);
    LOGI("[End]: [Res]: %d!", res);
    return res;
}

static int32_t RequestAddMultiMembersToGroup(int32_t osAccountId, const char *appId, const char *addParams)
{
    int32_t res = AddMultiMembersToGroupInner(osAccountId, appId, addParams);
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, addParams, appId, ADD_MULTI_MEMBER_EVENT);
    DEV_AUTH_REPORT_CALL_EVENT_WITH_RESULT(appId, ADD_MULTI_MEMBER_EVENT, osAccountId,
        res, PREOCESS_ADD_MULTI_MEMBERS_TO_GROUP);
    return res;
}

static int32_t DelMultiMembersFromGroupInner(int32_t osAccountId, const char *appId, const char *deleteParams)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (deleteParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    LOGI("[Start]: [AppId]: %s", appId);
    CJson *params = CreateJsonFromString(deleteParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t groupType = GROUP_TYPE_INVALID;
    if (GetIntFromJson(params, FIELD_GROUP_TYPE, &groupType) != HC_SUCCESS) {
        LOGE("Failed to get groupType from json!");
        FreeJson(params);
        return HC_ERR_JSON_GET;
    }
    if (!IsGroupTypeSupported(groupType)) {
        FreeJson(params);
        return HC_ERR_NOT_SUPPORT;
    }
    int32_t res;
    if (groupType == IDENTICAL_ACCOUNT_GROUP) {
        IdenticalAccountGroup *instance = (IdenticalAccountGroup *)GetIdenticalAccountGroupInstance();
        res = instance->delMultiMembersFromGroup(osAccountId, appId, params);
    } else if (groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        AcrossAccountGroup *instance = (AcrossAccountGroup *)GetAcrossAccountGroupInstance();
        res = instance->delMultiMembersFromGroup(osAccountId, appId, params);
    } else {
        LOGE("The input groupType is invalid! [GroupType]: %d", groupType);
        res = HC_ERR_INVALID_PARAMS;
    }
    FreeJson(params);
    LOGI("[End]: [Res]: %d!", res);
    return res;
}

static int32_t RequestDelMultiMembersFromGroup(int32_t osAccountId, const char *appId, const char *deleteParams)
{
    int32_t res = DelMultiMembersFromGroupInner(osAccountId, appId, deleteParams);
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, deleteParams, appId, DEL_MULTI_MEMBER_EVENT);
    DEV_AUTH_REPORT_CALL_EVENT_WITH_RESULT(appId, DEL_MULTI_MEMBER_EVENT, osAccountId,
        res, PROCESS_DEL_MULTI_MEMBERS_FROM_GROUP);
    return res;
}

static int32_t RegListener(const char *appId, const DataChangeListener *listener)
{
    if ((appId == NULL) || (listener == NULL)) {
        LOGE("The input parameter contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsBroadcastSupported()) {
        LOGE("Broadcast is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    return AddListener(appId, listener);
}

static int32_t UnRegListener(const char *appId)
{
    if (appId == NULL) {
        LOGE("The input appId is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsBroadcastSupported()) {
        LOGE("Broadcast is not supported!");
        return HC_ERR_NOT_SUPPORT;
    }
    return RemoveListener(appId);
}

static int32_t GetRegisterInfo(const char *reqJsonStr, char **returnRegisterInfo)
{
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(DEFAULT_OS_ACCOUNT, reqJsonStr, NULL, GET_REGISTER_INFO_EVENT);
    if ((reqJsonStr == NULL) || (returnRegisterInfo == NULL)) {
        LOGE("The input param is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *requestJson = CreateJsonFromString(reqJsonStr);
    if (requestJson == NULL) {
        LOGE("Failed to create request json!");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(requestJson, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED) != HC_SUCCESS) {
        LOGE("Failed to add credentialType to input json!");
        FreeJson(requestJson);
        return HC_ERR_JSON_GET;
    }
    CJson *registerInfo = CreateJson();
    if (registerInfo == NULL) {
        LOGE("Failed to allocate registerInfo memory!");
        FreeJson(requestJson);
        return HC_ERR_JSON_CREATE;
    }
    int32_t osAccountId;
    if (GetIntFromJson(requestJson, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGI("No osAccountId in request params, use current active osAccountId.");
        osAccountId = GetCurrentActiveOsAccountId();
    }
    int32_t result = ProcCred(ACCOUNT_RELATED_PLUGIN, osAccountId, REQUEST_SIGNATURE, requestJson, registerInfo);
    FreeJson(requestJson);
    if (result != HC_SUCCESS) {
        LOGE("Failed to get register info!");
        FreeJson(registerInfo);
        return result;
    }
    *returnRegisterInfo = PackJsonToString(registerInfo);
    FreeJson(registerInfo);
    if (*returnRegisterInfo == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t CheckAccessToGroup(int32_t osAccountId, const char *appId, const char *groupId)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (groupId == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    if (CheckGroupAccessible(osAccountId, groupId, appId) != HC_SUCCESS) {
        LOGE("You do not have the permission to query the group information!");
        return HC_ERR_ACCESS_DENIED;
    }
    return HC_SUCCESS;
}

static int32_t GetAccessibleGroupInfoById(int32_t osAccountId, const char *appId, const char *groupId,
    char **returnGroupInfo)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (groupId == NULL) || (returnGroupInfo == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    if (!IsGroupExistByGroupId(osAccountId, groupId)) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (CheckGroupAccessible(osAccountId, groupId, appId) != HC_SUCCESS) {
        LOGE("You do not have the permission to query the group information!");
        return HC_ERR_ACCESS_DENIED;
    }
    TrustedGroupEntry *groupEntry = GetGroupEntryById(osAccountId, groupId);
    if (groupEntry == NULL) {
        LOGE("Failed to get groupEntry from db!");
        return HC_ERR_DB;
    }
    CJson *groupInfoJson = CreateJson();
    if (groupInfoJson == NULL) {
        LOGE("Failed to allocate groupInfoJson memory!");
        DestroyGroupEntry(groupEntry);
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = GenerateReturnGroupInfo(groupEntry, groupInfoJson);
    DestroyGroupEntry(groupEntry);
    if (result != HC_SUCCESS) {
        FreeJson(groupInfoJson);
        return result;
    }
    *returnGroupInfo = PackJsonToString(groupInfoJson);
    FreeJson(groupInfoJson);
    if (*returnGroupInfo == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GetAccessibleGroupInfo(int32_t osAccountId, const char *appId, const char *queryParams,
    char **returnGroupVec, uint32_t *groupNum)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (queryParams == NULL) || (returnGroupVec == NULL) || (groupNum == NULL) ||
        (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    CJson *queryParamsJson = CreateJsonFromString(queryParams);
    if (queryParamsJson == NULL) {
        LOGE("Failed to create queryParamsJson from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t groupType = ALL_GROUP;
    (void)GetIntFromJson(queryParamsJson, FIELD_GROUP_TYPE, &groupType);
    if ((groupType != ALL_GROUP) && (!IsGroupTypeSupported(groupType))) {
        LOGE("Invalid group type!");
        FreeJson(queryParamsJson);
        return HC_ERR_INVALID_PARAMS;
    }
    const char *groupId = GetStringFromJson(queryParamsJson, FIELD_GROUP_ID);
    const char *groupName = GetStringFromJson(queryParamsJson, FIELD_GROUP_NAME);
    const char *groupOwner = GetStringFromJson(queryParamsJson, FIELD_GROUP_OWNER);
    if (!IsQueryParamsValid(groupType, groupId, groupName, groupOwner)) {
        LOGE("The query parameters cannot be all null!");
        FreeJson(queryParamsJson);
        return HC_ERR_INVALID_PARAMS;
    }
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    QueryGroupParams params = InitQueryGroupParams();
    params.groupId = groupId;
    params.groupName = groupName;
    params.ownerName = groupOwner;
    params.groupType = (uint32_t)groupType;
    int32_t result = GetGroupInfo(osAccountId, &params, &groupEntryVec);
    FreeJson(queryParamsJson);
    if (result != HC_SUCCESS) {
        ClearGroupEntryVec(&groupEntryVec);
        return result;
    }
    RemoveNoPermissionGroup(osAccountId, &groupEntryVec, appId);
    result = GenerateReturnGroupVec(&groupEntryVec, returnGroupVec, groupNum);
    ClearGroupEntryVec(&groupEntryVec);
    return result;
}

static int32_t GetAccessibleJoinedGroups(int32_t osAccountId, const char *appId, int groupType,
    char **returnGroupVec, uint32_t *groupNum)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (returnGroupVec == NULL) || (groupNum == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    if (!IsGroupTypeSupported(groupType)) {
        LOGE("Invalid group type!");
        return HC_ERR_INVALID_PARAMS;
    }
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    int32_t result = GetJoinedGroups(osAccountId, groupType, &groupEntryVec);
    if (result != HC_SUCCESS) {
        ClearGroupEntryVec(&groupEntryVec);
        return result;
    }
    RemoveNoPermissionGroup(osAccountId, &groupEntryVec, appId);
    result = GenerateReturnGroupVec(&groupEntryVec, returnGroupVec, groupNum);
    ClearGroupEntryVec(&groupEntryVec);
    return result;
}

static int32_t GetAccessibleRelatedGroups(int32_t osAccountId, const char *appId, const char *peerDeviceId,
    char **returnGroupVec, uint32_t *groupNum)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (peerDeviceId == NULL) || (returnGroupVec == NULL) || (groupNum == NULL) ||
        (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    PRINT_SENSITIVE_DATA("PeerUdid", peerDeviceId);
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    int32_t result = GetRelatedGroups(osAccountId, peerDeviceId, true, &groupEntryVec);
    if (result != HC_SUCCESS) {
        LOGE("Failed to get related groups by udid!");
        ClearGroupEntryVec(&groupEntryVec);
        return result;
    }
    if (groupEntryVec.size(&groupEntryVec) == 0) {
        LOGI("Group entry not found by udid, try to get by authId!");
        result = GetRelatedGroups(osAccountId, peerDeviceId, false, &groupEntryVec);
        if (result != HC_SUCCESS) {
            LOGE("Failed to get related groups by authId!");
            ClearGroupEntryVec(&groupEntryVec);
            return result;
        }
    }
    RemoveNoPermissionGroup(osAccountId, &groupEntryVec, appId);
    result = GenerateReturnGroupVec(&groupEntryVec, returnGroupVec, groupNum);
    ClearGroupEntryVec(&groupEntryVec);
    return result;
}

static int32_t CheckParams(int32_t osAccountId, const char *appId,
    const DeviceQueryParams *devQueryParams, const char *groupId, char **returnDeviceInfo)
{
    if ((appId == NULL) || (devQueryParams == NULL) || (devQueryParams->deviceId == NULL) ||
        (groupId == NULL) || (returnDeviceInfo == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

static int32_t GetAccessibleDeviceInfoById(int32_t osAccountId, const char *appId,
    const DeviceQueryParams *devQueryParams, const char *groupId, char **returnDeviceInfo)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (CheckParams(osAccountId, appId, devQueryParams, groupId, returnDeviceInfo) != HC_SUCCESS) {
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    if (!IsGroupExistByGroupId(osAccountId, groupId)) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (CheckGroupAccessible(osAccountId, groupId, appId) != HC_SUCCESS) {
        LOGE("You do not have the permission to query the group information!");
        return HC_ERR_ACCESS_DENIED;
    }
    TrustedDeviceEntry *deviceEntry = CreateDeviceEntry();
    if (deviceEntry == NULL) {
        LOGE("Failed to allocate deviceEntry memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetTrustedDevInfoById(osAccountId, devQueryParams->deviceId,
        devQueryParams->isUdid, groupId, deviceEntry) != HC_SUCCESS) {
        LOGE("No device is found based on the query parameters!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    CJson *devInfoJson = CreateJson();
    if (devInfoJson == NULL) {
        LOGE("Failed to allocate devInfoJson memory!");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_JSON_FAIL;
    }
    int32_t result = GenerateReturnDevInfo(deviceEntry, devInfoJson);
    DestroyDeviceEntry(deviceEntry);
    if (result != HC_SUCCESS) {
        FreeJson(devInfoJson);
        return result;
    }
    *returnDeviceInfo = PackJsonToString(devInfoJson);
    FreeJson(devInfoJson);
    if (*returnDeviceInfo == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GetAccessibleTrustedDevices(int32_t osAccountId, const char *appId, const char *groupId,
    char **returnDevInfoVec, uint32_t *deviceNum)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (groupId == NULL) || (returnDevInfoVec == NULL) || (deviceNum == NULL) ||
        (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    if (!IsGroupExistByGroupId(osAccountId, groupId)) {
        LOGE("No group is found based on the query parameters!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (CheckGroupAccessible(osAccountId, groupId, appId) != HC_SUCCESS) {
        LOGE("You do not have the permission to query the group information!");
        return HC_ERR_ACCESS_DENIED;
    }
    DeviceEntryVec deviceEntryVec = CreateDeviceEntryVec();
    int32_t result = GetTrustedDevices(osAccountId, groupId, &deviceEntryVec);
    if (result != HC_SUCCESS) {
        ClearDeviceEntryVec(&deviceEntryVec);
        return result;
    }
    result = GenerateReturnDeviceVec(&deviceEntryVec, returnDevInfoVec, deviceNum);
    ClearDeviceEntryVec(&deviceEntryVec);
    return result;
}

static bool IsDeviceInAccessibleGroup(int32_t osAccountId, const char *appId, const char *groupId,
    const char *deviceId, bool isUdid)
{
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (groupId == NULL) || (deviceId == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return false;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return false;
    }
    if (!IsGroupExistByGroupId(osAccountId, groupId)) {
        LOGE("No group is found based on the query parameters!");
        return false;
    }
    if (CheckGroupAccessible(osAccountId, groupId, appId) != HC_SUCCESS) {
        LOGE("You do not have the permission to query the group information!");
        return false;
    }
    return IsTrustedDeviceInGroup(osAccountId, groupId, deviceId, isUdid);
}

static int32_t GetPkInfoList(int32_t osAccountId, const char *appId, const char *queryParams,
    char **returnInfoList, uint32_t *returnInfoNum)
{
    LOGI("[Start]: start to get pk list!");
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, NULL, appId, GET_PK_INFO_LIST_EVENT);
    if ((appId == NULL) || (queryParams == NULL) || (returnInfoList == NULL) ||
        (returnInfoNum == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    CJson *params = CreateJsonFromString(queryParams);
    if (params == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_CREATE;
    }
    CJson *pkInfoList = CreateJsonArray();
    if (pkInfoList == NULL) {
        LOGE("Failed to create json array!");
        FreeJson(params);
        return HC_ERR_JSON_CREATE;
    }
    int32_t res = GeneratePkInfoList(osAccountId, params, pkInfoList);
    FreeJson(params);
    if (res != HC_SUCCESS) {
        FreeJson(pkInfoList);
        return res;
    }
    int32_t pkInfoNum = GetItemNum(pkInfoList);
    char *pkInfoListStr = PackJsonToString(pkInfoList);
    FreeJson(pkInfoList);
    if (pkInfoListStr == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    *returnInfoList = pkInfoListStr;
    *returnInfoNum = pkInfoNum;
    LOGI("[End]: Get pk list successfully! [PkInfoNum]: %" PRId32, pkInfoNum);
    return HC_SUCCESS;
}

static void DestroyInfo(char **returnInfo)
{
    if ((returnInfo == NULL) || (*returnInfo == NULL)) {
        return;
    }
    FreeJsonString(*returnInfo);
    *returnInfo = NULL;
}

static const GroupImpl GROUP_IMPL_INSTANCE = {
    .createGroup = RequestCreateGroup,
    .deleteGroup = RequestDeleteGroup,
    .deleteMember = RequestDeleteMemberFromGroup,
    .addMultiMembers = RequestAddMultiMembersToGroup,
    .delMultiMembers = RequestDelMultiMembersFromGroup,
    .regListener = RegListener,
    .unRegListener = UnRegListener,
    .getRegisterInfo = GetRegisterInfo,
    .checkAccessToGroup = CheckAccessToGroup,
    .getAccessibleGroupInfoById = GetAccessibleGroupInfoById,
    .getAccessibleGroupInfo = GetAccessibleGroupInfo,
    .getAccessibleJoinedGroups = GetAccessibleJoinedGroups,
    .getAccessibleRelatedGroups = GetAccessibleRelatedGroups,
    .getAccessibleDeviceInfoById = GetAccessibleDeviceInfoById,
    .getAccessibleTrustedDevices = GetAccessibleTrustedDevices,
    .isDeviceInAccessibleGroup = IsDeviceInAccessibleGroup,
    .getPkInfoList = GetPkInfoList,
    .destroyInfo = DestroyInfo
};

void DestroyGroupManagerTask(HcTaskBase *task)
{
    if (task == NULL) {
        LOGE("The input task is NULL!");
        return;
    }
    FreeJson(((GroupManagerTask *)task)->params);
}

static int32_t InitGroupManagerTask(GroupManagerTask *task, GMTaskParams *taskParams, TaskFunc func)
{
    task->base.doAction = func;
    task->base.destroy = DestroyGroupManagerTask;
    task->osAccountId = taskParams->osAccountId;
    task->opCode = taskParams->opCode;
    task->reqId = taskParams->reqId;
    task->params = taskParams->params;
    return BindCallbackToTask(task, taskParams->params);
}

int32_t AddReqInfoToJson(int64_t requestId, const char *appId, CJson *jsonParams)
{
    if (AddInt64StringToJson(jsonParams, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("Failed to add requestId to json!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(jsonParams, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("Failed to add appId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

int32_t BindCallbackToTask(GroupManagerTask *task, const CJson *jsonParams)
{
    const char *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    task->cb = GetGMCallbackByAppId(appId);
    if (task->cb == NULL) {
        LOGE("Failed to find callback by appId! [AppId]: %s", appId);
        return HC_ERR_CALLBACK_NOT_FOUND;
    }
    return HC_SUCCESS;
}

int32_t AddBindParamsToJson(int operationCode, int64_t requestId, const char *appId, CJson *jsonParams)
{
    if (AddIntToJson(jsonParams, FIELD_OPERATION_CODE, operationCode) != HC_SUCCESS) {
        LOGE("Failed to add operationCode to json!");
        return HC_ERR_JSON_FAIL;
    }
    return AddReqInfoToJson(requestId, appId, jsonParams);
}

int32_t InitAndPushGMTask(int32_t osAccountId, int32_t opCode, int64_t reqId, CJson *params, TaskFunc func)
{
    GroupManagerTask *task = (GroupManagerTask *)HcMalloc(sizeof(GroupManagerTask), 0);
    if (task == NULL) {
        LOGE("Failed to allocate task memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    GMTaskParams taskParams;
    taskParams.osAccountId = osAccountId;
    taskParams.opCode = opCode;
    taskParams.reqId = reqId;
    taskParams.params = params;
    if (InitGroupManagerTask(task, &taskParams, func) != HC_SUCCESS) {
        HcFree(task);
        return HC_ERR_INIT_TASK_FAIL;
    }
    if (PushTask((HcTaskBase *)task) != HC_SUCCESS) {
        HcFree(task);
        return HC_ERR_INIT_TASK_FAIL;
    }
    return HC_SUCCESS;
}

int32_t InitGroupRelatedModule(void)
{
    if (IsBroadcastSupported()) {
        if (InitBroadcastManager() != HC_SUCCESS) {
            LOGE("[End]: [Service]: Failed to init broadcast manage module!");
            return HC_ERR_SERVICE_NEED_RESTART;
        }
    }
    return HC_SUCCESS;
}

void DestroyGroupRelatedModule(void)
{
    DestroyBroadcastManager();
}

const GroupImpl *GetGroupImplInstance(void)
{
    return &GROUP_IMPL_INSTANCE;
}

bool IsGroupSupport(void)
{
    return true;
}