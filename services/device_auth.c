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

#include "device_auth.h"

#include "account_auth_plugin_proxy.h"
#include "alg_loader.h"
#include "callback_manager.h"
#include "channel_manager.h"
#include "common_defs.h"
#include "cred_manager.h"
#include "data_manager.h"
#include "dev_auth_module_manager.h"
#include "dev_session_mgr.h"
#include "group_manager.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_init_protection.h"
#include "hc_log.h"
#include "hc_time.h"
#include "hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "json_utils.h"
#include "key_manager.h"
#include "os_account_adapter.h"
#include "plugin_adapter.h"
#include "pseudonym_manager.h"
#include "task_manager.h"
#include "performance_dumper.h"
#include "identity_manager.h"

static GroupAuthManager *g_groupAuthManager =  NULL;
static DeviceGroupManager *g_groupManagerInstance = NULL;

typedef struct {
    HcTaskBase base;
    int64_t sessionId;
} StartSessionTask;

typedef struct {
    HcTaskBase base;
    int64_t sessionId;
    CJson *receivedMsg;
} ProcSessionTask;

static int32_t IsDeviceIdHashMatch(const char *udid, const char *subUdidHash)
{
    Uint8Buff udidBuf = { (uint8_t *)udid, (uint32_t)HcStrlen(udid) };
    uint8_t udidHashByte[SHA256_LEN] = { 0 };
    Uint8Buff udidHashBuf = { udidHashByte, sizeof(udidHashByte) };
    int32_t ret = GetLoaderInstance()->sha256(&udidBuf, &udidHashBuf);
    if (ret != HC_SUCCESS) {
        LOGE("sha256 failed, ret:%d", ret);
        return ret;
    }
    uint32_t udidHashLen = SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *udidHash = (char *)HcMalloc(udidHashLen, 0);
    if (udidHash == NULL) {
        LOGE("malloc udidHash string failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    ret = ByteToHexString(udidHashByte, SHA256_LEN, udidHash, udidHashLen);
    if (ret != HC_SUCCESS) {
        LOGE("Byte to hexString failed, ret:%d", ret);
        HcFree(udidHash);
        return ret;
    }
    char *subUdidHashUpper = NULL;
    ret = ToUpperCase(subUdidHash, &subUdidHashUpper);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to convert the input sub udid hash to upper case!");
        HcFree(udidHash);
        return ret;
    }
    if (strstr((const char *)udidHash, subUdidHashUpper) != NULL) {
        LOGI("udid hash is match!");
        HcFree(udidHash);
        HcFree(subUdidHashUpper);
        return HC_SUCCESS;
    }
    HcFree(udidHash);
    HcFree(subUdidHashUpper);
    return HC_ERROR;
}

static const char *GetUdidByGroup(int32_t osAccountId, const char *groupId, const char *deviceIdHash)
{
    uint32_t index;
    TrustedDeviceEntry **deviceEntry = NULL;
    DeviceEntryVec deviceEntryVec = CREATE_HC_VECTOR(DeviceEntryVec);
    QueryDeviceParams params = InitQueryDeviceParams();
    params.groupId = groupId;
    if (QueryDevices(osAccountId, &params, &deviceEntryVec) != HC_SUCCESS) {
        LOGE("query trusted devices failed!");
        ClearDeviceEntryVec(&deviceEntryVec);
        return NULL;
    }
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, deviceEntry) {
        const char *udid = StringGet(&(*deviceEntry)->udid);
        if (IsDeviceIdHashMatch(udid, deviceIdHash) == HC_SUCCESS) {
            ClearDeviceEntryVec(&deviceEntryVec);
            return udid;
        }
        continue;
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return NULL;
}

static const char *GetDeviceIdByUdidHash(int32_t osAccountId, const char *deviceIdHash)
{
    if (deviceIdHash == NULL) {
        LOGE("deviceIdHash is null");
        return NULL;
    }
    QueryGroupParams queryParams = InitQueryGroupParams();
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    int32_t ret = QueryGroups(osAccountId, &queryParams, &groupEntryVec);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to query groups!");
        ClearGroupEntryVec(&groupEntryVec);
        return NULL;
    }
    uint32_t index;
    TrustedGroupEntry **ptr = NULL;
    FOR_EACH_HC_VECTOR(groupEntryVec, index, ptr) {
        const TrustedGroupEntry *groupEntry = (const TrustedGroupEntry *)(*ptr);
        const char *groupId = StringGet(&(groupEntry->id));
        if (groupId == NULL) {
            continue;
        }
        const char *udid = GetUdidByGroup(osAccountId, groupId, deviceIdHash);
        if (udid != NULL) {
            ClearGroupEntryVec(&groupEntryVec);
            return udid;
        }
    }
    ClearGroupEntryVec(&groupEntryVec);
    return NULL;
}

static const char *GetPeerUdidFromJson(int32_t osAccountId, const CJson *in)
{
    const char *peerConnDeviceId = GetStringFromJson(in, FIELD_PEER_CONN_DEVICE_ID);
    if (peerConnDeviceId == NULL) {
        LOGI("get peerConnDeviceId from json fail.");
        return NULL;
    }
    bool isUdidHash = false;
    (void)GetBoolFromJson(in, FIELD_IS_UDID_HASH, &isUdidHash);
    if (isUdidHash) {
        const char *deviceId = GetDeviceIdByUdidHash(osAccountId, peerConnDeviceId);
        return (deviceId == NULL ? peerConnDeviceId : deviceId);
    }
    return peerConnDeviceId;
}

static int32_t AddGroupInfoToContextByInput(const CJson *receivedMsg, CJson *context)
{
    const char *groupId = GetStringFromJson(receivedMsg, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("get groupId from json fail.");
        return HC_ERR_JSON_GET;
    }
    const char *groupName = GetStringFromJson(receivedMsg, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to json!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP) != HC_SUCCESS) {
        LOGE("Failed to add groupType to json!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(context, FIELD_GROUP_NAME, groupName) != HC_SUCCESS) {
        LOGE("Failed to add groupName to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddDevInfoToContextByInput(CJson *context)
{
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(context, FIELD_USER_TYPE, &userType);
    const char *authId = GetStringFromJson(context, FIELD_DEVICE_ID);
    char udid[INPUT_UDID_LEN] = { 0 };
    if (authId == NULL) {
        LOGD("No authId is found. The default value is udid!");
        int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get local udid! res: %d", res);
            return HC_ERR_DB;
        }
        authId = udid;
    }
    if (AddStringToJson(context, FIELD_AUTH_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_USER_TYPE, userType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupInfoToContextByDb(const char *groupId, CJson *context)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("get osAccountId from json fail.");
        return HC_ERR_JSON_GET;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        LOGE("Failed to get groupEntry from db!");
        return HC_ERR_DB;
    }
    if (AddStringToJson(context, FIELD_GROUP_ID, StringGet(&entry->id)) != HC_SUCCESS) {
        LOGE("Failed to add groupId to json!");
        DestroyGroupEntry(entry);
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_GROUP_TYPE, entry->type) != HC_SUCCESS) {
        LOGE("Failed to add groupType to json!");
        DestroyGroupEntry(entry);
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(context, FIELD_GROUP_NAME, StringGet(&entry->name)) != HC_SUCCESS) {
        LOGE("Failed to add groupName to json!");
        DestroyGroupEntry(entry);
        return HC_ERR_JSON_FAIL;
    }
    DestroyGroupEntry(entry);
    return HC_SUCCESS;
}

static int32_t AddDevInfoToContextByDb(const char *groupId, CJson *context)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("get osAccountId from json fail.");
        return HC_ERR_JSON_GET;
    }
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return HC_ERR_DB;
    }
    TrustedDeviceEntry *devAuthParams = CreateDeviceEntry();
    if (devAuthParams == NULL) {
        LOGE("Failed to allocate devEntry memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetTrustedDevInfoById(osAccountId, udid, true, groupId, devAuthParams) != HC_SUCCESS) {
        LOGE("Failed to obtain the local device information from the database!");
        DestroyDeviceEntry(devAuthParams);
        return HC_ERR_DB;
    }
    if (AddStringToJson(context, FIELD_AUTH_ID, StringGet(&devAuthParams->authId)) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        DestroyDeviceEntry(devAuthParams);
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_USER_TYPE, devAuthParams->devType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        DestroyDeviceEntry(devAuthParams);
        return HC_ERR_JSON_FAIL;
    }
    DestroyDeviceEntry(devAuthParams);
    return HC_SUCCESS;
}

static int32_t GetOpCodeFromContext(const CJson *context)
{
    bool isAdmin = true;
    (void)GetBoolFromJson(context, FIELD_IS_ADMIN, &isAdmin);
    return isAdmin ? MEMBER_INVITE : MEMBER_JOIN;
}

static int32_t AddClientReqInfoToContext(int32_t osAccountId, int64_t requestId, const char *appId, CJson *context)
{
    const char *groupId = GetStringFromJson(context, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("get groupId from json fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, true) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, true) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add osAccountId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    int32_t opCode = GetOpCodeFromContext(context);
    if (AddIntToJson(context, FIELD_OPERATION_CODE, opCode) != HC_SUCCESS) {
        LOGE("add operationCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (opCode == MEMBER_JOIN) {
        return AddDevInfoToContextByInput(context);
    }
    int32_t res = AddDevInfoToContextByDb(groupId, context);
    if (res != HC_SUCCESS) {
        return res;
    }
    return AddGroupInfoToContextByDb(groupId, context);
}

static int32_t AddChannelInfoToContext(int32_t channelType, int64_t channelId, CJson *context)
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

static int32_t BuildClientBindContext(int32_t osAccountId, int64_t requestId, const char *appId,
    const DeviceAuthCallback *callback, CJson *context)
{
    int32_t res = AddClientReqInfoToContext(osAccountId, requestId, appId, context);
    if (res != HC_SUCCESS) {
        return res;
    }
    ChannelType channelType = GetChannelType(callback, context);
    int64_t channelId;
    res = OpenChannel(channelType, context, requestId, &channelId);
    if (res != HC_SUCCESS) {
        LOGE("open channel fail.");
        return res;
    }
    return AddChannelInfoToContext(channelType, channelId, context);
}

static void DoStartSession(HcTaskBase *task)
{
    LOGI("start session task begin.");
    if (task == NULL) {
        LOGE("The input task is NULL, can't start session!");
        return;
    }
    StartSessionTask *realTask = (StartSessionTask *)task;
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(realTask->sessionId);
    int32_t res = StartDevSession(realTask->sessionId);
    if (res != HC_SUCCESS) {
        LOGE("start session fail.[Res]: %d", res);
        CloseDevSession(realTask->sessionId);
    }
}

static void DoProcSession(HcTaskBase *task)
{
    LOGI("proc session task begin.");
    if (task == NULL) {
        LOGE("The input task is NULL, can't start session!");
        return;
    }
    ProcSessionTask *realTask = (ProcSessionTask *)task;
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(realTask->sessionId);
    bool isFinish = false;
    int32_t res = ProcessDevSession(realTask->sessionId, realTask->receivedMsg, &isFinish);
    if (res != HC_SUCCESS) {
        LOGE("ProcessDevSession fail. [Res]: %d", res);
        CloseDevSession(realTask->sessionId);
        return;
    }
    LOGI("ProcessDevSession success. [State]: %s", isFinish ? "FINISH" : "CONTINUE");
    if (isFinish) {
        CloseDevSession(realTask->sessionId);
    }
}

static void InitStartSessionTask(StartSessionTask *task, int64_t sessionId)
{
    task->base.doAction = DoStartSession;
    task->base.destroy = NULL;
    task->sessionId = sessionId;
}

static void DestroyProcSessionTask(HcTaskBase *task)
{
    ProcSessionTask *realTask = (ProcSessionTask *)task;
    FreeJson(realTask->receivedMsg);
}

static void InitProcSessionTask(ProcSessionTask *task, int64_t sessionId, CJson *receivedMsg)
{
    task->base.doAction = DoProcSession;
    task->base.destroy = DestroyProcSessionTask;
    task->sessionId = sessionId;
    task->receivedMsg = receivedMsg;
}

static int32_t PushStartSessionTask(int64_t sessionId)
{
    StartSessionTask *task = (StartSessionTask *)HcMalloc(sizeof(StartSessionTask), 0);
    if (task == NULL) {
        LOGE("Failed to allocate memory for task!");
        return HC_ERR_ALLOC_MEMORY;
    }
    InitStartSessionTask(task, sessionId);
    if (PushTask((HcTaskBase*)task) != HC_SUCCESS) {
        LOGE("push start session task fail.");
        HcFree(task);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("push start session task success.");
    return HC_SUCCESS;
}

static int32_t AddOriginDataForPlugin(CJson *receivedMsg, const uint8_t *data)
{
    if ((receivedMsg == NULL) || (data == NULL)) {
        LOGE("Invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    return AddStringToJson(receivedMsg, FIELD_PLUGIN_EXT_DATA, (const char *)data);
}

static int32_t PushProcSessionTask(int64_t sessionId, CJson *receivedMsg)
{
    ProcSessionTask *task = (ProcSessionTask *)HcMalloc(sizeof(ProcSessionTask), 0);
    if (task == NULL) {
        LOGE("Failed to allocate memory for task!");
        return HC_ERR_ALLOC_MEMORY;
    }
    InitProcSessionTask(task, sessionId, receivedMsg);
    if (PushTask((HcTaskBase*)task) != HC_SUCCESS) {
        LOGE("push start session task fail.");
        HcFree(task);
        return HC_ERR_INIT_TASK_FAIL;
    }
    LOGI("push start session task success.");
    return HC_SUCCESS;
}

#ifdef ENABLE_P2P_BIND_LITE_PROTOCOL_CHECK
// If bind with iso short pin, groupVisibility must be private
static int32_t CheckGroupVisibility(const CJson *context)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(context, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId!");
        return HC_ERR_JSON_GET;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        LOGE("Failed to get group entry!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (entry->visibility != GROUP_VISIBILITY_PRIVATE) {
        LOGE("Group is not private, can not bind old version wearable device!");
        DestroyGroupEntry(entry);
        return HC_ERR_INVALID_PARAMS;
    }
    DestroyGroupEntry(entry);
    return HC_SUCCESS;
}
#endif

#ifdef ENABLE_P2P_BIND_LITE_PROTOCOL_CHECK
static int32_t CheckBindParams(const CJson *context, bool isClient)
{
    int32_t opCode;
    if (GetIntFromJson(context, FIELD_OPERATION_CODE, &opCode) != HC_SUCCESS) {
        LOGE("Failed to get operation code!");
        return HC_ERR_JSON_GET;
    }
    if ((isClient && opCode == MEMBER_INVITE) || (!isClient && opCode == MEMBER_JOIN)) {
        int32_t protocolExpandVal = INVALID_PROTOCOL_EXPAND_VALUE;
        (void)GetIntFromJson(context, FIELD_PROTOCOL_EXPAND, &protocolExpandVal);
        if (protocolExpandVal == LITE_PROTOCOL_COMPATIBILITY_MODE) {
            return CheckGroupVisibility(context);
        }
    }
    return HC_SUCCESS;
}
#endif

static int32_t StartClientBindSession(int32_t osAccountId, int64_t requestId, const char *appId,
    const char *contextParams, const DeviceAuthCallback *callback)
{
    CJson *context = CreateJsonFromString(contextParams);
    if (context == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t res = BuildClientBindContext(osAccountId, requestId, appId, callback, context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
#ifdef ENABLE_P2P_BIND_LITE_PROTOCOL_CHECK
    res = CheckBindParams(context, true);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
#endif
    ChannelType channelType = GetChannelType(callback, context);
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(requestId, appId, &params);
    FreeJson(context);
    if (res != HC_SUCCESS) {
        LOGE("OpenDevSession fail. [Res]: %d", res);
        return res;
    }
    if (channelType == SERVICE_CHANNEL) {
        res = PushStartSessionTask(requestId);
        if (res != HC_SUCCESS) {
            return res;
        }
    }
    return HC_SUCCESS;
}

#ifdef DEV_AUTH_HIVIEW_ENABLE
static const char *GetAddMemberCallEventFuncName(const char *addParams)
{
    if (addParams == NULL) {
        LOGE("add params is null!");
        return ADD_MEMBER_EVENT;
    }
    CJson *in = CreateJsonFromString(addParams);
    if (in == NULL) {
        LOGE("Failed to create json param!");
        return ADD_MEMBER_EVENT;
    }
    int32_t protocolExpandVal = INVALID_PROTOCOL_EXPAND_VALUE;
    (void)GetIntFromJson(in, FIELD_PROTOCOL_EXPAND, &protocolExpandVal);
    FreeJson(in);
    if (protocolExpandVal == LITE_PROTOCOL_STANDARD_MODE) {
        return ADD_MEMBER_WITH_LITE_STANDARD;
    } else if (protocolExpandVal == LITE_PROTOCOL_COMPATIBILITY_MODE) {
        return ADD_MEMBER_WITH_LITE_COMPATIBILITY;
    } else {
        return ADD_MEMBER_EVENT;
    }
}
#endif

static int32_t AddMemberToGroupInner(int32_t osAccountId, int64_t requestId, const char *appId, const char *addParams)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(requestId);
    ADD_PERFORM_DATA(requestId, true, true, HcGetCurTimeInMillis());
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (addParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    LOGI("Start to add member to group. [ReqId]: %" PRId64 ", [AppId]: %s", requestId, appId);
    const DeviceAuthCallback *callback = GetGMCallbackByAppId(appId);
    if (callback == NULL) {
        LOGE("Failed to find callback by appId! [AppId]: %s", appId);
        return HC_ERR_CALLBACK_NOT_FOUND;
    }
    return StartClientBindSession(osAccountId, requestId, appId, addParams, callback);
}

static int32_t AddMemberToGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *addParams)
{
    int32_t res = AddMemberToGroupInner(osAccountId, requestId, appId, addParams);
#ifdef DEV_AUTH_HIVIEW_ENABLE
    const char *callEventFuncName = GetAddMemberCallEventFuncName(addParams);
    DEV_AUTH_REPORT_CALL_EVENT(requestId, callEventFuncName, appId, osAccountId, res);
#endif
    return res;
}

static int32_t CheckAndGetValidOsAccountId(const CJson *context, int32_t *osAccountId)
{
    (void)GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, osAccountId);
    *osAccountId = DevAuthGetRealOsAccountLocalId(*osAccountId);
    if (*osAccountId == INVALID_OS_ACCOUNT) {
        LOGE("Invalid os accountId!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(*osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    return HC_SUCCESS;
}

static int32_t AddServerReqInfoToContext(int64_t requestId, const char *appId, int32_t opCode,
    const CJson *receivedMsg, CJson *context)
{
    const char *groupId = GetStringFromJson(receivedMsg, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("get groupId from json fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, true) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, false) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    int32_t osAccountId = ANY_OS_ACCOUNT;
    int32_t ret = CheckAndGetValidOsAccountId(context, &osAccountId);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add osAccountId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, opCode) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    int32_t res;
    if (opCode == MEMBER_INVITE) {
        res = AddGroupInfoToContextByInput(receivedMsg, context);
        if (res != HC_SUCCESS) {
            return res;
        }
        return AddDevInfoToContextByInput(context);
    }
    res = AddGroupInfoToContextByDb(groupId, context);
    if (res != HC_SUCCESS) {
        return res;
    }
    return AddDevInfoToContextByDb(groupId, context);
}

static int32_t BuildServerBindContext(int64_t requestId, const char *appId, int32_t opCode,
    const CJson *receivedMsg, CJson *context)
{
    int32_t res = AddServerReqInfoToContext(requestId, appId, opCode, receivedMsg, context);
    if (res != HC_SUCCESS) {
        return res;
    }
    int32_t channelType;
    int64_t channelId = DEFAULT_CHANNEL_ID;
    if (GetByteFromJson(receivedMsg, FIELD_CHANNEL_ID, (uint8_t *)&channelId, sizeof(int64_t)) == HC_SUCCESS) {
        channelType = SOFT_BUS;
    } else {
        channelType = SERVICE_CHANNEL;
    }
    return AddChannelInfoToContext(channelType, channelId, context);
}

static int32_t CheckAcceptRequest(const CJson *context)
{
    uint32_t confirmation = REQUEST_REJECTED;
    if (GetUnsignedIntFromJson(context, FIELD_CONFIRMATION, &confirmation) != HC_SUCCESS) {
        LOGE("Failed to get confimation from json!");
        return HC_ERR_JSON_GET;
    }
    if (confirmation == REQUEST_ACCEPTED) {
        LOGI("The service accepts this request!");
    } else {
        LOGE("The service rejects this request!");
    }
    return HC_SUCCESS;
}

static const char *GetAppIdFromReceivedMsg(const CJson *receivedMsg)
{
    const char *appId = GetStringFromJson(receivedMsg, FIELD_APP_ID);
    if (appId == NULL) {
        LOGW("use default device manager appId.");
        appId = DM_APP_ID;
    }
    return appId;
}

static int32_t OpenServerBindSession(int64_t requestId, const CJson *receivedMsg)
{
    const char *appId = GetAppIdFromReceivedMsg(receivedMsg);
    const DeviceAuthCallback *callback = GetGMCallbackByAppId(appId);
    if (callback == NULL) {
        LOGE("Failed to find callback by appId! [AppId]: %s", appId);
        return HC_ERR_CALLBACK_NOT_FOUND;
    }
    int32_t opCode;
    if (GetIntFromJson(receivedMsg, FIELD_GROUP_OP, &opCode) != HC_SUCCESS) {
        if (GetIntFromJson(receivedMsg, FIELD_OP_CODE, &opCode) != HC_SUCCESS) {
            opCode = MEMBER_JOIN;
            LOGW("use default opCode.");
        }
    }
    char *returnDataStr = ProcessRequestCallback(requestId, opCode, NULL, callback);
    if (returnDataStr == NULL) {
        LOGE("The OnRequest callback is fail!");
        return HC_ERR_REQ_REJECTED;
    }
    CJson *context = CreateJsonFromString(returnDataStr);
    FreeJsonString(returnDataStr);
    if (context == NULL) {
        LOGE("Failed to create context from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t res = CheckAcceptRequest(context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    res = BuildServerBindContext(requestId, appId, opCode, receivedMsg, context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
#ifdef ENABLE_P2P_BIND_LITE_PROTOCOL_CHECK
    res = CheckBindParams(context, false);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
#endif
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(requestId, appId, &params);
    FreeJson(context);
    return res;
}

static int32_t ProcessBindData(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(requestId);
    if (!IsSessionExist(requestId)) {
        ADD_PERFORM_DATA(requestId, true, false, HcGetCurTimeInMillis());
    } else {
        UPDATE_PERFORM_DATA_BY_SELF_INDEX(requestId, HcGetCurTimeInMillis());
    }
    if ((data == NULL) || (dataLen == 0) || (dataLen > MAX_DATA_BUFFER_SIZE)) {
        LOGE("The input data is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[Start]: RequestProcessBindData! [ReqId]: %" PRId64, requestId);
    CJson *receivedMsg = CreateJsonFromString((const char *)data);
    if (receivedMsg == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t res;
    if (!IsSessionExist(requestId)) {
        res = OpenServerBindSession(requestId, receivedMsg);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    res = PushProcSessionTask(requestId, receivedMsg);
    if (res != HC_SUCCESS) {
        FreeJson(receivedMsg);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t BuildClientAuthContext(int32_t osAccountId, int64_t requestId, const char *appId, CJson *context)
{
    const char *peerUdid = GetPeerUdidFromJson(osAccountId, context);
    if (peerUdid != NULL) {
        char *deviceId = NULL;
        if (DeepCopyString(peerUdid, &deviceId) != HC_SUCCESS) {
            LOGE("Failed to copy peerUdid!");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (AddStringToJson(context, FIELD_PEER_UDID, deviceId) != HC_SUCCESS) {
            LOGE("add peerUdid to context fail.");
            HcFree(deviceId);
            return HC_ERR_JSON_ADD;
        }
        if (AddStringToJson(context, FIELD_PEER_CONN_DEVICE_ID, deviceId) != HC_SUCCESS) {
            LOGE("add peerConnDeviceId to context fail.");
            HcFree(deviceId);
            return HC_ERR_JSON_ADD;
        }
        PRINT_SENSITIVE_DATA("PeerUdid", deviceId);
        HcFree(deviceId);
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, false) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, true) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add osAccountId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, AUTH_FORM_ACCOUNT_UNRELATED) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

static int32_t BuildP2PBindContext(CJson *context)
{
    int32_t acquireType = -1;
    if (GetIntFromJson(context, FIELD_ACQURIED_TYPE, &acquireType) != HC_SUCCESS) {
        LOGE("Failed to get acquireType from reqJsonStr!");
        return HC_ERR_JSON_FAIL;
    }
    if ((acquireType == P2P_BIND) && AddBoolToJson(context, FIELD_IS_DIRECT_AUTH, true) != HC_SUCCESS) {
        LOGE("add isDirectAuth to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, acquireType) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    const char *serviceType = GetStringFromJson(context, FIELD_SERVICE_TYPE);
    if (serviceType == NULL) {
        if ((acquireType == P2P_BIND) &&
            AddStringToJson(context, FIELD_SERVICE_TYPE, DEFAULT_SERVICE_TYPE) != HC_SUCCESS) {
            LOGE("add serviceType to context fail.");
            return HC_ERR_JSON_ADD;
        }
    }
    return HC_SUCCESS;
}

static int32_t AuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    ADD_PERFORM_DATA(authReqId, false, true, HcGetCurTimeInMillis());
    LOGI("Begin AuthDevice. [ReqId]:%" PRId64, authReqId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((authParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT) || (gaCallback == NULL)) {
        LOGE("The input auth params is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    CJson *context = CreateJsonFromString(authParams);
    if (context == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    const char *appId = GetStringFromJson(context, FIELD_SERVICE_PKG_NAME);
    if (appId == NULL) {
        LOGE("get servicePkgName from json fail.");
        FreeJson(context);
        return HC_ERR_JSON_GET;
    }
    int32_t res = BuildClientAuthContext(osAccountId, authReqId, appId, context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *gaCallback };
    res = OpenDevSession(authReqId, appId, &params);
    FreeJson(context);
    if (res != HC_SUCCESS) {
        LOGE("OpenDevSession fail. [Res]: %d", res);
        return res;
    }
    return PushStartSessionTask(authReqId);
}

static int32_t AddDeviceIdToJson(CJson *context, const char *peerUdid)
{
    char *deviceId = NULL;
    if (DeepCopyString(peerUdid, &deviceId) != HC_SUCCESS) {
        LOGE("Failed to copy peerUdid!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddStringToJson(context, FIELD_PEER_UDID, deviceId) != HC_SUCCESS) {
        LOGE("add peerUdid to context fail.");
        HcFree(deviceId);
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_PEER_CONN_DEVICE_ID, deviceId) != HC_SUCCESS) {
        LOGE("add peerConnDeviceId to context fail.");
        HcFree(deviceId);
        return HC_ERR_JSON_ADD;
    }
    HcFree(deviceId);
    return HC_SUCCESS;
}

static int32_t BuildServerAuthContext(int64_t requestId, int32_t opCode, const char *appId, CJson *context)
{
    int32_t osAccountId = ANY_OS_ACCOUNT;
    (void)GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (osAccountId == INVALID_OS_ACCOUNT) {
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    const char *peerUdid = GetPeerUdidFromJson(osAccountId, context);
    if (peerUdid == NULL) {
        LOGE("get peerUdid from json fail.");
        return HC_ERR_JSON_GET;
    }
    PRINT_SENSITIVE_DATA("PeerUdid", peerUdid);
    if (AddDeviceIdToJson(context, peerUdid) != HC_SUCCESS) {
        LOGE("add deviceId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, false) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, false) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add operationCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, opCode) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

static int32_t BuildServerP2PAuthContext(int64_t requestId, int32_t opCode, const char *appId, CJson *context)
{
    int32_t osAccountId = ANY_OS_ACCOUNT;
    (void)GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (osAccountId == INVALID_OS_ACCOUNT) {
        return HC_ERR_INVALID_PARAMS;
    }
    if (!IsOsAccountUnlocked(osAccountId)) {
        LOGE("Os account is not unlocked!");
        return HC_ERR_OS_ACCOUNT_NOT_UNLOCKED;
    }
    const char *peerUdid = GetStringFromJson(context, FIELD_PEER_CONN_DEVICE_ID);
    const char *pinCode = GetStringFromJson(context, FIELD_PIN_CODE);
    if (peerUdid == NULL && pinCode == NULL) {
        LOGE("need peerConnDeviceId or pinCode!");
        return HC_ERR_JSON_GET;
    }
    if (peerUdid != NULL) {
        PRINT_SENSITIVE_DATA("PeerUdid", peerUdid);
        if (AddDeviceIdToJson(context, peerUdid) != HC_SUCCESS) {
            LOGE("add deviceId to context fail.");
            return HC_ERR_JSON_ADD;
        }
    }
    if (AddBoolToJson(context, FIELD_IS_BIND, false) != HC_SUCCESS) {
        LOGE("add isBind to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddBoolToJson(context, FIELD_IS_CLIENT, false) != HC_SUCCESS) {
        LOGE("add isClient to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add operationCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddInt64StringToJson(context, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("add requestId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(context, FIELD_APP_ID, appId) != HC_SUCCESS) {
        LOGE("add appId to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(context, FIELD_OPERATION_CODE, opCode) != HC_SUCCESS) {
        LOGE("add opCode to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return AddChannelInfoToContext(SERVICE_CHANNEL, DEFAULT_CHANNEL_ID, context);
}

static int32_t OpenServerAuthSession(int64_t requestId, const CJson *receivedMsg, const DeviceAuthCallback *callback)
{
    int32_t opCode = AUTH_FORM_ACCOUNT_UNRELATED;
    if (GetIntFromJson(receivedMsg, FIELD_AUTH_FORM, &opCode) != HC_SUCCESS) {
        if (GetIntFromJson(receivedMsg, FIELD_OP_CODE, &opCode) != HC_SUCCESS) {
            opCode = AUTH_FORM_INVALID_TYPE;
            LOGW("use default opCode.");
        }
    }
    char *returnDataStr = ProcessRequestCallback(requestId, opCode, NULL, callback);
    if (returnDataStr == NULL) {
        LOGE("The OnRequest callback is fail!");
        return HC_ERR_REQ_REJECTED;
    }
    CJson *context = CreateJsonFromString(returnDataStr);
    FreeJsonString(returnDataStr);
    if (context == NULL) {
        LOGE("Failed to create context from string!");
        return HC_ERR_JSON_FAIL;
    }
    const char *appId = GetStringFromJson(context, FIELD_SERVICE_PKG_NAME);
    if (appId == NULL) {
        LOGE("get appId from json fail.");
        FreeJson(context);
        return HC_ERR_JSON_GET;
    }
    int32_t res = CheckAcceptRequest(context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    res = BuildServerAuthContext(requestId, opCode, appId, context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(requestId, appId, &params);
    FreeJson(context);
    return res;
}

static int32_t OpenServerAuthSessionForP2P(
    int64_t requestId, const CJson *receivedMsg, const DeviceAuthCallback *callback)
{
    int32_t opCode = P2P_BIND;
    if (GetIntFromJson(receivedMsg, FIELD_OP_CODE, &opCode) != HC_SUCCESS) {
        opCode = P2P_BIND;
        LOGW("use default opCode.");
    }
    char *returnDataStr = ProcessRequestCallback(requestId, opCode, NULL, callback);
    if (returnDataStr == NULL) {
        LOGE("The OnRequest callback is fail!");
        return HC_ERR_REQ_REJECTED;
    }
    CJson *context = CreateJsonFromString(returnDataStr);
    FreeJsonString(returnDataStr);
    if (context == NULL) {
        LOGE("Failed to create context from string!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddBoolToJson(context, FIELD_IS_DIRECT_AUTH, true) != HC_SUCCESS) {
        LOGE("Failed to add isDirectAuth to context!");
        FreeJson(context);
        return HC_ERR_JSON_ADD;
    }
    const char *pkgName = GetStringFromJson(context, FIELD_SERVICE_PKG_NAME);
    if (pkgName == NULL && AddStringToJson(context, FIELD_SERVICE_PKG_NAME, DEFAULT_PACKAGE_NAME) != HC_SUCCESS) {
        LOGE("Failed to add default package name to context!");
        FreeJson(context);
        return HC_ERR_JSON_ADD;
    }
    const char *serviceType = GetStringFromJson(context, FIELD_SERVICE_TYPE);
    if (serviceType == NULL && AddStringToJson(context, FIELD_SERVICE_TYPE, DEFAULT_SERVICE_TYPE) != HC_SUCCESS) {
        LOGE("Failed to add default package name to context!");
        FreeJson(context);
        return HC_ERR_JSON_ADD;
    }
    const char *appId = pkgName != NULL ? pkgName : DEFAULT_PACKAGE_NAME;
    int32_t res = CheckAcceptRequest(context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    res = BuildServerP2PAuthContext(requestId, opCode, appId, context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(requestId, appId, &params);
    FreeJson(context);
    return res;
}

static int32_t ProcessData(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *gaCallback)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    if (!IsSessionExist(authReqId)) {
        ADD_PERFORM_DATA(authReqId, false, false, HcGetCurTimeInMillis());
    } else {
        UPDATE_PERFORM_DATA_BY_SELF_INDEX(authReqId, HcGetCurTimeInMillis());
    }
    LOGI("[GA] Begin ProcessData. [DataLen]: %u, [ReqId]: %" PRId64, dataLen, authReqId);
    if ((data == NULL) || (dataLen > MAX_DATA_BUFFER_SIZE)) {
        LOGE("Invalid input for ProcessData!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *receivedMsg = CreateJsonFromString((const char *)data);
    if (receivedMsg == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t res;
    if (!IsSessionExist(authReqId)) {
        res = OpenServerAuthSession(authReqId, receivedMsg, gaCallback);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    if (HasAccountAuthPlugin() == HC_SUCCESS) {
        res = AddOriginDataForPlugin(receivedMsg, data);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    res = PushProcSessionTask(authReqId, receivedMsg);
    if (res != HC_SUCCESS) {
        FreeJson(receivedMsg);
        return res;
    }
    return HC_SUCCESS;
}

static void CancelRequest(int64_t requestId, const char *appId)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(requestId);
    if (appId == NULL) {
        LOGE("Invalid app id!");
        return;
    }
    LOGI("cancel request. [AppId]: %s, [ReqId]: %" PRId64, appId, requestId);
    CancelDevSession(requestId, appId);
}

static int32_t GetRealInfo(int32_t osAccountId, const char *pseudonymId, char **realInfo)
{
    if (pseudonymId == NULL || realInfo == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    PseudonymManager *pseudonymInstance = GetPseudonymInstance();
    if (pseudonymInstance == NULL) {
        LOGE("not support privacy enhancement!");
        return HC_ERR_NOT_SUPPORT;
    }
    return pseudonymInstance->getRealInfo(osAccountId, pseudonymId, realInfo);
}

static int32_t GetPseudonymId(int32_t osAccountId, const char *indexKey, char **pseudonymId)
{
    if (indexKey == NULL || pseudonymId == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }
    PseudonymManager *pseudonymInstance = GetPseudonymInstance();
    if (pseudonymInstance == NULL) {
        LOGE("not support privacy enhancement!");
        return HC_ERR_NOT_SUPPORT;
    }
    return pseudonymInstance->getPseudonymId(osAccountId, indexKey, pseudonymId);
}

DEVICE_AUTH_API_PUBLIC int32_t ProcessCredential(int32_t operationCode, const char *reqJsonStr, char **returnData)
{
    if (reqJsonStr == NULL || returnData == NULL) {
        LOGE("Invalid params!");
        return HC_ERR_INVALID_PARAMS;
    }

    const CredentialOperator *credOperator = GetCredentialOperator();
    if (credOperator == NULL) {
        LOGE("credOperator is null!");
        return HC_ERR_NOT_SUPPORT;
    }

    int32_t res = HC_ERR_UNSUPPORTED_OPCODE;
    switch (operationCode) {
        case CRED_OP_QUERY:
            res = credOperator->queryCredential(reqJsonStr, returnData);
            break;
        case CRED_OP_CREATE:
            res = credOperator->genarateCredential(reqJsonStr, returnData);
            break;
        case CRED_OP_IMPORT:
            res = credOperator->importCredential(reqJsonStr, returnData);
            break;
        case CRED_OP_DELETE:
            res = credOperator->deleteCredential(reqJsonStr, returnData);
            break;
        default:
            LOGE("invalid opCode: %d", operationCode);
            break;
    }

    return res;
}

DEVICE_AUTH_API_PUBLIC int32_t ProcessAuthDevice(
    int64_t authReqId, const char *authParams, const DeviceAuthCallback *callback)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    LOGI("[DA] Begin ProcessAuthDevice [ReqId]: %" PRId64, authReqId);
    if (authParams == NULL) {
        LOGE("Invalid input for ProcessData!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *json = CreateJsonFromString(authParams);
    if (json == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    const char *data = GetStringFromJson(json, "data");
    if (data == NULL) {
        LOGE("Failed to get received data from parameter!");
        FreeJson(json);
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *receivedMsg = CreateJsonFromString(data);
    FreeJson(json);
    if (receivedMsg == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t res;
    if (!IsSessionExist(authReqId)) {
        res = OpenServerAuthSessionForP2P(authReqId, receivedMsg, callback);
        if (res != HC_SUCCESS) {
            FreeJson(receivedMsg);
            return res;
        }
    }
    res = PushProcSessionTask(authReqId, receivedMsg);
    if (res != HC_SUCCESS) {
        FreeJson(receivedMsg);
        return res;
    }
    return HC_SUCCESS;
}

DEVICE_AUTH_API_PUBLIC int32_t StartAuthDevice(
    int64_t authReqId, const char *authParams, const DeviceAuthCallback *callback)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    LOGI("StartAuthDevice. [ReqId]:%" PRId64, authReqId);

    if ((authParams == NULL) || (callback == NULL)) {
        LOGE("The input auth params is invalid!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *context = CreateJsonFromString(authParams);
    if (context == NULL) {
        LOGE("Failed to create json from string!");
        return HC_ERR_JSON_FAIL;
    }
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId from json!");
        FreeJson(context);
        return HC_ERR_JSON_FAIL;
    }

    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (osAccountId == INVALID_OS_ACCOUNT) {
        FreeJson(context);
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = BuildClientAuthContext(osAccountId, authReqId, DEFAULT_PACKAGE_NAME, context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    res = BuildP2PBindContext(context);
    if (res != HC_SUCCESS) {
        FreeJson(context);
        return res;
    }
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(authReqId, DEFAULT_PACKAGE_NAME, &params);
    FreeJson(context);
    if (res != HC_SUCCESS) {
        LOGE("OpenDevSession fail. [Res]: %d", res);
        return res;
    }
    return PushStartSessionTask(authReqId);
}

DEVICE_AUTH_API_PUBLIC int32_t CancelAuthRequest(int64_t requestId, const char *authParams)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(requestId);
    if (authParams == NULL) {
        LOGE("Invalid authParams!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("cancel request. [ReqId]: %" PRId64, requestId);
    CancelDevSession(requestId, DEFAULT_PACKAGE_NAME);
    return HC_SUCCESS;
}

static int32_t AllocGmAndGa(void)
{
    if (g_groupManagerInstance == NULL) {
        g_groupManagerInstance = (DeviceGroupManager *)HcMalloc(sizeof(DeviceGroupManager), 0);
        if (g_groupManagerInstance == NULL) {
            LOGE("Failed to allocate groupManager Instance memory!");
            return HC_ERR_ALLOC_MEMORY;
        }
    }
    if (g_groupAuthManager == NULL) {
        g_groupAuthManager = (GroupAuthManager *)HcMalloc(sizeof(GroupAuthManager), 0);
        if (g_groupAuthManager == NULL) {
            LOGE("Failed to allocate groupAuth Instance memory!");
            HcFree(g_groupManagerInstance);
            g_groupManagerInstance = NULL;
            return HC_ERR_ALLOC_MEMORY;
        }
    }
    return HC_SUCCESS;
}

static void DestroyGmAndGa(void)
{
    if (g_groupAuthManager != NULL) {
        HcFree(g_groupAuthManager);
        g_groupAuthManager = NULL;
    }
    if (g_groupManagerInstance != NULL) {
        HcFree(g_groupManagerInstance);
        g_groupManagerInstance = NULL;
    }
}

static int32_t InitAllModules(void)
{
    int32_t res = GetLoaderInstance()->initAlg();
    if (res != HC_SUCCESS) {
        LOGE("[End]: [Service]: Failed to init algorithm module!");
        return res;
    }
    res = InitCredMgr();
    if (res != HC_SUCCESS) {
        LOGE("[End]: [Service]: Failed to init cred mgr!");
        return res;
    }
    res = InitModules();
    if (res != HC_SUCCESS) {
        LOGE("[End]: [Service]: Failed to init all authenticator modules!");
        goto CLEAN_CRED;
    }
    res = InitCallbackManager();
    if (res != HC_SUCCESS) {
        LOGE("[End]: [Service]: Failed to init callback manage module!");
        goto CLEAN_MODULE;
    }
    res = InitGroupManager();
    if (res != HC_SUCCESS) {
        goto CLEAN_CALLBACK;
    }
    res = InitDevSessionManager();
    if (res != HC_SUCCESS) {
        goto CLEAN_GROUP_MANAGER;
    }
    res = InitTaskManager();
    if (res != HC_SUCCESS) {
        LOGE("[End]: [Service]: Failed to init worker thread!");
        goto CLEAN_ALL;
    }
    return res;
CLEAN_ALL:
    DestroyDevSessionManager();
CLEAN_GROUP_MANAGER:
    DestroyGroupManager();
CLEAN_CALLBACK:
    DestroyCallbackManager();
CLEAN_MODULE:
    DestroyModules();
CLEAN_CRED:
    DestroyCredMgr();
    return res;
}

static void InitPseudonymModule(void)
{
    PseudonymManager *manager = GetPseudonymInstance();
    if (manager == NULL) {
        LOGE("Pseudonym manager is null!");
        return;
    }
    manager->loadPseudonymData();
}

DEVICE_AUTH_API_PUBLIC int InitDeviceAuthService(void)
{
    LOGI("[Service]: Start to init device auth service!");
    if (CheckInit() == FINISH_INIT) {
        LOGI("[End]: [Service]: Device auth service is running!");
        return HC_SUCCESS;
    }
    int32_t res = AllocGmAndGa();
    if (res != HC_SUCCESS) {
        return res;
    }
    InitOsAccountAdapter();
    res = InitAllModules();
    if (res != HC_SUCCESS) {
        DestroyGmAndGa();
        return res;
    }
    INIT_PERFORMANCE_DUMPER();
    (void)GenerateDeviceKeyPair();
    InitPseudonymModule();
    DEV_AUTH_LOAD_PLUGIN();
    SetInitStatus();
    LOGI("[End]: [Service]: Init device auth service successfully!");
    return HC_SUCCESS;
}

DEVICE_AUTH_API_PUBLIC void DestroyDeviceAuthService(void)
{
    LOGI("[Service]: Start to destroy device auth service!");
    if (CheckDestroy() == FINISH_DESTROY) {
        LOGI("[End]: [Service]: The service has not been initialized!");
        return;
    }
    DestroyTaskManager();
    DestroyDevSessionManager();
    DestroyGroupManager();
    DestroyGmAndGa();
    DEV_AUTH_UNLOAD_PLUGIN();
    DestroyModules();
    DestroyCredMgr();
    DestroyChannelManager();
    DestroyCallbackManager();
    DESTROY_PERFORMANCE_DUMPER();
    DestroyPseudonymManager();
    DestroyOsAccountAdapter();
    SetDeInitStatus();
    LOGI("[End]: [Service]: Destroy device auth service successfully!");
}

DEVICE_AUTH_API_PUBLIC const DeviceGroupManager *GetGmInstance(void)
{
    if (g_groupManagerInstance == NULL) {
        LOGE("Service not init.");
        return NULL;
    }

    g_groupManagerInstance->regCallback = RegGroupManagerCallback;
    g_groupManagerInstance->unRegCallback = UnRegGroupManagerCallback;
    g_groupManagerInstance->regDataChangeListener = RegListenerImpl;
    g_groupManagerInstance->unRegDataChangeListener = UnRegListenerImpl;
    g_groupManagerInstance->createGroup = CreateGroupImpl;
    g_groupManagerInstance->deleteGroup = DeleteGroupImpl;
    g_groupManagerInstance->addMemberToGroup = AddMemberToGroup;
    g_groupManagerInstance->deleteMemberFromGroup = DeleteMemberFromGroupImpl;
    g_groupManagerInstance->addMultiMembersToGroup = AddMultiMembersToGroupImpl;
    g_groupManagerInstance->delMultiMembersFromGroup = DelMultiMembersFromGroupImpl;
    g_groupManagerInstance->processData = ProcessBindData;
    g_groupManagerInstance->getRegisterInfo = GetRegisterInfoImpl;
    g_groupManagerInstance->checkAccessToGroup = CheckAccessToGroupImpl;
    g_groupManagerInstance->getPkInfoList = GetPkInfoListImpl;
    g_groupManagerInstance->getGroupInfoById = GetGroupInfoByIdImpl;
    g_groupManagerInstance->getGroupInfo = GetGroupInfoImpl;
    g_groupManagerInstance->getJoinedGroups = GetJoinedGroupsImpl;
    g_groupManagerInstance->getRelatedGroups = GetRelatedGroupsImpl;
    g_groupManagerInstance->getDeviceInfoById = GetDeviceInfoByIdImpl;
    g_groupManagerInstance->getTrustedDevices = GetTrustedDevicesImpl;
    g_groupManagerInstance->isDeviceInGroup = IsDeviceInGroupImpl;
    g_groupManagerInstance->cancelRequest = CancelRequest;
    g_groupManagerInstance->destroyInfo = DestroyInfoImpl;
    return g_groupManagerInstance;
}

DEVICE_AUTH_API_PUBLIC const GroupAuthManager *GetGaInstance(void)
{
    if (g_groupAuthManager == NULL) {
        LOGE("Service not init.");
        return NULL;
    }

    g_groupAuthManager->processData = ProcessData;
    g_groupAuthManager->authDevice = AuthDevice;
    g_groupAuthManager->cancelRequest = CancelRequest;
    g_groupAuthManager->getRealInfo = GetRealInfo;
    g_groupAuthManager->getPseudonymId = GetPseudonymId;
    return g_groupAuthManager;
}
