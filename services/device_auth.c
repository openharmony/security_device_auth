/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "alg_loader.h"
#include "callback_manager.h"
#include "channel_manager.h"
#include "common_defs.h"
#include "cred_manager.h"
#include "data_manager.h"
#include "dev_auth_module_manager.h"
#include "dev_session_mgr.h"
#include "group_auth_manager.h"
#include "group_manager.h"
#include "group_operation_common.h"
#include "hc_dev_info.h"
#include "hc_init_protection.h"
#include "hc_log.h"
#include "hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "json_utils.h"
#include "os_account_adapter.h"
#include "plugin_adapter.h"
#include "session_manager.h"
#include "task_manager.h"

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
    bool isFinish;
    int32_t res = ProcessDevSession(realTask->sessionId, realTask->receivedMsg, &isFinish);
    if (res != HC_SUCCESS) {
        LOGE("ProcessDevSession fail. [Res]: %d", res);
        CloseDevSession(realTask->sessionId);
        return;
    }
    LOGE("ProcessDevSession success. [State]: %s", isFinish ? "FINISH" : "CONTINUE");
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

static int32_t AddMemberToGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *addParams)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(requestId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((appId == NULL) || (addParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT)) {
        LOGE("Invalid input parameters!");
        return HC_ERR_INVALID_PARAMS;
    }
    LOGI("[Start]: AddMemberToGroup! [AppId]: %s, [RequestId]: %" PRId64, appId, requestId);
    DEV_AUTH_REPORT_CALL_EVENT(ADD_MEMBER_EVENT, osAccountId, requestId, appId);
    const DeviceAuthCallback *callback = GetGMCallbackByAppId(appId);
    if (callback == NULL) {
        LOGE("Failed to find callback by appId! [AppId]: %s", appId);
        return HC_ERR_CALLBACK_NOT_FOUND;
    }
    return StartClientBindSession(osAccountId, requestId, appId, addParams, callback);
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
    (void)GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (osAccountId == INVALID_OS_ACCOUNT) {
        return HC_ERR_INVALID_PARAMS;
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

static int32_t OpenServerBindSession(int64_t requestId, const CJson *receivedMsg)
{
    const char *appId = GetStringFromJson(receivedMsg, FIELD_APP_ID);
    if (appId == NULL) {
        appId = DM_APP_ID;
        LOGW("use default device manager appId.");
    }
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
    LOGE("onRequest Data: %s", returnDataStr);
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
    SessionInitParams params = { context, *callback };
    res = OpenDevSession(requestId, appId, &params);
    FreeJson(context);
    return res;
}

static int32_t ProcessBindData(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(requestId);
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
    const char *peerUdid = GetStringFromJson(context, FIELD_PEER_CONN_DEVICE_ID);
    if (peerUdid != NULL) {
        if (AddStringToJson(context, FIELD_PEER_UDID, peerUdid) != HC_SUCCESS) {
            LOGE("add peerUdid to context fail.");
            return HC_ERR_JSON_ADD;
        }
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

static int32_t AuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    LOGI("Begin AuthDevice. [requestId]:%" PRId64, authReqId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if ((authParams == NULL) || (osAccountId == INVALID_OS_ACCOUNT) || (gaCallback == NULL)) {
        LOGE("The input auth params is invalid!");
        return HC_ERR_INVALID_PARAMS;
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

static int32_t BuildServerAuthContext(int64_t requestId, int32_t opCode, const char *appId, CJson *context)
{
    int32_t osAccountId = ANY_OS_ACCOUNT;
    (void)GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId);
    osAccountId = DevAuthGetRealOsAccountLocalId(osAccountId);
    if (osAccountId == INVALID_OS_ACCOUNT) {
        return HC_ERR_INVALID_PARAMS;
    }
    const char *peerUdid = GetStringFromJson(context, FIELD_PEER_CONN_DEVICE_ID);
    if (peerUdid == NULL) {
        LOGE("get peerUdid from json fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_PEER_UDID, peerUdid) != HC_SUCCESS) {
        LOGE("add peerUdid to context fail.");
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
    LOGE("onRequest Data: %s", returnDataStr);
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

static int32_t ProcessData(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *gaCallback)
{
    SET_LOG_MODE(TRACE_MODE);
    SET_TRACE_ID(authReqId);
    LOGI("[GA] Begin ProcessData. [requestId]: %" PRId64, authReqId);
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
    LOGI("cancel request. [ReqId]: %" PRId64 ", [AppId]: %s", requestId, appId);
    CancelDevSession(requestId, appId);
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
    InitSessionManager();
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
    DestroySessionManager();
    DestroyGroupManager();
CLEAN_CALLBACK:
    DestroyCallbackManager();
CLEAN_MODULE:
    DestroyModules();
CLEAN_CRED:
    DestroyCredMgr();
    return res;
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
    res = InitAllModules();
    if (res != HC_SUCCESS) {
        DestroyGmAndGa();
        return res;
    }
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
    DestroyGroupManager();
    DestroySessionManager();
    DestroyGmAndGa();
    DEV_AUTH_UNLOAD_PLUGIN();
    DestroyModules();
    DestroyCredMgr();
    DestroyChannelManager();
    DestroyCallbackManager();
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
    return g_groupAuthManager;
}
