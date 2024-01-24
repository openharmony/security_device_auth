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

#include "ipc_service.h"

#include "common_defs.h"
#include "device_auth_defines.h"
#include "device_auth.h"
#include "hc_condition.h"
#include "hc_log.h"
#include "hc_thread.h"
#include "ipc_adapt.h"
#include "ipc_sdk.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

static const int32_t IPC_RESULT_NUM_1 = 1;
static const int32_t IPC_RESULT_NUM_2 = 2;
static const char *g_serviceAppId = "deviceauth_service";
static DeviceGroupManager g_devGroupMgrMethod = {NULL};
static GroupAuthManager g_groupAuthMgrMethod = {NULL};
static DeviceAuthCallback g_bindCbAdt = {NULL};
static DeviceAuthCallback g_authCbAdt = {NULL};
static DataChangeListener g_listenCbAdt = {NULL};

static int32_t BindRequestIdWithAppId(const char *data)
{
    const char *appId = NULL;
    int32_t ret;
    int64_t requestId = -1;
    CJson *dataJson = CreateJsonFromString(data);
    if (dataJson == NULL) {
        LOGE("failed to create json from string!");
        return HC_ERROR;
    }

    appId = GetStringFromJson(dataJson, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("failed to get appId from json object!");
        FreeJson(dataJson);
        return HC_ERROR;
    }
    (void)GetInt64FromJson(dataJson, FIELD_REQUEST_ID, &requestId);
    ret = AddReqIdByAppId(appId, requestId);
    FreeJson(dataJson);
    return ret;
}

static int32_t IpcServiceGmRegCallback(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const char *appId = NULL;
    const DeviceAuthCallback *callback = NULL;
    int32_t cbObjIdx = -1;
    int32_t inOutLen;

    LOGI("starting ...");
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&callback, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(DeviceAuthCallback))) {
        LOGE("get param error, type %d", PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddIpcCallBackByAppId(appId, (const uint8_t *)callback, sizeof(DeviceAuthCallback), CB_TYPE_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        LOGE("add ipc callback failed");
        return HC_ERROR;
    }

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByAppId(appId, cbObjIdx, CB_TYPE_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_bindCbAdt, CB_TYPE_DEV_AUTH);
    callRet = g_devGroupMgrMethod.regCallback(appId, &g_bindCbAdt);
    if (callRet != HC_SUCCESS) {
        DelIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
    }
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmUnRegCallback(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet = HC_SUCCESS;
    int32_t ret;
    const char *appId = NULL;

    LOGI("starting ...");
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    DelIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmRegDataChangeListener(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const char *appId = NULL;
    const DataChangeListener *callback = NULL;
    static int32_t registered = 0;
    int32_t cbObjIdx = -1;
    int32_t inOutLen;

    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    inOutLen = sizeof(DataChangeListener);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_LISTERNER, (uint8_t *)&callback, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(DataChangeListener))) {
        LOGE("get param error, type %d", PARAM_TYPE_LISTERNER);
        return HC_ERR_IPC_BAD_PARAM;
    }

    ret = AddIpcCallBackByAppId(appId, (const uint8_t *)callback, sizeof(DataChangeListener), CB_TYPE_LISTENER);
    if (ret != HC_SUCCESS) {
        LOGE("add ipc callback failed");
        return HC_ERROR;
    }

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByAppId(appId, cbObjIdx, CB_TYPE_LISTENER);

    callRet = HC_SUCCESS;
    if (registered == 0) {
        InitDevAuthListenerCbCtx(&g_listenCbAdt);
        callRet = g_devGroupMgrMethod.regDataChangeListener(g_serviceAppId, &g_listenCbAdt);
        if (callRet == HC_SUCCESS) {
            registered = 1;
        } else {
            DelIpcCallBackByAppId(appId, CB_TYPE_LISTENER);
        }
    }
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmUnRegDataChangeListener(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet = HC_SUCCESS;
    int32_t ret;
    const char *appId = NULL;

    LOGI("starting ...");
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    DelIpcCallBackByAppId(appId, CB_TYPE_LISTENER);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmCreateGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t osAccountId;
    int64_t requestId = 0;
    int32_t inOutLen;
    const char *createParams = NULL;
    const char *appId = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(int64_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CREATE_PARAMS, (uint8_t *)&createParams, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CREATE_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddReqIdByAppId(appId, requestId);
    if (ret != 0) {
        LOGE("bind request id by app id failed");
        return ret;
    }
    callRet = g_devGroupMgrMethod.createGroup(osAccountId, requestId, appId, createParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmDelGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t osAccountId;
    int64_t requestId = 0;
    int32_t inOutLen;
    const char *appId = NULL;
    const char *delParams = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(int64_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEL_PARAMS, (uint8_t *)&delParams, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_DEL_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddReqIdByAppId(appId, requestId);
    if (ret != 0) {
        LOGE("bind request id by app id failed");
        return ret;
    }
    callRet = g_devGroupMgrMethod.deleteGroup(osAccountId, requestId, appId, delParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmAddMemberToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    int64_t requestId = 0;
    const char *addParams = NULL;
    const char *appId = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(int64_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_ADD_PARAMS, (uint8_t *)&addParams, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_ADD_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddReqIdByAppId(appId, requestId);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    callRet = g_devGroupMgrMethod.addMemberToGroup(osAccountId, requestId, appId, addParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmDelMemberFromGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    int64_t requestId = 0;
    const char *delParams = NULL;
    const char *appId = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(int64_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEL_PARAMS, (uint8_t *)&delParams, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_DEL_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddReqIdByAppId(appId, requestId);
    if (ret != 0) {
        LOGE("bind request id by app id failed");
        return ret;
    }
    callRet = g_devGroupMgrMethod.deleteMemberFromGroup(osAccountId, requestId, appId, delParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmAddMultiMembersToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *addParams = NULL;
    const char *appId = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_ADD_PARAMS, (uint8_t *)&addParams, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_ADD_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    callRet = g_devGroupMgrMethod.addMultiMembersToGroup(osAccountId, appId, addParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmDelMultiMembersFromGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *delParams = NULL;
    const char *appId = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return ret;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEL_PARAMS, (uint8_t *)&delParams, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_DEL_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    callRet = g_devGroupMgrMethod.delMultiMembersFromGroup(osAccountId, appId, delParams);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t dataLen;
    int32_t inOutLen;
    int64_t requestId = 0;
    const uint8_t *data = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(int64_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    dataLen = 0;
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_COMM_DATA, (uint8_t *)&data, &dataLen);
    if ((dataLen <= 0) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d, data length %d", PARAM_TYPE_COMM_DATA, dataLen);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = BindRequestIdWithAppId((const char *)data);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    callRet = g_devGroupMgrMethod.processData(requestId, data, dataLen);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmApplyRegisterInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const char *reqJsonStr = NULL;
    char *registerInfo = NULL;

    LOGI("starting ...");
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQ_JSON, (uint8_t *)&reqJsonStr, NULL);
    if ((reqJsonStr == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQ_JSON);
        return HC_ERR_IPC_BAD_PARAM;
    }
    callRet = g_devGroupMgrMethod.getRegisterInfo(reqJsonStr, &registerInfo);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
                              (const uint8_t *)&IPC_RESULT_NUM_1, sizeof(int32_t));
    if (registerInfo != NULL) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_REG_INFO,
            (const uint8_t *)registerInfo, strlen(registerInfo) + 1);
        g_devGroupMgrMethod.destroyInfo(&registerInfo);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_REG_INFO, NULL, 0);
    }
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmCheckAccessToGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = NULL;
    const char *groupId = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, NULL);
    if ((groupId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_GROUPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.checkAccessToGroup(osAccountId, appId, groupId);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmGetPkInfoList(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = NULL;
    const char *queryParams = NULL;
    char *returnInfoList = NULL;
    uint32_t returnInfoNum = 0;

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_QUERY_PARAMS, (uint8_t *)&queryParams, NULL);
    if ((queryParams == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_QUERY_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.getPkInfoList(osAccountId, appId, queryParams, &returnInfoList, &returnInfoNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
                              (const uint8_t *)&IPC_RESULT_NUM_2, sizeof(int32_t));
    if (returnInfoList != NULL) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, (const uint8_t *)returnInfoList,
                                  strlen(returnInfoList) + 1);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, NULL, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&returnInfoNum, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    g_devGroupMgrMethod.destroyInfo(&returnInfoList);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetGroupInfoById(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = NULL;
    const char *groupId = NULL;
    char *groupInfo = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, NULL);
    if ((groupId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_GROUPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.getGroupInfoById(osAccountId, appId, groupId, &groupInfo);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
                              (const uint8_t *)&IPC_RESULT_NUM_1, sizeof(int32_t));
    if (groupInfo != NULL) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, (const uint8_t *)groupInfo, strlen(groupInfo) + 1);
        g_devGroupMgrMethod.destroyInfo(&groupInfo);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, NULL, 0);
    }
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetGroupInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = NULL;
    const char *queryParams = NULL;
    char *outGroups = NULL;
    uint32_t groupNum = 0;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_QUERY_PARAMS, (uint8_t *)&queryParams, NULL);
    if ((queryParams == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_QUERY_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.getGroupInfo(osAccountId, appId, queryParams, &outGroups, &groupNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
                              (const uint8_t *)&IPC_RESULT_NUM_2, sizeof(int32_t));
    if (outGroups != NULL) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, (const uint8_t *)outGroups, strlen(outGroups) + 1);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, NULL, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&groupNum, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    g_devGroupMgrMethod.destroyInfo(&outGroups);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetJoinedGroups(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t groupType = 0;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = NULL;
    char *outGroups = NULL;
    uint32_t groupNum = 0;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(groupType);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_GROUP_TYPE, (uint8_t *)&groupType, &inOutLen);
    if ((inOutLen != sizeof(groupType)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_GROUP_TYPE);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.getJoinedGroups(osAccountId, appId, groupType, &outGroups, &groupNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
                              (const uint8_t *)&IPC_RESULT_NUM_2, sizeof(int32_t));
    if (outGroups != NULL) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, (const uint8_t *)outGroups, strlen(outGroups) + 1);
        g_devGroupMgrMethod.destroyInfo(&outGroups);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, NULL, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&groupNum, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetRelatedGroups(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = NULL;
    const char *peerUdid = NULL;
    char *outGroups = NULL;
    uint32_t groupNum = 0;

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_UDID, (uint8_t *)&peerUdid, NULL);
    if ((peerUdid == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_UDID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.getRelatedGroups(osAccountId, appId, peerUdid, &outGroups, &groupNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
                              (const uint8_t *)&IPC_RESULT_NUM_2, sizeof(int32_t));
    if (outGroups != NULL) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, (const uint8_t *)outGroups, strlen(outGroups) + 1);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_GROUP_INFO, NULL, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&groupNum, sizeof(int32_t));
    g_devGroupMgrMethod.destroyInfo(&outGroups);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetDeviceInfoById(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = NULL;
    const char *peerUdid = NULL;
    const char *groupId = NULL;
    char *outDevInfo = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_UDID, (uint8_t *)&peerUdid, NULL);
    if ((peerUdid == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_UDID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, NULL);
    if ((groupId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_GROUPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.getDeviceInfoById(osAccountId, appId, peerUdid, groupId, &outDevInfo);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
                              (const uint8_t *)&IPC_RESULT_NUM_1, sizeof(int32_t));
    if (outDevInfo != NULL) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DEVICE_INFO,
            (const uint8_t *)outDevInfo, strlen(outDevInfo) + 1);
        g_devGroupMgrMethod.destroyInfo(&outDevInfo);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DEVICE_INFO, NULL, 0);
    }
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmGetTrustedDevices(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    const char *appId = NULL;
    const char *groupId = NULL;
    char *outDevInfo = NULL;
    uint32_t outDevNum = 0;

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, NULL);
    if ((groupId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_GROUPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    callRet = g_devGroupMgrMethod.getTrustedDevices(osAccountId, appId, groupId, &outDevInfo, &outDevNum);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT_NUM,
                              (const uint8_t *)&IPC_RESULT_NUM_2, sizeof(int32_t));
    if (outDevInfo != NULL) {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DEVICE_INFO,
            (const uint8_t *)outDevInfo, strlen(outDevInfo) + 1);
    } else {
        ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DEVICE_INFO, NULL, 0);
    }
    ret += IpcEncodeCallReply(outCache, PARAM_TYPE_DATA_NUM, (const uint8_t *)&outDevNum, sizeof(int32_t));
    g_devGroupMgrMethod.destroyInfo(&outDevInfo);
    return (ret == HC_SUCCESS) ? ret : HC_ERROR;
}

static int32_t IpcServiceGmIsDeviceInGroup(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    int32_t inOutLen;
    int32_t osAccountId;
    bool bRet = false;
    const char *appId = NULL;
    const char *udid = NULL;
    const char *groupId = NULL;

    LOGI("starting ...");
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_UDID, (uint8_t *)&udid, NULL);
    if ((udid == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_UDID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_GROUPID, (uint8_t *)&groupId, NULL);
    if ((groupId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_GROUPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    bRet = g_devGroupMgrMethod.isDeviceInGroup(osAccountId, appId, groupId, udid);
    callRet = ((bRet == true) ? HC_SUCCESS : HC_ERROR);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceGmCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int64_t requestId = 0;
    const char *appId = NULL;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(requestId)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    g_devGroupMgrMethod.cancelRequest(requestId, appId);
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceGaProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const DeviceAuthCallback *gaCallback = NULL;
    int64_t reqId = 0;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t inOutLen;
    int32_t cbObjIdx = -1;

    LOGI("starting ...");
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&reqId, &inOutLen);
    if ((inOutLen != sizeof(int64_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_COMM_DATA, (uint8_t *)&data, (int32_t *)&dataLen);
    if ((data == NULL) || (dataLen == 0) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_COMM_DATA);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&gaCallback, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(DeviceAuthCallback))) {
        LOGE("get param error, type %d", PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BAD_PARAM;
    }
    /* add call back */
    ret = AddIpcCallBackByReqId(reqId, (const uint8_t *)gaCallback, sizeof(DeviceAuthCallback), CB_TYPE_TMP_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        LOGE("add ipc callback failed");
        return ret;
    }
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByReqId(reqId, CB_TYPE_TMP_DEV_AUTH, true);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByReqId(reqId, cbObjIdx, CB_TYPE_TMP_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_authCbAdt, CB_TYPE_TMP_DEV_AUTH);
    callRet = g_groupAuthMgrMethod.processData(reqId, data, dataLen, &g_authCbAdt);
    if (callRet != HC_SUCCESS) {
        DelIpcCallBackByReqId(reqId, CB_TYPE_TMP_DEV_AUTH, true);
    }
    return IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
}

static int32_t IpcServiceGaAuthDevice(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    DeviceAuthCallback *gaCallback = NULL;
    int32_t osAccountId;
    int64_t reqId = 0;
    const char *authParams = NULL;
    int32_t inOutLen;
    int32_t cbObjIdx = -1;

    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&reqId, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(int64_t))) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_AUTH_PARAMS, (uint8_t *)&authParams, NULL);
    if ((ret != HC_SUCCESS) || (authParams == NULL)) {
        LOGE("get param error, type %d", PARAM_TYPE_AUTH_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&gaCallback, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(DeviceAuthCallback))) {
        LOGE("get param error, type %d", PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BAD_PARAM;
    }

    /* add call back */
    ret = AddIpcCallBackByReqId(reqId, (const uint8_t *)gaCallback, sizeof(DeviceAuthCallback), CB_TYPE_TMP_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByReqId(reqId, CB_TYPE_TMP_DEV_AUTH, true);
        return ret;
    }
    AddIpcCbObjByReqId(reqId, cbObjIdx, CB_TYPE_TMP_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_authCbAdt, CB_TYPE_TMP_DEV_AUTH);
    ret = g_groupAuthMgrMethod.authDevice(osAccountId, reqId, authParams, &g_authCbAdt);
    if (ret != HC_SUCCESS) {
        DelIpcCallBackByReqId(reqId, CB_TYPE_TMP_DEV_AUTH, true);
    }
    return IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&ret, sizeof(int32_t));
}

static int32_t IpcServiceGaCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int64_t requestId = 0;
    const char *appId = NULL;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(requestId)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_APPID, (uint8_t *)&appId, NULL);
    if ((appId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_APPID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    g_groupAuthMgrMethod.cancelRequest(requestId, appId);
    DelIpcCallBackByReqId(requestId, CB_TYPE_TMP_DEV_AUTH, true);
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceGaGetRealInfo(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int32_t osAccountId;
    const char *pseudonymId = NULL;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_PSEUDONYM_ID, (uint8_t *)&pseudonymId, NULL);
    if ((pseudonymId == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_PSEUDONYM_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }

    char *realInfo = NULL;
    ret = g_groupAuthMgrMethod.getRealInfo(osAccountId, pseudonymId, &realInfo);
    if ((realInfo != NULL) && (ret == HC_SUCCESS)) {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, (const uint8_t *)realInfo,
            strlen(realInfo) + 1);
        HcFree(realInfo);
    } else {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, NULL, 0);
    }
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceGaGetPseudonymId(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int32_t osAccountId;
    const char *indexKey = NULL;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OS_ACCOUNT_ID, (uint8_t *)&osAccountId, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_INDEX_KEY, (uint8_t *)&indexKey, NULL);
    if ((indexKey == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_INDEX_KEY);
        return HC_ERR_IPC_BAD_PARAM;
    }

    char *pseudonymId = NULL;
    ret = g_groupAuthMgrMethod.getPseudonymId(osAccountId, indexKey, &pseudonymId);
    if ((pseudonymId != NULL) && (ret == HC_SUCCESS)) {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, (const uint8_t *)pseudonymId,
            strlen(pseudonymId) + 1);
        HcFree(pseudonymId);
    } else {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, NULL, 0);
    }
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceDaProcessCredential(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int32_t operationCode = 0;
    const char *reqJsonStr = NULL;
    char *returnData = NULL;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_OPCODE, (uint8_t *)&operationCode, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_OPCODE);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQ_JSON, (uint8_t *)&reqJsonStr, NULL);
    if ((reqJsonStr == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQ_JSON);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = ProcessCredential(operationCode, reqJsonStr, &returnData);
    if (ret != HC_SUCCESS) {
        LOGI("call ProcessCredential failed %d", ret);
    }
    if (returnData != NULL) {
        ret = IpcEncodeCallReply(
            outCache, PARAM_TYPE_RETURN_DATA, (const uint8_t *)returnData, strlen(returnData) + 1);
        HcFree(returnData);
    } else {
        ret = IpcEncodeCallReply(outCache, PARAM_TYPE_RETURN_DATA, NULL, 0);
    }
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

static int32_t IpcServiceDaProcessData(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    const DeviceAuthCallback *callback = NULL;
    int64_t authReqId = 0;
    const char *authParams = NULL;
    int32_t inOutLen;
    int32_t cbObjIdx = -1;

    LOGI("starting ...");
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&authReqId, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(authReqId))) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_AUTH_PARAMS, (uint8_t *)&authParams, NULL);
    if ((ret != HC_SUCCESS) || (authParams == NULL)) {
        LOGE("get param error, type %d", PARAM_TYPE_AUTH_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&callback, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(DeviceAuthCallback))) {
        LOGE("get param error, type %d", PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddIpcCallBackByReqId(
        authReqId, (const uint8_t *)callback, sizeof(DeviceAuthCallback), CB_TYPE_TMP_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByReqId(authReqId, CB_TYPE_TMP_DEV_AUTH, true);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByReqId(authReqId, cbObjIdx, CB_TYPE_TMP_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_authCbAdt, CB_TYPE_TMP_DEV_AUTH);
    callRet = ProcessAuthDevice(authReqId, authParams, &g_authCbAdt);
    if (callRet != HC_SUCCESS) {
        DelIpcCallBackByReqId(authReqId, CB_TYPE_TMP_DEV_AUTH, true);
    }
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceDaAuthDevice(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t callRet;
    int32_t ret;
    DeviceAuthCallback *callback = NULL;
    int64_t authReqId = 0;
    const char *authParams = NULL;
    int32_t inOutLen;
    int32_t cbObjIdx = -1;

    LOGI("starting ...");
    inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&authReqId, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(int64_t))) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_AUTH_PARAMS, (uint8_t *)&authParams, NULL);
    if ((ret != HC_SUCCESS) || (authParams == NULL)) {
        LOGE("get param error, type %d", PARAM_TYPE_AUTH_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    inOutLen = sizeof(DeviceAuthCallback);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_DEV_AUTH_CB, (uint8_t *)&callback, &inOutLen);
    if ((ret != HC_SUCCESS) || (inOutLen != sizeof(DeviceAuthCallback))) {
        LOGE("get param error, type %d", PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = AddIpcCallBackByReqId(
        authReqId, (const uint8_t *)callback, sizeof(DeviceAuthCallback), CB_TYPE_TMP_DEV_AUTH);
    if (ret != HC_SUCCESS) {
        LOGE("add ipc callback failed");
        return ret;
    }
    inOutLen = sizeof(int32_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_CB_OBJECT, (uint8_t *)&cbObjIdx, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("get param error, type %d", PARAM_TYPE_CB_OBJECT);
        DelIpcCallBackByReqId(authReqId, CB_TYPE_TMP_DEV_AUTH, true);
        return HC_ERR_IPC_BAD_PARAM;
    }
    AddIpcCbObjByReqId(authReqId, cbObjIdx, CB_TYPE_TMP_DEV_AUTH);
    InitDeviceAuthCbCtx(&g_authCbAdt, CB_TYPE_TMP_DEV_AUTH);
    callRet = StartAuthDevice(authReqId, authParams, &g_authCbAdt);
    if (callRet != HC_SUCCESS) {
        DelIpcCallBackByReqId(authReqId, CB_TYPE_TMP_DEV_AUTH, true);
    }
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&callRet, sizeof(int32_t));
    LOGI("process done, call ret %d, ipc ret %d", callRet, ret);
    return ret;
}

static int32_t IpcServiceDaCancelRequest(const IpcDataInfo *ipcParams, int32_t paramNum, uintptr_t outCache)
{
    int32_t ret;
    int64_t requestId = 0;
    const char *authParams = NULL;

    LOGI("starting ...");
    int32_t inOutLen = sizeof(int64_t);
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_REQID, (uint8_t *)&requestId, &inOutLen);
    if ((inOutLen != sizeof(requestId)) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_REQID);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = GetIpcRequestParamByType(ipcParams, paramNum, PARAM_TYPE_AUTH_PARAMS, (uint8_t *)&authParams, NULL);
    if ((authParams == NULL) || (ret != HC_SUCCESS)) {
        LOGE("get param error, type %d", PARAM_TYPE_AUTH_PARAMS);
        return HC_ERR_IPC_BAD_PARAM;
    }
    ret = CancelAuthRequest(requestId, authParams);
    DelIpcCallBackByReqId(requestId, CB_TYPE_TMP_DEV_AUTH, true);
    ret = IpcEncodeCallReply(outCache, PARAM_TYPE_IPC_RESULT, (const uint8_t *)&ret, sizeof(int32_t));
    LOGI("process done, ipc ret %d", ret);
    return ret;
}

#ifndef DEV_AUTH_FUZZ_TEST
static void DeMainRescInit(void)
{
    if (g_devGroupMgrMethod.unRegDataChangeListener != NULL) {
        (void)g_devGroupMgrMethod.unRegDataChangeListener(g_serviceAppId);
    }
    DeInitIpcCallBackList();
}
#endif

int32_t AddMethodMap(uintptr_t ipcInstance)
{
    uint32_t ret;

    // Group Manager Interfaces
    ret = SetIpcCallMap(ipcInstance, IpcServiceGmRegCallback, IPC_CALL_ID_REG_CB);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmUnRegCallback, IPC_CALL_ID_UNREG_CB);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmRegDataChangeListener, IPC_CALL_ID_REG_LISTENER);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmUnRegDataChangeListener, IPC_CALL_ID_UNREG_LISTENER);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmCreateGroup, IPC_CALL_ID_CREATE_GROUP);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmDelGroup, IPC_CALL_ID_DEL_GROUP);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmAddMemberToGroup, IPC_CALL_ID_ADD_GROUP_MEMBER);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmDelMemberFromGroup, IPC_CALL_ID_DEL_GROUP_MEMBER);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmAddMultiMembersToGroup, IPC_CALL_ID_ADD_MULTI_GROUP_MEMBERS);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmDelMultiMembersFromGroup, IPC_CALL_ID_DEL_MULTI_GROUP_MEMBERS);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmProcessData, IPC_CALL_ID_GM_PROC_DATA);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmApplyRegisterInfo, IPC_CALL_ID_APPLY_REG_INFO);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmCheckAccessToGroup, IPC_CALL_ID_CHECK_ACCESS_TO_GROUP);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmGetPkInfoList, IPC_CALL_ID_GET_PK_INFO_LIST);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmGetGroupInfoById, IPC_CALL_ID_GET_GROUP_INFO);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmGetGroupInfo, IPC_CALL_ID_SEARCH_GROUPS);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmGetJoinedGroups, IPC_CALL_ID_GET_JOINED_GROUPS);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmGetRelatedGroups, IPC_CALL_ID_GET_RELATED_GROUPS);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmGetDeviceInfoById, IPC_CALL_ID_GET_DEV_INFO_BY_ID);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmGetTrustedDevices, IPC_CALL_ID_GET_TRUST_DEVICES);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmIsDeviceInGroup, IPC_CALL_ID_IS_DEV_IN_GROUP);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGmCancelRequest, IPC_CALL_GM_CANCEL_REQUEST);

    // Group Auth Interfaces
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGaProcessData, IPC_CALL_ID_GA_PROC_DATA);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGaAuthDevice, IPC_CALL_ID_AUTH_DEVICE);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGaCancelRequest, IPC_CALL_GA_CANCEL_REQUEST);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGaGetRealInfo, IPC_CALL_ID_GET_REAL_INFO);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceGaGetPseudonymId, IPC_CALL_ID_GET_PSEUDONYM_ID);

    // Direct Auth Interfaces
    ret &= SetIpcCallMap(ipcInstance, IpcServiceDaProcessCredential, IPC_CALL_ID_PROCESS_CREDENTIAL);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceDaAuthDevice, IPC_CALL_ID_DA_AUTH_DEVICE);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceDaProcessData, IPC_CALL_ID_DA_PROC_DATA);
    ret &= SetIpcCallMap(ipcInstance, IpcServiceDaCancelRequest, IPC_CALL_ID_DA_CANCEL_REQUEST);
    LOGI("process done, ret %u", ret);
    return ret;
}

int32_t MainRescInit(void)
{
    int32_t ret;
    const DeviceGroupManager *gmInst = NULL;
    const GroupAuthManager *gaInst = NULL;

    LOGI("starting ...");
    ret = InitIpcCallBackList();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    gmInst = GetGmInstance();
    gaInst = GetGaInstance();
    if ((gmInst == NULL) || (gaInst == NULL)) {
        DeInitIpcCallBackList();
        LOGE("MainInit, GetGmInstance failed");
        return HC_ERROR;
    }
    g_devGroupMgrMethod = (DeviceGroupManager)(*gmInst);
    g_groupAuthMgrMethod = (GroupAuthManager)(*gaInst);
    InitDevAuthListenerCbCtx(&g_listenCbAdt);
    ret = gmInst->regDataChangeListener(g_serviceAppId, &g_listenCbAdt);
    if (ret != HC_SUCCESS) {
        DeInitIpcCallBackList();
        LOGE("MainInit, register ipc listener failed, ret %d", ret);
        return HC_ERROR;
    }

    LOGI("process done");
    return HC_SUCCESS;
}

#ifndef DEV_AUTH_FUZZ_TEST
int32_t main(int32_t argc, char const *argv[])
{
    int32_t ret;
    HcCondition cond;

    (void)argc;
    (void)argv;
    LOGI("device authentication service starting ...");
    ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        LOGE("device auth service main, InitDeviceAuthService failed, ret %d", ret);
        return 1;
    }

    ret = MainRescInit();
    if (ret != HC_SUCCESS) {
        DestroyDeviceAuthService();
        LOGE("device auth service main, init work failed");
        return 1;
    }

    ret = AddDevAuthServiceToManager();
    if (ret != HC_SUCCESS) {
        DeMainRescInit();
        DestroyDeviceAuthService();
        LOGE("device auth service main, AddDevAuthServiceToManager failed, ret %d", ret);
        return 1;
    }
    LOGI("device authentication service register to IPC manager done, service running...");
    (void)memset_s(&cond, sizeof(cond), 0, sizeof(cond));
    InitHcCond(&cond, NULL);
    cond.wait(&cond);
    DestroyHcCond(&cond);
    return 0;
}
#endif

#ifdef __cplusplus
}
#endif
