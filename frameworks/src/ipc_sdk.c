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

#include "ipc_sdk.h"

#include "common_defs.h"
#include "device_auth_defines.h"
#include "device_auth.h"
#include "hc_log.h"
#include "hc_mutex.h"

#include "ipc_adapt.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPC_DATA_CACHES_1 1
#define IPC_DATA_CACHES_3 3
#define IPC_DATA_CACHES_4 4
#define REPLAY_CACHE_NUM(caches) (sizeof(caches) / sizeof(IpcDataInfo))
#define IPC_APPID_LEN 128

#define IS_COMM_DATA_VALID(dPtr, dLen) (((dPtr) != NULL) && ((dLen) > 0) && ((dLen) <= 4096))

static const int32_t IPC_RESULT_NUM_1 = 1;
static const int32_t IPC_RESULT_NUM_2 = 2;

typedef struct {
    uintptr_t inst;
    char appId[IPC_APPID_LEN];
} IpcProxyCbInfo;
static IpcProxyCbInfo g_ipcProxyCbList = { 0 };
static IpcProxyCbInfo g_ipcListenerCbList = { 0 };
static HcMutex g_ipcMutex;

static bool IsStrInvalid(const char *str)
{
    return (str == NULL || str[0] == 0);
}

static void DelIpcCliCallbackCtx(const char *appId, IpcProxyCbInfo *cbCache)
{
    int32_t ret;

    if (cbCache->appId[0] == 0) {
        return;
    }
    g_ipcMutex.lock(&g_ipcMutex);
    ret = memcmp(appId, cbCache->appId, strlen(cbCache->appId) + 1);
    if (ret == 0) {
        cbCache->appId[0] = 0;
    }
    g_ipcMutex.unlock(&g_ipcMutex);
    return;
}

static void AddIpcCliCallbackCtx(const char *appId, uintptr_t cbInst, IpcProxyCbInfo *cbCache)
{
    errno_t eno;

    g_ipcMutex.lock(&g_ipcMutex);
    eno = memcpy_s(cbCache->appId, IPC_APPID_LEN, appId, strlen(appId) + 1);
    if (eno != EOK) {
        g_ipcMutex.unlock(&g_ipcMutex);
        LOGE("memory copy failed");
        return;
    }
    cbCache->inst = cbInst;
    g_ipcMutex.unlock(&g_ipcMutex);
}

static void GetIpcReplyByType(const IpcDataInfo *ipcData,
    int32_t dataNum, int32_t type, uint8_t *outCache, int32_t *cacheLen)
{
    int32_t i;
    errno_t eno;

    for (i = 0; i < dataNum; i++) {
        if (ipcData[i].type != type) {
            continue;
        }
        switch (type) {
            case PARAM_TYPE_REG_INFO:
            case PARAM_TYPE_DEVICE_INFO:
            case PARAM_TYPE_GROUP_INFO:
            case PARAM_TYPE_RETURN_DATA:
                *(uint8_t **)outCache = ipcData[i].val;
                break;
            case PARAM_TYPE_IPC_RESULT:
            case PARAM_TYPE_IPC_RESULT_NUM:
            case PARAM_TYPE_COMM_DATA:
            case PARAM_TYPE_DATA_NUM:
                eno = memcpy_s(outCache, *cacheLen, ipcData[i].val, ipcData[i].valSz);
                if (eno != EOK) {
                    break;
                }
                *cacheLen = ipcData[i].valSz;
                break;
            default:
                LOGE("un-expectation type case");
                break;
        }
    }
    return;
}

static int32_t IpcGmRegCallback(const char *appId, const DeviceAuthCallback *callback)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;

    LOGI("starting ...");
    if (IsStrInvalid(appId) || callback == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }

    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEV_AUTH_CB, (const uint8_t *)callback, sizeof(*callback));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_DEV_AUTH_CB);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_BIND_ID);
    ret = DoBinderCall(callCtx, IPC_CALL_ID_REG_CB, true);
    if (ret == HC_SUCCESS) {
        AddIpcCliCallbackCtx(appId, 0, &g_ipcProxyCbList);
    }
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return (ret == HC_SUCCESS) ? HC_SUCCESS : HC_ERR_IPC_PROC_FAILED;
}

static int32_t IpcGmUnRegCallback(const char *appId)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;

    LOGI("starting ...");
    if (IsStrInvalid(appId)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }

    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d", ret);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_UNREG_CB, true);
    if (ret == HC_SUCCESS) {
        DelIpcCliCallbackCtx(appId, &g_ipcProxyCbList);
    }
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", HC_SUCCESS);
    return HC_SUCCESS;
}

static int32_t IpcGmRegDataChangeListener(const char *appId, const DataChangeListener *listener)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;

    LOGI("starting ...");
    if (IsStrInvalid(appId) || (listener == NULL)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }

    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_LISTERNER, (const uint8_t *)listener, sizeof(*listener));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_LISTERNER);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_BIND_ID);
    ret = DoBinderCall(callCtx, IPC_CALL_ID_REG_LISTENER, true);
    if (ret == HC_SUCCESS) {
        AddIpcCliCallbackCtx(appId, 0, &g_ipcListenerCbList);
    }
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return (ret == HC_SUCCESS) ? HC_SUCCESS : HC_ERR_IPC_PROC_FAILED;
}

static int32_t IpcGmUnRegDataChangeListener(const char *appId)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;

    LOGI("starting ...");
    if (IsStrInvalid(appId)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }

    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d", ret);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_UNREG_LISTENER, true);
    if (ret == HC_SUCCESS) {
        DelIpcCliCallbackCtx(appId, &g_ipcListenerCbList);
    }
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done");
    return HC_SUCCESS;
}

static int32_t EncodeCreateGroupParams(uintptr_t callCtx, int32_t osAccountId, int64_t requestId,
    const char *appId, const char *createParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)&requestId, sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_REQID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_CREATE_PARAMS,
                                  (const uint8_t *)createParams, strlen(createParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_CREATE_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t IpcGmCreateGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *createParams)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(createParams) || IsStrInvalid(appId)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeCreateGroupParams(callCtx, osAccountId, requestId, appId, createParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CREATE_GROUP, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return ret;
}

static int32_t EncodeDeleteGroupParams(uintptr_t callCtx, int32_t osAccountId, int64_t requestId,
    const char *appId, const char *delParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)&requestId, sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_REQID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEL_PARAMS, (const uint8_t *)delParams, strlen(delParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_DEL_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t IpcGmDeleteGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *delParams)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(delParams) || IsStrInvalid(appId)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeDeleteGroupParams(callCtx, osAccountId, requestId, appId, delParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_DEL_GROUP, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return ret;
}

static int32_t EncodeAddMemberParams(uintptr_t callCtx, int32_t osAccountId, int64_t requestId,
    const char *appId, const char *addParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)&requestId, sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_REQID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_ADD_PARAMS, (const uint8_t *)addParams, strlen(addParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_ADD_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t IpcGmAddMemberToGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *addParams)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(appId) || IsStrInvalid(addParams)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeAddMemberParams(callCtx, osAccountId, requestId, appId, addParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_ADD_GROUP_MEMBER, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return ret;
}

static int32_t EncodeDeleteMemberParams(uintptr_t callCtx, int32_t osAccountId, int64_t requestId,
    const char *appId, const char *delParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)&requestId, sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_REQID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEL_PARAMS, (const uint8_t *)delParams, strlen(delParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_DEL_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t IpcGmDelMemberFromGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *delParams)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(appId) || IsStrInvalid(delParams)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeDeleteMemberParams(callCtx, osAccountId, requestId, appId, delParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_DEL_GROUP_MEMBER, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return ret;
}

static int32_t IpcGmAddMultiMembersToGroup(int32_t osAccountId, const char *appId, const char *addParams)
{
    LOGI("starting ...");
    if (IsStrInvalid(appId) || IsStrInvalid(addParams)) {
        LOGE("Invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    uintptr_t callCtx = 0x0;
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_ADD_PARAMS, (const uint8_t *)addParams, strlen(addParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_ADD_PARAMS);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_ADD_MULTI_GROUP_MEMBERS, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    IpcDataInfo replyCache = { 0 };
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return ret;
}

static int32_t IpcGmDelMultiMembersFromGroup(int32_t osAccountId, const char *appId, const char *delParams)
{
    LOGI("starting ...");
    if (IsStrInvalid(appId) || IsStrInvalid(delParams)) {
        LOGE("Invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    uintptr_t callCtx = 0x0;
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEL_PARAMS, (const uint8_t *)delParams, strlen(delParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_DEL_PARAMS);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_DEL_MULTI_GROUP_MEMBERS, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    IpcDataInfo replyCache = { 0 };
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return ret;
}

static int32_t IpcGmProcessData(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (!IS_COMM_DATA_VALID(data, dataLen)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)&requestId, sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_REQID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_COMM_DATA, data, dataLen);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_COMM_DATA);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GM_PROC_DATA, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %d", ret);
    return ret;
}

static int32_t IpcGmGetRegisterInfo(const char *reqJsonStr, char **registerInfo)
{
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;

    if (IsStrInvalid(reqJsonStr) || (registerInfo == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQ_JSON, (const uint8_t *)reqJsonStr, strlen(reqJsonStr) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_REQ_JSON);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_APPLY_REG_INFO, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if ((inOutLen != sizeof(int32_t)) || (ret != HC_SUCCESS)) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BAD_PARAM;
    }
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        LOGE("done, ret %d", HC_ERR_IPC_OUT_DATA_NUM);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_REG_INFO, (uint8_t *)&outInfo, NULL);
    if ((outInfo == NULL) || (strlen(outInfo) == 0)) {
        LOGE("done, ret %d", HC_ERR_IPC_OUT_DATA);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_OUT_DATA;
    }
    *registerInfo = strdup(outInfo);
    DestroyCallCtx(&callCtx, NULL);
    return (*registerInfo != NULL) ? HC_SUCCESS : HC_ERR_NULL_PTR;
}

static int32_t IpcGmCheckAccessToGroup(int32_t osAccountId, const char *appId, const char *groupId)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(appId) || IsStrInvalid(groupId)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_GROUPID, (const uint8_t *)groupId, strlen(groupId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_GROUPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CHECK_ACCESS_TO_GROUP, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    LOGI("process done, ret %d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t ParseReturnResult(const IpcDataInfo *replies, int32_t cacheNum, char **returnData, uint32_t *returnNum)
{
    int32_t ret;
    int32_t inOutLen;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_2) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_RETURN_DATA, (uint8_t *)returnData, NULL);
    if (*returnData == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *returnData = strdup(*returnData);
    if (*returnData == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_DATA_NUM, (uint8_t *)returnNum, &inOutLen);
    return HC_SUCCESS;
}

static int32_t IpcGmGetPkInfoList(int32_t osAccountId, const char *appId, const char *queryParams,
                                  char **returnInfoList, uint32_t *returnInfoNum)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };

    if (IsStrInvalid(appId) || IsStrInvalid(queryParams) || (returnInfoList == NULL) || (returnInfoNum == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID,
        (const uint8_t *)&osAccountId, sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_QUERY_PARAMS,
        (const uint8_t *)queryParams, strlen(queryParams) + 1);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GET_PK_INFO_LIST, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = ParseReturnResult(replyCache, REPLAY_CACHE_NUM(replyCache), returnInfoList, returnInfoNum);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t GroupInfoIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **outGroupInfo)
{
    int32_t inOutLen;
    int32_t ret;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_GROUP_INFO, (uint8_t *)outGroupInfo, NULL);
    if (*outGroupInfo == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *outGroupInfo = strdup(*outGroupInfo);
    if (*outGroupInfo == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t IpcGmGetGroupInfoById(int32_t osAccountId, const char *appId, const char *groupId, char **outGroupInfo)
{
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    if (IsStrInvalid(groupId) || IsStrInvalid(appId) || (outGroupInfo == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_GROUPID, (const uint8_t *)groupId, strlen(groupId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_GROUPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GET_GROUP_INFO, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = GroupInfoIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), outGroupInfo);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t SearchGroupsIpcResult(const IpcDataInfo *replies,
    int32_t cacheNum, char **outGroupVec, uint32_t *groupNum)
{
    int32_t ret;
    int32_t inOutLen;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_2) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_GROUP_INFO, (uint8_t *)outGroupVec, NULL);
    if (*outGroupVec == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *outGroupVec = strdup(*outGroupVec);
    if (*outGroupVec == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_DATA_NUM, (uint8_t *)groupNum, &inOutLen);
    return HC_SUCCESS;
}

static int32_t IpcGmGetGroupInfo(int32_t osAccountId, const char *appId, const char *queryParams,
    char **outGroupVec, uint32_t *groupNum)
{
    uintptr_t callCtx = 0x0;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };

    if (IsStrInvalid(queryParams) || IsStrInvalid(appId) || (outGroupVec == NULL) || (groupNum == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_QUERY_PARAMS,
        (const uint8_t *)queryParams, strlen(queryParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_QUERY_PARAMS);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_SEARCH_GROUPS, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = SearchGroupsIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), outGroupVec, groupNum);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t JoinedGroupsIpcResult(const IpcDataInfo *replies,
    int32_t cacheNum, char **outGroupVec, uint32_t *groupNum)
{
    int32_t ret;
    int32_t inOutLen;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_2) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_GROUP_INFO, (uint8_t *)outGroupVec, NULL);
    if (*outGroupVec == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *outGroupVec = strdup(*outGroupVec);
    if (*outGroupVec == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_DATA_NUM, (uint8_t *)groupNum, &inOutLen);
    return HC_SUCCESS;
}

static int32_t IpcGmGetJoinedGroups(int32_t osAccountId, const char *appId, int32_t groupType,
    char **outGroupVec, uint32_t *groupNum)
{
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };

    if (IsStrInvalid(appId) || (outGroupVec == NULL) || (groupNum == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_GROUP_TYPE, (const uint8_t *)&groupType, sizeof(groupType));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_GROUP_TYPE);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GET_JOINED_GROUPS, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = JoinedGroupsIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), outGroupVec, groupNum);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t RelatedGroupsIpcResult(const IpcDataInfo *replies,
    int32_t cacheNum, char **outGroupVec, uint32_t *groupNum)
{
    int32_t ret;
    int32_t inOutLen;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_2) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_GROUP_INFO, (uint8_t *)outGroupVec, NULL);
    if (*outGroupVec == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *outGroupVec = strdup(*outGroupVec);
    if (*outGroupVec == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_DATA_NUM, (uint8_t *)groupNum, &inOutLen);
    return HC_SUCCESS;
}

static int32_t IpcGmGetRelatedGroups(int32_t osAccountId, const char *appId, const char *peerUdid,
    char **outGroupVec, uint32_t *groupNum)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };

    if (IsStrInvalid(appId) || IsStrInvalid(peerUdid) || (outGroupVec == NULL) || (groupNum == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId, sizeof(int32_t));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_UDID, (const uint8_t *)peerUdid, strlen(peerUdid) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_UDID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GET_RELATED_GROUPS, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("Service return exception, ret: %d", ret);
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = RelatedGroupsIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), outGroupVec, groupNum);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t DevInfoByIdIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **outDevInfo)
{
    int32_t ret;
    int32_t inOutLen;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_DEVICE_INFO, (uint8_t *)outDevInfo, NULL);
    if (*outDevInfo == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *outDevInfo = strdup(*outDevInfo);
    if (*outDevInfo == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t FormParamsForGettingDeviceInfo(int32_t osAccountId, const char *appId,
    const char *peerUdid, const char *groupId, uintptr_t callCtx)
{
    int32_t ret;
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_UDID, (const uint8_t *)peerUdid, strlen(peerUdid) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_UDID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_GROUPID, (const uint8_t *)groupId, strlen(groupId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_GROUPID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t IpcGmGetDeviceInfoById(int32_t osAccountId, const char *appId, const char *peerUdid, const char *groupId,
    char **outDevInfo)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(appId) || IsStrInvalid(peerUdid) || IsStrInvalid(groupId) || (outDevInfo == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = FormParamsForGettingDeviceInfo(osAccountId, appId, peerUdid, groupId, callCtx);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GET_DEV_INFO_BY_ID, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        LOGE("Service return exception, ret: %d", ret);
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DevInfoByIdIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), outDevInfo);
    LOGI("proc result done, ret %d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t TrustedDevIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **outDevInfoVec, uint32_t *devNum)
{
    int32_t ret;
    int32_t inOutLen;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_2) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_DEVICE_INFO, (uint8_t *)outDevInfoVec, NULL);
    if (*outDevInfoVec == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *outDevInfoVec = strdup(*outDevInfoVec);
    if (*outDevInfoVec == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_DATA_NUM, (uint8_t *)devNum, &inOutLen);
    return HC_SUCCESS;
}

static int32_t IpcGmGetTrustedDevices(int32_t osAccountId, const char *appId,
    const char *groupId, char **outDevInfoVec, uint32_t *deviceNum)
{
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };

    if (IsStrInvalid(appId) || IsStrInvalid(groupId) || (outDevInfoVec == NULL) || (deviceNum == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_GROUPID, (const uint8_t *)groupId, strlen(groupId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_GROUPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GET_TRUST_DEVICES, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = TrustedDevIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), outDevInfoVec, deviceNum);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static bool IpcGmIsDeviceInGroup(int32_t osAccountId, const char *appId, const char *groupId, const char *udid)
{
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    if (IsStrInvalid(appId) || IsStrInvalid(groupId) || IsStrInvalid(udid)) {
        LOGE("Invalid params.");
        return false;
    }
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return false;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return false;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return false;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_GROUPID, (const uint8_t *)groupId, strlen(groupId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_GROUPID);
        DestroyCallCtx(&callCtx, NULL);
        return false;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_UDID, (const uint8_t *)udid, strlen(udid) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_UDID);
        DestroyCallCtx(&callCtx, NULL);
        return false;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_IS_DEV_IN_GROUP, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx, NULL);
        return false;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    return (ret == HC_SUCCESS) ? true : false;
}

static void IpcGmDestroyInfo(char **returnInfo)
{
    if ((returnInfo == NULL) || (*returnInfo == NULL)) {
        return;
    }
    FreeJsonString(*returnInfo);
    *returnInfo = NULL;
}

static void IpcGmCancelRequest(int64_t requestId, const char *appId)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;

    LOGI("starting ...");
    if (IsStrInvalid(appId)) {
        LOGE("Invalid params.");
        return;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&requestId), sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_REQID);
        DestroyCallCtx(&callCtx, NULL);
        return;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_GM_CANCEL_REQUEST, true);
    DestroyCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("ipc call failed");
    } else {
        LOGI("process done, ret %d", ret);
    }
}

static void InitIpcGmMethods(DeviceGroupManager *gmMethodObj)
{
    gmMethodObj->regCallback = IpcGmRegCallback;
    gmMethodObj->unRegCallback = IpcGmUnRegCallback;
    gmMethodObj->regDataChangeListener = IpcGmRegDataChangeListener;
    gmMethodObj->unRegDataChangeListener = IpcGmUnRegDataChangeListener;
    gmMethodObj->createGroup = IpcGmCreateGroup;
    gmMethodObj->deleteGroup = IpcGmDeleteGroup;
    gmMethodObj->addMemberToGroup = IpcGmAddMemberToGroup;
    gmMethodObj->deleteMemberFromGroup = IpcGmDelMemberFromGroup;
    gmMethodObj->addMultiMembersToGroup = IpcGmAddMultiMembersToGroup;
    gmMethodObj->delMultiMembersFromGroup = IpcGmDelMultiMembersFromGroup;
    gmMethodObj->processData = IpcGmProcessData;
    gmMethodObj->getRegisterInfo = IpcGmGetRegisterInfo;
    gmMethodObj->checkAccessToGroup = IpcGmCheckAccessToGroup;
    gmMethodObj->getPkInfoList = IpcGmGetPkInfoList;
    gmMethodObj->getGroupInfoById = IpcGmGetGroupInfoById;
    gmMethodObj->getGroupInfo = IpcGmGetGroupInfo;
    gmMethodObj->getJoinedGroups = IpcGmGetJoinedGroups;
    gmMethodObj->getRelatedGroups = IpcGmGetRelatedGroups;
    gmMethodObj->getDeviceInfoById = IpcGmGetDeviceInfoById;
    gmMethodObj->getTrustedDevices = IpcGmGetTrustedDevices;
    gmMethodObj->isDeviceInGroup = IpcGmIsDeviceInGroup;
    gmMethodObj->cancelRequest = IpcGmCancelRequest;
    gmMethodObj->destroyInfo = IpcGmDestroyInfo;
    return;
}

static int32_t EncodeProcessDataParams(uintptr_t callCtx, int64_t authReqId,
    const uint8_t *data, uint32_t dataLen, const DeviceAuthCallback *callback)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&authReqId), sizeof(authReqId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_REQID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_COMM_DATA, (const uint8_t *)data, dataLen);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_COMM_DATA);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEV_AUTH_CB, (const uint8_t *)callback, sizeof(*callback));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    SetCbCtxToDataCtx(callCtx, 0x0);
    return HC_SUCCESS;
}

static int32_t IpcGaProcessData(int64_t authReqId,
    const uint8_t *data, uint32_t dataLen, const DeviceAuthCallback *callback)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (!IS_COMM_DATA_VALID(data, dataLen) || (callback == NULL)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeProcessDataParams(callCtx, authReqId, data, dataLen, callback);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GA_PROC_DATA, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    LOGI("process done, ret %d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t EncodeAuthDeviceParams(uintptr_t callCtx, int32_t osAccountId, int64_t authReqId,
    const char *authParams, const DeviceAuthCallback *callback)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&authReqId), sizeof(authReqId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_REQID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_AUTH_PARAMS, (const uint8_t *)authParams, strlen(authParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_AUTH_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEV_AUTH_CB, (const uint8_t *)callback, sizeof(*callback));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_AUTH_ID);
    return HC_SUCCESS;
}

static int32_t IpcGaAuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *callback)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(authParams) || (callback == NULL)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeAuthDeviceParams(callCtx, osAccountId, authReqId, authParams, callback);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_AUTH_DEVICE, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    LOGI("process done, ret %d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static void IpcGaCancelRequest(int64_t requestId, const char *appId)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;

    LOGI("starting ...");
    if (IsStrInvalid(appId)) {
        LOGE("Invalid params.");
        return;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&requestId), sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_REQID);
        DestroyCallCtx(&callCtx, NULL);
        return;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId, strlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_GA_CANCEL_REQUEST, true);
    DestroyCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("ipc call failed");
    } else {
        LOGI("process done, ret %d", ret);
    }
}

static int32_t GetIpcReplyByTypeInner(const IpcDataInfo *replies, int32_t cacheNum, char **outInfo)
{
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_RETURN_DATA, (uint8_t *)outInfo, NULL);
    if (*outInfo == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *outInfo = strdup(*outInfo);
    if (*outInfo == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t IpcGaGetRealInfo(int32_t osAccountId, const char *pseudonymId, char **realInfo)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(pseudonymId) || (realInfo == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_PSEUDONYM_ID, (const uint8_t *)pseudonymId,
        strlen(pseudonymId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_PSEUDONYM_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GET_REAL_INFO, true);
    if (ret != HC_SUCCESS) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    LOGI("process done, ret %d", ret);
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = GetIpcReplyByTypeInner(replyCache, REPLAY_CACHE_NUM(replyCache), realInfo);
    if (ret != HC_SUCCESS) {
        LOGE("GetIpcReplyByType failed, ret %d", ret);
    }
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t IpcGaGetPseudonymId(int32_t osAccountId, const char *indexKey, char **pseudonymId)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(indexKey) || (pseudonymId == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_INDEX_KEY, (const uint8_t *)indexKey, strlen(indexKey) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_INDEX_KEY);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_GET_PSEUDONYM_ID, true);
    if (ret != HC_SUCCESS) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    LOGI("process done, ret %d", ret);
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = GetIpcReplyByTypeInner(replyCache, REPLAY_CACHE_NUM(replyCache), pseudonymId);
    if (ret != HC_SUCCESS) {
        LOGE("GetIpcReplyByType failed, ret %d", ret);
    }
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static void InitIpcGaMethods(GroupAuthManager *gaMethodObj)
{
    gaMethodObj->processData = IpcGaProcessData;
    gaMethodObj->authDevice = IpcGaAuthDevice;
    gaMethodObj->cancelRequest = IpcGaCancelRequest;
    gaMethodObj->getRealInfo = IpcGaGetRealInfo;
    gaMethodObj->getPseudonymId = IpcGaGetPseudonymId;
    return;
}

DEVICE_AUTH_API_PUBLIC int32_t ProcessCredential(int32_t operationCode, const char *reqJsonStr, char **returnData)
{
    uintptr_t callCtx = IPC_CALL_CONTEXT_INIT;
    int32_t ret;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(reqJsonStr) || (returnData == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(
        callCtx, PARAM_TYPE_OPCODE, (const uint8_t *)&operationCode, sizeof(operationCode));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_OPCODE);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret =
        SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQ_JSON, (const uint8_t *)reqJsonStr, strlen(reqJsonStr) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_REQ_JSON);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_PROCESS_CREDENTIAL, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = GetIpcReplyByTypeInner(&replyCache, REPLAY_CACHE_NUM(replyCache), returnData);
    if (ret != HC_SUCCESS) {
        LOGE("GetIpcReplyByType failed, ret %d", ret);
    }
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

DEVICE_AUTH_API_PUBLIC int32_t ProcessAuthDevice(
    int64_t requestId, const char *authParams, const DeviceAuthCallback *callback)
{
    uintptr_t callCtx = IPC_CALL_CONTEXT_INIT;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(authParams) || (callback == NULL)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&requestId), sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_REQID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(
        callCtx, PARAM_TYPE_AUTH_PARAMS, (const uint8_t *)authParams, strlen(authParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_AUTH_PARAMS);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEV_AUTH_CB, (const uint8_t *)callback, sizeof(*callback));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_DEV_AUTH_CB);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_DIRECT_AUTH_ID);
    ret = DoBinderCall(callCtx, IPC_CALL_ID_DA_PROC_DATA, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(
        &replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    LOGI("process done, ret %d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

DEVICE_AUTH_API_PUBLIC int32_t StartAuthDevice(
    int64_t authReqId, const char *authParams, const DeviceAuthCallback *callback)
{
    uintptr_t callCtx = IPC_CALL_CONTEXT_INIT;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(authParams) || (callback == NULL)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&authReqId), sizeof(authReqId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_REQID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(
        callCtx, PARAM_TYPE_AUTH_PARAMS, (const uint8_t *)authParams, strlen(authParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_AUTH_PARAMS);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEV_AUTH_CB, (const uint8_t *)callback, sizeof(*callback));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_DEV_AUTH_CB);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_DIRECT_AUTH_ID);
    ret = DoBinderCall(callCtx, IPC_CALL_ID_DA_AUTH_DEVICE, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(
        &replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    LOGI("process done, ret %d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

DEVICE_AUTH_API_PUBLIC int32_t CancelAuthRequest(int64_t requestId, const char *authParams)
{
    uintptr_t callCtx = IPC_CALL_CONTEXT_INIT;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(authParams)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %d", ret);
        return HC_ERR_NULL_PTR;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&requestId), sizeof(requestId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, type %d", ret, PARAM_TYPE_REQID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_NULL_PTR;
    }
    ret = SetCallRequestParamInfo(
        callCtx, PARAM_TYPE_AUTH_PARAMS, (const uint8_t *)authParams, strlen(authParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %d, param id %d", ret, PARAM_TYPE_AUTH_PARAMS);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_NULL_PTR;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_DA_CANCEL_REQUEST, true);
    if (ret != HC_SUCCESS) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(
        &replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    LOGI("process done, ret %d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

DEVICE_AUTH_API_PUBLIC int InitDeviceAuthService(void)
{
    InitHcMutex(&g_ipcMutex);
    return InitProxyAdapt();
}

DEVICE_AUTH_API_PUBLIC void DestroyDeviceAuthService(void)
{
    UnInitProxyAdapt();
    DestroyHcMutex(&g_ipcMutex);
}

DEVICE_AUTH_API_PUBLIC const GroupAuthManager *GetGaInstance(void)
{
    static GroupAuthManager gaInstCtx;
    static GroupAuthManager *gaInstPtr = NULL;

    if (gaInstPtr == NULL) {
        InitIpcGaMethods(&gaInstCtx);
        gaInstPtr = &gaInstCtx;
    }
    return (const GroupAuthManager *)(gaInstPtr);
}

DEVICE_AUTH_API_PUBLIC const DeviceGroupManager *GetGmInstance(void)
{
    static DeviceGroupManager gmInstCtx;
    static DeviceGroupManager *gmInstPtr = NULL;

    if (gmInstPtr == NULL) {
        InitIpcGmMethods(&gmInstCtx);
        gmInstPtr = &gmInstCtx;
    }
    return (const DeviceGroupManager *)(gmInstPtr);
}

#ifdef __cplusplus
}
#endif
