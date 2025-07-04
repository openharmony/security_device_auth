/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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
#include "identity_service_ipc_sdk.h"
#include "ipc_sdk_defines.h"
#include "device_auth.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"

#include "ipc_adapt.h"
#include "securec.h"
#include "sa_load_on_demand.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPC_DATA_CACHES_1 1
#define IPC_DATA_CACHES_2 2
#define IPC_DATA_CACHES_3 3
#define IPC_DATA_CACHES_4 4
#define IPC_DATA_CACHES_6 6
#define REPLAY_CACHE_NUM(caches) (sizeof(caches) / sizeof(IpcDataInfo))
#define IPC_APPID_LEN 128

#define IS_COMM_DATA_VALID(dPtr, dLen) (((dPtr) != NULL) && ((dLen) > 0) && ((dLen) <= 4096))

static const int32_t IPC_RESULT_NUM_1 = 1;
static const int32_t IPC_RESULT_NUM_2 = 2;
static const int32_t IPC_RESULT_NUM_4 = 4;

typedef struct {
    uintptr_t inst;
    char appId[IPC_APPID_LEN];
} IpcProxyCbInfo;
static IpcProxyCbInfo g_ipcProxyCbList = { 0 };
static IpcProxyCbInfo g_ipcListenerCbList = { 0 };
static HcMutex g_ipcMutex;
static bool g_devAuthServiceStatus = false;

static bool IsStrInvalid(const char *str)
{
    return (str == NULL || str[0] == 0);
}

static void AddIpcCliCallbackCtx(const char *appId, uintptr_t cbInst, IpcProxyCbInfo *cbCache)
{
    errno_t eno;

    (void)LockHcMutex(&g_ipcMutex);
    eno = memcpy_s(cbCache->appId, IPC_APPID_LEN, appId, HcStrlen(appId) + 1);
    if (eno != EOK) {
        UnlockHcMutex(&g_ipcMutex);
        LOGE("memory copy failed");
        return;
    }
    cbCache->inst = cbInst;
    UnlockHcMutex(&g_ipcMutex);
}

static void DelIpcCliCallbackCtx(const char *appId, IpcProxyCbInfo *cbCache)
{
    int32_t ret;

    if (cbCache->appId[0] == 0) {
        return;
    }
    (void)LockHcMutex(&g_ipcMutex);
    ret = memcmp(appId, cbCache->appId, HcStrlen(cbCache->appId) + 1);
    if (ret == 0) {
        cbCache->appId[0] = 0;
    }
    UnlockHcMutex(&g_ipcMutex);
    return;
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
            case PARAM_TYPE_CRED_ID:
            case PARAM_TYPE_CRED_INFO:
            case PARAM_TYPE_CRED_INFO_LIST:
            case PARAM_TYPE_CRED_VAL:
            case PARAM_TYPE_RETURN_DATA:
            case PARAM_TYPE_SHARED_KEY_VAL:
            case PARAM_TYPE_RANDOM_VAL:
                *(uint8_t **)outCache = ipcData[i].val;
                break;
            case PARAM_TYPE_IPC_RESULT:
            case PARAM_TYPE_IPC_RESULT_NUM:
            case PARAM_TYPE_COMM_DATA:
            case PARAM_TYPE_DATA_NUM:
            case PARAM_TYPE_SHARED_KEY_LEN:
            case PARAM_TYPE_RANDOM_LEN:
                eno = memcpy_s(outCache, *cacheLen, ipcData[i].val, ipcData[i].valSz);
                if (eno != EOK) {
                    break;
                }
                *cacheLen = ipcData[i].valSz;
                break;
            default:
                LOGE("un-expectation type case.");
                break;
        }
    }
    return;
}

static int32_t IpcGmRegCallbackInner(const char *appId, const DeviceAuthCallback *callback, bool needCache)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || callback == NULL));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEV_AUTH_CB, callback, sizeof(*callback));
        SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_BIND_ID);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_REG_CB, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        AddIpcCliCallbackCtx(appId, 0, &g_ipcProxyCbList);
        if (needCache) {
            ret = AddCallbackInfoToList(appId, callback, NULL, NULL, DEVAUTH_CALLBACK);
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmRegCallback(const char *appId, const DeviceAuthCallback *callback)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    LOGI("starting ...");
    return IpcGmRegCallbackInner(appId, callback, true);
}

static int32_t IpcGmUnRegCallback(const char *appId)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    uintptr_t callCtx = 0x0;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    int32_t inOutLen;
    int32_t ret;
    LOGI("starting ...");

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(appId));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_UNREG_CB, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        DelIpcCliCallbackCtx(appId, &g_ipcProxyCbList);
        ret = RemoveCallbackInfoFromList(appId, DEVAUTH_CALLBACK);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmRegDataChangeListenerInner(const char *appId, const DataChangeListener *listener, bool needCache)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || (listener == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_LISTENER, listener, sizeof(*listener));
        SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_BIND_ID);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_REG_LISTENER, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        AddIpcCliCallbackCtx(appId, 0, &g_ipcListenerCbList);
        if (needCache) {
            ret = AddCallbackInfoToList(appId, NULL, listener, NULL, GROUP_CHANGE_LISTENER);
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmRegDataChangeListener(const char *appId, const DataChangeListener *listener)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    LOGI("starting ...");
    return IpcGmRegDataChangeListenerInner(appId, listener, true);
}

static int32_t IpcGmUnRegDataChangeListener(const char *appId)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(appId));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_UNREG_LISTENER, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        DelIpcCliCallbackCtx(appId, &g_ipcListenerCbList);
        ret = RemoveCallbackInfoFromList(appId, GROUP_CHANGE_LISTENER);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmCreateGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *createParams)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(createParams)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_CREATE_PARAMS, createParams, HcStrlen(createParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CREATE_GROUP, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmDeleteGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *delParams)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    int32_t ret;
    LOGI("starting ...");

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(delParams)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEL_PARAMS, delParams, HcStrlen(delParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_DEL_GROUP, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmAddMemberToGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *addParams)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(addParams)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_ADD_PARAMS, addParams, HcStrlen(addParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_ADD_GROUP_MEMBER, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmDelMemberFromGroup(int32_t osAccountId, int64_t requestId, const char *appId, const char *delParams)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(delParams)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEL_PARAMS, delParams, HcStrlen(delParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_DEL_GROUP_MEMBER, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmAddMultiMembersToGroup(int32_t osAccountId, const char *appId, const char *addParams)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(addParams)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_ADD_PARAMS, addParams, HcStrlen(addParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_ADD_MULTI_GROUP_MEMBERS, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmDelMultiMembersFromGroup(int32_t osAccountId, const char *appId, const char *delParams)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(delParams)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEL_PARAMS, delParams, HcStrlen(delParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_DEL_MULTI_GROUP_MEMBERS, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmProcessData(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((!IS_COMM_DATA_VALID(data, dataLen)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_COMM_DATA, data, dataLen);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GM_PROC_DATA, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmGetRegisterInfo(const char *reqJsonStr, char **registerInfo)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    LOGI("starting ...");
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(reqJsonStr) || (registerInfo == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQ_JSON, reqJsonStr, HcStrlen(reqJsonStr) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_APPLY_REG_INFO, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_REG_INFO, outInfo);
        *registerInfo = strdup(outInfo);
        if (*registerInfo == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGmCheckAccessToGroup(int32_t osAccountId, const char *appId, const char *groupId)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(groupId)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_GROUPID, groupId, HcStrlen(groupId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CHECK_ACCESS_TO_GROUP, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static int32_t IpcGmGetPkInfoList(int32_t osAccountId, const char *appId, const char *queryParams,
                                  char **returnInfoList, uint32_t *returnInfoNum)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(queryParams) || (returnInfoList == NULL)
        || (returnInfoNum == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_QUERY_PARAMS, queryParams, HcStrlen(queryParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GET_PK_INFO_LIST, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_2);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_RETURN_DATA, outInfo);
        *returnInfoList = strdup(outInfo);
        if (*returnInfoList == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
        GET_IPC_REPLY_INT(replyCache, PARAM_TYPE_DATA_NUM, returnInfoNum);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static int32_t IpcGmGetGroupInfoById(int32_t osAccountId, const char *appId, const char *groupId, char **outGroupInfo)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(groupId) || (outGroupInfo == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_GROUPID, groupId, HcStrlen(groupId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GET_GROUP_INFO, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_GROUP_INFO, outInfo);
        *outGroupInfo = strdup(outInfo);
        if (*outGroupInfo == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static int32_t IpcGmGetGroupInfo(int32_t osAccountId, const char *appId, const char *queryParams,
    char **outGroupVec, uint32_t *groupNum)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(queryParams)
        || (outGroupVec == NULL) || (groupNum == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_QUERY_PARAMS, queryParams, HcStrlen(queryParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_SEARCH_GROUPS, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_2);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_GROUP_INFO, outInfo);
        *outGroupVec = strdup(outInfo);
        if (*outGroupVec == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
        GET_IPC_REPLY_INT(replyCache, PARAM_TYPE_DATA_NUM, groupNum);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static int32_t IpcGmGetJoinedGroups(int32_t osAccountId, const char *appId, int32_t groupType,
    char **outGroupVec, uint32_t *groupNum)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || (outGroupVec == NULL) || (groupNum == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_GROUP_TYPE, &groupType, sizeof(groupType));
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GET_JOINED_GROUPS, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_2);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_GROUP_INFO, outInfo);
        *outGroupVec = strdup(outInfo);
        if (*outGroupVec == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
        GET_IPC_REPLY_INT(replyCache, PARAM_TYPE_DATA_NUM, groupNum);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static int32_t IpcGmGetRelatedGroups(int32_t osAccountId, const char *appId, const char *peerUdid,
    char **outGroupVec, uint32_t *groupNum)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(peerUdid) ||
        (outGroupVec == NULL) || (groupNum == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_UDID, peerUdid, HcStrlen(peerUdid) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GET_RELATED_GROUPS, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_2);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_GROUP_INFO, outInfo);
        *outGroupVec = strdup(outInfo);
        if (*outGroupVec == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
        GET_IPC_REPLY_INT(replyCache, PARAM_TYPE_DATA_NUM, groupNum);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static int32_t IpcGmGetDeviceInfoById(int32_t osAccountId, const char *appId, const char *peerUdid, const char *groupId,
    char **outDevInfo)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(peerUdid) ||
        IsStrInvalid(groupId) || (outDevInfo == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_UDID, peerUdid, HcStrlen(peerUdid) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_GROUPID, groupId, HcStrlen(groupId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GET_DEV_INFO_BY_ID, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_DEVICE_INFO, outInfo);
        *outDevInfo = strdup(outInfo);
        if (*outDevInfo == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static int32_t IpcGmGetTrustedDevices(int32_t osAccountId, const char *appId,
    const char *groupId, char **outDevInfoVec, uint32_t *deviceNum)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(groupId) ||
        (outDevInfoVec == NULL) || (deviceNum == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_GROUPID, groupId, HcStrlen(groupId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GET_TRUST_DEVICES, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_2);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_DEVICE_INFO, outInfo);
        *outDevInfoVec = strdup(outInfo);
        if (*outDevInfoVec == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
        GET_IPC_REPLY_INT(replyCache, PARAM_TYPE_DATA_NUM, deviceNum);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static bool IpcGmIsDeviceInGroup(int32_t osAccountId, const char *appId, const char *groupId, const char *udid)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_BOOL_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId) || IsStrInvalid(groupId) || IsStrInvalid(udid)));
    RETURN_BOOL_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_GROUPID, groupId, HcStrlen(groupId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_UDID, udid, HcStrlen(udid) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_IS_DEV_IN_GROUP, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return (ret == HC_SUCCESS) ? true : false;
}

static void IpcGmDestroyInfo(char **returnInfo)
{
    RETURN_VOID_IF_LOAD_DEVAUTH_FAILED();
    if ((returnInfo == NULL) || (*returnInfo == NULL)) {
        return;
    }
    FreeJsonString(*returnInfo);
    *returnInfo = NULL;
}

static void IpcGmCancelRequest(int64_t requestId, const char *appId)
{
    RETURN_VOID_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;

    RETURN_VOID_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId)));
    RETURN_VOID_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_GM_CANCEL_REQUEST, true);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
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

static int32_t IpcGaProcessData(int64_t authReqId,
    const uint8_t *data, uint32_t dataLen, const DeviceAuthCallback *callback)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((!IS_COMM_DATA_VALID(data, dataLen) || (callback == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &authReqId, sizeof(authReqId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_COMM_DATA, data, dataLen);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEV_AUTH_CB, callback, sizeof(*callback));
        SetCbCtxToDataCtx(callCtx, 0x0);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GA_PROC_DATA, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcGaAuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *callback)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    LOGI("starting ...");
    int32_t ret;
    int32_t inOutLen;
    uintptr_t callCtx = 0x0;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(authParams) || (callback == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &authReqId, sizeof(authReqId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_AUTH_PARAMS, authParams, HcStrlen(authParams) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEV_AUTH_CB, callback, sizeof(*callback));
        SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_AUTH_ID);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_AUTH_DEVICE, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static void IpcGaCancelRequest(int64_t requestId, const char *appId)
{
    RETURN_VOID_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;

    RETURN_VOID_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(appId)));
    RETURN_VOID_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_GA_CANCEL_REQUEST, true);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
}

static int32_t IpcGaGetRealInfo(int32_t osAccountId, const char *pseudonymId, char **realInfo)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_2] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(pseudonymId) || (realInfo == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_PSEUDONYM_ID, pseudonymId, HcStrlen(pseudonymId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GET_REAL_INFO, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_RETURN_DATA, outInfo);
        *realInfo = strdup(outInfo);
        if (*realInfo == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    return ret;
}

static int32_t IpcGaGetPseudonymId(int32_t osAccountId, const char *indexKey, char **pseudonymId)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_2] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(indexKey) || (pseudonymId == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_INDEX_KEY, indexKey, HcStrlen(indexKey) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_GET_PSEUDONYM_ID, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_RETURN_DATA, outInfo);
        *pseudonymId = strdup(outInfo);
        if (*pseudonymId == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

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

static int32_t SetReturnSharedKey(const uint8_t *sharedKeyVal, uint32_t sharedKeyLen, DataBuff *returnSharedKey)
{
    uint8_t *tmpSharedKeyVal = (uint8_t *)HcMalloc(sharedKeyLen, 0);
    if (tmpSharedKeyVal == NULL) {
        LOGE("malloc temp shared key failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(tmpSharedKeyVal, sharedKeyLen, sharedKeyVal, sharedKeyLen) != EOK) {
        LOGE("memcpy_s temp shared key failed.");
        HcFree(tmpSharedKeyVal);
        return HC_ERR_MEMORY_COPY;
    }
    returnSharedKey->data = tmpSharedKeyVal;
    returnSharedKey->length = sharedKeyLen;
    return HC_SUCCESS;
}

static int32_t SetReturnRandom(const uint8_t *randomVal, uint32_t randomLen, DataBuff *returnRandom)
{
    uint8_t *tmpRandomVal = (uint8_t *)HcMalloc(randomLen, 0);
    if (tmpRandomVal == NULL) {
        LOGE("malloc temp random failed.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(tmpRandomVal, randomLen, randomVal, randomLen) != EOK) {
        LOGE("memcpy_s temp random failed.");
        HcFree(tmpRandomVal);
        return HC_ERR_MEMORY_COPY;
    }
    returnRandom->data = tmpRandomVal;
    returnRandom->length = randomLen;
    return HC_SUCCESS;
}

static void IpcAvDestroyDataBuff(DataBuff *dataBuff)
{
    RETURN_VOID_IF_LOAD_DEVAUTH_FAILED();
    if (dataBuff == NULL || dataBuff->data == NULL) {
        return;
    }
    HcFree(dataBuff->data);
    dataBuff->data = NULL;
    dataBuff->length = 0;
}

static int32_t GetSharedKeyAndRandom(const IpcDataInfo *replies, int32_t cacheNum, DataBuff *returnSharedKey,
    DataBuff *returnRandom)
{
    int32_t resultNum;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&resultNum, &inOutLen);
    if ((resultNum < IPC_RESULT_NUM_4) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }

    uint8_t *sharedKeyVal = NULL;
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_SHARED_KEY_VAL, (uint8_t *)&sharedKeyVal, NULL);
    if (sharedKeyVal == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    inOutLen = sizeof(int32_t);
    uint32_t sharedKeyLen = 0;
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_SHARED_KEY_LEN, (uint8_t *)&sharedKeyLen, &inOutLen);
    if (sharedKeyLen == 0) {
        return HC_ERR_IPC_OUT_DATA;
    }

    uint8_t *randomVal = NULL;
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_RANDOM_VAL, (uint8_t *)&randomVal, NULL);
    if (randomVal == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    inOutLen = sizeof(int32_t);
    uint32_t randomLen = 0;
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_RANDOM_LEN, (uint8_t *)&randomLen, &inOutLen);
    if (randomLen == 0) {
        return HC_ERR_IPC_OUT_DATA;
    }
    int32_t ret = SetReturnSharedKey(sharedKeyVal, sharedKeyLen, returnSharedKey);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = SetReturnRandom(randomVal, randomLen, returnRandom);
    if (ret != HC_SUCCESS) {
        IpcAvDestroyDataBuff(returnSharedKey);
    }
    return ret;
}

static int32_t IpcAvGetClientSharedKey(const char *peerPkWithSig, const char *serviceId, DataBuff *returnSharedKey,
    DataBuff *returnRandom)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    if ((peerPkWithSig == NULL) || (serviceId == NULL) || (returnSharedKey == NULL) || (returnRandom == NULL)) {
        LOGE("Error occurs, params invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    uintptr_t callCtx = 0x0;
    int32_t ret = CreateCallCtx(&callCtx);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_PK_WITH_SIG, (const uint8_t *)peerPkWithSig,
        HcStrlen(peerPkWithSig) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("IpcAvGetClientSharedKey set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d",
            ret, PARAM_TYPE_PK_WITH_SIG);
        DestroyCallCtx(&callCtx);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_SERVICE_ID, (const uint8_t *)serviceId, HcStrlen(serviceId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("IpcAvGetClientSharedKey set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d",
            ret, PARAM_TYPE_SERVICE_ID);
        DestroyCallCtx(&callCtx);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_AV_GET_CLIENT_SHARED_KEY, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx);
        return HC_ERR_IPC_PROC_FAILED;
    }
    IpcDataInfo replyCache[IPC_DATA_CACHES_6] = { { 0 } };
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx);
        return ret;
    }
    ret = GetSharedKeyAndRandom(replyCache, REPLAY_CACHE_NUM(replyCache), returnSharedKey, returnRandom);
    DestroyCallCtx(&callCtx);
    return ret;
}

static int32_t GetSharedKey(const IpcDataInfo *replies, int32_t cacheNum, DataBuff *returnSharedKey)
{
    int32_t resultNum;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&resultNum, &inOutLen);
    if ((resultNum < IPC_RESULT_NUM_2) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }

    uint8_t *sharedKeyVal = NULL;
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_SHARED_KEY_VAL, (uint8_t *)&sharedKeyVal, NULL);
    if (sharedKeyVal == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    inOutLen = sizeof(int32_t);
    uint32_t sharedKeyLen = 0;
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_SHARED_KEY_LEN, (uint8_t *)&sharedKeyLen, &inOutLen);
    if (sharedKeyLen == 0) {
        return HC_ERR_IPC_OUT_DATA;
    }
    return SetReturnSharedKey(sharedKeyVal, sharedKeyLen, returnSharedKey);
}

static int32_t IpcAvGetServerSharedKey(const char *peerPkWithSig, const char *serviceId, const DataBuff *random,
    DataBuff *returnSharedKey)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    if ((peerPkWithSig == NULL) || (serviceId == NULL) || (random == NULL) || (random->data == NULL) ||
        (returnSharedKey == NULL)) {
        LOGE("Invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    uintptr_t callCtx = 0x0;
    int32_t ret = CreateCallCtx(&callCtx);
    if (ret != HC_SUCCESS) {
        LOGE("IpcAvGetServerSharedKey CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_PK_WITH_SIG, (const uint8_t *)peerPkWithSig,
        HcStrlen(peerPkWithSig) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_PK_WITH_SIG);
        DestroyCallCtx(&callCtx);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_SERVICE_ID, (const uint8_t *)serviceId, HcStrlen(serviceId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_SERVICE_ID);
        DestroyCallCtx(&callCtx);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_RANDOM, (const uint8_t *)random->data, random->length);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_RANDOM);
        DestroyCallCtx(&callCtx);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_AV_GET_SERVER_SHARED_KEY, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        DestroyCallCtx(&callCtx);
        return HC_ERR_IPC_PROC_FAILED;
    }
    IpcDataInfo replyCache[IPC_DATA_CACHES_4] = { { 0 } };
    DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx);
        return ret;
    }
    ret = GetSharedKey(replyCache, REPLAY_CACHE_NUM(replyCache), returnSharedKey);
    DestroyCallCtx(&callCtx);
    return ret;
}

static void InitIpcAccountVerifierMethods(AccountVerifier *accountVerifier)
{
    accountVerifier->getClientSharedKey = IpcAvGetClientSharedKey;
    accountVerifier->getServerSharedKey = IpcAvGetServerSharedKey;
    accountVerifier->destroyDataBuff = IpcAvDestroyDataBuff;
}

DEVICE_AUTH_API_PUBLIC int32_t ProcessCredential(int32_t operationCode, const char *reqJsonStr, char **returnData)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_2] = { { 0 } };
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(reqJsonStr) || (returnData == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OPCODE, &operationCode, sizeof(operationCode));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQ_JSON, reqJsonStr, HcStrlen(reqJsonStr) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_PROCESS_CREDENTIAL, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_RETURN_DATA, outInfo);
        *returnData = strdup(outInfo);
        if (*returnData == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

DEVICE_AUTH_API_PUBLIC int32_t ProcessAuthDevice(
    int64_t requestId, const char *authParams, const DeviceAuthCallback *callback)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(authParams) || (callback == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_AUTH_PARAMS, authParams, HcStrlen(authParams) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEV_AUTH_CB, callback, sizeof(*callback));
        SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_DIRECT_AUTH_ID);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_DA_PROC_DATA, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

DEVICE_AUTH_API_PUBLIC int32_t StartAuthDevice(
    int64_t authReqId, const char *authParams, const DeviceAuthCallback *callback)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(authParams) || (callback == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &authReqId, sizeof(authReqId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_AUTH_PARAMS, authParams, HcStrlen(authParams) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEV_AUTH_CB, callback, sizeof(*callback));
        SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_DIRECT_AUTH_ID);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_DA_AUTH_DEVICE, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

DEVICE_AUTH_API_PUBLIC int32_t CancelAuthRequest(int64_t requestId, const char *authParams)
{
    RETURN_ERROR_CODE_IF_LOAD_DEVAUTH_FAILED();
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    int32_t ret;
    uintptr_t callCtx = 0x0;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(authParams)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &requestId, sizeof(requestId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_AUTH_PARAMS, authParams, HcStrlen(authParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_DA_CANCEL_REQUEST, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

DEVICE_AUTH_API_PUBLIC int InitDeviceAuthService(void)
{
    if (g_devAuthServiceStatus == true) {
        LOGI("device auth sdk already init");
        return HC_SUCCESS;
    }
    int32_t ret = InitHcMutex(&g_ipcMutex, false);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = InitLoadOnDemand();
    if (ret != HC_SUCCESS) {
        DestroyHcMutex(&g_ipcMutex);
        return ret;
    }
    ret = InitISIpc();
    if (ret != HC_SUCCESS) {
        DeInitLoadOnDemand();
        DestroyHcMutex(&g_ipcMutex);
        return ret;
    }
    ret = InitProxyAdapt();
    if (ret != HC_SUCCESS) {
        DeInitISIpc();
        DeInitLoadOnDemand();
        DestroyHcMutex(&g_ipcMutex);
        return ret;
    }
    g_devAuthServiceStatus = true;
    SetRegCallbackFunc(IpcGmRegCallbackInner);
    SetRegDataChangeListenerFunc(IpcGmRegDataChangeListenerInner);
    SubscribeDeviceAuthSa();
    return HC_SUCCESS;
}

DEVICE_AUTH_API_PUBLIC void DestroyDeviceAuthService(void)
{
    UnSubscribeDeviceAuthSa();
    UnInitProxyAdapt();
    DeInitISIpc();
    DeInitLoadOnDemand();
    DestroyHcMutex(&g_ipcMutex);
    g_devAuthServiceStatus = false;
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

DEVICE_AUTH_API_PUBLIC const AccountVerifier *GetAccountVerifierInstance(void)
{
    static AccountVerifier avInstCtx;
    static AccountVerifier *avInstPtr = NULL;
    InitIpcAccountVerifierMethods(&avInstCtx);
    avInstPtr = &avInstCtx;
    return (const AccountVerifier *)(avInstPtr);
}

#ifdef __cplusplus
}
#endif
