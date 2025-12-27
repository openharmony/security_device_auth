/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "identity_service_ipc_sdk.h"

#include "common_defs.h"
#include "device_auth_defines.h"
#include "device_auth.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "sa_load_on_demand.h"
#include "ipc_sdk_defines.h"

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

typedef struct {
    uintptr_t inst;
    char appId[IPC_APPID_LEN];
} IpcProxyCbInfo;

static IpcProxyCbInfo g_ipcCredListenerCbList = { 0 };
static HcMutex g_ipcMutex;

static void DelIpcCliCallbackCtx(const char *appId, IpcProxyCbInfo *cbCache)
{
    (void)LockHcMutex(&g_ipcMutex);
    if (cbCache->appId[0] == 0) {
        UnlockHcMutex(&g_ipcMutex);
        return;
    }
    int32_t ret = memcmp(appId, cbCache->appId, HcStrlen(cbCache->appId) + 1);
    if (ret == 0) {
        cbCache->appId[0] = 0;
    }
    UnlockHcMutex(&g_ipcMutex);
    return;
}

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
        LOGE("memory copy appId to cbcache failed.");
        return;
    }
    cbCache->inst = cbInst;
    UnlockHcMutex(&g_ipcMutex);
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

static int32_t IpcCmAddCredential(int32_t osAccountId, const char *requestParams, char **returnData)
{
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(requestParams) || returnData == NULL);
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQUEST_PARAMS, requestParams, HcStrlen(requestParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_ADD_CREDENTIAL, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_CRED_ID, outInfo);
        *returnData = strdup(outInfo);
        if (*returnData == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);
    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmRegChangeListenerInner(const char *appId, CredChangeListener *listener, bool needCache)
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
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_REG_LISTENER, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        AddIpcCliCallbackCtx(appId, 0, &g_ipcCredListenerCbList);
        if (needCache) {
            ret = AddCallbackInfoToList(appId, NULL, NULL, listener, CRED_CHANGE_LISTENER);
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);
    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmRegChangeListener(const char *appId, CredChangeListener *listener)
{
    LOGI("starting ...");
    return IpcCmRegChangeListenerInner(appId, listener, true);
}

static int32_t IpcCmUnRegChangeListener(const char *appId)
{
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(appId));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_APPID, appId, HcStrlen(appId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_UNREG_LISTENER, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        DelIpcCliCallbackCtx(appId, &g_ipcCredListenerCbList);
        ret = RemoveCallbackInfoFromList(appId, CRED_CHANGE_LISTENER);
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmExportCredential(int32_t osAccountId, const char *credId, char **returnData)
{
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    int32_t inOutLen;
    char *outInfo = NULL;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(credId) || returnData == NULL);
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_CRED_ID, credId, HcStrlen(credId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_EXPORT_CREDENTIAL, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_CRED_VAL, outInfo);
        *returnData = strdup(outInfo);
        if (*returnData == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);
    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmQueryCredByParams(int32_t osAccountId, const char *requestParams, char **returnCredList)
{
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;
    int32_t ret;
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(requestParams) || returnCredList == NULL);
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_QUERY_PARAMS, requestParams, HcStrlen(requestParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_PARAMS, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_CRED_INFO_LIST, outInfo);
        *returnCredList = strdup(outInfo);
        if (*returnCredList == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);
    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmQueryCredInfoByCredId(int32_t osAccountId, const char *credId, char **returnCredInfo)
{
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;
    int32_t ret;
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(credId) || returnCredInfo == NULL);
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_CRED_ID, credId, HcStrlen(credId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_CRED_ID, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_CRED_INFO, outInfo);
        *returnCredInfo = strdup(outInfo);
        if (*returnCredInfo == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmDeleteCredential(int32_t osAccountId, const char *credId)
{
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(credId));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_CRED_ID, credId, HcStrlen(credId) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_DEL_CREDENTIAL, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);

    DESTROY_IPC_CTX(callCtx);
    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmUpdateCredInfo(int32_t osAccountId, const char *credId, const char *requestParams)
{
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(credId) || IsStrInvalid(requestParams));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_CRED_ID, credId, HcStrlen(credId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQUEST_PARAMS, requestParams, HcStrlen(requestParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_UPDATE_CRED_INFO, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);

    DESTROY_IPC_CTX(callCtx);
    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmAgreeCredential(int32_t osAccountId, const char *selfCredId, const char *requestParams,
    char **returnData)
{
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    char *outInfo = NULL;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(selfCredId) ||
        IsStrInvalid(requestParams) || returnData == NULL);
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_CRED_ID, selfCredId, HcStrlen(selfCredId) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQUEST_PARAMS, requestParams, HcStrlen(requestParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_AGREE_CREDENTIAL, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_CRED_ID, outInfo);
        *returnData = strdup(outInfo);
        if (*returnData == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmDelCredByParams(int32_t osAccountId, const char *requestParams, char **returnData)
{
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(requestParams) || returnData == NULL);
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQUEST_PARAMS, requestParams, HcStrlen(requestParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_DEL_CRED_BY_PARAMS, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_CRED_INFO_LIST, outInfo);
        *returnData = strdup(outInfo);
        if (*returnData == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmBatchUpdateCredentials(int32_t osAccountId, const char *requestParams, char **returnData)
{
    RegisterDevAuthCallbackIfNeed();
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };
    char *outInfo = NULL;
    int32_t inOutLen;

    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(IsStrInvalid(requestParams) || returnData == NULL);
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQUEST_PARAMS, requestParams, HcStrlen(requestParams) + 1);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CM_BATCH_UPDATE_CREDENTIALS, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
        BREAK_IF_GET_IPC_RESULT_NUM_FAILED(replyCache, PARAM_TYPE_IPC_RESULT_NUM, IPC_RESULT_NUM_1);
        BREAK_IF_GET_IPC_REPLY_STR_FAILED(replyCache, PARAM_TYPE_CRED_INFO_LIST, outInfo);
        *returnData = strdup(outInfo);
        if (*returnData == NULL) {
            ret = HC_ERR_ALLOC_MEMORY;
            break;
        }
    } while (0);
    DESTROY_IPC_CTX(callCtx);

    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static bool IsJsonString(const char *str)
{
    CJson *json = CreateJsonFromString(str);
    if (json == NULL) {
        LOGE("Input str is not json str.");
        return false;
    }
    FreeJson(json);
    return true;
}

static void IpcCmDestroyInfo(char **returnData)
{
    if (returnData == NULL || *returnData == NULL) {
        return;
    }
    if (IsJsonString(*returnData)) {
        FreeJsonString(*returnData);
    } else {
        HcFree(*returnData);
    }
    *returnData = NULL;
}

static void InitIpcCmMethods(CredManager *cmMethodObj)
{
    cmMethodObj->addCredential = IpcCmAddCredential;
    cmMethodObj->exportCredential = IpcCmExportCredential;
    cmMethodObj->registerChangeListener = IpcCmRegChangeListener;
    cmMethodObj->unregisterChangeListener = IpcCmUnRegChangeListener;
    cmMethodObj->queryCredentialByParams = IpcCmQueryCredByParams;
    cmMethodObj->queryCredInfoByCredId = IpcCmQueryCredInfoByCredId;
    cmMethodObj->deleteCredential = IpcCmDeleteCredential;
    cmMethodObj->updateCredInfo = IpcCmUpdateCredInfo;
    cmMethodObj->agreeCredential = IpcCmAgreeCredential;
    cmMethodObj->deleteCredByParams = IpcCmDelCredByParams;
    cmMethodObj->batchUpdateCredentials = IpcCmBatchUpdateCredentials;
    cmMethodObj->destroyInfo = IpcCmDestroyInfo;
    return;
}

static int32_t IpcCmAuthCredential(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *caCallback)
{
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED((IsStrInvalid(authParams) || (caCallback == NULL)));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, &osAccountId, sizeof(osAccountId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &authReqId, sizeof(authReqId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_AUTH_PARAMS, authParams, HcStrlen(authParams) + 1);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEV_AUTH_CB, caCallback, sizeof(*caCallback));
        SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_AUTH_ID);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CA_AUTH_CREDENTIAL, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);
    LOGI("process done, ret: %" LOG_PUB "d", ret);
    DestroyCallCtx(&callCtx);
    return ret;
}

static int32_t IpcCmProcessCredData(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *callback)
{
    LOGI("starting ...");
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache[IPC_DATA_CACHES_1] = { { 0 } };
    RETURN_INT_IF_CHECK_IPC_PARAMS_FAILED(!IS_COMM_DATA_VALID(data, dataLen) || (callback == NULL));
    RETURN_INT_IF_CREATE_IPC_CTX_FAILED(callCtx);
    do {
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_REQID, &authReqId, sizeof(authReqId));
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_COMM_DATA, data, dataLen);
        BREAK_IF_SET_IPC_PARAM_FAILED(callCtx, PARAM_TYPE_DEV_AUTH_CB, callback, sizeof(*callback));
        SetCbCtxToDataCtx(callCtx, 0x0);
        BREAK_IF_DO_IPC_CALL_FAILED(callCtx, IPC_CALL_ID_CA_PROCESS_CRED_DATA, true);
        DecodeCallReply(callCtx, replyCache, REPLAY_CACHE_NUM(replyCache));
        BREAK_IF_CHECK_IPC_RESULT_FAILED(replyCache, ret);
    } while (0);
    DESTROY_IPC_CTX(callCtx);
    LOGI("process done, ret: %" LOG_PUB "d", ret);
    return ret;
}

static void InitIpcCaMethods(CredAuthManager *caMethodObj)
{
    caMethodObj->authCredential = IpcCmAuthCredential;
    caMethodObj->processCredData = IpcCmProcessCredData;
    return;
}

int32_t InitISIpc(void)
{
    int32_t ret = InitHcMutex(&g_ipcMutex, false);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    SetRegCredChangeListenerFunc(IpcCmRegChangeListenerInner);
    return IS_SUCCESS;
}

void DeInitISIpc(void)
{
    DestroyHcMutex(&g_ipcMutex);
}

DEVICE_AUTH_API_PUBLIC const CredManager *GetCredMgrInstance(void)
{
    static CredManager cmInstCtx;
    static CredManager *cmInstPtr = NULL;

    if (cmInstPtr == NULL) {
        InitIpcCmMethods(&cmInstCtx);
        cmInstPtr = &cmInstCtx;
    }
    return (const CredManager *)(cmInstPtr);
}

DEVICE_AUTH_API_PUBLIC const CredAuthManager *GetCredAuthInstance(void)
{
    static CredAuthManager caInstCtx;
    static CredAuthManager *caInstPtr = NULL;

    if (caInstPtr == NULL) {
        InitIpcCaMethods(&caInstCtx);
        caInstPtr = &caInstCtx;
    }
    return (const CredAuthManager *)(caInstPtr);
}

#ifdef __cplusplus
}
#endif
