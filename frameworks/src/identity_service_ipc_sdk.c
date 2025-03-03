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
    (void)LockHcMutex(&g_ipcMutex);
    ret = memcmp(appId, cbCache->appId, HcStrlen(cbCache->appId) + 1);
    if (ret == 0) {
        cbCache->appId[0] = 0;
    }
    UnlockHcMutex(&g_ipcMutex);
    return;
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

static int32_t EncodeAddCredentialParams(uintptr_t callCtx, int32_t osAccountId, const char *requestParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQUEST_PARAMS, (const uint8_t *)requestParams,
        HcStrlen(requestParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_REQUEST_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t AddCredentialIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **returnData)
{
    int32_t inOutLen;
    int32_t ret;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_CRED_ID, (uint8_t *)returnData, NULL);
    if (*returnData == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *returnData = strdup(*returnData);
    if (*returnData == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t AgreeCredentialIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **returnData)
{
    int32_t inOutLen;
    int32_t ret;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_CRED_ID, (uint8_t *)returnData, NULL);
    if (*returnData == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *returnData = strdup(*returnData);
    if (*returnData == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmAddCredential(int32_t osAccountId, const char *requestParams, char **returnData)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(requestParams) || returnData == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeAddCredentialParams(callCtx, osAccountId, requestParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_ADD_CREDENTIAL, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
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
    ret = AddCredentialIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), returnData);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return ret;
}

static int32_t IpcCmRegChangeListener(const char *appId, CredChangeListener *listener)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;

    LOGI("starting ...");
    if (IsStrInvalid(appId) || listener == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId,
        HcStrlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_LISTERNER, (const uint8_t *)listener,
        sizeof(*listener));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_LISTERNER);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    // why do this ?
    SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_BIND_ID);
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_REG_LISTENER, true);
    if (ret == HC_SUCCESS) {
        AddIpcCliCallbackCtx(appId, 0, &g_ipcCredListenerCbList);
    }
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return (ret == HC_SUCCESS) ? HC_SUCCESS : HC_ERR_IPC_PROC_FAILED;
}

static int32_t IpcCmUnRegChangeListener(const char *appId)
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
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_APPID, (const uint8_t *)appId,
        HcStrlen(appId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_APPID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_UNREG_LISTENER, true);
    if (ret == HC_SUCCESS) {
        DelIpcCliCallbackCtx(appId, &g_ipcCredListenerCbList);
    }
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return HC_SUCCESS;
}

static int32_t EncodeExportCredentialParams(uintptr_t callCtx, int32_t osAccountId, const char *credId)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_CRED_ID, (const uint8_t *)credId,
        HcStrlen(credId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_CRED_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t ExportCredentialIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **returnData)
{
    int32_t inOutLen;
    int32_t ret;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_CRED_VAL, (uint8_t *)returnData, NULL);
    if (*returnData == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *returnData = strdup(*returnData);
    if (*returnData == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmExportCredential(int32_t osAccountId, const char *credId, char **returnData)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(credId) || returnData == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeExportCredentialParams(callCtx, osAccountId, credId);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_EXPORT_CREDENTIAL, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
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
    ret = ExportCredentialIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), returnData);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return ret;
}

static int32_t SearchCredsIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **returnCredList)
{
    int32_t inOutLen;
    int32_t ret;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_CRED_INFO_LIST, (uint8_t *)returnCredList, NULL);
    if (*returnCredList == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *returnCredList = strdup(*returnCredList);
    if (*returnCredList == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmQueryCredByParams(int32_t osAccountId, const char *requestParams, char **returnCredList)
{
    uintptr_t callCtx = 0x0;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(requestParams) || returnCredList == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_QUERY_PARAMS, (const uint8_t *)requestParams,
        HcStrlen(requestParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_QUERY_PARAMS);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }

    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_PARAMS, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
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
    ret = SearchCredsIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), returnCredList);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return ret;
}

static int32_t SearchCredInfoIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **returnCredInfo)
{
    int32_t inOutLen;
    int32_t ret;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_CRED_INFO, (uint8_t *)returnCredInfo, NULL);
    if (*returnCredInfo == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *returnCredInfo = strdup(*returnCredInfo);
    if (*returnCredInfo == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmQueryCredInfoByCredId(int32_t osAccountId, const char *credId, char **returnCredInfo)
{
    uintptr_t callCtx = 0x0;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(credId) || returnCredInfo == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_CRED_ID, (const uint8_t *)credId,
        HcStrlen(credId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_QUERY_PARAMS);
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_BUILD_PARAM;
    }

    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_CRED_ID, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
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
    ret = SearchCredInfoIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), returnCredInfo);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t EncodeDeleteCredentialParams(uintptr_t callCtx, int32_t osAccountId, const char *credId)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_CRED_ID, (const uint8_t *)credId, HcStrlen(credId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_CRED_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmDeleteCredential(int32_t osAccountId, const char *credId)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(credId)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeDeleteCredentialParams(callCtx, osAccountId, credId);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_DEL_CREDENTIAL, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return ret;
}

static int32_t EncodeUpdateParams(uintptr_t callCtx, int32_t osAccountId, const char *credId, const char *requestParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_CRED_ID, (const uint8_t *)credId, HcStrlen(credId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_CRED_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQUEST_PARAMS, (const uint8_t *)requestParams,
        HcStrlen(requestParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_REQUEST_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmUpdateCredInfo(int32_t osAccountId, const char *credId, const char *requestParams)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(credId) || IsStrInvalid(requestParams)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeUpdateParams(callCtx, osAccountId, credId, requestParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_UPDATE_CRED_INFO, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    int32_t inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return ret;
}

static int32_t EncodeAgreeCredentialParams(uintptr_t callCtx, int32_t osAccountId, const char *selfCredId,
    const char *requestParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_CRED_ID, (const uint8_t *)selfCredId, HcStrlen(selfCredId) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_CRED_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQUEST_PARAMS, (const uint8_t *)requestParams,
        HcStrlen(requestParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_REQUEST_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmAgreeCredential(int32_t osAccountId, const char *selfCredId, const char *requestParams,
    char **returnData)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(selfCredId) || IsStrInvalid(requestParams) || returnData == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeAgreeCredentialParams(callCtx, osAccountId, selfCredId, requestParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_AGREE_CREDENTIAL, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
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
    ret = AgreeCredentialIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), returnData);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return ret;
}

static int32_t EncodeDelCredByParams(uintptr_t callCtx, int32_t osAccountId, const char *requestParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQUEST_PARAMS, (const uint8_t *)requestParams,
        HcStrlen(requestParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_REQUEST_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t DelCredByParamsIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **returnData)
{
    int32_t inOutLen;
    int32_t ret;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_CRED_INFO_LIST, (uint8_t *)returnData, NULL);
    if (*returnData == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *returnData = strdup(*returnData);
    if (*returnData == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmDelCredByParams(int32_t osAccountId, const char *requestParams, char **returnData)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(requestParams) || returnData == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeDelCredByParams(callCtx, osAccountId, requestParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_DEL_CRED_BY_PARAMS, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
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
    ret = DelCredByParamsIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), returnData);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return ret;
}

static int32_t EncodeBatchUpdateParam(uintptr_t callCtx, int32_t osAccountId, const char *requestParams)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQUEST_PARAMS, (const uint8_t *)requestParams,
        HcStrlen(requestParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_REQUEST_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    return HC_SUCCESS;
}

static int32_t BatchUpdateCredIpcResult(const IpcDataInfo *replies, int32_t cacheNum, char **returnData)
{
    int32_t inOutLen;
    int32_t ret;

    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_IPC_RESULT_NUM, (uint8_t *)&ret, &inOutLen);
    if ((ret < IPC_RESULT_NUM_1) || (inOutLen != sizeof(int32_t))) {
        return HC_ERR_IPC_OUT_DATA_NUM;
    }
    GetIpcReplyByType(replies, cacheNum, PARAM_TYPE_CRED_INFO_LIST, (uint8_t *)returnData, NULL);
    if (*returnData == NULL) {
        return HC_ERR_IPC_OUT_DATA;
    }
    *returnData = strdup(*returnData);
    if (*returnData == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t IpcCmBatchUpdateCredentials(int32_t osAccountId, const char *requestParams, char **returnData)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    IpcDataInfo replyCache[IPC_DATA_CACHES_3] = { { 0 } };

    LOGI("starting ...");
    if (IsStrInvalid(requestParams) || returnData == NULL) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeBatchUpdateParam(callCtx, osAccountId, requestParams);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CM_BATCH_UPDATE_CREDENTIALS, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
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
    ret = BatchUpdateCredIpcResult(replyCache, REPLAY_CACHE_NUM(replyCache), returnData);
    DestroyCallCtx(&callCtx, NULL);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    return ret;
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
    return;
}


static int32_t EncodeAuthDeviceParams(uintptr_t callCtx, int32_t osAccountId, int64_t authReqId,
    const char *authParams, const DeviceAuthCallback *callback)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_OS_ACCOUNT_ID, (const uint8_t *)&osAccountId,
        sizeof(osAccountId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, param id %" LOG_PUB "d", ret, PARAM_TYPE_OS_ACCOUNT_ID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&authReqId), sizeof(authReqId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, type %" LOG_PUB "d", ret, PARAM_TYPE_REQID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_AUTH_PARAMS, (const uint8_t *)authParams,
        HcStrlen(authParams) + 1);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, type %" LOG_PUB "d", ret, PARAM_TYPE_AUTH_PARAMS);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEV_AUTH_CB, (const uint8_t *)callback, sizeof(*callback));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, type %" LOG_PUB "d", ret, PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    SetCbCtxToDataCtx(callCtx, IPC_CALL_BACK_STUB_AUTH_ID);
    return HC_SUCCESS;
}

static int32_t IpcCmAuthCredential(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *caCallback)
{
    uintptr_t callCtx = 0x0;
    int32_t ret;
    int32_t inOutLen;
    IpcDataInfo replyCache = { 0 };

    LOGI("starting ...");
    if (IsStrInvalid(authParams) || (caCallback == NULL)) {
        LOGE("invalid params");
        return HC_ERR_INVALID_PARAMS;
    }
    ret = CreateCallCtx(&callCtx, NULL);
    if (ret != HC_SUCCESS) {
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeAuthDeviceParams(callCtx, osAccountId, authReqId, authParams, caCallback);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CA_AUTH_DEVICE, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static int32_t EncodeProcessDataParams(uintptr_t callCtx, int64_t authReqId,
    const uint8_t *data, uint32_t dataLen, const DeviceAuthCallback *callback)
{
    int32_t ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_REQID, (const uint8_t *)(&authReqId), sizeof(authReqId));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, type %" LOG_PUB "d", ret, PARAM_TYPE_REQID);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_COMM_DATA, (const uint8_t *)data, dataLen);
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, type %" LOG_PUB "d", ret, PARAM_TYPE_COMM_DATA);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    ret = SetCallRequestParamInfo(callCtx, PARAM_TYPE_DEV_AUTH_CB, (const uint8_t *)callback, sizeof(*callback));
    if (ret != HC_SUCCESS) {
        LOGE("set request param failed, ret %" LOG_PUB "d, type %" LOG_PUB "d", ret, PARAM_TYPE_DEV_AUTH_CB);
        return HC_ERR_IPC_BUILD_PARAM;
    }
    SetCbCtxToDataCtx(callCtx, 0x0);
    return HC_SUCCESS;
}

static int32_t IpcCmProcessCredData(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *callback)
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
        LOGE("CreateCallCtx failed, ret %" LOG_PUB "d", ret);
        return HC_ERR_IPC_INIT;
    }
    ret = EncodeProcessDataParams(callCtx, authReqId, data, dataLen, callback);
    if (ret != HC_SUCCESS) {
        DestroyCallCtx(&callCtx, NULL);
        return ret;
    }
    ret = DoBinderCall(callCtx, IPC_CALL_ID_CA_PROCESS_CRED_DATA, true);
    if (ret == HC_ERR_IPC_INTERNAL_FAILED) {
        LOGE("ipc call failed");
        DestroyCallCtx(&callCtx, NULL);
        return HC_ERR_IPC_PROC_FAILED;
    }
    DecodeCallReply(callCtx, &replyCache, REPLAY_CACHE_NUM(replyCache));
    ret = HC_ERR_IPC_UNKNOW_REPLY;
    inOutLen = sizeof(int32_t);
    GetIpcReplyByType(&replyCache, REPLAY_CACHE_NUM(replyCache), PARAM_TYPE_IPC_RESULT, (uint8_t *)&ret, &inOutLen);
    LOGI("process done, ret %" LOG_PUB "d", ret);
    DestroyCallCtx(&callCtx, NULL);
    return ret;
}

static void InitIpcCaMethods(CredAuthManager *caMethodObj)
{
    caMethodObj->authCredential = IpcCmAuthCredential;
    caMethodObj->processCredData = IpcCmProcessCredData;
    return;
}

void InitISIpc(void)
{
    InitHcMutex(&g_ipcMutex, false);
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
