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

#include "ipc_adapt.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "hc_mutex.h"
#include "ipc_callback_stub.h"
#include "ipc_dev_auth_proxy.h"
#include "ipc_dev_auth_stub.h"
#include "ipc_sdk_defines.h"
#include "ipc_service_lite.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include "string_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BUFF_MAX_SZ 128
#define IPC_CALL_BACK_MAX_NODES 64

typedef struct {
    int32_t callbackId;
    const IpcDataInfo *cbDataCache;
    int32_t cacheNum;
    IpcIo *reply;
} CallbackParams;

typedef void (*CallbackStub)(CallbackParams params);
typedef struct {
    int64_t requestId;
    char appId[BUFF_MAX_SZ];
    int32_t cbType;
    int32_t delOnFni;
    int32_t methodId;
    int32_t proxyId;
    int32_t nodeIdx;
} IpcCallBackNode;

static struct {
    IpcCallBackNode *ctx;
    int32_t nodeCnt;
} g_ipcCallBackList = {NULL, 0};

typedef struct {
    char appId[BUFF_MAX_SZ];
    uint8_t type;
    bool delCallBack;
    int64_t requestId;
    union {
        DeviceAuthCallback devAuth;
        DataChangeListener listener;
    } callback;
} SdkIpcCallBackNode;

DECLARE_HC_VECTOR(SdkIpcCallBackList, SdkIpcCallBackNode)
IMPLEMENT_HC_VECTOR(SdkIpcCallBackList, SdkIpcCallBackNode, 1)
static SdkIpcCallBackList g_sdkIpcCallBackList;

static HcMutex g_cbListLock;
static HcMutex g_cbSdkListLock;

static StubDevAuthCb g_sdkCbStub;
static IClientProxy *g_proxyInstance = NULL;
static IpcObjectStub g_objectStub;

int32_t InitSdkIpcCallBackList(void)
{
    g_sdkIpcCallBackList = CREATE_HC_VECTOR(SdkIpcCallBackList);
    (void)InitHcMutex(&g_cbSdkListLock, false);
    return HC_SUCCESS;
}

void DeInitSdkIpcCallBackList(void)
{
    DestroyHcMutex(&g_cbSdkListLock);
    DESTROY_HC_VECTOR(SdkIpcCallBackList, &g_sdkIpcCallBackList);
}

int32_t AddSdkCallBackByAppId(const char *appId, uint8_t cbType, uint8_t *val, int32_t valSize)
{
    (void)LockHcMutex(&g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = NULL;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == NULL || entry->appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(entry->appId, appId) && entry->type == cbType) {
            LOGW("start to update callback, appId: %" LOG_PUB "s, cbType: %" LOG_PUB "u", appId, cbType);
            if (memcpy_s(&entry->callback, sizeof(entry->callback), val, valSize) != EOK) {
                UnlockHcMutex(&g_cbSdkListLock);
                return HC_ERR_MEMORY_COPY;
            }
            UnlockHcMutex(&g_cbSdkListLock);
            return HC_SUCCESS;
        }
    }
    SdkIpcCallBackNode node;
    if (memcpy_s(&node.callback, sizeof(node.callback), val, valSize) != EOK) {
        UnlockHcMutex(&g_cbSdkListLock);
        LOGE("copy callback failed.");
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(&node.appId, sizeof(node.appId), appId, HcStrlen(appId) + 1) != EOK) {
        memset_s(&node, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
        UnlockHcMutex(&g_cbSdkListLock);
        LOGE("copy appId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    node.delCallBack = false;
    node.type = cbType;
    if (g_sdkIpcCallBackList.pushBack(&g_sdkIpcCallBackList, &node) == NULL) {
        memset_s(&node, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
        UnlockHcMutex(&g_cbSdkListLock);
        LOGE("Failed ot add callback node");
        return HC_ERR_ALLOC_MEMORY;
    }
    UnlockHcMutex(&g_cbSdkListLock);
    LOGI("AddSdkCallBackByAppId successfully, size: %" LOG_PUB "d, appId: %" LOG_PUB "s, cbType: %" LOG_PUB "u",
        g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList), appId, cbType);
    return HC_SUCCESS;
}

int32_t AddSdkCallBackByRequestId(int64_t requestId, uint8_t cbType, uint8_t *val, int32_t valSize)
{
    (void)LockHcMutex(&g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = NULL;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == NULL) {
            continue;
        }
        if (entry->requestId == requestId && entry->type == cbType) {
            LOGW("start to update callback, requestId: %" LOG_PUB PRId64 ", cbType: %" LOG_PUB "u", requestId, cbType);
            if (memcpy_s(&entry->callback, sizeof(entry->callback), val, valSize) != EOK) {
                UnlockHcMutex(&g_cbSdkListLock);
                return HC_ERR_MEMORY_COPY;
            }
            UnlockHcMutex(&g_cbSdkListLock);
            return HC_SUCCESS;
        }
    }
    SdkIpcCallBackNode node;
    if (memcpy_s(&node.callback, sizeof(node.callback), val, valSize) != EOK) {
        LOGE("copy callback failed.");
        UnlockHcMutex(&g_cbSdkListLock);
        return HC_ERR_MEMORY_COPY;
    }
    node.type = cbType;
    node.requestId = requestId;
    node.delCallBack = true;
    if (g_sdkIpcCallBackList.pushBack(&g_sdkIpcCallBackList, &node) == NULL) {
        memset_s(&node, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
        LOGE("Failed to add callback node");
        UnlockHcMutex(&g_cbSdkListLock);
        return HC_ERR_ALLOC_MEMORY;
    }
    LOGI("AddSdkCallBackByRequestId successfully, size: %" LOG_PUB "d, requestId: %" LOG_PUB PRId64 ","
        "cbType: %" LOG_PUB "u", g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList), requestId, cbType);
    UnlockHcMutex(&g_cbSdkListLock);
    return HC_SUCCESS;
}

static uint8_t GetCbType(int32_t callbackId)
{
    if (callbackId >= CB_ID_ON_TRANS && callbackId <= CB_ID_ON_REQUEST) {
        return CB_TYPE_DEV_AUTH;
    } else if (callbackId >= CB_ID_ON_TRANS_TMP && callbackId <= CB_ID_ON_REQUEST_TMP) {
        return CB_TYPE_TMP_DEV_AUTH;
    }
    return 0;
}

static int32_t GetSdkCallBackByRequestId(int64_t callbackId, int64_t requestId, uint8_t *val, int32_t valSize)
{
    LOGI("requestId: %" LOG_PUB PRId64 ", callbackId: %" LOG_PUB PRId64 ".", requestId, callbackId);
    uint8_t cbType = GetCbType(callbackId);
    if (cbType == 0) {
        return HC_ERR_IPC_CALLBACK_NOT_MATCH;
    }
    uint32_t index;
    (void)LockHcMutex(&g_cbSdkListLock);
    SdkIpcCallBackNode *entry = NULL;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == NULL) {
            continue;
        }
        if (entry->requestId == requestId && entry->type == cbType) {
            if (memcpy_s(val, valSize, &entry->callback, valSize) != EOK) {
                LOGE("copy callback failed.");
                UnlockHcMutex(&g_cbSdkListLock);
                return HC_ERR_MEMORY_COPY;
            }
            UnlockHcMutex(&g_cbSdkListLock);
            return HC_SUCCESS;
        }
    }
    LOGE("callback not found.");
    UnlockHcMutex(&g_cbSdkListLock);
    return HC_ERR_IPC_CALLBACK_NOT_MATCH;
}

static int32_t GetSdkCallBackByAppId(const char *appId, uint8_t cbType, uint8_t *val, int32_t valSize)
{
    (void)LockHcMutex(&g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = NULL;
    LOGI("appId: %" LOG_PUB "s, cbType: %" LOG_PUB "u", appId, cbType);
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == NULL || entry->appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(entry->appId, appId) && entry->type == cbType) {
            if (memcpy_s(val, valSize, &entry->callback, valSize) != EOK) {
                UnlockHcMutex(&g_cbSdkListLock);
                LOGE("copy callback failed.");
                return HC_ERR_MEMORY_COPY;
            }
            UnlockHcMutex(&g_cbSdkListLock);
            return HC_SUCCESS;
        }
    }
    LOGW("callback not found, cbType: %" LOG_PUB "u", cbType);
    UnlockHcMutex(&g_cbSdkListLock);
    return HC_ERR_IPC_CALLBACK_NOT_MATCH;
}

static void RemoveSdkCallBackByCallBackId(int64_t callbackId, int64_t requestId)
{
    LOGI("requestId: %" LOG_PUB PRId64 ", callbackId: %" LOG_PUB PRId64 "", requestId, callbackId);
    uint8_t cbType = GetCbType(callbackId);
    if (cbType == 0) {
        return;
    }
    RemoveSdkCallBackByRequestId(requestId, cbType);
}

int32_t AddRequestIdByAppId(const char *appId, int64_t requestId)
{
    (void)LockHcMutex(&g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = NULL;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == NULL || entry->appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(entry->appId, appId) && entry->type == CB_TYPE_DEV_AUTH) {
            LOGI("AddRequestIdByAppId successfully, requestId: %" LOG_PUB PRId64 ", appId: %" LOG_PUB "s",
                requestId, appId);
            entry->requestId = requestId;
            UnlockHcMutex(&g_cbSdkListLock);
            return HC_SUCCESS;
        }
    }
    UnlockHcMutex(&g_cbSdkListLock);
    LOGE("callback not found.");
    return HC_ERR_IPC_CALLBACK_NOT_MATCH;
}

void RemoveSdkCallBackByAppId(const char *appId, uint8_t cbType)
{
    (void)LockHcMutex(&g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = NULL;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == NULL || entry->appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(entry->appId, appId) && entry->type == cbType) {
            SdkIpcCallBackNode deleteNode;
            HC_VECTOR_POPELEMENT(&g_sdkIpcCallBackList, &deleteNode, index);
            LOGI("deleteNode appId : %" LOG_PUB "s, requestId : %" LOG_PUB PRId64 ", cbType : %" LOG_PUB "u",
                deleteNode.appId, deleteNode.requestId, cbType);
            (void)memset_s(&deleteNode, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
            LOGI("g_sdkIpcCallBackList size : %" LOG_PUB "d", g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList));
            UnlockHcMutex(&g_cbSdkListLock);
            return;
        }
    }
    LOGW("callback not found.");
    UnlockHcMutex(&g_cbSdkListLock);
    return;
}

void RemoveSdkCallBackByRequestId(int64_t requestId, uint8_t cbType)
{
    (void)LockHcMutex(&g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = NULL;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == NULL) {
            continue;
        }
        if (entry->requestId == requestId && entry->type == cbType && entry->delCallBack) {
            SdkIpcCallBackNode deleteNode;
            HC_VECTOR_POPELEMENT(&g_sdkIpcCallBackList, &deleteNode, index);
            LOGI("deleteNode appId : %" LOG_PUB "s, requestId : %" LOG_PUB PRId64 ", cbType : %" LOG_PUB "u",
                deleteNode.appId, requestId, cbType);
            (void)memset_s(&deleteNode, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
            LOGI("g_sdkIpcCallBackList size : %" LOG_PUB "d", g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList));
            UnlockHcMutex(&g_cbSdkListLock);
            return;
        }
    }
    LOGW("callback not fuond.");
    UnlockHcMutex(&g_cbSdkListLock);
    return;
}

int32_t GetAndValSize32Param(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, paramSize);
    if ((*paramSize) != sizeof(int32_t) || ret != HC_SUCCESS) {
        LOGE("get param error, type %" LOG_PUB "d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

int32_t GetAndValSize64Param(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, paramSize);
    if ((*paramSize) != sizeof(int64_t) || ret != HC_SUCCESS) {
        LOGE("get param error, type %" LOG_PUB "d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

int32_t GetAndValSizeCbParam(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, paramSize);
    if ((*paramSize) != sizeof(DeviceAuthCallback) || ret != HC_SUCCESS) {
        LOGE("get param error, type %" LOG_PUB "d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

int32_t GetAndValNullParam(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    (void)paramSize;
    int32_t size = 0;
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, &size);
    if ((ret != HC_SUCCESS) || (param == NULL) || (size <= 0)) {
        LOGE("get param error, type %" LOG_PUB "d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    char *str = (*(char **)param);
    if ((str == NULL) || (str[size - 1] != '\0')) {
        LOGE("The input parameter is not a valid string type.");
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

static void SetIpcCallBackNodeDefault(IpcCallBackNode *node)
{
    (void)memset_s(node, sizeof(IpcCallBackNode), 0, sizeof(IpcCallBackNode));
    node->proxyId = -1;
    node->nodeIdx = -1;
    return;
}

int32_t InitIpcCallBackList(void)
{
    int32_t i;

    LOGI("initializing ...");
    if (g_ipcCallBackList.ctx != NULL) {
        LOGI("has initialized");
        return HC_SUCCESS;
    }

    g_ipcCallBackList.ctx = HcMalloc(sizeof(IpcCallBackNode) * IPC_CALL_BACK_MAX_NODES, 0);
    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("initialized failed");
        return HC_ERROR;
    }
    for (i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        SetIpcCallBackNodeDefault(g_ipcCallBackList.ctx + i);
    }
    (void)InitHcMutex(&g_cbListLock, false);
    g_ipcCallBackList.nodeCnt = 0;
    LOGI("initialized successful");
    return HC_SUCCESS;
}

static void ResetIpcCallBackNode(IpcCallBackNode *node)
{
    ResetRemoteObject(node->proxyId);
    SetIpcCallBackNodeDefault(node);
    return;
}

static void LockCallbackList(void)
{
    (void)LockHcMutex(&g_cbListLock);
    return;
}

static void UnLockCallbackList(void)
{
    UnlockHcMutex(&g_cbListLock);
    return;
}

void DeInitIpcCallBackList(void)
{
    int32_t i;

    if (g_ipcCallBackList.ctx == NULL) {
        return;
    }
    for (i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        ResetIpcCallBackNode(g_ipcCallBackList.ctx + i);
    }
    HcFree((void *)g_ipcCallBackList.ctx);
    g_ipcCallBackList.ctx = NULL;
    DestroyHcMutex(&g_cbListLock);
    return;
}

void ResetIpcCallBackNodeByNodeId(int32_t nodeIdx)
{
    LOGI("starting..., index %" LOG_PUB "d", nodeIdx);
    if ((nodeIdx < 0) || (nodeIdx >= IPC_CALL_BACK_MAX_NODES)) {
        return;
    }
    if (g_ipcCallBackList.ctx == NULL) {
        return;
    }
    LockCallbackList();
    ResetIpcCallBackNode(g_ipcCallBackList.ctx + nodeIdx);
    UnLockCallbackList();
    LOGI("done, index %" LOG_PUB "d", nodeIdx);
    return;
}

static IpcCallBackNode *GetIpcCallBackByAppId(const char *appId, int32_t type)
{
    int32_t i;

    LOGI("appid: %" LOG_PUB "s", appId);
    for (i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(g_ipcCallBackList.ctx[i].appId, appId) && (g_ipcCallBackList.ctx[i].cbType == type)) {
            return &g_ipcCallBackList.ctx[i];
        }
    }
    return NULL;
}

static IpcCallBackNode *GetFreeIpcCallBackNode(void)
{
    int32_t i;

    for (i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if ((g_ipcCallBackList.ctx[i].appId[0] == 0) && (g_ipcCallBackList.ctx[i].cbType == 0)) {
            g_ipcCallBackList.ctx[i].nodeIdx = i;
            return &g_ipcCallBackList.ctx[i];
        }
    }
    return NULL;
}

static void SetCbDeathRecipient(int32_t type, int32_t objIdx, int32_t cbDataIdx)
{
    if ((type == CB_TYPE_DEV_AUTH) || (type == CB_TYPE_LISTENER)) {
        AddCbDeathRecipient(objIdx, cbDataIdx);
    }
    return;
}

void AddIpcCbObjByAppId(const char *appId, int32_t objIdx, int32_t type)
{
    IpcCallBackNode *node = NULL;

    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("list not inited");
        return;
    }

    LockCallbackList();
    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        UnLockCallbackList();
        LOGE("list is full");
        return;
    }

    node = GetIpcCallBackByAppId(appId, type);
    if (node != NULL) {
        node->proxyId = objIdx;
        SetCbDeathRecipient(type, objIdx, node->nodeIdx);
        LOGI("ipc object add success, appid: %" LOG_PUB "s, proxyId %" LOG_PUB "d", appId, node->proxyId);
    }
    UnLockCallbackList();
    return;
}

int32_t AddIpcCallBackByAppId(const char *appId, int32_t type)
{
    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("list not inited");
        return HC_ERROR;
    }

    LockCallbackList();
    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        UnLockCallbackList();
        LOGE("list is full");
        return HC_ERROR;
    }

    IpcCallBackNode *node = GetIpcCallBackByAppId(appId, type);
    if (node != NULL) {
        if (node->proxyId >= 0) {
            ResetRemoteObject(node->proxyId);
            node->proxyId = -1;
        }
        UnLockCallbackList();
        return HC_SUCCESS;
    }

    node = GetFreeIpcCallBackNode();
    if (node == NULL) {
        UnLockCallbackList();
        LOGE("get free node failed");
        return HC_ERROR;
    }
    node->cbType = type;
    if (memcpy_s(&(node->appId), sizeof(node->appId), appId, HcStrlen(appId) + 1) != EOK) {
        ResetIpcCallBackNode(node);
        UnLockCallbackList();
        LOGE("appid memory copy failed");
        return HC_ERROR;
    }
    node->proxyId = -1;
    g_ipcCallBackList.nodeCnt++;
    UnLockCallbackList();
    return HC_SUCCESS;
}

void DelIpcCallBackByAppId(const char *appId, int32_t type)
{
    IpcCallBackNode *node = NULL;

    if ((g_ipcCallBackList.nodeCnt <= 0) || (g_ipcCallBackList.ctx == NULL)) {
        return;
    }

    LockCallbackList();
    node = GetIpcCallBackByAppId(appId, type);
    if (node != NULL) {
        ResetIpcCallBackNode(node);
        g_ipcCallBackList.nodeCnt--;
    }
    UnLockCallbackList();
    return;
}

static IpcCallBackNode *GetIpcCallBackByReqId(int64_t reqId, int32_t type)
{
    int32_t i;

    for (i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if ((reqId == g_ipcCallBackList.ctx[i].requestId) &&
            (g_ipcCallBackList.ctx[i].cbType == type)) {
            return &g_ipcCallBackList.ctx[i];
        }
    }
    return NULL;
}

int32_t AddReqIdByAppId(const char *appId, int64_t reqId)
{
    IpcCallBackNode *node = NULL;

    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("ipc callback list not inited");
        return HC_ERROR;
    }

    LockCallbackList();
    node = GetIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
    if (node == NULL) {
        UnLockCallbackList();
        LOGE("ipc callback node not found, appid: %" LOG_PUB "s", appId);
        return HC_ERROR;
    }
    node->requestId = reqId;
    node->delOnFni = 0;
    UnLockCallbackList();
    LOGI("success, appid: %" LOG_PUB "s, requestId: %" LOG_PUB PRId64, appId, reqId);
    return HC_SUCCESS;
}

void AddIpcCbObjByReqId(int64_t reqId, int32_t objIdx, int32_t type)
{
    IpcCallBackNode *node = NULL;

    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("list not inited");
        return;
    }

    LockCallbackList();
    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        UnLockCallbackList();
        LOGE("list is full");
        return;
    }

    node = GetIpcCallBackByReqId(reqId, type);
    if (node != NULL) {
        node->proxyId = objIdx;
        LOGI("ipc object add success, request id %" LOG_PUB PRId64 ", type %" LOG_PUB "d, proxy id %" LOG_PUB "d",
            reqId, type, node->proxyId);
    }
    UnLockCallbackList();
    return;
}

int32_t AddIpcCallBackByReqId(int64_t reqId, int32_t type)
{
    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("list is full");
        return HC_ERROR;
    }

    LockCallbackList();
    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        UnLockCallbackList();
        LOGE("list is full");
        return HC_ERROR;
    }

    IpcCallBackNode *node = GetIpcCallBackByReqId(reqId, type);
    if (node != NULL) {
        if (node->proxyId >= 0) {
            ResetRemoteObject(node->proxyId);
            node->proxyId = -1;
        }
        UnLockCallbackList();
        return HC_SUCCESS;
    }

    node = GetFreeIpcCallBackNode();
    if (node == NULL) {
        UnLockCallbackList();
        LOGE("get free node failed");
        return HC_ERROR;
    }
    node->cbType = type;
    node->requestId = reqId;
    node->delOnFni = 1;
    node->proxyId = -1;
    g_ipcCallBackList.nodeCnt++;
    UnLockCallbackList();
    return HC_SUCCESS;
}

static void DelCallBackByReqId(int64_t reqId, int32_t type)
{
    IpcCallBackNode *node = NULL;

    if ((g_ipcCallBackList.nodeCnt <= 0) || (g_ipcCallBackList.ctx == NULL)) {
        return;
    }

    node = GetIpcCallBackByReqId(reqId, type);
    if ((node != NULL) && (node->delOnFni == 1)) {
        ResetIpcCallBackNode(node);
        g_ipcCallBackList.nodeCnt--;
    }
    return;
}

void DelIpcCallBackByReqId(int64_t reqId, int32_t type, bool withLock)
{
    if (withLock) {
        LockCallbackList();
        DelCallBackByReqId(reqId, type);
        UnLockCallbackList();
        return;
    }
    DelCallBackByReqId(reqId, type);
    return;
}

static void OnTransmitStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t inOutLen = sizeof(requestId);
    uint8_t *data = NULL;
    uint32_t dataLen = 0u;
    bool bRet = false;
    DeviceAuthCallback callback;
    int32_t ret;

    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        (uint8_t *)(&requestId), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_COMM_DATA, (uint8_t *)&data, (int32_t *)(&dataLen));
    ret = GetSdkCallBackByRequestId(params.callbackId, requestId, (uint8_t *)(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        WriteInt32(params.reply, ret);
        return;
    }
    if (callback.onTransmit != NULL) {
        bRet = callback.onTransmit(requestId, data, dataLen);
        LOGI("onTransmit successfully.");
        (bRet == true) ? WriteInt32(params.reply, HC_SUCCESS) : WriteInt32(params.reply, HC_ERROR);
    }
    return;
}

static void OnSessKeyStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t inOutLen = sizeof(requestId);
    uint8_t *keyData = NULL;
    uint32_t dataLen = 0u;
    int32_t ret;
    DeviceAuthCallback callback;

    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        (uint8_t *)(&requestId), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_SESS_KEY,
        (uint8_t *)(&keyData), (int32_t *)(&dataLen));
    ret = GetSdkCallBackByRequestId(params.callbackId, requestId, (uint8_t *)(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        return;
    }
    if (callback.onSessionKeyReturned != NULL) {
        callback.onSessionKeyReturned(requestId, keyData, dataLen);
        WriteInt32(params.reply, HC_SUCCESS);
        LOGI("onSessionKeyReturned successfully.");
    }
    return;
}

static void OnFinishStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t opCode = 0;
    int32_t inOutLen;
    char *data = NULL;
    DeviceAuthCallback callback;
    int32_t ret;

    inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        (uint8_t *)(&requestId), &inOutLen);
    inOutLen = sizeof(opCode);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_OPCODE,
        (uint8_t *)(&opCode), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_COMM_DATA, (uint8_t *)(&data), NULL);
    ret = GetSdkCallBackByRequestId(params.callbackId, requestId, (uint8_t *)(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        return;
    }
    if (callback.onFinish != NULL) {
        callback.onFinish(requestId, opCode, data);
        RemoveSdkCallBackByCallBackId(params.callbackId, requestId);
        WriteInt32(params.reply, HC_SUCCESS);
        LOGI("onFinish successfully.");
    }
    return;
}

static void OnErrorStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t opCode = 0;
    int32_t errCode = 0;
    int32_t inOutLen;
    char *errInfo = NULL;
    int32_t ret;
    DeviceAuthCallback callback;

    inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        (uint8_t *)(&requestId), &inOutLen);
    inOutLen = sizeof(opCode);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_OPCODE,
        (uint8_t *)(&opCode), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_ERRCODE,
        (uint8_t *)(&errCode), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_ERR_INFO,
        (uint8_t *)(&errInfo), NULL);
    ret = GetSdkCallBackByRequestId(params.callbackId, requestId, (uint8_t *)(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        WriteInt32(params.reply, ret);
        return;
    }
    if (callback.onError != NULL) {
        callback.onError(requestId, opCode, errCode, errInfo);
        RemoveSdkCallBackByCallBackId(params.callbackId, requestId);
        LOGI("onError successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
    }
    return;
}

static void OnRequestStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t opCode = 0;
    int32_t inOutLen;
    char *reqParams = NULL;
    char *reqResult = NULL;
    int32_t ret;
    DeviceAuthCallback callback;

    inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        (uint8_t *)(&requestId), &inOutLen);
    inOutLen = sizeof(opCode);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_OPCODE,
        (uint8_t *)(&opCode), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQ_INFO,
        (uint8_t *)(&reqParams), NULL);

    ret = GetSdkCallBackByRequestId(params.callbackId, requestId, (uint8_t *)(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        WriteInt32(params.reply, ret);
        return;
    }
    if (callback.onRequest != NULL) {
        reqResult = callback.onRequest(requestId, opCode, reqParams);
        if (reqResult == NULL) {
            WriteInt32(params.reply, HC_ERROR);
            return;
        }
        LOGI("onRequest successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
        WriteString(params.reply, (const char *)(reqResult));
        HcFree(reqResult);
        reqResult = NULL;
    }
    return;
}

static void OnGroupCreatedStub(CallbackParams params)
{
    const char *groupInfo = NULL;
    const char *appId = NULL;
    DataChangeListener callback;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_GROUP_INFO, (uint8_t *)(&groupInfo), NULL);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        (uint8_t *)(&appId), NULL);

    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, (uint8_t *)(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onGroupCreated != NULL) {
        callback.onGroupCreated(groupInfo);
        LOGI("onGroupCreated successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
    }
    return;
}

static void OnGroupDeletedStub(CallbackParams params)
{
    const char *groupInfo = NULL;
    const char *appId = NULL;
    DataChangeListener callback;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_GROUP_INFO, (uint8_t *)(&groupInfo), NULL);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        (uint8_t *)(&appId), NULL);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, (uint8_t *)(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onGroupDeleted != NULL) {
        callback.onGroupDeleted(groupInfo);
        LOGI("onGroupDeleted successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
    }
    return;
}

static void OnDevBoundStub(CallbackParams params)
{
    const char *groupInfo = NULL;
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_GROUP_INFO, (uint8_t *)(&groupInfo), NULL);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        (uint8_t *)(&appId), NULL);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, (uint8_t *)(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onDeviceBound != NULL) {
        callback.onDeviceBound(udid, groupInfo);
        LOGI("onDeviceBound successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
    }
    return;
}

static void OnDevUnboundStub(CallbackParams params)
{
    const char *groupInfo = NULL;
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_GROUP_INFO, (uint8_t *)(&groupInfo), NULL);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        (uint8_t *)(&appId), NULL);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, (uint8_t *)(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onDeviceUnBound != NULL) {
        callback.onDeviceUnBound(udid, groupInfo);
        LOGI("onDeviceUnBound successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
    }
    return;
}

static void OnDevUnTrustStub(CallbackParams params)
{
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        (uint8_t *)(&appId), NULL);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, (uint8_t *)(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onDeviceNotTrusted != NULL) {
        callback.onDeviceNotTrusted(udid);
        LOGI("onDeviceNotTrusted successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
    }
    return;
}

static void OnDelLastGroupStub(CallbackParams params)
{
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;
    int32_t groupType = 0;
    int32_t inOutLen = 0;
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);
    inOutLen = sizeof(groupType);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_GROUP_TYPE, (uint8_t *)(&groupType), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        (uint8_t *)(&appId), NULL);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, (uint8_t *)(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onLastGroupDeleted != NULL) {
        callback.onLastGroupDeleted(udid, groupType);
        LOGI("onLastGroupDeleted successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
    }
    return;
}

static void OnTrustDevNumChangedStub(CallbackParams params)
{
    const char *appId = NULL;
    DataChangeListener callback;
    int32_t devNum = 0;
    int32_t inOutLen = 0;

    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_DATA_NUM, (uint8_t *)(&devNum), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        (uint8_t *)(&appId), NULL);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, (uint8_t *)(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onTrustedDeviceNumChanged != NULL) {
        callback.onTrustedDeviceNumChanged(devNum);
        LOGI("onTrustedDeviceNumChanged successfully.");
        WriteInt32(params.reply, HC_SUCCESS);
    }
    return;
}

void ProcCbHook(int32_t callbackId, const IpcDataInfo *cbDataCache, int32_t cacheNum, uintptr_t replyCtx)
{
    CallbackStub stubTable[] = {
        OnTransmitStub, OnSessKeyStub, OnFinishStub, OnErrorStub,
        OnRequestStub, OnGroupCreatedStub, OnGroupDeletedStub, OnDevBoundStub,
        OnDevUnboundStub, OnDevUnTrustStub, OnDelLastGroupStub, OnTrustDevNumChangedStub,
        OnTransmitStub, OnSessKeyStub, OnFinishStub, OnErrorStub, OnRequestStub,
    };
    IpcIo *reply = (IpcIo *)(replyCtx);
    if ((callbackId < CB_ID_ON_TRANS) || (callbackId > CB_ID_ON_REQUEST_TMP)) {
        LOGE("Invalid call back id");
        return;
    }
    LOGI("call service callback start. CbId: %" LOG_PUB "d", callbackId);
    CallbackParams params = { callbackId, cbDataCache, cacheNum, reply };
    stubTable[callbackId - 1](params);
    LOGI("call service callback end");
    return;
}

static uint32_t EncodeCallData(IpcIo *dataParcel, int32_t type, const uint8_t *param, int32_t paramSz)
{
    const uint8_t *paramTmp = NULL;
    int32_t zeroVal = 0;

    paramTmp = param;
    if ((param == NULL) || (paramSz == 0)) {
        paramTmp = (const uint8_t *)(&zeroVal);
        paramSz = sizeof(zeroVal);
    }
    WriteInt32(dataParcel, type);
    WriteUint32(dataParcel, (uint32_t)paramSz);
    bool ret = WriteBuffer(dataParcel, (const void *)(paramTmp), (uint32_t)paramSz);
    if (!ret) {
        return (uint32_t)(HC_ERROR);
    }
    return (uint32_t)(HC_SUCCESS);
}

/* group auth callback adapter */
static bool GaCbOnTransmitWithType(int64_t requestId, const uint8_t *data, uint32_t dataLen, int32_t type,
    int32_t callbackId)
{
    uint32_t ret;
    IpcIo *dataParcel = NULL;
    IpcIo reply;
    uint8_t dataBuf[IPC_STACK_BUFF_SZ] = { 0 };
    IpcCallBackNode *node = NULL;

    LOGI("starting ... request id: %" LOG_PUB PRId64 ", type %" LOG_PUB "d", requestId, type);
    IpcIoInit(&reply, (void *)dataBuf, sizeof(dataBuf), 0);
    LockCallbackList();
    node = GetIpcCallBackByReqId(requestId, type);
    if (node == NULL) {
        UnLockCallbackList();
        LOGE("onTransmit hook is null, request id %" LOG_PUB PRId64, requestId);
        return false;
    }
    dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    if (dataParcel == NULL) {
        UnLockCallbackList();
        return false;
    }
    ret = EncodeCallData(dataParcel, PARAM_TYPE_REQID, (const uint8_t *)(&requestId), sizeof(requestId));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_COMM_DATA, data, dataLen);
    if (ret != HC_SUCCESS) {
        UnLockCallbackList();
        HcFree((void *)dataParcel);
        LOGE("build trans data failed");
        return false;
    }
    ActCallback(node->proxyId, callbackId, dataParcel, &reply);
    UnLockCallbackList();
    HcFree((void *)dataParcel);
    LOGI("process done, request id: %" LOG_PUB PRId64, requestId);
    int32_t value;
    ReadInt32(&reply, &value);
    if (value == HC_SUCCESS) {
        return true;
    }
    return false;
}

static bool IpcGaCbOnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    return GaCbOnTransmitWithType(requestId, data, dataLen, CB_TYPE_DEV_AUTH, CB_ID_ON_TRANS);
}

static bool TmpIpcGaCbOnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    return GaCbOnTransmitWithType(requestId, data, dataLen, CB_TYPE_TMP_DEV_AUTH, CB_ID_ON_TRANS_TMP);
}

static void GaCbOnSessionKeyRetWithType(int64_t requestId, const uint8_t *sessKey, uint32_t sessKeyLen, int32_t type,
    int32_t callbackId)
{
    uint32_t ret;
    IpcIo *dataParcel = NULL;
    IpcCallBackNode *node = NULL;

    LOGI("starting ... request id: %" LOG_PUB PRId64 ", type %" LOG_PUB "d", requestId, type);
    LockCallbackList();
    node = GetIpcCallBackByReqId(requestId, type);
    if (node == NULL) {
        UnLockCallbackList();
        LOGE("onSessionKeyReturned hook is null, request id %" LOG_PUB PRId64, requestId);
        return;
    }
    dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    if (dataParcel == NULL) {
        UnLockCallbackList();
        return;
    }
    ret = EncodeCallData(dataParcel, PARAM_TYPE_REQID, (uint8_t *)(&requestId), sizeof(requestId));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_SESS_KEY, sessKey, sessKeyLen);
    if (ret != HC_SUCCESS) {
        UnLockCallbackList();
        HcFree((void *)dataParcel);
        LOGE("build trans data failed");
        return;
    }
    ActCallback(node->proxyId, callbackId, dataParcel, NULL);
    UnLockCallbackList();
    HcFree((void *)dataParcel);
    LOGI("process done, request id: %" LOG_PUB PRId64, requestId);
    return;
}

static void IpcGaCbOnSessionKeyReturned(int64_t requestId, const uint8_t *sessKey, uint32_t sessKeyLen)
{
    GaCbOnSessionKeyRetWithType(requestId, sessKey, sessKeyLen, CB_TYPE_DEV_AUTH, CB_ID_SESS_KEY_DONE);
    return;
}

static void TmpIpcGaCbOnSessionKeyReturned(int64_t requestId, const uint8_t *sessKey, uint32_t sessKeyLen)
{
    GaCbOnSessionKeyRetWithType(requestId, sessKey, sessKeyLen, CB_TYPE_TMP_DEV_AUTH, CB_ID_SESS_KEY_DONE_TMP);
    return;
}

static void GaCbOnFinishWithType(int64_t requestId, int32_t operationCode, const char *returnData, int32_t type,
    int32_t callbackId)
{
    uint32_t ret;
    IpcIo *dataParcel = NULL;
    IpcCallBackNode *node = NULL;

    LOGI("starting ... request id: %" LOG_PUB PRId64 ", type %" LOG_PUB "d", requestId, type);
    LockCallbackList();
    node = GetIpcCallBackByReqId(requestId, type);
    if (node == NULL) {
        UnLockCallbackList();
        LOGE("onFinish hook is null, request id %" LOG_PUB PRId64, requestId);
        return;
    }
    dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    if (dataParcel == NULL) {
        UnLockCallbackList();
        return;
    }
    ret = EncodeCallData(dataParcel, PARAM_TYPE_REQID, (uint8_t *)(&requestId), sizeof(requestId));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_OPCODE, (uint8_t *)(&operationCode), sizeof(operationCode));
    if (returnData != NULL) {
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_COMM_DATA, (const uint8_t *)(returnData),
            HcStrlen(returnData) + 1);
    }
    if (ret != HC_SUCCESS) {
        UnLockCallbackList();
        HcFree((void *)dataParcel);
        LOGE("build trans data failed");
        return;
    }
    ActCallback(node->proxyId, callbackId, dataParcel, NULL);
    /* delete request id */
    DelIpcCallBackByReqId(requestId, type, false);
    UnLockCallbackList();
    HcFree((void *)dataParcel);
    LOGI("process done, request id: %" LOG_PUB PRId64, requestId);
    return;
}

static void IpcGaCbOnFinish(int64_t requestId, int32_t operationCode, const char *returnData)
{
    GaCbOnFinishWithType(requestId, operationCode, returnData, CB_TYPE_DEV_AUTH, CB_ID_ON_FINISH);
    return;
}

static void TmpIpcGaCbOnFinish(int64_t requestId, int32_t operationCode, const char *returnData)
{
    GaCbOnFinishWithType(requestId, operationCode, returnData, CB_TYPE_TMP_DEV_AUTH, CB_ID_ON_FINISH_TMP);
    return;
}

static void GaCbOnErrorWithType(int64_t requestId, int32_t operationCode,
    int32_t errorCode, const char *errorReturn, int32_t type)
{
    uint32_t ret;
    IpcIo *dataParcel = NULL;
    IpcCallBackNode *node = NULL;

    LOGI("starting ... request id: %" LOG_PUB PRId64 ", type %" LOG_PUB "d", requestId, type);
    LockCallbackList();
    node = GetIpcCallBackByReqId(requestId, type);
    if (node == NULL) {
        UnLockCallbackList();
        LOGE("onError hook is null, request id %" LOG_PUB PRId64, requestId);
        return;
    }
    dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    if (dataParcel == NULL) {
        UnLockCallbackList();
        return;
    }
    ret = EncodeCallData(dataParcel, PARAM_TYPE_REQID, (uint8_t *)(&requestId), sizeof(requestId));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_OPCODE, (uint8_t *)(&operationCode), sizeof(operationCode));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_ERRCODE, (uint8_t *)(&errorCode), sizeof(errorCode));
    if (errorReturn != NULL) {
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_ERR_INFO, (const uint8_t *)(errorReturn),
            HcStrlen(errorReturn) + 1);
    }
    if (ret != HC_SUCCESS) {
        UnLockCallbackList();
        HcFree((void *)dataParcel);
        LOGE("build trans data failed");
        return;
    }
    if (type == CB_TYPE_DEV_AUTH) {
        ActCallback(node->proxyId, CB_ID_ON_ERROR, dataParcel, NULL);
    }
    if (type == CB_TYPE_TMP_DEV_AUTH) {
        ActCallback(node->proxyId, CB_ID_ON_ERROR_TMP, dataParcel, NULL);
    }
    /* delete request id */
    DelIpcCallBackByReqId(requestId, type, false);
    UnLockCallbackList();
    HcFree((void *)dataParcel);
    LOGI("process done, request id: %" LOG_PUB PRId64, requestId);
    return;
}

static void IpcGaCbOnError(int64_t requestId, int32_t operationCode, int32_t errorCode, const char *errorReturn)
{
    GaCbOnErrorWithType(requestId, operationCode, errorCode, errorReturn, CB_TYPE_DEV_AUTH);
    return;
}

static void TmpIpcGaCbOnError(int64_t requestId, int32_t operationCode, int32_t errorCode, const char *errorReturn)
{
    GaCbOnErrorWithType(requestId, operationCode, errorCode, errorReturn, CB_TYPE_TMP_DEV_AUTH);
    return;
}

static char *GaCbOnRequestWithType(int64_t requestId, int32_t operationCode, const char *reqParams, int32_t type,
    int32_t callbackId)
{
    int32_t ret;
    uint32_t uRet;
    IpcIo *dataParcel = NULL;
    IpcIo reply;
    uint8_t dataBuf[IPC_STACK_BUFF_SZ] = { 0 };
    const char *dPtr = NULL;
    IpcCallBackNode *node = NULL;

    LOGI("starting ... request id: %" LOG_PUB PRId64 ", type %" LOG_PUB "d", requestId, type);
    IpcIoInit(&reply, (void *)dataBuf, sizeof(dataBuf), 0);
    LockCallbackList();
    node = GetIpcCallBackByReqId(requestId, type);
    if (node == NULL) {
        UnLockCallbackList();
        LOGE("onRequest hook is null, request id %" LOG_PUB PRId64, requestId);
        return NULL;
    }
    dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    if (dataParcel == NULL) {
        UnLockCallbackList();
        return NULL;
    }
    uRet = EncodeCallData(dataParcel, PARAM_TYPE_REQID, (uint8_t *)(&requestId), sizeof(requestId));
    uRet |= EncodeCallData(dataParcel, PARAM_TYPE_OPCODE, (uint8_t *)(&operationCode), sizeof(operationCode));
    if (reqParams != NULL) {
        uRet |= EncodeCallData(dataParcel, PARAM_TYPE_REQ_INFO, (const uint8_t *)(reqParams), HcStrlen(reqParams) + 1);
    }
    if (uRet != HC_SUCCESS) {
        UnLockCallbackList();
        HcFree((void *)dataParcel);
        LOGE("build trans data failed");
        return NULL;
    }

    ActCallback(node->proxyId, callbackId, dataParcel, &reply);
    UnLockCallbackList();
    HcFree((void *)dataParcel);
    ReadInt32(&reply, &ret);
    if (ret == HC_SUCCESS) {
        dPtr = (const char *)ReadString(&reply, NULL);
    }
    LOGI("process done, request id: %" LOG_PUB PRId64 ", %" LOG_PUB "s result", requestId,
        (dPtr != NULL) ? "valid" : "invalid");
    return (dPtr != NULL) ? strdup(dPtr) : NULL;
}

static bool CanFindCbByReqId(int64_t requestId)
{
    LockCallbackList();
    IpcCallBackNode *node = GetIpcCallBackByReqId(requestId, CB_TYPE_DEV_AUTH);
    UnLockCallbackList();
    return (node != NULL) ? true : false;
}

static char *IpcGaCbOnRequest(int64_t requestId, int32_t operationCode, const char *reqParams)
{
    if (!CanFindCbByReqId(requestId)) {
        CJson *reqParamsJson = CreateJsonFromString(reqParams);
        if (reqParamsJson == NULL) {
            LOGE("failed to create json from string!");
            return NULL;
        }
        const char *callerAppId = GetStringFromJson(reqParamsJson, FIELD_APP_ID);
        if (callerAppId == NULL) {
            LOGE("failed to get appId from json object!");
            FreeJson(reqParamsJson);
            return NULL;
        }
        int32_t ret = AddReqIdByAppId(callerAppId, requestId);
        FreeJson(reqParamsJson);
        if (ret != HC_SUCCESS) {
            return NULL;
        }
    }
    return GaCbOnRequestWithType(requestId, operationCode, reqParams, CB_TYPE_DEV_AUTH, CB_ID_ON_REQUEST);
}

static char *TmpIpcGaCbOnRequest(int64_t requestId, int32_t operationCode, const char *reqParams)
{
    return GaCbOnRequestWithType(requestId, operationCode, reqParams, CB_TYPE_TMP_DEV_AUTH, CB_ID_ON_REQUEST_TMP);
}

void IpcOnGroupCreated(const char *groupInfo)
{
    if (groupInfo == NULL) {
        LOGE("IpcOnGroupCreated, params error");
        return;
    }

    LockCallbackList();
    if (g_ipcCallBackList.ctx == NULL) {
        UnLockCallbackList();
        LOGE("IpcCallBackList not initialized.");
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        IpcIo *dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
        if (dataParcel == NULL) {
            UnLockCallbackList();
            LOGE("Failed to InitIpcDataCache.");
            continue;
        }
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_GROUP_INFO,
            (const uint8_t *)(groupInfo), HcStrlen(groupInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID, (const uint8_t *)(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            UnLockCallbackList();
            HcFree((void *)dataParcel);
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_GROUP_CREATED, dataParcel, NULL);
        HcFree((void *)dataParcel);
    }
    UnLockCallbackList();
    return;
}

void IpcOnGroupDeleted(const char *groupInfo)
{
    if (groupInfo == NULL) {
        LOGE("GroupInfo is NULL, params error.");
        return;
    }

    LockCallbackList();
    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("IpcCallBackList is not initialized.");
        UnLockCallbackList();
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        IpcIo *dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
        if (dataParcel == NULL) {
            UnLockCallbackList();
            LOGE("Failed to InitIpcDataCache.");
            continue;
        }
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_GROUP_INFO,
            (const uint8_t *)(groupInfo), HcStrlen(groupInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID, (const uint8_t *)(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            UnLockCallbackList();
            HcFree((void *)dataParcel);
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_GROUP_DELETED, dataParcel, NULL);
        HcFree((void *)dataParcel);
    }
    UnLockCallbackList();
    return;
}

void IpcOnDeviceBound(const char *peerUdid, const char *groupInfo)
{
    if ((peerUdid == NULL) || (groupInfo == NULL)) {
        LOGE("Param is NULL.");
        return;
    }

    LockCallbackList();
    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("Error occurs, callBackList is not initialized.");
        UnLockCallbackList();
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        IpcIo *dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
        if (dataParcel == NULL) {
            UnLockCallbackList();
            LOGE("Failed to InitIpcDataCache.");
            continue;
        }
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_UDID, (const uint8_t *)(peerUdid),
            HcStrlen(peerUdid) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_GROUP_INFO,
            (const uint8_t *)(groupInfo), HcStrlen(groupInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID, (const uint8_t *)(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            UnLockCallbackList();
            HcFree((void *)dataParcel);
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_DEV_BOUND, dataParcel, NULL);
        HcFree((void *)dataParcel);
    }
    UnLockCallbackList();
    return;
}

void IpcOnDeviceUnBound(const char *peerUdid, const char *groupInfo)
{
    if ((peerUdid == NULL) || (groupInfo == NULL)) {
        LOGE("Argument Error");
        return;
    }

    LockCallbackList();
    if (g_ipcCallBackList.ctx == NULL) {
        UnLockCallbackList();
        LOGE("CallBackList ctx is not initialized!");
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        IpcIo *dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
        if (dataParcel == NULL) {
            UnLockCallbackList();
            LOGE("Failed to InitIpcDataCache.");
            continue;
        }
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_UDID, (const uint8_t *)(peerUdid),
            HcStrlen(peerUdid) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_GROUP_INFO,
            (const uint8_t *)(groupInfo), HcStrlen(groupInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID, (const uint8_t *)(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            UnLockCallbackList();
            HcFree((void *)dataParcel);
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_DEV_UNBOUND, dataParcel, NULL);
        HcFree((void *)dataParcel);
    }
    UnLockCallbackList();
    return;
}

void IpcOnDeviceNotTrusted(const char *peerUdid)
{
    if (peerUdid == NULL) {
        LOGE("Invalid Params!");
        return;
    }

    LockCallbackList();
    if (g_ipcCallBackList.ctx == NULL) {
        UnLockCallbackList();
        LOGE("IpcCallBackList uninitialized!");
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        IpcIo *dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
        if (dataParcel == NULL) {
            UnLockCallbackList();
            LOGE("Failed to InitIpcDataCache.");
            continue;
        }
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_UDID, (const uint8_t *)(peerUdid),
            HcStrlen(peerUdid) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID, (const uint8_t *)(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            UnLockCallbackList();
            HcFree((void *)dataParcel);
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_DEV_UNTRUSTED, dataParcel, NULL);
        HcFree((void *)dataParcel);
    }
    UnLockCallbackList();
    return;
}

void IpcOnLastGroupDeleted(const char *peerUdid, int32_t groupType)
{
    if (peerUdid == NULL) {
        LOGE("Error occurs, peerUdid is NULL.");
        return;
    }

    LockCallbackList();
    if (g_ipcCallBackList.ctx == NULL) {
        UnLockCallbackList();
        LOGE("IpcCallBackList node is not initialized.");
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        IpcIo *dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
        if (dataParcel == NULL) {
            UnLockCallbackList();
            LOGE("Failed to InitIpcDataCache.");
            continue;
        }
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_UDID, (const uint8_t *)(peerUdid),
            HcStrlen(peerUdid) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_GROUP_TYPE,
            (const uint8_t *)(groupType), sizeof(groupType));
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID, (const uint8_t *)(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            UnLockCallbackList();
            HcFree((void *)dataParcel);
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_LAST_GROUP_DELETED, dataParcel, NULL);
        HcFree((void *)dataParcel);
    }
    UnLockCallbackList();
    return;
}

void IpcOnTrustedDeviceNumChanged(int32_t curTrustedDeviceNum)
{
    LockCallbackList();
    if (g_ipcCallBackList.ctx == NULL) {
        LOGE("IpcCallBackList un-initialized");
        UnLockCallbackList();
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        IpcIo *dataParcel = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
        if (dataParcel == NULL) {
            UnLockCallbackList();
            LOGE("Failed to InitIpcDataCache.");
            continue;
        }
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_DATA_NUM, (const uint8_t *)(&curTrustedDeviceNum),
            sizeof(curTrustedDeviceNum));
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID, (const uint8_t *)(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            UnLockCallbackList();
            HcFree((void *)dataParcel);
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_TRUST_DEV_NUM_CHANGED, dataParcel, NULL);
        HcFree((void *)dataParcel);
    }
    UnLockCallbackList();
    return;
}

void InitDeviceAuthCbCtx(DeviceAuthCallback *ctx, int32_t type)
{
    if (ctx == NULL) {
        return;
    }
    if (type == CB_TYPE_DEV_AUTH) {
        ctx->onTransmit = IpcGaCbOnTransmit;
        ctx->onSessionKeyReturned = IpcGaCbOnSessionKeyReturned;
        ctx->onError = IpcGaCbOnError;
        ctx->onRequest = IpcGaCbOnRequest;
        ctx->onFinish = IpcGaCbOnFinish;
    }
    if (type == CB_TYPE_TMP_DEV_AUTH) {
        ctx->onTransmit = TmpIpcGaCbOnTransmit;
        ctx->onSessionKeyReturned = TmpIpcGaCbOnSessionKeyReturned;
        ctx->onError = TmpIpcGaCbOnError;
        ctx->onRequest = TmpIpcGaCbOnRequest;
        ctx->onFinish = TmpIpcGaCbOnFinish;
    }
    return;
}

void InitDevAuthListenerCbCtx(DataChangeListener *ctx)
{
    if (ctx == NULL) {
        LOGE("Input ctx is NULL.");
        return;
    }
    ctx->onGroupCreated = IpcOnGroupCreated;
    ctx->onGroupDeleted = IpcOnGroupDeleted;
    ctx->onDeviceNotTrusted = IpcOnDeviceNotTrusted;
    ctx->onDeviceBound = IpcOnDeviceBound;
    ctx->onDeviceUnBound = IpcOnDeviceUnBound;
    ctx->onLastGroupDeleted = IpcOnLastGroupDeleted;
    ctx->onTrustedDeviceNumChanged = IpcOnTrustedDeviceNumChanged;
    return;
}

/* ipc client process adapter */
int32_t CreateCallCtx(uintptr_t *callCtx)
{
    if (callCtx == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }

    ProxyDevAuthData *dataCache = (ProxyDevAuthData *)HcMalloc(sizeof(ProxyDevAuthData), 0);
    if (dataCache == NULL) {
        LOGE("call context alloc failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    dataCache->data = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    dataCache->tmpData = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    dataCache->reply = InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    if ((dataCache->data == NULL) || (dataCache->tmpData == NULL) || (dataCache->reply == NULL)) {
        DestroyCallCtx((uintptr_t *)(dataCache));
        return HC_ERROR;
    }
    /* linux lite, ipc io init with : token + SvcIdentity */
    dataCache->ioBuffOffset = IpcIoBufferOffset();
    *callCtx = (uintptr_t)(dataCache);
    return HC_SUCCESS;
}

void DestroyCallCtx(uintptr_t *callCtx)
{
    ProxyDevAuthData *dataCache = NULL;
    if ((callCtx != NULL) && (*callCtx != 0)) {
        dataCache = (ProxyDevAuthData *)(*callCtx);
        if (dataCache->data != NULL) {
            HcFree((void *)dataCache->data);
            dataCache->data = NULL;
        }
        if (dataCache->tmpData != NULL) {
            HcFree((void *)dataCache->tmpData);
            dataCache->tmpData = NULL;
        }
        if (dataCache->reply != NULL) {
            HcFree((void *)dataCache->reply);
            dataCache->reply = NULL;
        }
        HcFree((void *)dataCache);
        *callCtx = 0;
    }
    return;
}

void SetCbCtxToDataCtx(uintptr_t callCtx, int32_t cbIdx)
{
    ProxyDevAuthData *dataCache = NULL;
    const SvcIdentity *stubInfo = &g_sdkCbStub.stubIdentity;
    (void)cbIdx;
    if (!g_sdkCbStub.registered) {
        LOGW("SDK callback stub un-registered");
        return;
    }
    ShowIpcSvcInfo(stubInfo);
    dataCache = (ProxyDevAuthData *)(callCtx);
    SetCallbackStub(dataCache, stubInfo);
    return;
}

int32_t SetCallRequestParamInfo(uintptr_t callCtx, int32_t type, const uint8_t *param, int32_t paramSz)
{
    ProxyDevAuthData *dataCache = (ProxyDevAuthData *)(callCtx);

    return EncodeCallRequest(dataCache, type, param, paramSz);
}

int32_t DoBinderCall(uintptr_t callCtx, int32_t methodId, bool withSync)
{
    (void)withSync;
    int32_t ret;
    ProxyDevAuthData *dataCache = (ProxyDevAuthData *)(callCtx);

    ret = FinalCallRequest(dataCache, methodId);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    return ActCall(g_proxyInstance, dataCache);
}

/* ipc service process adapter */
uint32_t SetIpcCallMap(uintptr_t ipcInstance, IpcServiceCall method, int32_t methodId)
{
    (void)ipcInstance;
    if ((method == NULL) || (methodId <= 0)) {
        return HC_ERR_INVALID_PARAMS;
    }

    return (uint32_t)SetCallMap(method, methodId);
}

int32_t CreateServiceInstance(uintptr_t *ipcInstance)
{
    *ipcInstance = 0x0;
    return HC_SUCCESS;
}

void DestroyServiceInstance(uintptr_t ipcInstance)
{
    (void)ipcInstance;
}

int32_t AddDevAuthServiceToManager(uintptr_t serviceInstance)
{
    (void)serviceInstance;
    SAMGR_Bootstrap();
    InitCbStubTable();
    LOGI("AddSystemAbility to SA manager success");
    return HC_SUCCESS;
}

int32_t IpcEncodeCallReply(uintptr_t replayCache, int32_t type, const uint8_t *result, int32_t resultSz)
{
    int32_t ret = HC_SUCCESS;
    IpcIo *replyParcel = NULL;
    unsigned long valZero = 0uL;

    replyParcel = (IpcIo *)(replayCache);
    WriteInt32(replyParcel, type);
    bool value;
    if ((result != NULL) && (resultSz > 0)) {
        WriteUint32(replyParcel, (uint32_t)resultSz);
        value = WriteBuffer(replyParcel, (const void *)result, (uint32_t)resultSz);
    } else {
        WriteUint32(replyParcel, sizeof(valZero));
        value = WriteBuffer(replyParcel, (const void *)(&valZero), sizeof(valZero));
    }
    if (!value) {
        LOGE("encode call reply fail.");
        return HC_FALSE;
    }
    return ret;
}

int32_t DecodeIpcData(uintptr_t data, int32_t *type, uint8_t **val, int32_t *valSz)
{
    IpcIo *dataPtr = NULL;

    dataPtr = (IpcIo *)(data);
    if (dataPtr->bufferLeft <= 0) {
        return HC_SUCCESS;
    }
    ReadInt32(dataPtr, type);
    ReadUint32(dataPtr, (uint32_t *)valSz);
    *val = (uint8_t *)ReadBuffer(dataPtr, *valSz);
    return HC_SUCCESS;
}

void DecodeCallReply(uintptr_t callCtx, IpcDataInfo *replyCache, int32_t cacheNum)
{
    int32_t i;
    int32_t ret;
    uint32_t replyLen;

    ProxyDevAuthData *dataCache = (ProxyDevAuthData *)(callCtx);
    ReadUint32(dataCache->reply, &replyLen);
    if (replyLen == 0) {
        return;
    }

    for (i = 0; i < cacheNum; i++) {
        ret = DecodeIpcData((uintptr_t)(dataCache->reply),
            &(replyCache[i].type), &(replyCache[i].val), &(replyCache[i].valSz));
        if (ret != HC_SUCCESS) {
            LOGE("Ipc data decode failed.");
            return;
        }
    }
    return;
}

static bool IsTypeForCpyData(int32_t type)
{
    int32_t typeList[] = {
        PARAM_TYPE_REQID, PARAM_TYPE_GROUP_TYPE, PARAM_TYPE_OPCODE, PARAM_TYPE_ERRCODE, PARAM_TYPE_OS_ACCOUNT_ID
    };
    int32_t i;
    int32_t n = sizeof(typeList) / sizeof(typeList[0]);
    for (i = 0; i < n; i++) {
        if (typeList[i] == type) {
            return true;
        }
    }
    return false;
}

static bool IsTypeForSettingPtr(int32_t type)
{
    int32_t typeList[] = {
        PARAM_TYPE_APPID, PARAM_TYPE_DEV_AUTH_CB, PARAM_TYPE_LISTENER, PARAM_TYPE_CREATE_PARAMS,
        PARAM_TYPE_GROUPID, PARAM_TYPE_UDID, PARAM_TYPE_ADD_PARAMS, PARAM_TYPE_DEL_PARAMS,
        PARAM_TYPE_QUERY_PARAMS, PARAM_TYPE_COMM_DATA, PARAM_TYPE_SESS_KEY,
        PARAM_TYPE_REQ_INFO, PARAM_TYPE_GROUP_INFO, PARAM_TYPE_AUTH_PARAMS, PARAM_TYPE_REQ_JSON,
        PARAM_TYPE_PSEUDONYM_ID, PARAM_TYPE_INDEX_KEY, PARAM_TYPE_ERR_INFO
    };
    int32_t i;
    int32_t n = sizeof(typeList) / sizeof(typeList[0]);
    for (i = 0; i < n; i++) {
        if (typeList[i] == type) {
            return true;
        }
    }
    return false;
}

int32_t GetIpcRequestParamByType(const IpcDataInfo *ipcParams, int32_t paramNum,
    int32_t type, uint8_t *paramCache, int32_t *cacheLen)
{
    int32_t i;
    errno_t eno;

    int32_t ret = HC_ERR_IPC_BAD_MSG_TYPE;
    for (i = 0; i < paramNum; i++) {
        if (ipcParams[i].type != type) {
            continue;
        }
        ret = HC_SUCCESS;
        if (IsTypeForSettingPtr(type)) {
            *(uint8_t **)paramCache = ipcParams[i].val;
            if (cacheLen != NULL) {
                *cacheLen = ipcParams[i].valSz;
            }
            break;
        }
        if (IsTypeForCpyData(type)) {
            if ((ipcParams[i].val == NULL) || (ipcParams[i].valSz <= 0)) {
                ret = HC_ERR_INVALID_PARAMS;
                break;
            }
            eno = memcpy_s(paramCache, *cacheLen, ipcParams[i].val, ipcParams[i].valSz);
            if (eno != EOK) {
                ret = HC_ERR_MEMORY_COPY;
            }
            *cacheLen = ipcParams[i].valSz;
            break;
        }
        if ((type == PARAM_TYPE_CB_OBJECT) && (*(uint32_t *)cacheLen >= sizeof(ipcParams[i].idx))) {
            *(int32_t *)paramCache = ipcParams[i].idx;
        }
        break;
    }
    return ret;
}

bool IsCallbackMethod(int32_t methodId)
{
    if ((methodId == IPC_CALL_ID_REG_CB) || (methodId == IPC_CALL_ID_REG_LISTENER) ||
        (methodId == IPC_CALL_ID_GA_PROC_DATA) || (methodId == IPC_CALL_ID_AUTH_DEVICE)) {
        return true;
    }
    return false;
}

IpcIo *InitIpcDataCache(uint32_t buffSz)
{
    IpcIo *ioPtr = NULL;
    uint8_t *buf = NULL;
    uint32_t len;

    if (buffSz == 0) {
        LOGE("invalid param");
        return NULL;
    }
    len = sizeof(IpcIo) + buffSz;
    ioPtr = (IpcIo *)HcMalloc(len, 0);
    if (ioPtr == NULL) {
        LOGE("alloc memory failed");
        return NULL;
    }
    buf = (uint8_t *)ioPtr + sizeof(IpcIo);
    /* ipcio inited with 4 svc objects */
    IpcIoInit(ioPtr, (void *)buf, buffSz, 4);
    return ioPtr;
}

int32_t GetIpcIoDataLength(const IpcIo *io)
{
    uintptr_t beginPos;
    uintptr_t endPos;

    if (io == NULL) {
        return 0;
    }
    beginPos = (uintptr_t)(io->bufferBase + IpcIoBufferOffset());
    endPos = (uintptr_t)(io->bufferCur);
    return (endPos <= beginPos) ? 0 : (int32_t)(endPos - beginPos);
}

void ShowIpcSvcInfo(const SvcIdentity *svc)
{
    LOGI("svc information - handle(%" LOG_PUB "u), token(%" LOG_PUB "u), cookie(%" LOG_PUB "u)", svc->handle,
        svc->token, svc->cookie);
}

int32_t InitProxyAdapt(void)
{
    if (g_proxyInstance == NULL) {
        g_proxyInstance = (IClientProxy *)GetProxyInstance(DEV_AUTH_SERVICE_NAME);
        if (g_proxyInstance == NULL) {
            LOGE("get proxy instance failed");
            return HC_ERR_IPC_INIT;
        }
    }

    if (!g_sdkCbStub.registered) {
        g_objectStub.func = CbStubOnRemoteRequest;
        g_objectStub.isRemote = false;
        g_objectStub.args = NULL;

        g_sdkCbStub.stubIdentity.token = SERVICE_TYPE_ANONYMOUS;
        g_sdkCbStub.stubIdentity.handle = IPC_INVALID_HANDLE;
        g_sdkCbStub.stubIdentity.cookie = (uintptr_t)&g_objectStub;

        ShowIpcSvcInfo(&(g_sdkCbStub.stubIdentity));
        g_sdkCbStub.registered = true;
    }
    return HC_SUCCESS;
}

void UnInitProxyAdapt(void)
{
    g_proxyInstance = NULL;
    g_sdkCbStub.registered = false;
    return;
}

int32_t IpcIoBufferOffset(void)
{
    int8_t buf[64]; /* 64 buffer size */
    IpcIo ioCache;

    IpcIoInit(&ioCache, (void *)buf, sizeof(buf), 0);
    if (ioCache.bufferCur <= ioCache.bufferBase) {
        return 0;
    }
    return (int32_t)((uintptr_t)(ioCache.bufferCur) - (uintptr_t)(ioCache.bufferBase));
}

#ifdef __cplusplus
}
#endif

