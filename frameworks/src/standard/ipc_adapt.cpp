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
#include "hc_log.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "ipc_callback_proxy.h"
#include "ipc_callback_stub.h"
#include "ipc_dev_auth_proxy.h"
#include "ipc_dev_auth_stub.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "parameter.h"
#include "string_util.h"

using namespace std;
using namespace OHOS;
namespace {
    static const int32_t BUFF_MAX_SZ = 128;
    static const int32_t IPC_CALL_BACK_MAX_NODES = 64;
    static const int32_t IPC_CALL_BACK_STUB_NODES = 4;
    static const uint32_t DEV_AUTH_MAX_THREAD_NUM = 2;
    static const int32_t DEFAULT_CALLBACK_PROXY_ID = -1;
    static const int32_t DEFAULT_CALLBACK_NODE_IDX = -1;
}

static sptr<StubDevAuthCb> g_sdkCbStub[IPC_CALL_BACK_STUB_NODES] = { nullptr, nullptr, nullptr, nullptr };

typedef struct {
    int32_t callbackId;
    const IpcDataInfo *cbDataCache;
    int32_t cacheNum;
    MessageParcel &reply;
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
} g_ipcCallBackList = {nullptr, 0};

typedef struct {
    char appId[BUFF_MAX_SZ];
    uint8_t type;
    bool delCallBack;
    int64_t requestId;
    union {
        DeviceAuthCallback devAuth;
        DataChangeListener listener;
        CredChangeListener credListener;
    } callback;
} SdkIpcCallBackNode;

DECLARE_HC_VECTOR(SdkIpcCallBackList, SdkIpcCallBackNode)
IMPLEMENT_HC_VECTOR(SdkIpcCallBackList, SdkIpcCallBackNode, 1)
static SdkIpcCallBackList g_sdkIpcCallBackList;

static std::mutex g_cbListLock;
static std::recursive_mutex g_cbSdkListLock;

static void FreeSdkIpcCallBackList(SdkIpcCallBackList *ipcCallBackList)
{
    uint32_t index;
    SdkIpcCallBackNode *node = nullptr;
    FOR_EACH_HC_VECTOR(*ipcCallBackList, index, node) {
        if (node == nullptr) {
            continue;
        }
        memset_s(node, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
    }
}

int32_t InitSdkIpcCallBackList(void)
{
    g_sdkIpcCallBackList = CREATE_HC_VECTOR(SdkIpcCallBackList);
    return HC_SUCCESS;
}

void DeInitSdkIpcCallBackList(void)
{
    FreeSdkIpcCallBackList(&g_sdkIpcCallBackList);
    DESTROY_HC_VECTOR(SdkIpcCallBackList, &g_sdkIpcCallBackList);
    return;
}

int32_t AddSdkCallBackByAppId(const char *appId, uint8_t cbType, uint8_t *val, int32_t valSize)
{
    std::lock_guard<std::recursive_mutex> Lock(g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == nullptr || entry->appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(entry->appId, appId) && entry->type == cbType) {
            LOGW("start to update callback, appId: %" LOG_PUB "s, cbType: %" LOG_PUB "u", appId, cbType);
            if (memcpy_s(&entry->callback, sizeof(entry->callback), val, valSize) != EOK) {
                return HC_ERR_MEMORY_COPY;
            }
            return HC_SUCCESS;
        }
    }
    SdkIpcCallBackNode node;
    if (memcpy_s(&node.callback, sizeof(node.callback), val, valSize) != EOK) {
        LOGE("copy callback failed.");
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(&node.appId, sizeof(node.appId), appId, HcStrlen(appId) + 1) != EOK) {
        memset_s(&node, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
        LOGE("copy appId failed.");
        return HC_ERR_MEMORY_COPY;
    }
    node.delCallBack = false;
    node.type = cbType;
    if (g_sdkIpcCallBackList.pushBack(&g_sdkIpcCallBackList, &node) == nullptr) {
        memset_s(&node, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
        LOGE("Failed to add callback node");
        return HC_ERR_ALLOC_MEMORY;
    }
    LOGI("AddSdkCallBackByAppId successfully, size: %" LOG_PUB "d, appId: %" LOG_PUB "s, cbType: %" LOG_PUB "u",
            g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList), appId, cbType);
    return HC_SUCCESS;
}

int32_t AddSdkCallBackByRequestId(int64_t requestId, uint8_t cbType, uint8_t *val, int32_t valSize)
{
    std::lock_guard<std::recursive_mutex> Lock(g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == nullptr) {
            continue;
        }
        if (entry->requestId == requestId && entry->type == cbType) {
            LOGW("start to update callback, requestId: %" LOG_PUB "lld, cbType: %" LOG_PUB "u",
                static_cast<long long>(requestId), cbType);
            if (memcpy_s(&entry->callback, sizeof(entry->callback), val, valSize) != EOK) {
                return HC_ERR_MEMORY_COPY;
            }
            return HC_SUCCESS;
        }
    }
    SdkIpcCallBackNode node;
    if (memcpy_s(&node.callback, sizeof(node.callback), val, valSize) != EOK) {
        LOGE("copy callback failed.");
        return HC_ERR_MEMORY_COPY;
    }
    node.type = cbType;
    node.requestId = requestId;
    node.delCallBack = true;
    if (g_sdkIpcCallBackList.pushBack(&g_sdkIpcCallBackList, &node) == nullptr) {
        memset_s(&node, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
        LOGE("Failed to add callback node");
        return HC_ERR_ALLOC_MEMORY;
    }
    LOGI("AddSdkCallBackByRequestId successfully, size: %" LOG_PUB "d, requestId: %" LOG_PUB "lld, "
        "cbType: %" LOG_PUB "u", g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList),
        static_cast<long long>(requestId), cbType);
    return HC_SUCCESS;
}

static uint8_t GetCbType(int32_t callbackId)
{
    if (callbackId >= CB_ID_ON_TRANS && callbackId <= CB_ID_ON_REQUEST) {
        return CB_TYPE_DEV_AUTH;
    } else if (callbackId >= CB_ID_ON_TRANS_TMP && callbackId <= CB_ID_ON_REQUEST_TMP) {
        return CB_TYPE_TMP_DEV_AUTH;
    } else if (callbackId >= CB_ID_ON_TRANS_CRED && callbackId <= CB_ID_ON_REQUEST_CRED) {
        return CB_TYPE_CRED_DEV_AUTH;
    }
    return 0;
}

static int32_t GetSdkCallBackByRequestId(int64_t callbackId, int64_t requestId, uint8_t *val, int32_t valSize)
{
    std::lock_guard<std::recursive_mutex> Lock(g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    LOGI("requestId: %" LOG_PUB "lld, callbackId: %" LOG_PUB "lld", static_cast<long long>(requestId),
        static_cast<long long>(callbackId));
    uint8_t cbType = GetCbType(callbackId);
    if (cbType == 0) {
        return HC_ERR_IPC_CALLBACK_NOT_MATCH;
    }
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == nullptr) {
            continue;
        }
        if (entry->requestId == requestId && entry->type == cbType) {
            if (memcpy_s(val, valSize, &entry->callback, valSize) != EOK) {
                LOGE("copy callback failed.");
                return HC_ERR_MEMORY_COPY;
            }
            return HC_SUCCESS;
        }
    }
    LOGE("callback not found.");
    return HC_ERR_IPC_CALLBACK_NOT_MATCH;
}

static int32_t GetSdkCallBackByAppId(const char *appId, uint8_t cbType, uint8_t *val, int32_t valSize)
{
    std::lock_guard<std::recursive_mutex> Lock(g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    LOGI("appId: %" LOG_PUB "s, cbType: %" LOG_PUB "u", appId, cbType);
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == nullptr || entry->appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(entry->appId, appId) && entry->type == cbType) {
            if (memcpy_s(val, valSize, &entry->callback, valSize) != EOK) {
                LOGE("copy callback failed.");
                return HC_ERR_MEMORY_COPY;
            }
            return HC_SUCCESS;
        }
    }
    LOGE("callback not found.");
    return HC_ERR_IPC_CALLBACK_NOT_MATCH;
}

static void RemoveSdkCallBackByCallBackId(int64_t callbackId, int64_t requestId)
{
    LOGI("requestId: %" LOG_PUB "lld, callbackId: %" LOG_PUB "lld", static_cast<long long>(requestId),
        static_cast<long long>(callbackId));
    uint8_t cbType = GetCbType(callbackId);
    if (cbType == 0) {
        return;
    }
    RemoveSdkCallBackByRequestId(requestId, cbType);
}

int32_t AddRequestIdByAppId(const char *appId, int64_t requestId)
{
    std::lock_guard<std::recursive_mutex> Lock(g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == nullptr || entry->appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(entry->appId, appId) && entry->type == CB_TYPE_DEV_AUTH) {
            LOGI("AddRequestIdByAppId successfully, requestId: %" LOG_PUB "lld, appId: %" LOG_PUB "s",
                static_cast<long long>(requestId), appId);
            entry->requestId = requestId;
            return HC_SUCCESS;
        }
    }
    LOGE("callback not found.");
    return HC_ERR_IPC_CALLBACK_NOT_MATCH;
}

void RemoveSdkCallBackByAppId(const char *appId, uint8_t cbType)
{
    std::lock_guard<std::recursive_mutex> Lock(g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == nullptr || entry->appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(entry->appId, appId) && entry->type == cbType) {
            SdkIpcCallBackNode deleteNode;
            HC_VECTOR_POPELEMENT(&g_sdkIpcCallBackList, &deleteNode, index);
            LOGI("deleteNode appId : %" LOG_PUB "s, requestId : %" LOG_PUB "lld, cbType : %" LOG_PUB "u",
                deleteNode.appId, static_cast<long long>(deleteNode.requestId), cbType);
            (void)memset_s(&deleteNode, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
            LOGI("g_sdkIpcCallBackList size : %" LOG_PUB "d", g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList));
            return;
        }
    }
    LOGW("callback not found.");
    return;
}

void RemoveSdkCallBackByRequestId(int64_t requestId, uint8_t cbType)
{
    std::lock_guard<std::recursive_mutex> Lock(g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == nullptr) {
            continue;
        }
        if (entry->requestId == requestId && entry->type == cbType && entry->delCallBack) {
            SdkIpcCallBackNode deleteNode;
            HC_VECTOR_POPELEMENT(&g_sdkIpcCallBackList, &deleteNode, index);
            LOGI("deleteNode appId : %" LOG_PUB "s, requestId : %" LOG_PUB "lld, cbType : %" LOG_PUB "u",
                deleteNode.appId, static_cast<long long>(requestId), cbType);
            (void)memset_s(&deleteNode, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
            LOGI("g_sdkIpcCallBackList size : %" LOG_PUB "d", g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList));
            return;
        }
    }
    LOGW("callback not found, cbType: %" LOG_PUB "u", cbType);
    return;
}

static void CopySdkCallBackFromCache(SdkIpcCallBackList *tmpIpcCallBackList)
{
    std::lock_guard<std::recursive_mutex> Lock(g_cbSdkListLock);
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    LOGI("g_sdkIpcCallBackList size: %" LOG_PUB "d", g_sdkIpcCallBackList.size(&g_sdkIpcCallBackList));
    FOR_EACH_HC_VECTOR(g_sdkIpcCallBackList, index, entry) {
        if (entry == nullptr || entry->appId[0] == 0) {
            continue;
        }
        SdkIpcCallBackNode node;
        if (memcpy_s(&node, sizeof(SdkIpcCallBackNode), entry, sizeof(SdkIpcCallBackNode)) != HC_SUCCESS) {
            continue;
        }
        if (tmpIpcCallBackList->pushBack(tmpIpcCallBackList, &node) == nullptr) {
            memset_s(&node, sizeof(SdkIpcCallBackNode), 0, sizeof(SdkIpcCallBackNode));
            continue;
        }
    }
}

static void RegisterSdkCallBackByCbType(SdkIpcCallBackList *tmpIpcCallBackList, RegCallbackFunc regCallbackFunc,
    RegDataChangeListenerFunc regDataChangeListenerFunc, RegCredChangeListenerFunc regCredChangeListenerFunc)
{
    uint32_t index;
    SdkIpcCallBackNode *entry = nullptr;
    int32_t ret = HC_SUCCESS;
    FOR_EACH_HC_VECTOR(*tmpIpcCallBackList, index, entry) {
        if (entry == nullptr || entry->appId[0] == 0) {
            continue;
        }
        switch (entry->type) {
            case CB_TYPE_DEV_AUTH:
                LOGI("regCallback.");
                ret = regCallbackFunc(entry->appId, &entry->callback.devAuth, false);
                break;
            case CB_TYPE_LISTENER:
                LOGI("regDataChangeListener.");
                ret = regDataChangeListenerFunc(entry->appId, &entry->callback.listener, false);
                break;
            case CB_TYPE_CRED_LISTENER:
                LOGI("regCredChangeListener.");
                ret = regCredChangeListenerFunc(entry->appId, &entry->callback.credListener, false);
                break;
            default:
                LOGE("invalid callback type: %" LOG_PUB "d.", entry->type);
                break;
        }
        LOGI("register result: %" LOG_PUB "d.", ret);
    }
}

void RegisterSdkCallBack(RegCallbackFunc regCallbackFunc, RegDataChangeListenerFunc regDataChangeListenerFunc,
    RegCredChangeListenerFunc regCredChangeListenerFunc)
{
    SdkIpcCallBackList tmpIpcCallBackList = CREATE_HC_VECTOR(SdkIpcCallBackList);

    CopySdkCallBackFromCache(&tmpIpcCallBackList);
    RegisterSdkCallBackByCbType(&tmpIpcCallBackList, regCallbackFunc, regDataChangeListenerFunc,
        regCredChangeListenerFunc);
    
    FreeSdkIpcCallBackList(&tmpIpcCallBackList);
    DESTROY_HC_VECTOR(SdkIpcCallBackList, &tmpIpcCallBackList);
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
    if ((ret != HC_SUCCESS) || (param == nullptr) || (size <= 0)) {
        LOGE("get param error, type %" LOG_PUB "d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    char *str = (*(char **)param);
    if ((str == nullptr) || (str[size - 1] != '\0')) {
        LOGE("The input parameter is not a valid string type.");
        return HC_ERR_IPC_BAD_PARAM;
    }
    return HC_SUCCESS;
}

static void SetIpcCallBackNodeDefault(IpcCallBackNode &node)
{
    (void)memset_s(&node, sizeof(IpcCallBackNode), 0, sizeof(IpcCallBackNode));
    node.proxyId = DEFAULT_CALLBACK_PROXY_ID;
    node.nodeIdx = DEFAULT_CALLBACK_NODE_IDX;
    return;
}

int32_t InitIpcCallBackList(void)
{
    int32_t i;

    LOGI("initializing ...");
    if (g_ipcCallBackList.ctx != nullptr) {
        LOGI("has initialized");
        return HC_SUCCESS;
    }

    g_ipcCallBackList.ctx = new(std::nothrow) IpcCallBackNode[IPC_CALL_BACK_MAX_NODES];
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("initialized failed");
        return HC_ERROR;
    }
    for (i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        SetIpcCallBackNodeDefault(g_ipcCallBackList.ctx[i]);
    }
    g_ipcCallBackList.nodeCnt = 0;
    LOGI("initialized successful");
    return HC_SUCCESS;
}

static void ResetIpcCallBackNode(IpcCallBackNode &node)
{
    if ((node.appId[0] != 0) && (node.appId[sizeof(node.appId) - 1] == 0)) {
        LOGI("appid is %" LOG_PUB "s ", node.appId);
    }
    ServiceDevAuth::ResetRemoteObject(node.proxyId);
    SetIpcCallBackNodeDefault(node);
    return;
}

void DeInitIpcCallBackList(void)
{
    int32_t i;

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        return;
    }
    for (i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].nodeIdx == DEFAULT_CALLBACK_NODE_IDX) {
            continue;
        }
        ResetIpcCallBackNode(g_ipcCallBackList.ctx[i]);
    }
    delete[] g_ipcCallBackList.ctx;
    g_ipcCallBackList.ctx = nullptr;
    return;
}

void ResetIpcCallBackNodeByNodeId(int32_t nodeIdx)
{
    LOGI("starting..., index %" LOG_PUB "d", nodeIdx);
    if ((nodeIdx < 0) || (nodeIdx >= IPC_CALL_BACK_MAX_NODES)) {
        LOGW("Invalid node index: %" LOG_PUB "d", nodeIdx);
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGW("Callback node list is null!");
        return;
    }
    if (g_ipcCallBackList.ctx[nodeIdx].proxyId < 0) {
        LOGW("Invalid node proxy id: %" LOG_PUB "d", g_ipcCallBackList.ctx[nodeIdx].proxyId);
        return;
    }
    ResetIpcCallBackNode(g_ipcCallBackList.ctx[nodeIdx]);
    g_ipcCallBackList.nodeCnt--;
    LOGI("done, index %" LOG_PUB "d", nodeIdx);
    return;
}

static IpcCallBackNode *GetIpcCallBackByAppId(const char *appId, int32_t type)
{
    int32_t i;

    for (i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].appId[0] == 0) {
            continue;
        }
        if (IsStrEqual(g_ipcCallBackList.ctx[i].appId, appId) && (g_ipcCallBackList.ctx[i].cbType == type)) {
            return &g_ipcCallBackList.ctx[i];
        }
    }
    return nullptr;
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
    return nullptr;
}

static void SetCbDeathRecipient(int32_t type, int32_t objIdx, int32_t cbDataIdx)
{
    if ((type == CB_TYPE_DEV_AUTH) || (type == CB_TYPE_LISTENER)) {
        ServiceDevAuth::AddCbDeathRecipient(objIdx, cbDataIdx);
    }
    return;
}

void AddIpcCbObjByAppId(const char *appId, int32_t objIdx, int32_t type)
{
    IpcCallBackNode *node = nullptr;

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("CallbackList is not init.");
        return;
    }

    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        LOGE("CallbackList is full.");
        return;
    }

    node = GetIpcCallBackByAppId(appId, type);
    if (node != nullptr) {
        node->proxyId = objIdx;
        SetCbDeathRecipient(type, objIdx, node->nodeIdx);
        LOGI("ipc object add success, appid: %" LOG_PUB "s, proxyId %" LOG_PUB "d", appId, node->proxyId);
    }
    return;
}

int32_t AddIpcCallBackByAppId(const char *appId, int32_t type)
{
    IpcCallBackNode *node = nullptr;
    errno_t eno;

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("list not inited");
        return HC_ERROR;
    }

    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        LOGE("list is full");
        return HC_ERROR;
    }

    node = GetIpcCallBackByAppId(appId, type);
    if (node != nullptr) {
        if (node->proxyId >= 0) {
            ServiceDevAuth::ResetRemoteObject(node->proxyId);
            node->proxyId = DEFAULT_CALLBACK_PROXY_ID;
        }
        LOGI("Callback add success, appid: %" LOG_PUB "s", appId);
        return HC_SUCCESS;
    }

    node = GetFreeIpcCallBackNode();
    if (node == nullptr) {
        LOGE("get free node failed");
        return HC_ERROR;
    }
    node->cbType = type;
    eno = memcpy_s(&(node->appId), sizeof(node->appId), appId, HcStrlen(appId) + 1);
    if (eno != EOK) {
        ResetIpcCallBackNode(*node);
        LOGE("appid memory copy failed");
        return HC_ERROR;
    }
    node->proxyId = DEFAULT_CALLBACK_PROXY_ID;
    g_ipcCallBackList.nodeCnt++;
    LOGI("callback add success, appid: %" LOG_PUB "s, type %" LOG_PUB "d", node->appId, node->cbType);
    return HC_SUCCESS;
}

void DelIpcCallBackByAppId(const char *appId, int32_t type)
{
    IpcCallBackNode *node = nullptr;

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if ((g_ipcCallBackList.nodeCnt <= 0) || (g_ipcCallBackList.ctx == nullptr)) {
        return;
    }

    node = GetIpcCallBackByAppId(appId, type);
    if (node != nullptr) {
        ResetIpcCallBackNode(*node);
        g_ipcCallBackList.nodeCnt--;
    }
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
    return nullptr;
}

int32_t AddReqIdByAppId(const char *appId, int64_t reqId)
{
    IpcCallBackNode *node = nullptr;

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("ipc callback list not inited");
        return HC_ERROR;
    }

    node = GetIpcCallBackByAppId(appId, CB_TYPE_DEV_AUTH);
    if (node == nullptr) {
        LOGE("ipc callback node not found, appid: %" LOG_PUB "s", appId);
        return HC_ERROR;
    }
    node->requestId = reqId;
    node->delOnFni = 0;
    LOGI("success, appid: %" LOG_PUB "s, requestId: %" LOG_PUB "lld", appId, static_cast<long long>(reqId));
    return HC_SUCCESS;
}

void AddIpcCbObjByReqId(int64_t reqId, int32_t objIdx, int32_t type)
{
    IpcCallBackNode *node = nullptr;

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("CallbackList not inited");
        return;
    }

    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        LOGE("list is full");
        return;
    }

    node = GetIpcCallBackByReqId(reqId, type);
    if (node != nullptr) {
        node->proxyId = objIdx;
        LOGI("ipc object add success, request id %" LOG_PUB "lld, type %" LOG_PUB "d, proxy id %" LOG_PUB "d",
            static_cast<long long>(reqId), type, node->proxyId);
    }
    return;
}

int32_t AddIpcCallBackByReqId(int64_t reqId, int32_t type)
{
    IpcCallBackNode *node = nullptr;

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("list is full");
        return HC_ERROR;
    }

    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        LOGE("list is full");
        return HC_ERROR;
    }

    node = GetIpcCallBackByReqId(reqId, type);
    if (node != nullptr) {
        if (node->proxyId >= 0) {
            ServiceDevAuth::ResetRemoteObject(node->proxyId);
            node->proxyId = DEFAULT_CALLBACK_PROXY_ID;
        }
        LOGI("callback replaced success, request id %" LOG_PUB "lld, type %" LOG_PUB "d",
            static_cast<long long>(reqId), type);
        return HC_SUCCESS;
    }

    LOGI("new callback to add, request id %" LOG_PUB "lld, type %" LOG_PUB "d",
        static_cast<long long>(reqId), type);
    node = GetFreeIpcCallBackNode();
    if (node == nullptr) {
        LOGE("get free node failed");
        return HC_ERROR;
    }
    node->cbType = type;
    node->requestId = reqId;
    node->delOnFni = 1;
    node->proxyId = DEFAULT_CALLBACK_PROXY_ID;
    g_ipcCallBackList.nodeCnt++;
    LOGI("callback added success, request id %" LOG_PUB "lld, type %" LOG_PUB "d",
        static_cast<long long>(reqId), type);
    return HC_SUCCESS;
}

static void DelCallBackByReqId(int64_t reqId, int32_t type)
{
    IpcCallBackNode *node = nullptr;

    if ((g_ipcCallBackList.nodeCnt <= 0) || (g_ipcCallBackList.ctx == nullptr)) {
        return;
    }

    node = GetIpcCallBackByReqId(reqId, type);
    if ((node != nullptr) && (node->delOnFni == 1)) {
        ResetIpcCallBackNode(*node);
        g_ipcCallBackList.nodeCnt--;
    }
    return;
}

void DelIpcCallBackByReqId(int64_t reqId, int32_t type, bool withLock)
{
    if (withLock) {
        std::lock_guard<std::mutex> autoLock(g_cbListLock);
        DelCallBackByReqId(reqId, type);
        return;
    }
    DelCallBackByReqId(reqId, type);
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnTransmitStub(CallbackParams params)
{
    int64_t requestId = 0;
    uint8_t *data = nullptr;
    uint32_t dataLen = 0u;
    DeviceAuthCallback callback;
    int32_t ret;

    int32_t inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        reinterpret_cast<uint8_t *>(&requestId), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_COMM_DATA, reinterpret_cast<uint8_t *>(&data), reinterpret_cast<int32_t *>(&dataLen));
    ret = GetSdkCallBackByRequestId(params.callbackId, requestId, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        params.reply.WriteInt32(ret);
        return;
    }
    if (callback.onTransmit != nullptr) {
        bool bRet = callback.onTransmit(requestId, data, dataLen);
        LOGI("onTransmit successfully.");
        (bRet == true) ? params.reply.WriteInt32(HC_SUCCESS) : params.reply.WriteInt32(HC_ERROR);
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnSessKeyStub(CallbackParams params)
{
    int64_t requestId = 0;
    uint8_t *keyData = nullptr;
    uint32_t dataLen = 0u;
    DeviceAuthCallback callback;

    (void)params.reply;
    int32_t inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        reinterpret_cast<uint8_t *>(&requestId), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_SESS_KEY,
        reinterpret_cast<uint8_t *>(&keyData), reinterpret_cast<int32_t *>(&dataLen));
    int32_t ret = GetSdkCallBackByRequestId(params.callbackId, requestId, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        return;
    }
    if (callback.onSessionKeyReturned != nullptr) {
        callback.onSessionKeyReturned(requestId, keyData, dataLen);
        LOGI("onSessionKeyReturned successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnFinishStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t opCode = 0;
    char *data = nullptr;
    DeviceAuthCallback callback;
    int32_t ret;

    (void)params.reply;
    int32_t inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        reinterpret_cast<uint8_t *>(&requestId), &inOutLen);
    inOutLen = sizeof(opCode);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_OPCODE,
        reinterpret_cast<uint8_t *>(&opCode), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_COMM_DATA,
        reinterpret_cast<uint8_t *>(&data), nullptr);
    ret = GetSdkCallBackByRequestId(params.callbackId, requestId, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        return;
    }
    if (callback.onFinish != nullptr) {
        callback.onFinish(requestId, opCode, data);
        RemoveSdkCallBackByCallBackId(params.callbackId, requestId);
        LOGI("onFinish successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnErrorStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t opCode = 0;
    int32_t errCode = 0;
    char *errInfo = nullptr;
    DeviceAuthCallback callback;

    int32_t inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        reinterpret_cast<uint8_t *>(&requestId), &inOutLen);
    inOutLen = sizeof(opCode);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_OPCODE,
        reinterpret_cast<uint8_t *>(&opCode), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_ERRCODE,
        reinterpret_cast<uint8_t *>(&errCode), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_ERR_INFO,
        reinterpret_cast<uint8_t *>(&errInfo), nullptr);
    int32_t ret = GetSdkCallBackByRequestId(params.callbackId, requestId, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        params.reply.WriteInt32(ret);
        return;
    }
    if (callback.onError != nullptr) {
        callback.onError(requestId, opCode, errCode, errInfo);
        RemoveSdkCallBackByCallBackId(params.callbackId, requestId);
        LOGI("onError successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnRequestStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t opCode = 0;
    char *reqParams = nullptr;
    DeviceAuthCallback callback;

    int32_t inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        reinterpret_cast<uint8_t *>(&requestId), &inOutLen);
    inOutLen = sizeof(opCode);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_OPCODE,
        reinterpret_cast<uint8_t *>(&opCode), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQ_INFO,
        reinterpret_cast<uint8_t *>(&reqParams), nullptr);

    int32_t ret = GetSdkCallBackByRequestId(params.callbackId, requestId, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
        params.reply.WriteInt32(ret);
        return;
    }
    if (callback.onRequest != nullptr) {
        char *reqResult = callback.onRequest(requestId, opCode, reqParams);
        if (reqResult == nullptr) {
            params.reply.WriteInt32(HC_ERROR);
            return;
        }
        LOGI("onRequest successfully.");
        params.reply.WriteInt32(HC_SUCCESS);
        params.reply.WriteCString(const_cast<const char *>(reqResult));
        HcFree(reqResult);
        reqResult = nullptr;
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnGroupCreatedStub(CallbackParams params)
{
    const char *groupInfo = nullptr;
    const char *appId = nullptr;
    DataChangeListener callback;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_GROUP_INFO,
        reinterpret_cast<uint8_t *>(&groupInfo), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);

    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onGroupCreated != nullptr) {
        callback.onGroupCreated(groupInfo);
        LOGI("onGroupCreated successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnGroupDeletedStub(CallbackParams params)
{
    const char *groupInfo = nullptr;
    const char *appId = nullptr;
    DataChangeListener callback;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_GROUP_INFO,
        reinterpret_cast<uint8_t *>(&groupInfo), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onGroupDeleted != nullptr) {
        callback.onGroupDeleted(groupInfo);
        LOGI("onGroupDeleted successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnDevBoundStub(CallbackParams params)
{
    const char *groupInfo = nullptr;
    const char *appId = nullptr;
    DataChangeListener callback;
    const char *udid = nullptr;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID,
        reinterpret_cast<uint8_t *>(&udid), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_GROUP_INFO,
        reinterpret_cast<uint8_t *>(&groupInfo), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onDeviceBound != nullptr) {
        callback.onDeviceBound(udid, groupInfo);
        LOGI("onDeviceBound successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnDevUnboundStub(CallbackParams params)
{
    const char *groupInfo = nullptr;
    const char *appId = nullptr;
    DataChangeListener callback;
    const char *udid = nullptr;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID,
        reinterpret_cast<uint8_t *>(&udid), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_GROUP_INFO,
        reinterpret_cast<uint8_t *>(&groupInfo), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onDeviceUnBound != nullptr) {
        callback.onDeviceUnBound(udid, groupInfo);
        LOGI("onDeviceUnBound successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnDevUnTrustStub(CallbackParams params)
{
    const char *appId = nullptr;
    DataChangeListener callback;
    const char *udid = nullptr;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID,
        reinterpret_cast<uint8_t *>(&udid), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onDeviceNotTrusted != nullptr) {
        callback.onDeviceNotTrusted(udid);
        LOGI("onDeviceNotTrusted successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnDelLastGroupStub(CallbackParams params)
{
    const char *appId = nullptr;
    DataChangeListener callback;
    const char *udid = nullptr;
    int32_t groupType = 0;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID,
        reinterpret_cast<uint8_t *>(&udid), nullptr);
    int32_t inOutLen = sizeof(groupType);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_GROUP_TYPE,
        reinterpret_cast<uint8_t *>(&groupType), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onLastGroupDeleted != nullptr) {
        callback.onLastGroupDeleted(udid, groupType);
        LOGI("onLastGroupDeleted successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnTrustDevNumChangedStub(CallbackParams params)
{
    const char *appId = nullptr;
    DataChangeListener callback;
    int32_t devNum = 0;

    int32_t inOutLen = sizeof(devNum);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_DATA_NUM,
        reinterpret_cast<uint8_t *>(&devNum), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DataChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onTrustedDeviceNumChanged != nullptr) {
        callback.onTrustedDeviceNumChanged(devNum);
        LOGI("onTrustedDeviceNumChanged successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnCredAddStub(CallbackParams params)
{
    char *credId = nullptr;
    const char *appId = nullptr;
    char *credInfo = nullptr;
    CredChangeListener callback;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_CRED_ID,
        reinterpret_cast<uint8_t *>(&credId), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_CRED_INFO,
        reinterpret_cast<uint8_t *>(&credInfo), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_CRED_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(CredChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onCredAdd != nullptr) {
        callback.onCredAdd(credId, credInfo);
        LOGI("onCredAdd successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnCredDeleteStub(CallbackParams params)
{
    char *credId = nullptr;
    const char *appId = nullptr;
    char *credInfo = nullptr;
    CredChangeListener callback;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_CRED_ID,
        reinterpret_cast<uint8_t *>(&credId), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_CRED_INFO,
        reinterpret_cast<uint8_t *>(&credInfo), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_CRED_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(CredChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onCredDelete != nullptr) {
        callback.onCredDelete(credId, credInfo);
        LOGI("onCredDelete successfully.");
    }
    return;
}

__attribute__((no_sanitize("cfi"))) static void OnCredUpdateStub(CallbackParams params)
{
    char *credId = nullptr;
    const char *appId = nullptr;
    char *credInfo = nullptr;
    CredChangeListener callback;

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_CRED_ID,
        reinterpret_cast<uint8_t *>(&credId), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_CRED_INFO,
        reinterpret_cast<uint8_t *>(&credInfo), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, CB_TYPE_CRED_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(CredChangeListener)) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return;
    }
    if (callback.onCredUpdate != nullptr) {
        callback.onCredUpdate(credId, credInfo);
        LOGI("onCredUpdate successfully.");
    }
    return;
}

void ProcCbHook(int32_t callbackId, const IpcDataInfo *cbDataCache, int32_t cacheNum, uintptr_t replyCtx)
{
    CallbackStub stubTable[] = {
        OnTransmitStub, OnSessKeyStub, OnFinishStub, OnErrorStub,
        OnRequestStub, OnGroupCreatedStub, OnGroupDeletedStub, OnDevBoundStub,
        OnDevUnboundStub, OnDevUnTrustStub, OnDelLastGroupStub, OnTrustDevNumChangedStub,
        OnCredAddStub, OnCredDeleteStub, OnCredUpdateStub, OnTransmitStub, OnSessKeyStub,
        OnFinishStub, OnErrorStub, OnRequestStub, OnTransmitStub, OnSessKeyStub,
        OnFinishStub, OnErrorStub, OnRequestStub,
    };
    MessageParcel *reply = reinterpret_cast<MessageParcel *>(replyCtx);
    if ((callbackId < CB_ID_ON_TRANS) || (callbackId > CB_ID_ON_REQUEST_CRED)) {
        LOGE("Invalid call back id");
        return;
    }
    CallbackParams params = { callbackId, cbDataCache, cacheNum, *reply };
    stubTable[callbackId - 1](params);
    return;
}

static uint32_t EncodeCallData(MessageParcel &dataParcel, int32_t type, const uint8_t *param, int32_t paramSz)
{
    int32_t zeroVal = 0;
    const uint8_t *paramTmp = param;
    if ((param == nullptr) || (paramSz == 0)) {
        paramTmp = reinterpret_cast<const uint8_t *>(&zeroVal);
        paramSz = sizeof(zeroVal);
    }
    if (dataParcel.WriteInt32(type) && dataParcel.WriteInt32(paramSz) &&
        dataParcel.WriteBuffer(reinterpret_cast<const void *>(paramTmp), static_cast<size_t>(paramSz))) {
        return static_cast<uint32_t>(HC_SUCCESS);
    }
    return static_cast<uint32_t>(HC_ERROR);
}

/* group or cred auth callback adapter */
static bool GaCbOnTransmitWithType(int64_t requestId, const uint8_t *data, uint32_t dataLen, int32_t type,
    int32_t callbackId)
{
    int32_t ret = -1;
    MessageParcel dataParcel;
    MessageParcel reply;

    LOGI("starting ... request id: %" LOG_PUB "lld, type %" LOG_PUB "d", static_cast<long long>(requestId), type);
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    IpcCallBackNode *node = GetIpcCallBackByReqId(requestId, type);
    if (node == nullptr) {
        LOGE("onTransmit hook is null, request id %" LOG_PUB "lld", static_cast<long long>(requestId));
        return false;
    }
    uint32_t uRet = EncodeCallData(dataParcel, PARAM_TYPE_REQID,
        reinterpret_cast<const uint8_t *>(&requestId), sizeof(requestId));
    uRet |= EncodeCallData(dataParcel, PARAM_TYPE_COMM_DATA, data, dataLen);
    if (uRet != HC_SUCCESS) {
        LOGE("Error occurs, encode trans data failed.");
        return false;
    }
    ServiceDevAuth::ActCallback(node->proxyId, callbackId, true, dataParcel, reply);
    LOGI("process done, request id: %" LOG_PUB "lld", static_cast<long long>(requestId));
    if (reply.ReadInt32(ret) && (ret == HC_SUCCESS)) {
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

static bool IpcCaCbOnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    return GaCbOnTransmitWithType(requestId, data, dataLen, CB_TYPE_CRED_DEV_AUTH, CB_ID_ON_TRANS_CRED);
}

static void GaCbOnSessionKeyRetWithType(int64_t requestId, const uint8_t *sessKey, uint32_t sessKeyLen, int32_t type,
    int32_t callbackId)
{
    MessageParcel dataParcel;
    MessageParcel reply;

    LOGI("starting ... request id: %" LOG_PUB "lld, type %" LOG_PUB "d", static_cast<long long>(requestId), type);
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    IpcCallBackNode *node = GetIpcCallBackByReqId(requestId, type);
    if (node == nullptr) {
        LOGE("onSessionKeyReturned hook is null, request id %" LOG_PUB "lld", static_cast<long long>(requestId));
        return;
    }

    uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_REQID, reinterpret_cast<uint8_t *>(&requestId),
        sizeof(requestId));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_SESS_KEY, sessKey, sessKeyLen);
    if (ret != HC_SUCCESS) {
        LOGE("Error occurs, encode trans data failed.");
        return;
    }
    ServiceDevAuth::ActCallback(node->proxyId, callbackId, false, dataParcel, reply);
    LOGI("process done, request id: %" LOG_PUB "lld", static_cast<long long>(requestId));
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

static void IpcCaCbOnSessionKeyReturned(int64_t requestId, const uint8_t *sessKey, uint32_t sessKeyLen)
{
    GaCbOnSessionKeyRetWithType(requestId, sessKey, sessKeyLen, CB_TYPE_CRED_DEV_AUTH, CB_ID_SESS_KEY_DONE_CRED);
    return;
}

static void GaCbOnFinishWithType(int64_t requestId, int32_t operationCode, const char *returnData, int32_t type,
    int32_t callbackId)
{
    MessageParcel dataParcel;
    MessageParcel reply;

    LOGI("starting ... request id: %" LOG_PUB "lld, type %" LOG_PUB "d", static_cast<long long>(requestId), type);
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    IpcCallBackNode *node = GetIpcCallBackByReqId(requestId, type);
    if (node == nullptr) {
        LOGE("onFinish hook is null, request id %" LOG_PUB "lld", static_cast<long long>(requestId));
        return;
    }
    uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_REQID, reinterpret_cast<uint8_t *>(&requestId),
        sizeof(requestId));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_OPCODE,
        reinterpret_cast<uint8_t *>(&operationCode), sizeof(operationCode));
    if (returnData != nullptr) {
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_COMM_DATA,
            reinterpret_cast<const uint8_t *>(returnData), HcStrlen(returnData) + 1);
    }
    if (ret != HC_SUCCESS) {
        LOGE("Error occurs, encode trans data failed.");
        return;
    }
    ServiceDevAuth::ActCallback(node->proxyId, callbackId, false, dataParcel, reply);
    /* delete request id */
    DelIpcCallBackByReqId(requestId, type, false);
    LOGI("process done, request id: %" LOG_PUB "lld", static_cast<long long>(requestId));
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

static void IpcCaCbOnFinish(int64_t requestId, int32_t operationCode, const char *returnData)
{
    GaCbOnFinishWithType(requestId, operationCode, returnData, CB_TYPE_CRED_DEV_AUTH, CB_ID_ON_FINISH_CRED);
    return;
}

static void GaCbOnErrorWithType(int64_t requestId, int32_t operationCode,
    int32_t errorCode, const char *errorReturn, int32_t type)
{
    MessageParcel dataParcel;
    MessageParcel reply;

    LOGI("starting ... request id: %" LOG_PUB "lld, type %" LOG_PUB "d", static_cast<long long>(requestId), type);
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    IpcCallBackNode *node = GetIpcCallBackByReqId(requestId, type);
    if (node == nullptr) {
        LOGE("onError hook is null, request id %" LOG_PUB "lld", static_cast<long long>(requestId));
        return;
    }
    uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_REQID, reinterpret_cast<uint8_t *>(&requestId),
        sizeof(requestId));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_OPCODE,
        reinterpret_cast<uint8_t *>(&operationCode), sizeof(operationCode));
    ret |= EncodeCallData(dataParcel, PARAM_TYPE_ERRCODE, reinterpret_cast<uint8_t *>(&errorCode), sizeof(errorCode));
    if (errorReturn != nullptr) {
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_ERR_INFO,
            reinterpret_cast<const uint8_t *>(errorReturn), HcStrlen(errorReturn) + 1);
    }
    if (ret != HC_SUCCESS) {
        LOGE("Error occurs, encode trans data failed.");
        return;
    }
    if (type == CB_TYPE_DEV_AUTH) {
        ServiceDevAuth::ActCallback(node->proxyId, CB_ID_ON_ERROR, false, dataParcel, reply);
    }
    if (type == CB_TYPE_TMP_DEV_AUTH) {
        ServiceDevAuth::ActCallback(node->proxyId, CB_ID_ON_ERROR_TMP, false, dataParcel, reply);
    }
    if (type == CB_TYPE_CRED_DEV_AUTH) {
        ServiceDevAuth::ActCallback(node->proxyId, CB_ID_ON_ERROR_CRED, false, dataParcel, reply);
    }
    /* delete request id */
    DelIpcCallBackByReqId(requestId, type, false);
    LOGI("process done, request id: %" LOG_PUB "lld", static_cast<long long>(requestId));
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

static void IpcCaCbOnError(int64_t requestId, int32_t operationCode, int32_t errorCode, const char *errorReturn)
{
    GaCbOnErrorWithType(requestId, operationCode, errorCode, errorReturn, CB_TYPE_CRED_DEV_AUTH);
    return;
}

static char *GaCbOnRequestWithType(int64_t requestId, int32_t operationCode, const char *reqParams, int32_t type,
    int32_t callbackId)
{
    int32_t ret = -1;
    MessageParcel dataParcel;
    MessageParcel reply;
    const char *dPtr = nullptr;

    LOGI("starting ... request id: %" LOG_PUB "lld, type %" LOG_PUB "d", static_cast<long long>(requestId), type);
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    IpcCallBackNode *node = GetIpcCallBackByReqId(requestId, type);
    if (node == nullptr) {
        LOGE("onRequest hook is null, request id %" LOG_PUB "lld", static_cast<long long>(requestId));
        return nullptr;
    }

    uint32_t uRet = EncodeCallData(dataParcel, PARAM_TYPE_REQID, reinterpret_cast<uint8_t *>(&requestId),
        sizeof(requestId));
    uRet |= EncodeCallData(dataParcel, PARAM_TYPE_OPCODE,
        reinterpret_cast<uint8_t *>(&operationCode), sizeof(operationCode));
    if (reqParams != nullptr) {
        uRet |= EncodeCallData(dataParcel, PARAM_TYPE_REQ_INFO,
            reinterpret_cast<const uint8_t *>(reqParams), HcStrlen(reqParams) + 1);
    }
    if (uRet != HC_SUCCESS) {
        LOGE("Error occurs, encode trans data failed.");
        return nullptr;
    }
    ServiceDevAuth::ActCallback(node->proxyId, callbackId, true, dataParcel, reply);
    if (reply.ReadInt32(ret) && (ret == HC_SUCCESS)) {
        if (reply.GetReadableBytes() == 0) {
            LOGE("onRequest has no data, but success");
            return nullptr;
        }
        dPtr = reply.ReadCString();
        LOGI("process done, request id: %" LOG_PUB "lld, %" LOG_PUB "s string", static_cast<long long>(requestId),
            (dPtr != nullptr) ? "valid" : "invalid");
        return (dPtr != nullptr) ? strdup(dPtr) : nullptr;
    }
    return nullptr;
}

static bool CanFindCbByReqId(int64_t requestId, int32_t type)
{
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    IpcCallBackNode *node = GetIpcCallBackByReqId(requestId, type);
    return (node != nullptr) ? true : false;
}

static char *IpcGaCbOnRequest(int64_t requestId, int32_t operationCode, const char *reqParams)
{
    if (!CanFindCbByReqId(requestId, CB_TYPE_DEV_AUTH)) {
        CJson *reqParamsJson = CreateJsonFromString(reqParams);
        if (reqParamsJson == nullptr) {
            LOGE("Create json from string occur error!");
            return nullptr;
        }
        const char *callerAppId = GetStringFromJson(reqParamsJson, FIELD_APP_ID);
        if (callerAppId == nullptr) {
            LOGE("failed to get appId from json object!");
            FreeJson(reqParamsJson);
            return nullptr;
        }
        int32_t ret = AddReqIdByAppId(callerAppId, requestId);
        FreeJson(reqParamsJson);
        if (ret != HC_SUCCESS) {
            return nullptr;
        }
    }
    return GaCbOnRequestWithType(requestId, operationCode, reqParams, CB_TYPE_DEV_AUTH, CB_ID_ON_REQUEST);
}

static char *TmpIpcGaCbOnRequest(int64_t requestId, int32_t operationCode, const char *reqParams)
{
    return GaCbOnRequestWithType(requestId, operationCode, reqParams, CB_TYPE_TMP_DEV_AUTH, CB_ID_ON_REQUEST_TMP);
}

static char *IpcCaCbOnRequest(int64_t requestId, int32_t operationCode, const char *reqParams)
{
    if (!CanFindCbByReqId(requestId, CB_TYPE_CRED_DEV_AUTH)) {
        CJson *reqParamsJson = CreateJsonFromString(reqParams);
        if (reqParamsJson == nullptr) {
            LOGE("Failed to create json from string!");
            return nullptr;
        }
        const char *callerAppId = GetStringFromJson(reqParamsJson, FIELD_APP_ID);
        if (callerAppId == nullptr) {
            LOGE("Failed to get appId from reqParams json!");
            FreeJson(reqParamsJson);
            return nullptr;
        }
        int32_t ret = AddReqIdByAppId(callerAppId, requestId);
        FreeJson(reqParamsJson);
        if (ret != HC_SUCCESS) {
            return nullptr;
        }
    }
    return GaCbOnRequestWithType(requestId, operationCode, reqParams, CB_TYPE_CRED_DEV_AUTH, CB_ID_ON_REQUEST_CRED);
}

namespace {
void IpcOnGroupCreated(const char *groupInfo)
{
    if (groupInfo == nullptr) {
        LOGE("IpcOnGroupCreated, params error");
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("IpcCallBackList is not initialized");
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_GROUP_INFO,
            reinterpret_cast<const uint8_t *>(groupInfo), HcStrlen(groupInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_GROUP_CREATED, false,
            dataParcel, reply);
    }
    return;
}

void IpcOnGroupDeleted(const char *groupInfo)
{
    if (groupInfo == nullptr) {
        LOGE("IpcOnGroupDeleted, params error");
        return;
    }

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("IpcCallBackList un-initialized");
        return;
    }

    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_GROUP_INFO,
            reinterpret_cast<const uint8_t *>(groupInfo), HcStrlen(groupInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_GROUP_DELETED, false, dataParcel, reply);
    }
    return;
}

void IpcOnDeviceBound(const char *peerUdid, const char *groupInfo)
{
    if ((peerUdid == nullptr) || (groupInfo == nullptr)) {
        LOGE("Error occurs, param is nullptr.");
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("CallBackList un-initialized.");
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_UDID,
            reinterpret_cast<const uint8_t *>(peerUdid), HcStrlen(peerUdid) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_GROUP_INFO,
            reinterpret_cast<const uint8_t *>(groupInfo), HcStrlen(groupInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_DEV_BOUND, false,
            dataParcel, reply);
    }
    return;
}

void IpcOnDeviceUnBound(const char *peerUdid, const char *groupInfo)
{
    if ((peerUdid == nullptr) || (groupInfo == nullptr)) {
        LOGE("peerUdid is nullptr or groupInfo is nullptr.");
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("CallBackList ctx is nullptr.");
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_UDID,
            reinterpret_cast<const uint8_t *>(peerUdid), HcStrlen(peerUdid) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_GROUP_INFO,
            reinterpret_cast<const uint8_t *>(groupInfo), HcStrlen(groupInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_DEV_UNBOUND, false,
            dataParcel, reply);
    }
    return;
}

void IpcOnDeviceNotTrusted(const char *peerUdid)
{
    if (peerUdid == nullptr) {
        LOGE("Error occurs, peerUdid is nullptr.");
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("Error occurs, callBackList ctx is nullptr.");
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_UDID,
            reinterpret_cast<const uint8_t *>(peerUdid), HcStrlen(peerUdid) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_DEV_UNTRUSTED, false,
            dataParcel, reply);
    }
    return;
}

void IpcOnLastGroupDeleted(const char *peerUdid, int32_t groupType)
{
    if (peerUdid == nullptr) {
        LOGE("Error occurs, param is nullptr.");
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("Error occurs, callBackList ctx is uninitialized.");
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_UDID,
            reinterpret_cast<const uint8_t *>(peerUdid), HcStrlen(peerUdid) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_GROUP_TYPE,
            reinterpret_cast<const uint8_t *>(&groupType), sizeof(groupType));
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_LAST_GROUP_DELETED, false,
            dataParcel, reply);
    }
    return;
}

void IpcOnTrustedDeviceNumChanged(int32_t curTrustedDeviceNum)
{
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("IpcCallBackList un-initialized");
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_DATA_NUM,
            reinterpret_cast<const uint8_t *>(&curTrustedDeviceNum), sizeof(curTrustedDeviceNum));
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_TRUST_DEV_NUM_CHANGED, false,
            dataParcel, reply);
    }
    return;
}

void IpcOnCredAdd(const char *credId, const char *credInfo)
{
    if (credId == nullptr) {
        LOGE("IpcOnCredAdd failed, params error.");
        return;
    }

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("IpcOnCredAdd failed, callBackList is un-initialized.");
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_CRED_LISTENER) {
            continue;
        }
        MessageParcel reply;
        MessageParcel dataParcel;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_CRED_ID,
            reinterpret_cast<const uint8_t *>(credId), HcStrlen(credId) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_CRED_INFO,
            reinterpret_cast<const uint8_t *>(credInfo), HcStrlen(credInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_CRED_ADD, false,
            dataParcel, reply);
    }
    return;
}

void IpcOnCredDelete(const char *credId, const char *credInfo)
{
    if (credId == nullptr) {
        LOGE("IpcOnCredDelete failed, credId is nullptr.");
        return;
    }

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("IpcOnCredDelete failed, CallBackList un-initialized");
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_CRED_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_CRED_ID,
            reinterpret_cast<const uint8_t *>(credId), HcStrlen(credId) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_CRED_INFO,
            reinterpret_cast<const uint8_t *>(credInfo), HcStrlen(credInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_CRED_DELETE, false,
            dataParcel, reply);
    }
    return;
}

void IpcOnCredUpdate(const char *credId, const char *credInfo)
{
    if (credId == nullptr) {
        LOGE("IpcOnCredUpdate failed, params error");
        return;
    }

    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("IpcOnCredUpdate failed, IpcCallBackList un-initialized");
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != CB_TYPE_CRED_LISTENER) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = EncodeCallData(dataParcel, PARAM_TYPE_CRED_ID,
            reinterpret_cast<const uint8_t *>(credId), HcStrlen(credId) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_CRED_INFO,
            reinterpret_cast<const uint8_t *>(credInfo), HcStrlen(credInfo) + 1);
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, CB_ID_ON_CRED_UPDATE, false,
            dataParcel, reply);
    }
    return;
}
};

void InitDeviceAuthCbCtx(DeviceAuthCallback *ctx, int32_t type)
{
    if (ctx == nullptr) {
        return;
    }
    if (type == CB_TYPE_DEV_AUTH) {
        ctx->onTransmit = IpcGaCbOnTransmit;
        ctx->onSessionKeyReturned = IpcGaCbOnSessionKeyReturned;
        ctx->onFinish = IpcGaCbOnFinish;
        ctx->onError = IpcGaCbOnError;
        ctx->onRequest = IpcGaCbOnRequest;
    }
    if (type == CB_TYPE_TMP_DEV_AUTH) {
        ctx->onTransmit = TmpIpcGaCbOnTransmit;
        ctx->onSessionKeyReturned = TmpIpcGaCbOnSessionKeyReturned;
        ctx->onFinish = TmpIpcGaCbOnFinish;
        ctx->onError = TmpIpcGaCbOnError;
        ctx->onRequest = TmpIpcGaCbOnRequest;
    }
    if (type == CB_TYPE_CRED_DEV_AUTH) {
        ctx->onTransmit = IpcCaCbOnTransmit;
        ctx->onSessionKeyReturned = IpcCaCbOnSessionKeyReturned;
        ctx->onFinish = IpcCaCbOnFinish;
        ctx->onError = IpcCaCbOnError;
        ctx->onRequest = IpcCaCbOnRequest;
    }
    return;
}

void InitDevAuthListenerCbCtx(DataChangeListener *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    ctx->onGroupCreated = IpcOnGroupCreated;
    ctx->onGroupDeleted = IpcOnGroupDeleted;
    ctx->onDeviceBound = IpcOnDeviceBound;
    ctx->onDeviceUnBound = IpcOnDeviceUnBound;
    ctx->onDeviceNotTrusted = IpcOnDeviceNotTrusted;
    ctx->onLastGroupDeleted = IpcOnLastGroupDeleted;
    ctx->onTrustedDeviceNumChanged = IpcOnTrustedDeviceNumChanged;
    return;
}

void InitDevAuthCredListenerCbCtx(CredChangeListener *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    ctx->onCredAdd = IpcOnCredAdd;
    ctx->onCredDelete = IpcOnCredDelete;
    ctx->onCredUpdate = IpcOnCredUpdate;
    return;
}

/* ipc client process adapter */
int32_t CreateCallCtx(uintptr_t *callCtx)
{
    if (callCtx == nullptr) {
        return HC_ERR_INVALID_PARAMS;
    }

    ProxyDevAuthData *dataCache = new(std::nothrow) ProxyDevAuthData();
    if (dataCache == nullptr) {
        LOGE("call context alloc failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    *callCtx = reinterpret_cast<uintptr_t>(dataCache);
    return HC_SUCCESS;
}

void DestroyCallCtx(uintptr_t *callCtx)
{
    if ((callCtx != nullptr) && (*callCtx != 0)) {
        ProxyDevAuthData *dataCache = reinterpret_cast<ProxyDevAuthData *>(*callCtx);
        delete dataCache;
        *callCtx = 0;
    }
    return;
}

void SetCbCtxToDataCtx(uintptr_t callCtx, int32_t cbIdx)
{
    sptr<IRemoteObject> remote = g_sdkCbStub[cbIdx];
    ProxyDevAuthData *dataCache = reinterpret_cast<ProxyDevAuthData *>(callCtx);
    dataCache->SetCallbackStub(remote);
    return;
}

int32_t SetCallRequestParamInfo(uintptr_t callCtx, int32_t type, const uint8_t *param, int32_t paramSz)
{
    ProxyDevAuthData *dataCache = reinterpret_cast<ProxyDevAuthData *>(callCtx);

    return dataCache->EncodeCallRequest(type, param, paramSz);
}

int32_t DoBinderCall(uintptr_t callCtx, int32_t methodId, bool withSync)
{
    ProxyDevAuthData *dataCache = reinterpret_cast<ProxyDevAuthData *>(callCtx);

    int32_t ret = dataCache->FinalCallRequest(methodId);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    ret = dataCache->ActCall(withSync);
    if (ret != HC_SUCCESS) {
        LOGW("call ipc failed, retry one time.");
        ret = dataCache->ActCall(withSync);
    }
    return ret;
}

/* ipc service process adapter */
uint32_t SetIpcCallMap(uintptr_t ipcInstance, IpcServiceCall method, int32_t methodId)
{
    if ((method == nullptr) || (methodId <= 0)) {
        return static_cast<uint32_t>(HC_ERR_INVALID_PARAMS);
    }

    ServiceDevAuth *service = reinterpret_cast<ServiceDevAuth *>(ipcInstance);
    return static_cast<uint32_t>(service->SetCallMap(method, methodId));
}

int32_t CreateServiceInstance(uintptr_t *ipcInstance)
{
    ServiceDevAuth *service = new(std::nothrow) ServiceDevAuth();
    if (service == nullptr) {
        return HC_ERR_ALLOC_MEMORY;
    }
    *ipcInstance = reinterpret_cast<uintptr_t>(service);
    return HC_SUCCESS;
}

void DestroyServiceInstance(uintptr_t ipcInstance)
{
    ServiceDevAuth *service = reinterpret_cast<ServiceDevAuth *>(ipcInstance);
    if (service == nullptr) {
        return;
    }
    delete service;
}

int32_t AddDevAuthServiceToManager(uintptr_t serviceInstance)
{
    // Wait samgr ready for up to 1 second to ensure adding service to samgr.
    WaitParameter("bootevent.samgr.ready", "true", 1);

    IPCSkeleton::SetMaxWorkThreadNum(DEV_AUTH_MAX_THREAD_NUM);

    sptr<ISystemAbilityManager> sysMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysMgr == nullptr) {
        LOGE("Failed to get system ability manager!");
        return HC_ERR_IPC_GET_SERVICE;
    }
    ServiceDevAuth *servicePtr = reinterpret_cast<ServiceDevAuth *>(serviceInstance);
    int32_t ret = sysMgr->AddSystemAbility(DEVICE_AUTH_SERVICE_ID, servicePtr);
    if (ret != ERR_OK) {
        LOGE("add service failed");
        return HC_ERROR;
    }
    LOGI("AddSystemAbility to SA manager success");
    return HC_SUCCESS;
}

int32_t IpcEncodeCallReply(uintptr_t replayCache, int32_t type, const uint8_t *result, int32_t resultSz)
{
    int32_t errCnt = 0;
    unsigned long valZero = 0uL;

    MessageParcel *replyParcel = reinterpret_cast<MessageParcel *>(replayCache);
    errCnt += replyParcel->WriteInt32(type) ? 0 : 1;
    errCnt += replyParcel->WriteInt32(resultSz) ? 0 : 1;
    if ((result != nullptr) && (resultSz > 0)) {
        errCnt += replyParcel->WriteBuffer(
            reinterpret_cast<const void *>(result), static_cast<size_t>(resultSz)) ? 0 : 1;
    } else {
        errCnt += replyParcel->WriteBuffer(
            reinterpret_cast<const void *>(&valZero), sizeof(unsigned long)) ? 0 : 1;
    }
    if (errCnt != 0) {
        LOGE("encode call reply fail.");
        return HC_ERROR;
    }
    return HC_SUCCESS;
}

int32_t DecodeIpcData(uintptr_t data, int32_t *type, uint8_t **val, int32_t *valSz)
{
    MessageParcel *dataPtr = reinterpret_cast<MessageParcel *>(data);
    if (dataPtr->GetReadableBytes() == 0) {
        return HC_SUCCESS;
    }
    if (dataPtr->GetReadableBytes() < sizeof(int32_t)) {
        LOGE("Insufficient data available in IPC container. [Data]: type");
        return HC_ERR_IPC_BAD_MESSAGE_LENGTH;
    }
    *type = dataPtr->ReadInt32();
    if (dataPtr->GetReadableBytes() < sizeof(int32_t)) {
        LOGE("Insufficient data available in IPC container. [Data]: valSz");
        return HC_ERR_IPC_BAD_MESSAGE_LENGTH;
    }
    *valSz = dataPtr->ReadInt32();
    if (*valSz < 0 || *valSz > static_cast<int32_t>(dataPtr->GetReadableBytes())) {
        LOGE("Insufficient data available in IPC container. [Data]: val");
        return HC_ERR_IPC_BAD_VAL_LENGTH;
    }
    *val = const_cast<uint8_t *>(dataPtr->ReadUnpadBuffer(*valSz));
    return HC_SUCCESS;
}

void DecodeCallReply(uintptr_t callCtx, IpcDataInfo *replyCache, int32_t cacheNum)
{
    ProxyDevAuthData *dataCache = reinterpret_cast<ProxyDevAuthData *>(callCtx);
    MessageParcel *tmpParcel = dataCache->GetReplyParcel();
    if (tmpParcel->GetReadableBytes() < sizeof(int32_t)) {
        LOGE("Insufficient data available in IPC container. [Data]: dataLen");
        return;
    }
    int32_t dataLen = tmpParcel->ReadInt32();
    if ((dataLen <= 0) || (dataLen != static_cast<int32_t>(tmpParcel->GetReadableBytes()))) {
        LOGE("decode failed, data length %" LOG_PUB "d", dataLen);
        return;
    }

    for (int32_t i = 0; i < cacheNum; i++) {
        int32_t ret = DecodeIpcData(reinterpret_cast<uintptr_t>(tmpParcel),
            &(replyCache[i].type), &(replyCache[i].val), &(replyCache[i].valSz));
        if (ret != HC_SUCCESS) {
            return;
        }
    }
    return;
}

static bool IsTypeForSettingPtr(int32_t type)
{
    int32_t typeList[] = {
        PARAM_TYPE_APPID, PARAM_TYPE_DEV_AUTH_CB, PARAM_TYPE_LISTENER, PARAM_TYPE_CREATE_PARAMS,
        PARAM_TYPE_GROUPID, PARAM_TYPE_UDID, PARAM_TYPE_ADD_PARAMS, PARAM_TYPE_DEL_PARAMS,
        PARAM_TYPE_QUERY_PARAMS, PARAM_TYPE_COMM_DATA, PARAM_TYPE_SESS_KEY,
        PARAM_TYPE_REQ_INFO, PARAM_TYPE_GROUP_INFO, PARAM_TYPE_AUTH_PARAMS, PARAM_TYPE_REQ_JSON,
        PARAM_TYPE_PSEUDONYM_ID, PARAM_TYPE_INDEX_KEY, PARAM_TYPE_ERR_INFO, PARAM_TYPE_REQUEST_PARAMS,
        PARAM_TYPE_CRED_ID, PARAM_TYPE_PK_WITH_SIG, PARAM_TYPE_SERVICE_ID, PARAM_TYPE_RANDOM, PARAM_TYPE_CRED_INFO,
    };
    int32_t n = sizeof(typeList) / sizeof(typeList[0]);
    for (int32_t i = 0; i < n; i++) {
        if (typeList[i] == type) {
            return true;
        }
    }
    return false;
}

static bool IsTypeForCpyData(int32_t type)
{
    int32_t typeList[] = {
        PARAM_TYPE_REQID, PARAM_TYPE_GROUP_TYPE, PARAM_TYPE_OPCODE, PARAM_TYPE_ERRCODE, PARAM_TYPE_OS_ACCOUNT_ID
    };
    int32_t n = sizeof(typeList) / sizeof(typeList[0]);
    for (int32_t i = 0; i < n; i++) {
        if (typeList[i] == type) {
            return true;
        }
    }
    return false;
}

void DevAuthDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    LOGI("remote is not actively, to reset local resource");
    ResetIpcCallBackNodeByNodeId(callbackIdx);
}

int32_t GetIpcRequestParamByType(const IpcDataInfo *ipcParams, int32_t paramNum,
    int32_t type, uint8_t *paramCache, int32_t *cacheLen)
{
    int32_t ret = HC_ERR_IPC_BAD_MSG_TYPE;
    errno_t eno;

    for (int32_t i = 0; i < paramNum; i++) {
        if (ipcParams[i].type != type) {
            continue;
        }
        ret = HC_SUCCESS;
        if (IsTypeForSettingPtr(type)) {
            *(reinterpret_cast<uint8_t **>(paramCache)) = ipcParams[i].val;
            if (cacheLen != nullptr) {
                *cacheLen = ipcParams[i].valSz;
            }
            break;
        }
        if (IsTypeForCpyData(type)) {
            if ((ipcParams[i].val == nullptr) || (ipcParams[i].valSz <= 0) || (cacheLen == nullptr)) {
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
        if ((type == PARAM_TYPE_CB_OBJECT) && (cacheLen != nullptr) &&
            (static_cast<uint32_t>(*cacheLen) >= sizeof(ipcParams[i].idx))) {
            *(reinterpret_cast<int32_t *>(paramCache)) = ipcParams[i].idx;
        }
        break;
    }
    return ret;
}

bool IsCallbackMethod(int32_t methodId)
{
    if ((methodId == IPC_CALL_ID_REG_CB) || (methodId == IPC_CALL_ID_REG_LISTENER) ||
        (methodId == IPC_CALL_ID_DA_AUTH_DEVICE) || (methodId == IPC_CALL_ID_DA_PROC_DATA) ||
        (methodId == IPC_CALL_ID_GA_PROC_DATA) || (methodId == IPC_CALL_ID_AUTH_DEVICE) ||
        (methodId == IPC_CALL_ID_CM_REG_LISTENER) || (methodId == IPC_CALL_ID_CA_AUTH_CREDENTIAL) ||
        (methodId == IPC_CALL_ID_CA_PROCESS_CRED_DATA) || (methodId == IPC_CALL_ID_LA_START_LIGHT_ACCOUNT_AUTH)||
        (methodId == IPC_CALL_ID_LA_PROCESS_LIGHT_ACCOUNT_AUTH)) {
        return true;
    }
    return false;
}

void UnInitProxyAdapt(void)
{
    g_sdkCbStub[IPC_CALL_BACK_STUB_AUTH_ID] = nullptr;
    g_sdkCbStub[IPC_CALL_BACK_STUB_BIND_ID] = nullptr;
    g_sdkCbStub[IPC_CALL_BACK_STUB_DIRECT_AUTH_ID] = nullptr;
    g_sdkCbStub[IPC_CALL_BACK_STUB_LIGHT_AUTH_ID] = nullptr;
    return;
}

int32_t InitProxyAdapt(void)
{
    g_sdkCbStub[IPC_CALL_BACK_STUB_AUTH_ID] = new(std::nothrow) StubDevAuthCb;
    g_sdkCbStub[IPC_CALL_BACK_STUB_BIND_ID] = new(std::nothrow) StubDevAuthCb;
    g_sdkCbStub[IPC_CALL_BACK_STUB_DIRECT_AUTH_ID] = new(std::nothrow) StubDevAuthCb;
    g_sdkCbStub[IPC_CALL_BACK_STUB_LIGHT_AUTH_ID] = new(std::nothrow) StubDevAuthCb;
    if (!g_sdkCbStub[IPC_CALL_BACK_STUB_AUTH_ID] || !g_sdkCbStub[IPC_CALL_BACK_STUB_BIND_ID] ||
        !g_sdkCbStub[IPC_CALL_BACK_STUB_DIRECT_AUTH_ID] || !g_sdkCbStub[IPC_CALL_BACK_STUB_LIGHT_AUTH_ID]) {
        LOGE("alloc callback stub object failed");
        UnInitProxyAdapt();
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}
