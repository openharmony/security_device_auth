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
    if (ipcCallBackList == nullptr) {
        return;
    }
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
    DESTROY_HC_VECTOR(SdkIpcCallBackList, &g_sdkIpcCallBackList);
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

        if (memcpy_s(&node, sizeof(SdkIpcCallBackNode), entry, sizeof(SdkIpcCallBackNode)) != EOK) {
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

static ParamCategory GetParamCategory(int32_t type)
{
    if (type == PARAM_TYPE_CB_OBJECT) {
        return PARAM_CAT_CB_OBJECT;
    }
    for (int32_t i = 0; i < static_cast<int32_t>(sizeof(CPY_TYPES) / sizeof(CPY_TYPES[0])); i++) {
        if (CPY_TYPES[i] == type) {
            return PARAM_CAT_CPY;
        }
    }
    if (type >= 1 && type <= PARAM_TYPE_RETURN_INFO) {
        return PARAM_CAT_PTR;
    }
    return PARAM_CAT_NONE;
}

static int32_t GetTypeExpectSize(int32_t paramType)
{
    if (paramType == PARAM_TYPE_DEV_AUTH_CB) {
        return static_cast<int32_t>(sizeof(DeviceAuthCallback));
    }
    if (paramType == PARAM_TYPE_REQID) {
        return static_cast<int32_t>(sizeof(int64_t));
    }
    if (GetParamCategory(paramType) == PARAM_CAT_CPY) {
        return static_cast<int32_t>(sizeof(int32_t));
    }
    return 0;
}

int32_t GetAndValSizeParam(const IpcDataInfo *ipcParams,
    int32_t paramNum, int32_t paramType, uint8_t *param, int32_t *paramSize)
{
    int32_t expectedSize = GetTypeExpectSize(paramType);
    if (expectedSize == 0) {
        LOGE("unsupported param type %" LOG_PUB "d", paramType);
        return HC_ERR_IPC_BAD_PARAM;
    }
    int32_t ret = GetIpcRequestParamByType(ipcParams, paramNum, paramType, param, paramSize);
    if ((*paramSize) != expectedSize || ret != HC_SUCCESS) {
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
    char *str = *(reinterpret_cast<char **>(param));
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
}

static bool g_checkCbListReady(std::lock_guard<std::mutex> &autoLock)
{
    (void)autoLock;
    if (g_ipcCallBackList.ctx == nullptr) {
        LOGE("list not inited");
        return false;
    }
    if (g_ipcCallBackList.nodeCnt >= IPC_CALL_BACK_MAX_NODES) {
        LOGE("list is full");
        return false;
    }
    return true;
}

static void ResetExistingCbNodeProxy(IpcCallBackNode *node)
{
    if (node->proxyId >= 0) {
        ServiceDevAuth::ResetRemoteObject(node->proxyId);
        node->proxyId = DEFAULT_CALLBACK_PROXY_ID;
    }
}

void AddIpcCbObjByAppId(const char *appId, int32_t objIdx, int32_t type)
{
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (!g_checkCbListReady(autoLock)) {
        return;
    }
    IpcCallBackNode *node = GetIpcCallBackByAppId(appId, type);
    if (node != nullptr) {
        ResetExistingCbNodeProxy(node);
        node->proxyId = objIdx;
        SetCbDeathRecipient(type, objIdx, node->nodeIdx);
        LOGI("ipc object add success, appid: %" LOG_PUB "s, proxyId %" LOG_PUB "d", appId, node->proxyId);
    }
}

int32_t AddIpcCallBackByAppId(const char *appId, int32_t type)
{
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (!g_checkCbListReady(autoLock)) {
        return HC_ERROR;
    }
    IpcCallBackNode *node = GetIpcCallBackByAppId(appId, type);
    if (node != nullptr) {
        ResetExistingCbNodeProxy(node);
        LOGI("Callback add success, appid: %" LOG_PUB "s", appId);
        return HC_SUCCESS;
    }
    node = GetFreeIpcCallBackNode();
    if (node == nullptr) {
        LOGE("get free node failed");
        return HC_ERROR;
    }
    node->cbType = type;
    errno_t eno = memcpy_s(&(node->appId), sizeof(node->appId), appId, HcStrlen(appId) + 1);
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
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if ((g_ipcCallBackList.nodeCnt <= 0) || (g_ipcCallBackList.ctx == nullptr)) {
        return;
    }
    IpcCallBackNode *node = GetIpcCallBackByAppId(appId, type);
    if (node != nullptr) {
        ResetIpcCallBackNode(*node);
        g_ipcCallBackList.nodeCnt--;
    }
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
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (!g_checkCbListReady(autoLock)) {
        return;
    }
    IpcCallBackNode *node = GetIpcCallBackByReqId(reqId, type);
    if (node != nullptr) {
        ResetExistingCbNodeProxy(node);
        node->proxyId = objIdx;
        LOGI("ipc object add success, request id %" LOG_PUB "lld, type %" LOG_PUB "d, proxy id %" LOG_PUB "d",
            static_cast<long long>(reqId), type, node->proxyId);
    }
}

int32_t AddIpcCallBackByReqId(int64_t reqId, int32_t type)
{
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (!g_checkCbListReady(autoLock)) {
        return HC_ERROR;
    }
    IpcCallBackNode *node = GetIpcCallBackByReqId(reqId, type);
    if (node != nullptr) {
        ResetExistingCbNodeProxy(node);
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
}

void DelIpcCallBackByReqId(int64_t reqId, int32_t type, bool withLock)
{
    if (withLock) {
        std::lock_guard<std::mutex> autoLock(g_cbListLock);
        DelCallBackByReqId(reqId, type);
        return;
    }
    DelCallBackByReqId(reqId, type);
}

static int32_t GetDevAuthCbByReqId(CallbackParams params, int64_t &requestId, DeviceAuthCallback &callback)
{
    int32_t inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        reinterpret_cast<uint8_t *>(&requestId), &inOutLen);
    int32_t ret = GetSdkCallBackByRequestId(params.callbackId, requestId,
        reinterpret_cast<uint8_t *>(&callback), sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) {
        LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
    }
    return ret;
}

static void OnTransmitStub(CallbackParams params)
{
    int64_t requestId = 0;
    uint8_t *data = nullptr;
    uint32_t dataLen = 0u;
    DeviceAuthCallback callback;
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_COMM_DATA, reinterpret_cast<uint8_t *>(&data), reinterpret_cast<int32_t *>(&dataLen));
    int32_t ret = GetDevAuthCbByReqId(params, requestId, callback);
    if (ret != HC_SUCCESS) {
        params.reply.WriteInt32(ret);
        return;
    }
    if (callback.onTransmit != nullptr) {
        bool bRet = callback.onTransmit(requestId, data, dataLen);
        (bRet == true) ? params.reply.WriteInt32(HC_SUCCESS) : params.reply.WriteInt32(HC_ERROR);
    }
}

static void OnSessKeyStub(CallbackParams params)
{
    int64_t requestId = 0;
    uint8_t *keyData = nullptr;
    uint32_t dataLen = 0u;
    DeviceAuthCallback callback;
    (void)params.reply;
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_SESS_KEY,
        reinterpret_cast<uint8_t *>(&keyData), reinterpret_cast<int32_t *>(&dataLen));
    if (GetDevAuthCbByReqId(params, requestId, callback) != HC_SUCCESS) {
        return;
    }
    if (callback.onSessionKeyReturned != nullptr) {
        callback.onSessionKeyReturned(requestId, keyData, dataLen);
    }
}

static void OnFinishStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t opCode = 0;
    char *data = nullptr;
    DeviceAuthCallback callback;
    (void)params.reply;
    int32_t inOutLen = sizeof(opCode);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_OPCODE,
        reinterpret_cast<uint8_t *>(&opCode), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_COMM_DATA,
        reinterpret_cast<uint8_t *>(&data), nullptr);
    if (GetDevAuthCbByReqId(params, requestId, callback) != HC_SUCCESS) {
        return;
    }
    if (callback.onFinish != nullptr) {
        callback.onFinish(requestId, opCode, data);
        RemoveSdkCallBackByCallBackId(params.callbackId, requestId);
    }
}

static void OnErrorStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t opCode = 0;
    int32_t errCode = 0;
    char *errInfo = nullptr;
    DeviceAuthCallback callback;
    int32_t inOutLen = sizeof(opCode);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_OPCODE,
        reinterpret_cast<uint8_t *>(&opCode), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_ERRCODE,
        reinterpret_cast<uint8_t *>(&errCode), &inOutLen);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_ERR_INFO,
        reinterpret_cast<uint8_t *>(&errInfo), nullptr);
    int32_t ret = GetDevAuthCbByReqId(params, requestId, callback);
    if (ret != HC_SUCCESS) {
        params.reply.WriteInt32(ret);
        return;
    }
    if (callback.onError != nullptr) {
        callback.onError(requestId, opCode, errCode, errInfo);
        RemoveSdkCallBackByCallBackId(params.callbackId, requestId);
    }
}

static int32_t GetSdkCallBackByReqParams(int64_t callbackId, char *reqParams, int64_t requestId,
    DeviceAuthCallback *callback)
{
    CJson *reqParamsJson = CreateJsonFromString(reqParams);
    if (reqParamsJson == nullptr) {
        LOGE("Create json from string occur error!");
        return HC_ERR_JSON_FAIL;
    }
    const char *callerAppId = GetStringFromJson(reqParamsJson, FIELD_APP_ID);
    if (callerAppId == nullptr) {
        LOGE("failed to get appId from json object!");
        FreeJson(reqParamsJson);
        return HC_ERR_JSON_GET;
    }
    int32_t ret = AddRequestIdByAppId(callerAppId, requestId);
    FreeJson(reqParamsJson);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    return GetSdkCallBackByRequestId(callbackId, requestId, reinterpret_cast<uint8_t *>(callback),
        sizeof(DeviceAuthCallback));
}

static void OnRequestStub(CallbackParams params)
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

    if (GetSdkCallBackByRequestId(params.callbackId, requestId, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DeviceAuthCallback)) != HC_SUCCESS) {
        int32_t ret = GetSdkCallBackByReqParams(params.callbackId, reqParams, requestId, &callback);
        if (ret != HC_SUCCESS) {
            LOGE("GetSdkCallBackByRequestId failed, ret: %" LOG_PUB "d", ret);
            params.reply.WriteInt32(ret);
            return;
        }
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
}

static bool GetCbByAppIdFromParams(CallbackParams params, uint8_t cbType, uint8_t *val, int32_t valSize)
{
    const char *appId = nullptr;
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_APPID,
        reinterpret_cast<uint8_t *>(&appId), nullptr);
    if (GetSdkCallBackByAppId(appId, cbType, val, valSize) != HC_SUCCESS) {
        LOGE("GetSdkCallBackByAppId failed.");
        return false;
    }
    return true;
}

static bool GetListenerCbFromParams(CallbackParams params, DataChangeListener &callback)
{
    return GetCbByAppIdFromParams(params, CB_TYPE_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(DataChangeListener));
}

static bool GetCredCbFromParams(CallbackParams params, CredChangeListener &callback)
{
    return GetCbByAppIdFromParams(params, CB_TYPE_CRED_LISTENER, reinterpret_cast<uint8_t *>(&callback),
        sizeof(CredChangeListener));
}

typedef void (*ListenerStrCbFunc)(const char *);
typedef void (*ListenerStrStrCbFunc)(const char *, const char *);

static void ListenerStrCbStub(CallbackParams params, int32_t paramType,
    ListenerStrCbFunc DataChangeListener::*cbField)
{
    const char *strParam = nullptr;
    DataChangeListener callback;
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, paramType,
        reinterpret_cast<uint8_t *>(&strParam), nullptr);
    if (!GetListenerCbFromParams(params, callback)) {
        return;
    }
    if ((callback.*cbField) != nullptr) {
        (callback.*cbField)(strParam);
    }
}

static void ListenerStrStrCbStub(CallbackParams params, int32_t paramType1, int32_t paramType2,
    ListenerStrStrCbFunc DataChangeListener::*cbField)
{
    const char *param1 = nullptr;
    const char *param2 = nullptr;
    DataChangeListener callback;
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, paramType1,
        reinterpret_cast<uint8_t *>(&param1), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, paramType2,
        reinterpret_cast<uint8_t *>(&param2), nullptr);
    if (!GetListenerCbFromParams(params, callback)) {
        return;
    }
    if ((callback.*cbField) != nullptr) {
        (callback.*cbField)(param1, param2);
    }
}

static void OnGroupCreatedStub(CallbackParams params)
{
    ListenerStrCbStub(params, PARAM_TYPE_GROUP_INFO, &DataChangeListener::onGroupCreated);
}

static void OnGroupDeletedStub(CallbackParams params)
{
    ListenerStrCbStub(params, PARAM_TYPE_GROUP_INFO, &DataChangeListener::onGroupDeleted);
}

static void OnDevBoundStub(CallbackParams params)
{
    ListenerStrStrCbStub(params, PARAM_TYPE_UDID, PARAM_TYPE_GROUP_INFO, &DataChangeListener::onDeviceBound);
}

static void OnDevUnboundStub(CallbackParams params)
{
    ListenerStrStrCbStub(params, PARAM_TYPE_UDID, PARAM_TYPE_GROUP_INFO, &DataChangeListener::onDeviceUnBound);
}

static void OnDevUnTrustStub(CallbackParams params)
{
    ListenerStrCbStub(params, PARAM_TYPE_UDID, &DataChangeListener::onDeviceNotTrusted);
}

static void OnDelLastGroupStub(CallbackParams params)
{
    const char *udid = nullptr;
    int32_t groupType = 0;
    DataChangeListener callback;
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, PARAM_TYPE_UDID,
        reinterpret_cast<uint8_t *>(&udid), nullptr);
    int32_t inOutLen = sizeof(groupType);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_GROUP_TYPE,
        reinterpret_cast<uint8_t *>(&groupType), &inOutLen);
    if (!GetListenerCbFromParams(params, callback)) {
        return;
    }
    if (callback.onLastGroupDeleted != nullptr) {
        callback.onLastGroupDeleted(udid, groupType);
    }
}

static void OnTrustDevNumChangedStub(CallbackParams params)
{
    int32_t devNum = 0;
    DataChangeListener callback;
    int32_t inOutLen = sizeof(devNum);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_DATA_NUM,
        reinterpret_cast<uint8_t *>(&devNum), &inOutLen);
    if (!GetListenerCbFromParams(params, callback)) {
        return;
    }
    if (callback.onTrustedDeviceNumChanged != nullptr) {
        callback.onTrustedDeviceNumChanged(devNum);
    }
}

static void OnGroupActiveInUserStub(CallbackParams params)
{
    ListenerStrCbStub(params, PARAM_TYPE_RETURN_INFO, &DataChangeListener::onGroupActiveInUser);
}

static void OnGroupInactiveInUserStub(CallbackParams params)
{
    ListenerStrCbStub(params, PARAM_TYPE_RETURN_INFO, &DataChangeListener::onGroupInactiveInUser);
}

static void OnDeviceActiveInUserStub(CallbackParams params)
{
    ListenerStrStrCbStub(params, PARAM_TYPE_UDID, PARAM_TYPE_RETURN_INFO, &DataChangeListener::onDeviceActiveInUser);
}

static void OnDeviceInactiveInUserStub(CallbackParams params)
{
    ListenerStrStrCbStub(params, PARAM_TYPE_UDID, PARAM_TYPE_RETURN_INFO, &DataChangeListener::onDeviceInactiveInUser);
}

static void OnDeviceNotTrustedInUserStub(CallbackParams params)
{
    ListenerStrStrCbStub(params, PARAM_TYPE_UDID, PARAM_TYPE_RETURN_INFO,
        &DataChangeListener::onDeviceNotTrustedInUser);
}

typedef void (*CredCbFunc)(const char *, const char *);

static void CredCbStub(CallbackParams params, int32_t paramType1, int32_t paramType2,
    CredCbFunc CredChangeListener::*cbField)
{
    const char *param1 = nullptr;
    const char *param2 = nullptr;
    CredChangeListener callback;
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, paramType1,
        reinterpret_cast<uint8_t *>(&param1), nullptr);
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum, paramType2,
        reinterpret_cast<uint8_t *>(&param2), nullptr);
    if (!GetCredCbFromParams(params, callback)) {
        return;
    }
    if ((callback.*cbField) != nullptr) {
        (callback.*cbField)(param1, param2);
    }
}

static void OnCredAddStub(CallbackParams params)
{
    CredCbStub(params, PARAM_TYPE_CRED_ID, PARAM_TYPE_CRED_INFO, &CredChangeListener::onCredAdd);
}

static void OnCredDeleteStub(CallbackParams params)
{
    CredCbStub(params, PARAM_TYPE_CRED_ID, PARAM_TYPE_CRED_INFO, &CredChangeListener::onCredDelete);
}

static void OnCredUpdateStub(CallbackParams params)
{
    CredCbStub(params, PARAM_TYPE_CRED_ID, PARAM_TYPE_CRED_INFO, &CredChangeListener::onCredUpdate);
}

static void OnCredActiveInUserStub(CallbackParams params)
{
    CredCbStub(params, PARAM_TYPE_CRED_ID, PARAM_TYPE_RETURN_INFO, &CredChangeListener::onCredActiveInUser);
}

static void OnCredInactiveInUserStub(CallbackParams params)
{
    CredCbStub(params, PARAM_TYPE_CRED_ID, PARAM_TYPE_RETURN_INFO, &CredChangeListener::onCredInactiveInUser);
}

void ProcCbHook(int32_t callbackId, const IpcDataInfo *cbDataCache, int32_t cacheNum, uintptr_t replyCtx)
{
    CallbackStub stubTable[] = {
        OnTransmitStub, OnSessKeyStub, OnFinishStub, OnErrorStub,
        OnRequestStub, OnGroupCreatedStub, OnGroupDeletedStub, OnDevBoundStub,
        OnDevUnboundStub, OnDevUnTrustStub, OnDelLastGroupStub, OnTrustDevNumChangedStub,
        OnCredAddStub, OnCredDeleteStub, OnCredUpdateStub, OnTransmitStub, OnSessKeyStub,
        OnFinishStub, OnErrorStub, OnRequestStub, OnTransmitStub, OnSessKeyStub,
        OnFinishStub, OnErrorStub, OnRequestStub, OnGroupActiveInUserStub, OnGroupInactiveInUserStub,
        OnDeviceActiveInUserStub, OnDeviceInactiveInUserStub, OnDeviceNotTrustedInUserStub,
        OnCredActiveInUserStub, OnCredInactiveInUserStub,
    };
    MessageParcel *reply = reinterpret_cast<MessageParcel *>(replyCtx);
    if ((callbackId < CB_ID_ON_TRANS) || (callbackId > CB_ID_ON_CRED_INACTIVE_IN_USER)) {
        LOGE("Invalid call back id");
        return;
    }
    CallbackParams params = { callbackId, cbDataCache, cacheNum, *reply };
    stubTable[callbackId - 1](params);
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
}

static void IpcGaCbOnSessionKeyReturned(int64_t requestId, const uint8_t *sessKey, uint32_t sessKeyLen)
{
    GaCbOnSessionKeyRetWithType(requestId, sessKey, sessKeyLen, CB_TYPE_DEV_AUTH, CB_ID_SESS_KEY_DONE);
}

static void TmpIpcGaCbOnSessionKeyReturned(int64_t requestId, const uint8_t *sessKey, uint32_t sessKeyLen)
{
    GaCbOnSessionKeyRetWithType(requestId, sessKey, sessKeyLen, CB_TYPE_TMP_DEV_AUTH, CB_ID_SESS_KEY_DONE_TMP);
}

static void IpcCaCbOnSessionKeyReturned(int64_t requestId, const uint8_t *sessKey, uint32_t sessKeyLen)
{
    GaCbOnSessionKeyRetWithType(requestId, sessKey, sessKeyLen, CB_TYPE_CRED_DEV_AUTH, CB_ID_SESS_KEY_DONE_CRED);
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
}

static void IpcGaCbOnFinish(int64_t requestId, int32_t operationCode, const char *returnData)
{
    GaCbOnFinishWithType(requestId, operationCode, returnData, CB_TYPE_DEV_AUTH, CB_ID_ON_FINISH);
}

static void TmpIpcGaCbOnFinish(int64_t requestId, int32_t operationCode, const char *returnData)
{
    GaCbOnFinishWithType(requestId, operationCode, returnData, CB_TYPE_TMP_DEV_AUTH, CB_ID_ON_FINISH_TMP);
}

static void IpcCaCbOnFinish(int64_t requestId, int32_t operationCode, const char *returnData)
{
    GaCbOnFinishWithType(requestId, operationCode, returnData, CB_TYPE_CRED_DEV_AUTH, CB_ID_ON_FINISH_CRED);
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
    static const int32_t ERROR_CB_IDS[] = {
        0, CB_ID_ON_ERROR, CB_ID_ON_ERROR_TMP, 0, 0, CB_ID_ON_ERROR_CRED
    };
    if (type >= 1 && type <= CB_TYPE_CRED_DEV_AUTH) {
        ServiceDevAuth::ActCallback(node->proxyId, ERROR_CB_IDS[type], false, dataParcel, reply);
    }
    DelIpcCallBackByReqId(requestId, type, false);
    LOGI("process done, request id: %" LOG_PUB "lld", static_cast<long long>(requestId));
}

static void IpcGaCbOnError(int64_t requestId, int32_t operationCode, int32_t errorCode, const char *errorReturn)
{
    GaCbOnErrorWithType(requestId, operationCode, errorCode, errorReturn, CB_TYPE_DEV_AUTH);
}

static void TmpIpcGaCbOnError(int64_t requestId, int32_t operationCode, int32_t errorCode, const char *errorReturn)
{
    GaCbOnErrorWithType(requestId, operationCode, errorCode, errorReturn, CB_TYPE_TMP_DEV_AUTH);
}

static void IpcCaCbOnError(int64_t requestId, int32_t operationCode, int32_t errorCode, const char *errorReturn)
{
    GaCbOnErrorWithType(requestId, operationCode, errorCode, errorReturn, CB_TYPE_CRED_DEV_AUTH);
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

static bool TryAddReqIdByAppId(int64_t requestId, const char *reqParams)
{
    CJson *reqParamsJson = CreateJsonFromString(reqParams);
    if (reqParamsJson == nullptr) {
        LOGE("Failed to create json from string!");
        return false;
    }
    const char *callerAppId = GetStringFromJson(reqParamsJson, FIELD_APP_ID);
    if (callerAppId == nullptr) {
        LOGE("Failed to get appId from reqParams json!");
        FreeJson(reqParamsJson);
        return false;
    }
    int32_t ret = AddReqIdByAppId(callerAppId, requestId);
    FreeJson(reqParamsJson);
    return ret == HC_SUCCESS;
}

static char *IpcGaCbOnRequest(int64_t requestId, int32_t operationCode, const char *reqParams)
{
    if (!CanFindCbByReqId(requestId, CB_TYPE_DEV_AUTH)) {
        if (!TryAddReqIdByAppId(requestId, reqParams)) {
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
        if (!TryAddReqIdByAppId(requestId, reqParams)) {
            return nullptr;
        }
    }
    return GaCbOnRequestWithType(requestId, operationCode, reqParams, CB_TYPE_CRED_DEV_AUTH, CB_ID_ON_REQUEST_CRED);
}

namespace {
struct IpcEncodeParam {
    int32_t type;
    const uint8_t *data;
    int32_t size;
};

static void BroadcastToCallbacks(int32_t cbType, int32_t cbId,
    const IpcEncodeParam *params, int32_t paramCount)
{
    std::lock_guard<std::mutex> autoLock(g_cbListLock);
    if (g_ipcCallBackList.ctx == nullptr) {
        return;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_MAX_NODES; i++) {
        if (g_ipcCallBackList.ctx[i].cbType != cbType) {
            continue;
        }
        MessageParcel dataParcel;
        MessageParcel reply;
        uint32_t ret = HC_SUCCESS;
        for (int32_t j = 0; j < paramCount; j++) {
            ret |= EncodeCallData(dataParcel, params[j].type, params[j].data, params[j].size);
        }
        ret |= EncodeCallData(dataParcel, PARAM_TYPE_APPID,
            reinterpret_cast<const uint8_t *>(g_ipcCallBackList.ctx[i].appId),
            HcStrlen(g_ipcCallBackList.ctx[i].appId) + 1);
        if (ret != HC_SUCCESS) {
            LOGE("Error occurs, encode trans data failed, appId: %" LOG_PUB "s", g_ipcCallBackList.ctx[i].appId);
            continue;
        }
        ServiceDevAuth::ActCallback(g_ipcCallBackList.ctx[i].proxyId, cbId, false, dataParcel, reply);
    }
}

static inline IpcEncodeParam MakeStrParam(int32_t type, const char *str)
{
    return { type, reinterpret_cast<const uint8_t *>(str), static_cast<int32_t>(HcStrlen(str) + 1) };
}

static inline IpcEncodeParam MakeBinParam(int32_t type, const uint8_t *data, int32_t size)
{
    return { type, data, size };
}

static void BroadcastStrCb(int32_t cbType, int32_t cbId, int32_t paramType, const char *strParam)
{
    if (strParam == nullptr) {
        return;
    }
    IpcEncodeParam params[] = { MakeStrParam(paramType, strParam) };
    BroadcastToCallbacks(cbType, cbId, params, sizeof(params) / sizeof(params[0]));
}

struct StrParamPair {
    int32_t paramType;
    const char *str;
};

static void BroadcastStrStrCb(int32_t cbType, int32_t cbId, const StrParamPair *param1,
    const StrParamPair *param2)
{
    if (param1 == nullptr || param1->str == nullptr || param2 == nullptr || param2->str == nullptr) {
        return;
    }
    IpcEncodeParam params[] = {
        MakeStrParam(param1->paramType, param1->str),
        MakeStrParam(param2->paramType, param2->str)
    };
    BroadcastToCallbacks(cbType, cbId, params, sizeof(params) / sizeof(params[0]));
}

void IpcOnGroupCreated(const char *groupInfo)
{
    BroadcastStrCb(CB_TYPE_LISTENER, CB_ID_ON_GROUP_CREATED, PARAM_TYPE_GROUP_INFO, groupInfo);
}

void IpcOnGroupDeleted(const char *groupInfo)
{
    BroadcastStrCb(CB_TYPE_LISTENER, CB_ID_ON_GROUP_DELETED, PARAM_TYPE_GROUP_INFO, groupInfo);
}

void IpcOnDeviceBound(const char *peerUdid, const char *groupInfo)
{
    StrParamPair param1 = { PARAM_TYPE_UDID, peerUdid };
    StrParamPair param2 = { PARAM_TYPE_GROUP_INFO, groupInfo };
    BroadcastStrStrCb(CB_TYPE_LISTENER, CB_ID_ON_DEV_BOUND, &param1, &param2);
}

void IpcOnDeviceUnBound(const char *peerUdid, const char *groupInfo)
{
    StrParamPair param1 = { PARAM_TYPE_UDID, peerUdid };
    StrParamPair param2 = { PARAM_TYPE_GROUP_INFO, groupInfo };
    BroadcastStrStrCb(CB_TYPE_LISTENER, CB_ID_ON_DEV_UNBOUND, &param1, &param2);
}

void IpcOnDeviceNotTrusted(const char *peerUdid)
{
    BroadcastStrCb(CB_TYPE_LISTENER, CB_ID_ON_DEV_UNTRUSTED, PARAM_TYPE_UDID, peerUdid);
}

void IpcOnLastGroupDeleted(const char *peerUdid, int32_t groupType)
{
    if (peerUdid == nullptr) {
        return;
    }
    IpcEncodeParam params[] = {
        MakeStrParam(PARAM_TYPE_UDID, peerUdid),
        MakeBinParam(PARAM_TYPE_GROUP_TYPE, reinterpret_cast<const uint8_t *>(&groupType), sizeof(groupType))
    };
    BroadcastToCallbacks(CB_TYPE_LISTENER, CB_ID_ON_LAST_GROUP_DELETED, params, sizeof(params) / sizeof(params[0]));
}

void IpcOnTrustedDeviceNumChanged(int32_t curTrustedDeviceNum)
{
    IpcEncodeParam params[] = {
        MakeBinParam(PARAM_TYPE_DATA_NUM, reinterpret_cast<const uint8_t *>(&curTrustedDeviceNum),
            sizeof(curTrustedDeviceNum))
    };
    BroadcastToCallbacks(CB_TYPE_LISTENER, CB_ID_ON_TRUST_DEV_NUM_CHANGED, params, sizeof(params) / sizeof(params[0]));
}

void IpcOnGroupActiveInUser(const char *returnInfo)
{
    BroadcastStrCb(CB_TYPE_LISTENER, CB_ID_ON_GROUP_ACTIVE_IN_USER, PARAM_TYPE_RETURN_INFO, returnInfo);
}

void IpcOnGroupInactiveInUser(const char *returnInfo)
{
    BroadcastStrCb(CB_TYPE_LISTENER, CB_ID_ON_GROUP_INACTIVE_IN_USER, PARAM_TYPE_RETURN_INFO, returnInfo);
}

void IpcOnDeviceActiveInUser(const char *udid, const char *returnInfo)
{
    StrParamPair param1 = { PARAM_TYPE_UDID, udid };
    StrParamPair param2 = { PARAM_TYPE_RETURN_INFO, returnInfo };
    BroadcastStrStrCb(CB_TYPE_LISTENER, CB_ID_ON_DEVICE_ACTIVE_IN_USER, &param1, &param2);
}

void IpcOnDeviceInactiveInUser(const char *udid, const char *returnInfo)
{
    StrParamPair param1 = { PARAM_TYPE_UDID, udid };
    StrParamPair param2 = { PARAM_TYPE_RETURN_INFO, returnInfo };
    BroadcastStrStrCb(CB_TYPE_LISTENER, CB_ID_ON_DEVICE_INACTIVE_IN_USER, &param1, &param2);
}

void IpcOnDeviceNotTrustedInUser(const char *udid, const char *returnInfo)
{
    StrParamPair param1 = { PARAM_TYPE_UDID, udid };
    StrParamPair param2 = { PARAM_TYPE_RETURN_INFO, returnInfo };
    BroadcastStrStrCb(CB_TYPE_LISTENER, CB_ID_ON_DEVICE_NOT_TRUSTED_IN_USER, &param1, &param2);
}

void IpcOnCredAdd(const char *credId, const char *credInfo)
{
    if (credId == nullptr) {
        return;
    }
    IpcEncodeParam params[] = {
        MakeStrParam(PARAM_TYPE_CRED_ID, credId),
        MakeStrParam(PARAM_TYPE_CRED_INFO, credInfo)
    };
    BroadcastToCallbacks(CB_TYPE_CRED_LISTENER, CB_ID_ON_CRED_ADD, params, sizeof(params) / sizeof(params[0]));
}

void IpcOnCredDelete(const char *credId, const char *credInfo)
{
    if (credId == nullptr) {
        return;
    }
    IpcEncodeParam params[] = {
        MakeStrParam(PARAM_TYPE_CRED_ID, credId),
        MakeStrParam(PARAM_TYPE_CRED_INFO, credInfo)
    };
    BroadcastToCallbacks(CB_TYPE_CRED_LISTENER, CB_ID_ON_CRED_DELETE, params, sizeof(params) / sizeof(params[0]));
}

void IpcOnCredUpdate(const char *credId, const char *credInfo)
{
    if (credId == nullptr) {
        return;
    }
    IpcEncodeParam params[] = {
        MakeStrParam(PARAM_TYPE_CRED_ID, credId),
        MakeStrParam(PARAM_TYPE_CRED_INFO, credInfo)
    };
    BroadcastToCallbacks(CB_TYPE_CRED_LISTENER, CB_ID_ON_CRED_UPDATE, params, sizeof(params) / sizeof(params[0]));
}

void IpcOnCredActiveInUser(const char *credId, const char *returnInfo)
{
    if (credId == nullptr || returnInfo == nullptr) {
        return;
    }
    IpcEncodeParam params[] = {
        MakeStrParam(PARAM_TYPE_CRED_ID, credId),
        MakeStrParam(PARAM_TYPE_RETURN_INFO, returnInfo)
    };
    BroadcastToCallbacks(CB_TYPE_CRED_LISTENER, CB_ID_ON_CRED_ACTIVE_IN_USER,
        params, sizeof(params) / sizeof(params[0]));
}

void IpcOnCredInactiveInUser(const char *credId, const char *returnInfo)
{
    if (credId == nullptr || returnInfo == nullptr) {
        return;
    }
    IpcEncodeParam params[] = {
        MakeStrParam(PARAM_TYPE_CRED_ID, credId),
        MakeStrParam(PARAM_TYPE_RETURN_INFO, returnInfo)
    };
    BroadcastToCallbacks(CB_TYPE_CRED_LISTENER, CB_ID_ON_CRED_INACTIVE_IN_USER,
        params, sizeof(params) / sizeof(params[0]));
}
};

void InitDeviceAuthCbCtx(DeviceAuthCallback *ctx, int32_t type)
{
    if (ctx == nullptr) {
        return;
    }
    struct DevAuthCbEntry {
        int32_t type;
        bool (*onTransmit)(int64_t, const uint8_t *, uint32_t);
        void (*onSessionKeyReturned)(int64_t, const uint8_t *, uint32_t);
        void (*onFinish)(int64_t, int32_t, const char *);
        void (*onError)(int64_t, int32_t, int32_t, const char *);
        char *(*onRequest)(int64_t, int32_t, const char *);
    };
    static const DevAuthCbEntry cbTable[] = {
        { CB_TYPE_DEV_AUTH, IpcGaCbOnTransmit, IpcGaCbOnSessionKeyReturned,
            IpcGaCbOnFinish, IpcGaCbOnError, IpcGaCbOnRequest },
        { CB_TYPE_TMP_DEV_AUTH, TmpIpcGaCbOnTransmit, TmpIpcGaCbOnSessionKeyReturned,
            TmpIpcGaCbOnFinish, TmpIpcGaCbOnError, TmpIpcGaCbOnRequest },
        { CB_TYPE_CRED_DEV_AUTH, IpcCaCbOnTransmit, IpcCaCbOnSessionKeyReturned,
            IpcCaCbOnFinish, IpcCaCbOnError, IpcCaCbOnRequest },
    };
    for (int32_t i = 0; i < static_cast<int32_t>(sizeof(cbTable) / sizeof(cbTable[0])); i++) {
        if (type == cbTable[i].type) {
            ctx->onTransmit = cbTable[i].onTransmit;
            ctx->onSessionKeyReturned = cbTable[i].onSessionKeyReturned;
            ctx->onFinish = cbTable[i].onFinish;
            ctx->onError = cbTable[i].onError;
            ctx->onRequest = cbTable[i].onRequest;
            return;
        }
    }
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
    ctx->onGroupActiveInUser = IpcOnGroupActiveInUser;
    ctx->onGroupInactiveInUser = IpcOnGroupInactiveInUser;
    ctx->onDeviceActiveInUser = IpcOnDeviceActiveInUser;
    ctx->onDeviceInactiveInUser = IpcOnDeviceInactiveInUser;
    ctx->onDeviceNotTrustedInUser = IpcOnDeviceNotTrustedInUser;
}

void InitDevAuthCredListenerCbCtx(CredChangeListener *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    ctx->onCredAdd = IpcOnCredAdd;
    ctx->onCredDelete = IpcOnCredDelete;
    ctx->onCredUpdate = IpcOnCredUpdate;
    ctx->onCredActiveInUser = IpcOnCredActiveInUser;
    ctx->onCredInactiveInUser = IpcOnCredInactiveInUser;
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
}

void SetCbCtxToDataCtx(uintptr_t callCtx, int32_t cbIdx)
{
    sptr<IRemoteObject> remote = g_sdkCbStub[cbIdx];
    ProxyDevAuthData *dataCache = reinterpret_cast<ProxyDevAuthData *>(callCtx);
    dataCache->SetCallbackStub(remote);
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
}

static int32_t ExtractParamByCategory(const IpcDataInfo *ipcParam, ParamCategory cat,
    uint8_t *paramCache, int32_t *cacheLen)
{
    if (cat == PARAM_CAT_PTR) {
        if (ipcParam->valSz <= 0) {
            return HC_ERR_INVALID_PARAMS;
        }
        *(reinterpret_cast<uint8_t **>(paramCache)) = ipcParam->val;
        if (cacheLen != nullptr) {
            *cacheLen = ipcParam->valSz;
        }
        return HC_SUCCESS;
    }
    if (cat == PARAM_CAT_CPY) {
        if ((ipcParam->val == nullptr) || (ipcParam->valSz <= 0) || (cacheLen == nullptr) || (*cacheLen <= 0)) {
            return HC_ERR_INVALID_PARAMS;
        }
        errno_t eno = memcpy_s(paramCache, *cacheLen, ipcParam->val, ipcParam->valSz);
        if (eno != EOK) {
            return HC_ERR_MEMORY_COPY;
        }
        *cacheLen = ipcParam->valSz;
        return HC_SUCCESS;
    }
    if ((cat == PARAM_CAT_CB_OBJECT) && (cacheLen != nullptr) &&
        (static_cast<uint32_t>(*cacheLen) >= sizeof(ipcParam->idx))) {
        *(reinterpret_cast<int32_t *>(paramCache)) = ipcParam->idx;
    }
    return HC_SUCCESS;
}

int32_t GetIpcRequestParamByType(const IpcDataInfo *ipcParams, int32_t paramNum,
    int32_t type, uint8_t *paramCache, int32_t *cacheLen)
{
    if (paramCache == nullptr) {
        return HC_ERR_INVALID_PARAMS;
    }
    for (int32_t i = 0; i < paramNum; i++) {
        if (ipcParams[i].type != type) {
            continue;
        }
        return ExtractParamByCategory(&ipcParams[i], GetParamCategory(type), paramCache, cacheLen);
    }
    return HC_ERR_IPC_BAD_MSG_TYPE;
}

bool IsCallbackMethod(int32_t methodId)
{
    static const int32_t callbackMethods[] = {
        IPC_CALL_ID_REG_CB, IPC_CALL_ID_REG_LISTENER,
        IPC_CALL_ID_DA_AUTH_DEVICE, IPC_CALL_ID_DA_PROC_DATA,
        IPC_CALL_ID_GA_PROC_DATA, IPC_CALL_ID_AUTH_DEVICE,
        IPC_CALL_ID_CM_REG_LISTENER, IPC_CALL_ID_CA_AUTH_CREDENTIAL,
        IPC_CALL_ID_CA_PROCESS_CRED_DATA, IPC_CALL_ID_LA_START_LIGHT_ACCOUNT_AUTH,
        IPC_CALL_ID_LA_PROCESS_LIGHT_ACCOUNT_AUTH
    };
    for (int32_t i = 0; i < static_cast<int32_t>(sizeof(callbackMethods) / sizeof(callbackMethods[0])); i++) {
        if (callbackMethods[i] == methodId) {
            return true;
        }
    }
    return false;
}

void UnInitProxyAdapt(void)
{
    for (int32_t i = 0; i < IPC_CALL_BACK_STUB_NODES; i++) {
        g_sdkCbStub[i] = nullptr;
    }
}

int32_t InitProxyAdapt(void)
{
    for (int32_t i = 0; i < IPC_CALL_BACK_STUB_NODES; i++) {
        g_sdkCbStub[i] = new(std::nothrow) StubDevAuthCb;
    }
    for (int32_t i = 0; i < IPC_CALL_BACK_STUB_NODES; i++) {
        if (!g_sdkCbStub[i]) {
            LOGE("alloc callback stub object failed");
            UnInitProxyAdapt();
            return HC_ERR_ALLOC_MEMORY;
        }
    }
    return HC_SUCCESS;
}
