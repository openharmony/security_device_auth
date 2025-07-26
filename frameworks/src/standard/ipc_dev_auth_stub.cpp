/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "ipc_dev_auth_stub.h"

#include "common_defs.h"
#include "hc_log.h"
#include "ipc_adapt.h"
#include "ipc_callback_stub.h"
#include "ipc_sdk_defines.h"
#include "permission_adapter.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "hc_string_vector.h"
#include "hidump_adapter.h"
#include "string_ex.h"
#include "critical_handler.h"

#ifdef DEV_AUTH_SERVICE_BUILD
#include "account_task_manager.h"
#include "group_data_manager.h"
#include "hisysevent_adapter.h"
#endif

#ifdef DEV_AUTH_USE_JEMALLOC
#include "malloc.h"
#endif

using namespace std;
namespace OHOS {
static std::mutex g_cBMutex;

struct CbStubInfo {
    sptr<IRemoteObject> cbStub;
    bool inUse;
};
static struct CbStubInfo g_cbStub[MAX_CBSTUB_SIZE];
static bool g_cbStubInited = false;
static const uint32_t RESTORE_CODE = 14701;
static const std::vector<int32_t> IPC_CALL_ID_UN_CRITICAL = {
    IPC_CALL_ID_APPLY_REG_INFO,
    IPC_CALL_ID_CHECK_ACCESS_TO_GROUP,
    IPC_CALL_ID_GET_PK_INFO_LIST,
    IPC_CALL_ID_GET_GROUP_INFO,
    IPC_CALL_ID_SEARCH_GROUPS,
    IPC_CALL_ID_GET_JOINED_GROUPS,
    IPC_CALL_ID_GET_RELATED_GROUPS,
    IPC_CALL_ID_GET_DEV_INFO_BY_ID,
    IPC_CALL_ID_GET_TRUST_DEVICES,
    IPC_CALL_ID_IS_DEV_IN_GROUP,
    IPC_CALL_ID_GET_REAL_INFO,
    IPC_CALL_ID_GET_PSEUDONYM_ID,
    IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_PARAMS,
    IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_CRED_ID
};

#ifdef DEV_AUTH_SERVICE_BUILD
static const uint32_t DEFAULT_UPGRADE_OS_ACCOUNT_ID = 100;
#endif

#define MAX_DATA_LEN 102400

ServiceDevAuth::ServiceDevAuth(bool serialInvokeFlag) : IRemoteStub(serialInvokeFlag)
{}

ServiceDevAuth::~ServiceDevAuth()
{
    maxCallMapSz = MAX_CALLMAP_SIZE;
    if (standardCallMapTable != nullptr) {
        delete[] standardCallMapTable;
        standardCallMapTable = nullptr;
    }
    callMapElemNum = 0;
}

int32_t ServiceDevAuth::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    std::vector<std::string> strArgs;
    for (auto arg : args) {
        strArgs.emplace_back(Str16ToStr8(arg));
    }
    uint32_t argc = strArgs.size();
    StringVector strArgVec = CreateStrVector();
    for (uint32_t i = 0; i < argc; i++) {
        HcString strArg = CreateString();
        if (!StringSetPointer(&strArg, strArgs[i].c_str())) {
            LOGE("Failed to set strArg!");
            DeleteString(&strArg);
            continue;
        }
        if (strArgVec.pushBackT(&strArgVec, strArg) == NULL) {
            LOGE("Failed to push strArg to strArgVec!");
            DeleteString(&strArg);
        }
    }
    DEV_AUTH_DUMP(fd, &strArgVec);
    DestroyStrVector(&strArgVec);
    return 0;
}

IpcServiceCall ServiceDevAuth::GetCallMethodByMethodId(int32_t methodId)
{
    int32_t i;

    if (standardCallMapTable == nullptr) {
        return nullptr;
    }

    for (i = 0; i < maxCallMapSz; i++) {
        if ((standardCallMapTable[i].methodId == methodId) && (standardCallMapTable[i].method != nullptr)) {
            return standardCallMapTable[i].method;
        }
    }
    return nullptr;
}

static int32_t DecodeCallRequest(MessageParcel &data, IpcDataInfo *paramsCache, int32_t cacheNum, int32_t &inParamNum)
{
    int32_t dataLen = 0;
    int32_t i;
    int32_t ret;

    if (data.GetReadableBytes() == 0) {
        return HC_SUCCESS;
    }

    if (data.GetReadableBytes() > MAX_DATA_LEN) {
        LOGE("Data len over MAX_DATA_LEN");
        return HC_ERR_IPC_BAD_MESSAGE_LENGTH;
    }

    if (data.GetReadableBytes() < sizeof(int32_t)) {
        LOGE("Insufficient data available in IPC container. [Data]: dataLen");
        return HC_ERR_IPC_BAD_MESSAGE_LENGTH;
    }
    data.ReadInt32(dataLen);
    if (dataLen > static_cast<int32_t>(data.GetReadableBytes())) {
        LOGE("Insufficient data available in IPC container. [Data]: data");
        return HC_ERR_IPC_BAD_MESSAGE_LENGTH;
    }

    if (data.GetReadableBytes() < sizeof(int32_t)) {
        LOGE("Insufficient data available in IPC container. [Data]: inParamNum");
        return HC_ERR_IPC_BAD_MESSAGE_LENGTH;
    }
    data.ReadInt32(inParamNum);
    if ((inParamNum < 0) || (inParamNum > cacheNum)) {
        LOGE("param number invalid, inParamNum - %" LOG_PUB "d", inParamNum);
        return HC_ERR_IPC_BAD_PARAM_NUM;
    }

    for (i = 0; i < inParamNum; i++) {
        ret = DecodeIpcData(reinterpret_cast<uintptr_t>(&data), &(paramsCache[i].type),
            &(paramsCache[i].val), &(paramsCache[i].valSz));
        if (ret != HC_SUCCESS) {
            LOGE("decode failed, ret %" LOG_PUB "d", ret);
            return ret;
        }
    }
    return HC_SUCCESS;
}

static int32_t GetMethodId(MessageParcel &data, int32_t &methodId)
{
    if (data.GetDataSize() < sizeof(int32_t)) {
        LOGE("Insufficient data available in IPC container. [Data]: methodId");
        return HC_ERR_IPC_CALL_DATA_LENGTH;
    }
    methodId = data.ReadInt32();
    return HC_SUCCESS;
}

static void WithObject(int32_t methodId, MessageParcel &data, IpcDataInfo &ipcData, int32_t &cnt)
{
    if (!IsCallbackMethod(methodId)) {
        return;
    }
    if (data.GetReadableBytes() < sizeof(int32_t)) {
        LOGE("Insufficient data available in IPC container. [Data]: type");
        return;
    }
    ipcData.type = data.ReadInt32();
    ipcData.valSz = sizeof(StubDevAuthCb);
    sptr<IRemoteObject> tmp = data.ReadRemoteObject();
    if (!tmp) {
        LOGE("should with remote object, but read failed");
        return;
    }
    ipcData.idx = ServiceDevAuth::SetRemoteObject(tmp);
    if (ipcData.idx >= 0) {
        ipcData.val = reinterpret_cast<uint8_t *>(&(ipcData.idx));
        LOGI("object trans success, set id %" LOG_PUB "d", ipcData.idx);
        cnt++;
    }
}

static void InitCbStubTable()
{
    int32_t i;
    if (g_cbStubInited) {
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_cBMutex);
    if (g_cbStubInited) { /* for first init at the same time */
        return;
    }
    for (i = 0; i < MAX_CBSTUB_SIZE; i++) {
        g_cbStub[i].inUse = false;
    }
    g_cbStubInited = true;
    return;
}

int32_t ServiceDevAuth::HandleRestoreCall(MessageParcel &data, MessageParcel &reply)
{
    IncreaseCriticalCnt(ADD_ONE);
#ifdef DEV_AUTH_SERVICE_BUILD
    int32_t osAccountId = DEFAULT_UPGRADE_OS_ACCOUNT_ID;
    data.ReadInt32(osAccountId);
    LOGI("Begin to upgrade data for osAccountId: %" LOG_PUB "d.", osAccountId);
    int32_t res = ExecuteAccountAuthCmd(osAccountId, UPGRADE_DATA, nullptr, nullptr);
    ReloadOsAccountDb(osAccountId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to upgrade data!");
        DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(UPGRADE_DATA_EVENT, PROCESS_UPDATE, res);
    }
    reply.WriteInt32(res);
#else
    (void)data;
    (void)reply;
#endif
    DecreaseCriticalCnt();
    return 0;
}

static void SetMethodCritical(int32_t methodId, bool criticalSwitch)
{
    if (std::count(IPC_CALL_ID_UN_CRITICAL.begin(), IPC_CALL_ID_UN_CRITICAL.end(), methodId) != 0) {
        return;
    }
    if (criticalSwitch) {
        IncreaseCriticalCnt(ADD_ONE);
    } else {
        DecreaseCriticalCnt();
    }
}

int32_t ServiceDevAuth::HandleDeviceAuthCall(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    SET_LOG_MODE(NORMAL_MODE);
    int32_t ret = HC_ERR_IPC_UNKNOW_OPCODE;
    uint32_t dataLen;
    int32_t methodId = 0;
    int32_t reqParamNum = 0;
    MessageParcel replyCache;
    IpcDataInfo reqParams[MAX_REQUEST_PARAMS_NUM] = { { 0 } };
    IpcServiceCall serviceCall = nullptr;
    switch (code) {
        case static_cast<uint32_t>(DevAuthInterfaceCode::DEV_AUTH_CALL_REQUEST):
            ret = GetMethodId(data, methodId);
            if (ret != HC_SUCCESS) {
                break;
            }
            ret = CheckPermission(methodId);
            if (ret != HC_SUCCESS) {
                return ret;
            }
            serviceCall = GetCallMethodByMethodId(methodId);
            if (serviceCall == nullptr) {
                LOGE("ServiceDevAuth::HandleDeviceAuthCall serviceCall is nullptr, methodId: %" LOG_PUB "d", methodId);
                ret = HC_ERR_IPC_METHOD_ID_INVALID;
                break;
            }
            ret = DecodeCallRequest(data, reqParams, MAX_REQUEST_PARAMS_NUM, reqParamNum);
            if (ret != HC_SUCCESS) {
                LOGE("ServiceDevAuth::HandleDeviceAuthCall DecodeCallRequest ret: %" LOG_PUB "d", ret);
                break;
            }
            if (reqParamNum < (MAX_REQUEST_PARAMS_NUM - 1)) {
                InitCbStubTable();
                WithObject(methodId, data, reqParams[reqParamNum], reqParamNum);
            }
            SetMethodCritical(methodId, true);
            ret = serviceCall(reqParams, reqParamNum, reinterpret_cast<uintptr_t>(&replyCache));
            SetMethodCritical(methodId, false);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    reply.WriteInt32(ret);
    dataLen = replyCache.GetDataSize();
    if (dataLen > 0) {
        reply.WriteInt32(dataLen);
        reply.WriteBuffer(reinterpret_cast<const void *>(replyCache.GetData()), dataLen);
    }
    return 0;
}

static void DevAuthInitMemoryPolicy(void)
{
#ifdef DEV_AUTH_USE_JEMALLOC
    (void)mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_DISABLE);
    (void)mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);
#endif
}

int32_t ServiceDevAuth::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DevAuthInitMemoryPolicy();
    std::u16string readToken = data.ReadInterfaceToken();
    bool isRestoreCall = ((code == RESTORE_CODE) && (readToken == std::u16string(u"OHOS.Updater.RestoreData")));
    if (readToken != GetDescriptor() && !isRestoreCall) {
        LOGE("[IPC][C->S]: The proxy interface token is invalid!");
        return -1;
    }
    if (isRestoreCall) {
        return HandleRestoreCall(data, reply);
    } else {
        return HandleDeviceAuthCall(code, data, reply, option);
    }
}

int32_t ServiceDevAuth::SetCallMap(IpcServiceCall method, int32_t methodId)
{
    int32_t len;
    errno_t eno;
    IpcServiceCallMap *callMapTmp = nullptr;

    if ((1 + callMapElemNum) > maxCallMapSz) {
        maxCallMapSz += MAX_CALLMAP_SIZE;
        if (standardCallMapTable != nullptr) {
            callMapTmp = standardCallMapTable;
            standardCallMapTable = nullptr;
        }
    }
    if (standardCallMapTable == nullptr) {
        standardCallMapTable = new(std::nothrow) IpcServiceCallMap[maxCallMapSz];
        if (standardCallMapTable == nullptr) {
            return HC_ERR_ALLOC_MEMORY;
        }
        len = sizeof(IpcServiceCallMap) * maxCallMapSz;
        (void)memset_s(standardCallMapTable, len, 0, len);
        if (callMapTmp != nullptr) {
            eno = memcpy_s(standardCallMapTable, len, callMapTmp, (sizeof(IpcServiceCallMap) * callMapElemNum));
            if (eno != EOK) {
                delete[] standardCallMapTable;
                standardCallMapTable = callMapTmp;
                maxCallMapSz -= MAX_CALLMAP_SIZE;
                return HC_ERR_MEMORY_COPY;
            }
            delete[] callMapTmp;
            callMapTmp = nullptr;
        }
    }

    standardCallMapTable[callMapElemNum].method = method;
    standardCallMapTable[callMapElemNum].methodId = methodId;
    callMapElemNum++;
    return HC_SUCCESS;
}

int32_t ServiceDevAuth::SetRemoteObject(sptr<IRemoteObject> &object)
{
    int32_t idx = -1;
    int32_t i;

    std::lock_guard<std::mutex> autoLock(g_cBMutex);
    for (i = 0; i < MAX_CBSTUB_SIZE; i++) {
        if (!g_cbStub[i].inUse) {
            idx = i;
            break;
        }
    }
    LOGI("remote object cache index %" LOG_PUB "d", idx);
    if (idx == -1) {
        return -1;
    }
    g_cbStub[idx].cbStub = object;
    g_cbStub[idx].inUse = true;
    return idx;
}

void ServiceDevAuth::AddCbDeathRecipient(int32_t cbStubIdx, int32_t cbDataIdx)
{
    bool bRet = false;
    if ((cbStubIdx < 0) || (cbStubIdx >= MAX_CBSTUB_SIZE) || (!g_cbStub[cbStubIdx].inUse)) {
        return;
    }

    std::lock_guard<std::mutex> autoLock(g_cBMutex);
    DevAuthDeathRecipient *deathRecipient = new(std::nothrow) DevAuthDeathRecipient(cbDataIdx);
    if (deathRecipient == nullptr) {
        LOGE("Failed to create death recipient");
        return;
    }
    bRet = g_cbStub[cbStubIdx].cbStub->AddDeathRecipient(deathRecipient);
    LOGI("AddDeathRecipient %" LOG_PUB "s, callback stub idx %" LOG_PUB "d", bRet ? "success" : "failed", cbStubIdx);
    return;
}

void ServiceDevAuth::ResetRemoteObject(int32_t idx)
{
    if ((idx >= 0) && (idx < MAX_CBSTUB_SIZE)) {
        LOGI("remote object used done, idx %" LOG_PUB "d", idx);
        std::lock_guard<std::mutex> autoLock(g_cBMutex);
        g_cbStub[idx].inUse = false;
    }
    return;
}

void ServiceDevAuth::ActCallback(int32_t objIdx, int32_t callbackId, bool sync,
    uintptr_t cbHook, MessageParcel &dataParcel, MessageParcel &reply)
{
    if ((objIdx < 0) || (objIdx >= MAX_CBSTUB_SIZE) || (!g_cbStub[objIdx].inUse)) {
        LOGW("nothing to do, callback id %" LOG_PUB "d, remote object id %" LOG_PUB "d", callbackId, objIdx);
        return;
    }
    MessageOption option(MessageOption::TF_SYNC);
    if (!sync) {
        option.SetFlags(MessageOption::TF_ASYNC);
    }
    std::lock_guard<std::mutex> autoLock(g_cBMutex);
    sptr<ICommIpcCallback> proxy = iface_cast<ICommIpcCallback>(g_cbStub[objIdx].cbStub);
    proxy->DoCallBack(callbackId, cbHook, dataParcel, reply, option);
    return;
}

DevAuthDeathRecipient::DevAuthDeathRecipient(int32_t cbIdx)
{
    callbackIdx = cbIdx;
}
}
