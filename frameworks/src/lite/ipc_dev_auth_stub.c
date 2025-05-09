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
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_types.h"
#include "ipc_skeleton.h"
#include "ipc_adapt.h"
#include "ipc_callback_proxy.h"
#include "ipc_sdk_defines.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DATA_LEN 102400
static HcMutex g_cBMutex;

struct CbStubInfo {
    SvcIdentity cbStub;
    uint32_t cbDieId;
    bool inUse;
};
static struct CbStubInfo g_cbStub[MAX_CBSTUB_SIZE];

IpcServiceCallMap *g_callMapTable = NULL;
int32_t g_maxCallMapSz = MAX_CALLMAP_SIZE;
int32_t g_callMapElemNum = 0;

#define BINDER_TYPE_ACQUIRE 1
#define BINDER_TYPE_ACQUIRE_AND_FREE 2
#define BINDER_TYPE_RELEASE 3

#define IPC_IO_BUFF_SZ 1024

void ResetCallMap(void)
{
    g_maxCallMapSz = MAX_CALLMAP_SIZE;
    if (g_callMapTable != NULL) {
        HcFree(g_callMapTable);
        g_callMapTable = NULL;
    }
    g_callMapElemNum = 0;
}

static IpcServiceCall GetCallMethodByMethodId(int32_t methodId)
{
    int32_t i;

    if (g_callMapTable == NULL) {
        return NULL;
    }

    for (i = 0; i < g_maxCallMapSz; i++) {
        if ((g_callMapTable[i].methodId == methodId) && (g_callMapTable[i].method != NULL)) {
            return g_callMapTable[i].method;
        }
    }
    return NULL;
}

static int32_t DecodeCallRequest(IpcIo *data, IpcDataInfo *paramsCache, int32_t cacheNum, int32_t *inParamNum)
{
    int32_t dataLen;
    int32_t i;
    int32_t ret;
    
    if (GetIpcIoDataLength(data) > MAX_DATA_LEN) {
        LOGE("Data len over MAX_DATA_LEN");
        return HC_ERR_IPC_BAD_MESSAGE_LENGTH;
    }

    ReadInt32(data, &dataLen);
    if (dataLen <= 0) {
        return HC_ERR_IPC_BAD_MESSAGE_LENGTH;
    }

    ReadInt32(data, inParamNum);
    if ((*inParamNum < 0) || (*inParamNum > cacheNum)) {
        LOGE("param number invalid, inParamNum(%" LOG_PUB "d)", *inParamNum);
        return HC_ERR_IPC_BAD_PARAM_NUM;
    }

    uint32_t len = 0;
    ReadUint32(data, &len); /* skip flat object length information */
    for (i = 0; i < *inParamNum; i++) {
        ret = DecodeIpcData((uintptr_t)data, &(paramsCache[i].type), &(paramsCache[i].val), &(paramsCache[i].valSz));
        if (ret != HC_SUCCESS) {
            LOGE("decode failed, ret %" LOG_PUB "d", ret);
            return ret;
        }
    }
    return HC_SUCCESS;
}

static int32_t GetMethodId(IpcIo *data, int32_t *methodId)
{
    ReadInt32(data, methodId);
    return HC_SUCCESS;
}

static void WithObject(int32_t methodId, IpcIo *data, IpcDataInfo *ipcData, int32_t *cnt)
{
    if (!IsCallbackMethod(methodId)) {
        return;
    }
    ReadInt32(data, &(ipcData->type));
    ipcData->valSz = 0;
    SvcIdentity tmp;
    bool ret = ReadRemoteObject(data, &tmp);
    if (!ret || (ipcData->type != PARAM_TYPE_CB_OBJECT)) {
        LOGE("should with remote object, but failed, param type %" LOG_PUB "d", ipcData->type);
        return;
    }
    ShowIpcSvcInfo(&tmp);
    ipcData->idx = SetRemoteObject(&tmp);
    if (ipcData->idx >= 0) {
        ipcData->val = (uint8_t *)(&(ipcData->idx));
        LOGI("object trans success, set id %" LOG_PUB "d", ipcData->idx);
        (*cnt)++;
    }
}

void InitCbStubTable(void)
{
    if (InitHcMutex(&g_cBMutex, false) != HC_SUCCESS) {
        LOGE("[DB]: Init mutex failed");
        return;
    }
    (void)memset_s(g_cbStub, sizeof(g_cbStub), 0, sizeof(g_cbStub));
    return;
}

static void LockCbStubTable(void)
{
    (void)LockHcMutex(&g_cBMutex);
    return;
}

static void UnLockCbStubTable(void)
{
    UnlockHcMutex(&g_cBMutex);
    return;
}

static int32_t DevAuthRequestCall(void *origin, IpcIo *req, IpcIo *reply)
{
    int32_t ret;
    int32_t methodId = -1;
    int32_t reqParamNum = 0;
    IpcDataInfo reqParams[MAX_REQUEST_PARAMS_NUM] = { { 0 } };
    IpcServiceCall serviceCall = NULL;

    (void)origin;
    ret = GetMethodId(req, &methodId);
    if (ret != HC_SUCCESS || methodId <= 0) {
        LOGE("GetMethodId failed, ret = %" LOG_PUB "d", ret);
        return HC_ERR_IPC_METHOD_ID_INVALID;
    }
    serviceCall = GetCallMethodByMethodId(methodId);
    if (serviceCall == NULL) {
        return HC_ERR_IPC_METHOD_ID_INVALID;
    }
    ret = DecodeCallRequest(req, reqParams, MAX_REQUEST_PARAMS_NUM, &reqParamNum);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    if (reqParamNum < (MAX_REQUEST_PARAMS_NUM - 1)) {
        WithObject(methodId, req, &reqParams[reqParamNum], &reqParamNum);
    }
    return serviceCall(reqParams, reqParamNum, (uintptr_t)(reply));
}

static struct {
    int32_t (*callCtx)(void *origin, IpcIo *req, IpcIo *reply);
    int32_t reqId;
} g_reqCallMaps[] = {
    {DevAuthRequestCall, DEV_AUTH_CALL_REQUEST},
};

int32_t OnRemoteInvoke(IServerProxy *iProxy, int32_t reqId, void *origin, IpcIo *req, IpcIo *reply)
{
    int32_t i;
    int32_t n;
    int32_t (*callCtx)(void *origin, IpcIo *req, IpcIo *reply) = NULL;
    IpcIo replyTmp;
    uint8_t dataBuff[IPC_IO_BUFF_SZ] = { 0 };
    int32_t ret = HC_ERR_IPC_UNKNOW_OPCODE;

    (void)origin;
    (void)iProxy;
    LOGI("request code %" LOG_PUB "u", reqId);
    n = sizeof(g_reqCallMaps) / sizeof(g_reqCallMaps[0]);
    for (i = 0; i < n; i++) {
        if ((int32_t)reqId == g_reqCallMaps[i].reqId) {
            callCtx = g_reqCallMaps[i].callCtx;
            break;
        }
    }
    (void)memset_s(&replyTmp, sizeof(IpcIo), 0, sizeof(IpcIo));
    IpcIoInit(&replyTmp, dataBuff, sizeof(dataBuff), 0);
    if (callCtx) {
        ret = callCtx(origin, req, &replyTmp);
    }
    WriteInt32(reply, ret);
    if (reply != NULL) {
        n = GetIpcIoDataLength(&replyTmp);
        if (n > 0) {
            WriteUint32(reply, n);
            if (!WriteBuffer(reply, (const void *)(replyTmp.bufferBase + IpcIoBufferOffset()), n)) {
                LOGI("WriteBuffer faild");
                return HC_ERROR;
            }
            LOGI("form service result done, result length(%" LOG_PUB "d)", n);
        }
    }
    LOGI("done, request code %" LOG_PUB "d, call result %" LOG_PUB "d", reqId, ret);
    return 0;
}

int32_t SetCallMap(IpcServiceCall method, int32_t methodId)
{
    int32_t len;
    IpcServiceCallMap *callMapTmp = NULL;

    if ((1 + g_callMapElemNum) > g_maxCallMapSz) {
        g_maxCallMapSz += MAX_CALLMAP_SIZE;
        if (g_callMapTable != NULL) {
            callMapTmp = g_callMapTable;
            g_callMapTable = NULL;
        }
    }
    if (g_callMapTable == NULL) {
        len = sizeof(IpcServiceCallMap) * g_maxCallMapSz;
        g_callMapTable = (IpcServiceCallMap *)HcMalloc(len, 0);
        if (g_callMapTable == NULL) {
            return HC_ERR_ALLOC_MEMORY;
        }
        (void)memset_s(g_callMapTable, len, 0, len);
        if (callMapTmp != NULL) {
            errno_t eno = memcpy_s(g_callMapTable, len, callMapTmp, (sizeof(IpcServiceCallMap) * g_callMapElemNum));
            if (eno != EOK) {
                HcFree((void *)g_callMapTable);
                g_callMapTable = callMapTmp;
                g_maxCallMapSz -= MAX_CALLMAP_SIZE;
                return HC_ERR_MEMORY_COPY;
            }
            HcFree((void *)callMapTmp);
            callMapTmp = NULL;
        }
    }
    g_callMapTable[g_callMapElemNum].method = method;
    g_callMapTable[g_callMapElemNum].methodId = methodId;
    g_callMapElemNum++;
    return HC_SUCCESS;
}

int32_t SetRemoteObject(const SvcIdentity *object)
{
    int32_t idx = -1;
    int32_t i;

    LockCbStubTable();
    for (i = 0; i < MAX_CBSTUB_SIZE; i++) {
        if (!g_cbStub[i].inUse) {
            idx = i;
            break;
        }
    }
    LOGI("remote object cache index %" LOG_PUB "d", idx);
    if (idx == -1) {
        UnLockCbStubTable();
        return -1;
    }
    g_cbStub[idx].cbStub = *object;
    g_cbStub[idx].cbDieId = 0;
    g_cbStub[idx].inUse = true;
    UnLockCbStubTable();
    ShowIpcSvcInfo(&(g_cbStub[idx].cbStub));
    return idx;
}

static void ClientDeathCallback(void *arg)
{
    int32_t callbackIdx = (int32_t)(size_t)arg;

    LOGI("remote is not actively, to reset local resource");
    ResetIpcCallBackNodeByNodeId(callbackIdx);
}

void AddCbDeathRecipient(int32_t cbStubIdx, int32_t cbDataIdx)
{
    int32_t ret;
    uint32_t cbId = 0;
    if ((cbStubIdx < 0) || (cbStubIdx >= MAX_CBSTUB_SIZE)) {
        return;
    }

    LockCbStubTable();
    if (!g_cbStub[cbStubIdx].inUse) {
        UnLockCbStubTable();
        return;
    }
    ret = AddDeathRecipient(g_cbStub[cbStubIdx].cbStub, ClientDeathCallback, (void *)(size_t)cbDataIdx, &cbId);
    if (ret == 0) {
        g_cbStub[cbStubIdx].cbDieId = cbId;
    }
    UnLockCbStubTable();
    LOGI("done, ret %" LOG_PUB "d, callback stub idx %" LOG_PUB "d", ret, cbStubIdx);
    return;
}

void ResetRemoteObject(int32_t idx)
{
    if ((idx >= 0) && (idx < MAX_CBSTUB_SIZE)) {
        LOGI("object idx %" LOG_PUB "d", idx);
        LockCbStubTable();
        if (!g_cbStub[idx].inUse) {
            UnLockCbStubTable();
            return;
        }
        RemoveDeathRecipient(g_cbStub[idx].cbStub, g_cbStub[idx].cbDieId);
        (void)memset_s(&(g_cbStub[idx].cbStub), sizeof(g_cbStub[idx].cbStub), 0, sizeof(g_cbStub[idx].cbStub));
        g_cbStub[idx].inUse = false;
        UnLockCbStubTable();
        LOGI("remote object used done, idx %" LOG_PUB "d", idx);
    }
    return;
}

void ActCallback(int32_t objIdx, int32_t callbackId, uintptr_t cbHook, IpcIo *dataParcel, IpcIo *reply)
{
    if ((objIdx < 0) || (objIdx >= MAX_CBSTUB_SIZE) || (!g_cbStub[objIdx].inUse)) {
        LOGW("nothing to do, callback id %" LOG_PUB "d, remote object id %" LOG_PUB "d", callbackId, objIdx);
        return;
    }

    ShowIpcSvcInfo(&g_cbStub[objIdx].cbStub);
    LockCbStubTable();
    CbProxySendRequest(g_cbStub[objIdx].cbStub, callbackId, cbHook, dataParcel, reply);
    UnLockCbStubTable();
    return;
}

#ifdef __cplusplus
}
#endif
