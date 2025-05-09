/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "soft_bus_channel.h"

#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "dev_session_mgr.h"
#include "group_manager.h"
#include "hc_log.h"
#include "inner_session.h"
#include "session.h"
#include "task_manager.h"

typedef struct {
    int64_t requestId;
    int64_t channelId;
} ChannelEntry;

DECLARE_HC_VECTOR(ChannelEntryVec, ChannelEntry);
IMPLEMENT_HC_VECTOR(ChannelEntryVec, ChannelEntry, 1)
static ChannelEntryVec g_channelVec;
static HcMutex *g_channelMutex = NULL;
static ChannelProxy proxy = { 0 };

static int32_t GetReqIdByChannelId(int64_t channelId, int64_t *returnReqId)
{
    uint32_t index;
    ChannelEntry *entry = NULL;
    (void)LockHcMutex(g_channelMutex);
    FOR_EACH_HC_VECTOR(g_channelVec, index, entry) {
        if (channelId == entry->channelId) {
            *returnReqId = entry->requestId;
            UnlockHcMutex(g_channelMutex);
            return HC_SUCCESS;
        }
    }
    UnlockHcMutex(g_channelMutex);
    return HC_ERR_REQUEST_NOT_FOUND;
}

static int32_t AddChannelEntry(int64_t requestId, int64_t channelId)
{
    int64_t tmpReqId = DEFAULT_REQUEST_ID;
    if (GetReqIdByChannelId(channelId, &tmpReqId) == HC_SUCCESS) {
        LOGE("A request to use the channel already exists!");
        return HC_ERR_REQUEST_EXIST;
    }
    ChannelEntry entry = {
        .channelId = channelId,
        .requestId = requestId
    };
    (void)LockHcMutex(g_channelMutex);
    if (g_channelVec.pushBack(&g_channelVec, &entry) == NULL) {
        LOGE("Failed to push channel entity!");
        UnlockHcMutex(g_channelMutex);
        return HC_ERR_ALLOC_MEMORY;
    }
    UnlockHcMutex(g_channelMutex);
    return HC_SUCCESS;
}

static void RemoveChannelEntry(int64_t channelId)
{
    uint32_t index;
    ChannelEntry *entry = NULL;
    (void)LockHcMutex(g_channelMutex);
    FOR_EACH_HC_VECTOR(g_channelVec, index, entry) {
        if (channelId == entry->channelId) {
            ChannelEntry tmpEntry;
            HC_VECTOR_POPELEMENT(&g_channelVec, &tmpEntry, index);
            UnlockHcMutex(g_channelMutex);
            return;
        }
    }
    UnlockHcMutex(g_channelMutex);
}

static char *GenRecvData(int64_t channelId, const void *data, uint32_t dataLen, int64_t *requestId)
{
    char *dataStr = (char *)HcMalloc(dataLen + 1, 0);
    if (dataStr == NULL) {
        LOGE("Failed to allocate dataStr memory!");
        return NULL;
    }
    if (memcpy_s(dataStr, dataLen + 1, data, dataLen) != HC_SUCCESS) {
        LOGE("Failed to copy data!");
        HcFree(dataStr);
        return NULL;
    }
    CJson *recvData = CreateJsonFromString(dataStr);
    HcFree(dataStr);
    if (recvData == NULL) {
        LOGE("Failed to create recvData from string!");
        return NULL;
    }
    if (GetInt64FromJson(recvData, FIELD_REQUEST_ID, requestId) != HC_SUCCESS) {
        LOGE("Failed to get requestId from recvData!");
        FreeJson(recvData);
        return NULL;
    }
    if (AddByteToJson(recvData, FIELD_CHANNEL_ID, (uint8_t *)&channelId, sizeof(int64_t)) != HC_SUCCESS) {
        LOGE("Failed to add channelId to recvData!");
        FreeJson(recvData);
        return NULL;
    }
    char *recvDataStr = PackJsonToString(recvData);
    FreeJson(recvData);
    if (recvDataStr == NULL) {
        LOGE("Failed to convert json to string!");
        return NULL;
    }
    return recvDataStr;
}

static bool IsServer(int sessionId)
{
    return GetSessionSide(sessionId) == 0;
}

static int OnChannelOpenedCb(int sessionId, int result)
{
    if (IsServer(sessionId)) {
        LOGI("Peer device open channel!");
        return HC_SUCCESS;
    }
    int64_t requestId = 0;
    if (GetReqIdByChannelId(sessionId, &requestId) != HC_SUCCESS) {
        LOGE("The request corresponding to the channel is not found!");
        return HC_ERR_REQUEST_NOT_FOUND;
    }
    int ret = proxy.onChannelOpened(requestId, result);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    return HC_SUCCESS;
}

static void OnChannelClosedCb(int sessionId)
{
    LOGI("[SoftBus][Out]: OnChannelClosed! sessionId: %" LOG_PUB "d", sessionId);
    if (IsServer(sessionId)) {
        return;
    }
    RemoveChannelEntry(sessionId);
    proxy.onChannelClosed();
}

static void OnBytesReceivedCb(int sessionId, const void *data, unsigned int dataLen)
{
    if ((data == NULL) || (dataLen == 0) || (dataLen > MAX_DATA_BUFFER_SIZE)) {
        LOGE("Invalid input params!");
        return;
    }
    LOGI("[Start]: OnMsgReceived! [ChannelId]: %" LOG_PUB "d", sessionId);
    int64_t requestId = DEFAULT_REQUEST_ID;
    char *recvDataStr = GenRecvData(sessionId, data, dataLen, &requestId);
    if (recvDataStr == NULL) {
        return;
    }
    proxy.onBytesReceived(requestId, (uint8_t *)recvDataStr, HcStrlen(recvDataStr) + 1);
    FreeJsonString(recvDataStr);
}

static int32_t OpenSoftBusChannel(const char *connectParams, int64_t requestId, int64_t *returnChannelId)
{
    if ((connectParams == NULL) || (returnChannelId == NULL)) {
        LOGE("The input connectParams or returnChannelId is NULL!");
        return HC_ERR_NULL_PTR;
    }
    LOGI("[SoftBus][In]: OpenChannel!");
    int64_t channelId = (int64_t)OpenAuthSession(GROUP_MANAGER_PACKAGE_NAME, NULL, 0, connectParams);
    LOGI("[SoftBus][Out]: OpenChannel! channelId: %" LOG_PUB PRId64, channelId);
    /* If the value of channelId is less than 0, the soft bus fails to open the channel */
    if (channelId < 0) {
        LOGE("Failed to open soft bus channel!");
        return HC_ERR_SOFT_BUS;
    }
    int32_t res = AddChannelEntry(requestId, channelId);
    if (res != HC_SUCCESS) {
        return res;
    }
    *returnChannelId = channelId;
    return HC_SUCCESS;
}

static void CloseSoftBusChannel(int64_t channelId)
{
    if (IsServer(channelId)) {
        return;
    }
    RemoveChannelEntry(channelId);
    LOGI("[SoftBus][In]: CloseSession!");
    CloseSession(channelId);
    LOGI("[SoftBus][Out]: CloseSession!");
}

static int32_t SendSoftBusMsg(int64_t channelId, const uint8_t *data, uint32_t dataLen)
{
    LOGI("[SoftBus][In]: SendMsg!");
    int32_t res = SendBytes(channelId, data, dataLen);
    LOGI("[SoftBus][Out]: SendMsg! res: %" LOG_PUB "d", res);
    if (res != HC_SUCCESS) {
        LOGE("An error occurs when the softbus sends data!");
        return HC_ERR_SOFT_BUS;
    }
    return HC_SUCCESS;
}

static void NotifySoftBusBindResult(int64_t channelId)
{
    LOGI("[SoftBus][In]: NotifyAuthSuccess!");
    NotifyAuthSuccess(channelId);
    LOGI("[SoftBus][Out]: NotifyAuthSuccess!");
}

SoftBus g_softBus = {
    .openChannel = OpenSoftBusChannel,
    .closeChannel = CloseSoftBusChannel,
    .sendMsg = SendSoftBusMsg,
    .notifyResult = NotifySoftBusBindResult
};

int32_t InitSoftBusChannelModule(ChannelProxy *channelProxy)
{
    if (g_channelMutex == NULL) {
        g_channelMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_channelMutex == NULL) {
            LOGE("Failed to allocate channel mutex memory!");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (InitHcMutex(g_channelMutex, false) != HC_SUCCESS) {
            LOGE("Init mutex failed!");
            HcFree(g_channelMutex);
            g_channelMutex = NULL;
            return HC_ERR_INIT_FAILED;
        }
    }
    proxy.onBytesReceived = channelProxy->onBytesReceived;
    proxy.onChannelOpened = channelProxy->onChannelOpened;
    proxy.onChannelClosed = channelProxy->onChannelClosed;
    g_channelVec = CREATE_HC_VECTOR(ChannelEntryVec);
    ISessionListener softBusListener = {
        .OnSessionOpened = OnChannelOpenedCb,
        .OnSessionClosed = OnChannelClosedCb,
        .OnBytesReceived = OnBytesReceivedCb,
        .OnMessageReceived = NULL
    };
    LOGI("[SoftBus][In]: CreateSessionServer!");
    int32_t res = CreateSessionServer(GROUP_MANAGER_PACKAGE_NAME, GROUP_MANAGER_PACKAGE_NAME, &softBusListener);
    LOGI("[SoftBus][Out]: CreateSessionServer! res: %" LOG_PUB "d", res);
    return res;
}

void DestroySoftBusChannelModule(void)
{
    (void)LockHcMutex(g_channelMutex);
    DESTROY_HC_VECTOR(ChannelEntryVec, &g_channelVec);
    UnlockHcMutex(g_channelMutex);
    DestroyHcMutex(g_channelMutex);
    HcFree(g_channelMutex);
    g_channelMutex = NULL;
    LOGI("[SoftBus][In]: RemoveSessionServer!");
    int32_t res = RemoveSessionServer(GROUP_MANAGER_PACKAGE_NAME, GROUP_MANAGER_PACKAGE_NAME);
    LOGI("[SoftBus][Out]: RemoveSessionServer! res: %" LOG_PUB "d", res);
}

SoftBus *GetSoftBusInstance(void)
{
    return &g_softBus;
}

bool IsSoftBusChannelSupported(void)
{
    return true;
}