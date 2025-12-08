/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "saloadondemand_fuzzer.h"
#include "device_auth.h"
#include "ipc_sdk_defines.h"
#include "device_auth_defines.h"
#include "securec.h"
#include <cstddef>
#include <cstdint>
#include <string>

#include "base/security/device_auth/frameworks/sdk/sa_load_on_demand/src/sa_load_on_demand.cpp"

namespace OHOS {
#define TEST_APP_ID "TestUserId"
#define TEST_APP_ID_1 "TestUserId1"

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
}

static void OnFinish(int64_t requestId, int operationCode, const char *authReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)authReturn;
}

static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
}

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return true;
}

static char *OnRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    return nullptr;
}


static void OnGroupCreated(const char *groupInfo)
{
    (void)groupInfo;
}

static void OnGroupDeleted(const char *groupInfo)
{
    (void)groupInfo;
}

static void OnDeviceBound(const char *peerUdid, const char *groupInfo)
{
    (void)peerUdid;
    (void)groupInfo;
}

static void OnDeviceUnBound(const char *peerUdid, const char *groupInfo)
{
    (void)peerUdid;
    (void)groupInfo;
}

static void OnDeviceNotTrusted(const char *peerUdid)
{
    (void)peerUdid;
}

static void OnLastGroupDeleted(const char *peerUdid, int groupType)
{
    (void)peerUdid;
    (void)groupType;
}

static void OnTrustedDeviceNumChanged(int curTrustedDeviceNum)
{
    (void)curTrustedDeviceNum;
}

static void TestOnCredAdd(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
}

static void TestOnCredUpdate(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
}

static void TestOnCredDelete(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
}

static DeviceAuthCallback g_gmCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnRequest,
};

static DataChangeListener g_listener = {
    .onGroupCreated = OnGroupCreated,
    .onGroupDeleted = OnGroupDeleted,
    .onDeviceBound = OnDeviceBound,
    .onDeviceUnBound = OnDeviceUnBound,
    .onDeviceNotTrusted = OnDeviceNotTrusted,
    .onLastGroupDeleted = OnLastGroupDeleted,
    .onTrustedDeviceNumChanged = OnTrustedDeviceNumChanged,
};

static CredChangeListener g_credChangeListener = {
    .onCredAdd = TestOnCredAdd,
    .onCredDelete = TestOnCredDelete,
    .onCredUpdate = TestOnCredUpdate,
};

static int32_t regCallbackMock(const char *appId, const DeviceAuthCallback *callback, bool needCache)
{
    (void)appId;
    (void)callback;
    (void)needCache;
    return HC_SUCCESS;
}

static int32_t regDataChangeListenerMock(const char *appId, const DataChangeListener *callback, bool needCache)
{
    (void)appId;
    (void)callback;
    (void)needCache;
    return HC_SUCCESS;
}

static int32_t regCredChangeListenerMock(const char *appId, CredChangeListener *callback, bool needCache)
{
    (void)appId;
    (void)callback;
    (void)needCache;
    return HC_SUCCESS;
}

static void SaLoadOnDemandFuzz001(void)
{
    SetRegCallbackFunc(regCallbackMock);
    SetRegDataChangeListenerFunc(regDataChangeListenerMock);
    SetRegCredChangeListenerFunc(regCredChangeListenerMock);
    RegisterDevAuthCallbackIfNeed();
}

static void SaLoadOnDemandFuzz002(void)
{
    SetRegCallbackFunc(regCallbackMock);
    SetRegDataChangeListenerFunc(regDataChangeListenerMock);
    SetRegCredChangeListenerFunc(regCredChangeListenerMock);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, DEVAUTH_CALLBACK);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, GROUP_CHANGE_LISTENER);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, CRED_CHANGE_LISTENER);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, DEVAUTH_CALLBACK);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, GROUP_CHANGE_LISTENER);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, CRED_CHANGE_LISTENER);
}

static void SaLoadOnDemandFuzz003(void)
{
    SetRegCallbackFunc(regCallbackMock);
    SetRegDataChangeListenerFunc(regDataChangeListenerMock);
    SetRegCredChangeListenerFunc(regCredChangeListenerMock);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, DEVAUTH_CALLBACK);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, DEVAUTH_CALLBACK);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, GROUP_CHANGE_LISTENER);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, GROUP_CHANGE_LISTENER);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, CRED_CHANGE_LISTENER);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, CRED_CHANGE_LISTENER);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, DEVAUTH_CALLBACK);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, GROUP_CHANGE_LISTENER);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, CRED_CHANGE_LISTENER);
}

static void SaLoadOnDemandFuzz004(void)
{
    SetRegCallbackFunc(regCallbackMock);
    SetRegDataChangeListenerFunc(regDataChangeListenerMock);
    SetRegCredChangeListenerFunc(regCredChangeListenerMock);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, DEVAUTH_CALLBACK);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, GROUP_CHANGE_LISTENER);
    (void)AddCallbackInfoToList(TEST_APP_ID, &g_gmCallback, &g_listener, &g_credChangeListener, CRED_CHANGE_LISTENER);
    (void)AddCallbackInfoToList(TEST_APP_ID_1, &g_gmCallback, &g_listener, &g_credChangeListener, DEVAUTH_CALLBACK);
    (void)AddCallbackInfoToList(TEST_APP_ID_1, &g_gmCallback, &g_listener, &g_credChangeListener,
        GROUP_CHANGE_LISTENER);
    (void)AddCallbackInfoToList(TEST_APP_ID_1, &g_gmCallback, &g_listener, &g_credChangeListener,
        CRED_CHANGE_LISTENER);
    RegisterDevAuthCallback();
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, DEVAUTH_CALLBACK);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, GROUP_CHANGE_LISTENER);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID, CRED_CHANGE_LISTENER);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID_1, DEVAUTH_CALLBACK);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID_1, GROUP_CHANGE_LISTENER);
    (void)RemoveCallbackInfoFromList(TEST_APP_ID_1, CRED_CHANGE_LISTENER);
}

bool FuzzDoSaLoadOnDemandFuzz(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)InitLoadOnDemand();
    LoadDeviceAuthSaIfNotLoad();
    SubscribeDeviceAuthSa();
    SaLoadOnDemandFuzz001();
    SaLoadOnDemandFuzz002();
    SaLoadOnDemandFuzz003();
    SaLoadOnDemandFuzz004();
    UnSubscribeDeviceAuthSa();
    DeInitLoadOnDemand();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoSaLoadOnDemandFuzz(data, size);
    return 0;
}
