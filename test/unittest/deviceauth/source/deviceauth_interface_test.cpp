/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <gtest/gtest.h>
#include <unistd.h>

#include "device_auth.h"
#include "device_auth_defines.h"
#include "device_auth_ext.h"
#include "account_auth_plugin_proxy.h"
#include "pake_protocol_dl_common.h"
#include "pake_v1_protocol_task_common.h"
#include "ipc_adapt.h"
#include "json_utils.h"
#include "alg_loader.h"
#include "mk_agree_task.h"
#include "cred_manager.h"
#include "channel_manager.h"
#include "soft_bus_channel.h"
#include "dev_auth_module_manager.h"
#include "mbedtls_ec_adapter.h"
#include "account_task_main.h"
#include "account_version_util.h"
#include "account_module.h"
#include "account_multi_task_manager.h"
#include "identical_account_group.h"
#include "broadcast_manager.h"
#include "iso_protocol_common.h"
#include "das_lite_token_manager.h"
#include "das_standard_token_manager.h"
#include "key_manager.h"
#include "group_auth_data_operation.h"
#include "compatible_bind_sub_session_util.h"
#include "compatible_bind_sub_session.h"
#include "compatible_auth_sub_session_common.h"
#include "compatible_auth_sub_session_util.h"
#include "account_unrelated_group_auth.h"
#include "das_task_common.h"
#include "das_version_util.h"
#include "pake_v1_protocol_common.h"
#include "dev_session_util.h"
#include "pake_v2_protocol_common.h"
#include "iso_task_common.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_PSEUDONYM_ID "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_PSEUDONYM_CHALLENGE "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_CONNECT_PARAMS "TestConnectParams"
#define TEST_TRANSMIT_DATA "TestTransmitData"
#define TEST_APP_ID "TestAppId"
#define TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define TEST_AUTH_ID "TestAuthId"

class DeviceAuthInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceAuthInterfaceTest::SetUpTestCase() {}
void DeviceAuthInterfaceTest::TearDownTestCase() {}
void DeviceAuthInterfaceTest::SetUp() {}
void DeviceAuthInterfaceTest::TearDown() {}

static int32_t CreateSessionTest(int32_t *sessionId, const cJSON *in, cJSON *out)
{
    (void)sessionId;
    (void)in;
    (void)out;
    return HC_SUCCESS;
}

static int32_t ExcuteCredMgrCmdTest(int32_t osAccount, int32_t cmdId, const cJSON *in, cJSON *out)
{
    (void)osAccount;
    (void)cmdId;
    (void)in;
    (void)out;
    return HC_SUCCESS;
}

static int32_t ProcessSessionTest(int32_t *sessionId, const cJSON *in, cJSON *out, int32_t *status)
{
    (void)sessionId;
    (void)in;
    (void)out;
    (void)status;
    return HC_SUCCESS;
}

static int32_t DestroySessionTest(int32_t sessionId)
{
    (void)sessionId;
    return HC_SUCCESS;
}

static int32_t InitTest(struct ExtPlugin *extPlugin, const cJSON *params, const struct ExtPluginCtx *context)
{
    (void)extPlugin;
    (void)params;
    (void)context;
    return HC_SUCCESS;
}

static void Destroy(struct ExtPlugin *extPlugin)
{
    (void)extPlugin;
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest001, TestSize.Level0)
{
    // account_auth_plugin_proxy.c interface test
    int32_t res = SetAccountAuthPlugin(nullptr, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = ExcuteCredMgrCmd(DEFAULT_OS_ACCOUNT, 0, nullptr, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = CreateAuthSession(0, nullptr, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = ProcessAuthSession(0, nullptr, nullptr, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = DestroyAuthSession(0);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    AccountAuthExtPlug plugin = { { 0 }, nullptr, nullptr, nullptr, nullptr };
    res = SetAccountAuthPlugin(nullptr, &plugin);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = ExcuteCredMgrCmd(DEFAULT_OS_ACCOUNT, 0, nullptr, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = CreateAuthSession(0, nullptr, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = ProcessAuthSession(0, nullptr, nullptr, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = DestroyAuthSession(0);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    plugin.createSession = CreateSessionTest;
    res = SetAccountAuthPlugin(nullptr, &plugin);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = CreateAuthSession(0, nullptr, nullptr);
    ASSERT_EQ(res, HC_SUCCESS);
    plugin.excuteCredMgrCmd = ExcuteCredMgrCmdTest;
    res = SetAccountAuthPlugin(nullptr, &plugin);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = ExcuteCredMgrCmd(DEFAULT_OS_ACCOUNT, 0, nullptr, nullptr);
    ASSERT_EQ(res, HC_SUCCESS);
    plugin.processSession = ProcessSessionTest;
    res = SetAccountAuthPlugin(nullptr, &plugin);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = ProcessAuthSession(0, nullptr, nullptr, nullptr);
    ASSERT_EQ(res, HC_SUCCESS);
    plugin.destroySession = DestroySessionTest;
    plugin.base.init = InitTest;
    res = SetAccountAuthPlugin(nullptr, &plugin);
    ASSERT_EQ(res, HC_SUCCESS);
    res = DestroyAuthSession(0);
    ASSERT_EQ(res, HC_SUCCESS);
    DestoryAccountAuthPlugin();
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest002, TestSize.Level0)
{
    // account_auth_plugin_proxy.c interface test
    int32_t res = SetAccountAuthPlugin(nullptr, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    DestoryAccountAuthPlugin();
    AccountAuthExtPlug plugin = { { 0 }, nullptr, nullptr, nullptr, nullptr };
    res = SetAccountAuthPlugin(nullptr, &plugin);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    DestoryAccountAuthPlugin();
    plugin.base.destroy = Destroy;
    res = SetAccountAuthPlugin(nullptr, &plugin);
    ASSERT_EQ(res, HC_ERR_INVALID_PARAMS);
    DestoryAccountAuthPlugin();
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest003, TestSize.Level0)
{
    // pake_protocol_dl_common.c interface test
    uint32_t alg = GetPakeDlAlg();
    ASSERT_EQ(alg, PAKE_ALG_DL);
    PakeBaseParams *baseParams = (PakeBaseParams *)HcMalloc(sizeof(PakeBaseParams), 0);
    baseParams->loader = GetLoaderInstance();
    baseParams->isClient = true;
    int32_t res = GenerateDlPakeParams(baseParams, nullptr);
    ASSERT_EQ(res, HC_ERR_INVALID_LEN);
    baseParams->epkPeer.length = PAKE_DL_PRIME_LEN;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_384;
    res = GenerateDlPakeParams(baseParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    baseParams->epkPeer.length = PAKE_DL_PRIME_SMALL_LEN;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_256;
    ASSERT_NE(res, HC_SUCCESS);
    baseParams->isClient = false;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_384;
    res = GenerateDlPakeParams(baseParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_256;
    res = GenerateDlPakeParams(baseParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_NONE;
    res = GenerateDlPakeParams(baseParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_256;
    uint8_t secretVal[16] = { 0 };
    Uint8Buff secret = { secretVal, 16 };
    res = GenerateDlPakeParams(baseParams, &secret);
    ASSERT_EQ(res, HC_SUCCESS);
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_NONE;
    res = AgreeDlSharedSecret(baseParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    baseParams->epkPeer.length = PAKE_DL_PRIME_LEN;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_384;
    res = AgreeDlSharedSecret(baseParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    baseParams->epkPeer.length = PAKE_DL_PRIME_SMALL_LEN;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_256;
    res = AgreeDlSharedSecret(baseParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    HcFree(baseParams);
}

static void ConstructPakeV1InParams(CJson *in)
{
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
    (void)AddIntToJson(in, FIELD_SELF_TYPE, 0);
    (void)AddStringToJson(in, FIELD_PKG_NAME, "testPkgName");
    (void)AddStringToJson(in, FIELD_SERVICE_TYPE, "TestServiceType");
    (void)AddStringToJson(in, FIELD_SELF_AUTH_ID, "TestAuthId");
    (void)AddStringToJson(in, FIELD_PEER_AUTH_ID, "TestPeerAuthId");
    (void)AddBoolToJson(in, FIELD_IS_SELF_FROM_UPGRADE, true);
    (void)AddBoolToJson(in, FIELD_IS_PEER_FROM_UPGRADE, true);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest004, TestSize.Level0)
{
    // pake_v1_protocol_task_common.c interface test
    DestroyDasPakeV1Params(nullptr);
    PakeParams *params = (PakeParams *)HcMalloc(sizeof(PakeParams), 0);
    params->pseudonymExtInfo.selfNextPseudonymId.val = (uint8_t *)HcMalloc(16, 0);
    ASSERT_NE(params->pseudonymExtInfo.selfNextPseudonymId.val, nullptr);
    params->pseudonymExtInfo.selfNextPseudonymChallenge.val = (uint8_t *)HcMalloc(16, 0);
    ASSERT_NE(params->pseudonymExtInfo.selfNextPseudonymChallenge.val, nullptr);
    params->pseudonymExtInfo.peerNextPseudonymId.val = (uint8_t *)HcMalloc(16, 0);
    ASSERT_NE(params->pseudonymExtInfo.peerNextPseudonymId.val, nullptr);
    DestroyDasPakeV1Params(params);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    int32_t res = InitDasPakeV1Params(params, in);
    ASSERT_NE(res, HC_SUCCESS);
    ConstructPakeV1InParams(in);
    res = InitDasPakeV1Params(params, in);
    ASSERT_EQ(res, HC_SUCCESS);
    res = LoadPseudonymExtInfoIfNeed(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = LoadPseudonymExtInfoIfNeed(params);
    ASSERT_NE(res, HC_SUCCESS);
    res = AddPseudonymIdAndChallenge(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = AddPseudonymIdAndChallenge(params, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *payload = CreateJson();
    ASSERT_NE(payload, nullptr);
    res = AddPseudonymIdAndChallenge(params, payload);
    ASSERT_NE(res, HC_SUCCESS);
    res = CheckPseudonymId(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = CheckPseudonymId(params, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    res = CheckPseudonymId(params, in);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddStringToJson(payload, FIELD_P2P_PSEUDONYM_ID, TEST_PSEUDONYM_ID);
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    res = CheckPseudonymId(params, in);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddStringToJson(payload, FIELD_PSEUDONYM_CHALLENGE, TEST_PSEUDONYM_CHALLENGE);
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    res = CheckPseudonymId(params, in);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(in);
    FreeJson(payload);
    DestroyDasPakeV1Params(params);
    HcFree(params);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest005, TestSize.Level0)
{
    // ipc_adapt.cpp interface test
    int32_t res = InitIpcCallBackList();
    ASSERT_EQ(res, HC_SUCCESS);
    res = InitIpcCallBackList();
    ASSERT_EQ(res, HC_SUCCESS);
    DeInitIpcCallBackList();
    DeInitIpcCallBackList();
    ResetIpcCallBackNodeByNodeId(-1);
    ResetIpcCallBackNodeByNodeId(65);
    ResetIpcCallBackNodeByNodeId(1);
    res = InitIpcCallBackList();
    ASSERT_EQ(res, HC_SUCCESS);
    ResetIpcCallBackNodeByNodeId(1);
    DeInitIpcCallBackList();
    AddIpcCbObjByAppId(TEST_APP_ID, 0, 0);
    (void)InitIpcCallBackList();
    AddIpcCbObjByAppId(TEST_APP_ID, 0, 0);
    DeInitIpcCallBackList();
    AddIpcCallBackByAppId(TEST_APP_ID, nullptr, 0, 0);
    (void)InitIpcCallBackList();
    AddIpcCallBackByAppId(TEST_APP_ID, nullptr, 0, 0);
    DeInitIpcCallBackList();
    DelIpcCallBackByAppId(TEST_APP_ID, 0);
    (void)InitIpcCallBackList();
    DelIpcCallBackByAppId(TEST_APP_ID, 0);
    DeInitIpcCallBackList();
    res = AddReqIdByAppId(TEST_APP_ID, 123);
    ASSERT_NE(res, HC_SUCCESS);
    (void)InitIpcCallBackList();
    res = AddReqIdByAppId(TEST_APP_ID, 123);
    ASSERT_NE(res, HC_SUCCESS);
    DeInitIpcCallBackList();
    AddIpcCbObjByReqId(123, 0, 0);
    (void)InitIpcCallBackList();
    AddIpcCbObjByReqId(123, 0, 0);
    DeInitIpcCallBackList();
    res = AddIpcCallBackByReqId(123, nullptr, 0, 0);
    ASSERT_NE(res, HC_SUCCESS);
    (void)InitIpcCallBackList();
    res = AddIpcCallBackByReqId(123, nullptr, 0, 0);
    ASSERT_NE(res, HC_SUCCESS);
    DeInitIpcCallBackList();
    DelIpcCallBackByReqId(123, 0, true);
    DelIpcCallBackByReqId(123, 0, false);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest006, TestSize.Level0)
{
    // ipc_adapt.cpp interface test
    InitDeviceAuthCbCtx(nullptr, 0);
    DeviceAuthCallback callback = { 0 };
    InitDeviceAuthCbCtx(&callback, 1);
    InitDeviceAuthCbCtx(&callback, 2);
    InitDevAuthListenerCbCtx(nullptr);
    DataChangeListener listener = { 0 };
    InitDevAuthListenerCbCtx(&listener);
    uintptr_t ptr = 0;
    int32_t res = CreateServiceInstance(&ptr);
    ASSERT_EQ(res, HC_SUCCESS);
    DestroyServiceInstance(ptr);
    bool isCallback = IsCallbackMethod(0);
    ASSERT_EQ(isCallback, false);
    isCallback = IsCallbackMethod(1);
    ASSERT_EQ(isCallback, true);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest007, TestSize.Level0)
{
    // mk_agree_task.c interface test
    int32_t res = CreateMkAgreeTask(0, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    res = CreateMkAgreeTask(0, in, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    MkAgreeTaskBase *task = nullptr;
    res = CreateMkAgreeTask(0, in, &task);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
    res = CreateMkAgreeTask(TASK_TYPE_ISO, in, &task);
    ASSERT_NE(res, HC_SUCCESS);
    res = CreateMkAgreeTask(2, in, &task);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(in);
}

static int32_t InitCredPlugin(void)
{
    return HC_SUCCESS;
}

static int32_t InitCredPluginFail(void)
{
    return HC_ERROR;
}

static void DestroyCredPlugin(void) {}

static int32_t ProcessCredTest(int32_t osAccountId, int32_t cmdId, CJson *in, CJson *out)
{
    (void)osAccountId;
    (void)cmdId;
    (void)in;
    (void)out;
    return HC_SUCCESS;
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest008, TestSize.Level0)
{
    // cred_manager.c interface test
    int32_t res = InitCredMgr();
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcCred(0, DEFAULT_OS_ACCOUNT, 0, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = AddCredPlugin(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CredPlugin plugin = { 0 };
    res = AddCredPlugin(&plugin);
    ASSERT_NE(res, HC_SUCCESS);
    plugin.init = InitCredPlugin;
    res = AddCredPlugin(&plugin);
    ASSERT_NE(res, HC_SUCCESS);
    plugin.destroy = DestroyCredPlugin;
    res = AddCredPlugin(&plugin);
    ASSERT_NE(res, HC_SUCCESS);
    plugin.procCred = ProcessCredTest;
    res = AddCredPlugin(&plugin);
    ASSERT_EQ(res, HC_SUCCESS);
    plugin.init = InitCredPluginFail;
    res = AddCredPlugin(&plugin);
    ASSERT_NE(res, HC_SUCCESS);
    plugin.init = InitCredPlugin;
    res = AddCredPlugin(&plugin);
    ASSERT_EQ(res, HC_SUCCESS);
    DelCredPlugin(0);
    DestroyCredMgr();
}

static int OnChannelOpenedTest(int64_t requestId, int result)
{
    (void)requestId;
    (void)result;
    return 0;
}

static void OnChannelClosedTest(void) {}

static void OnBytesReceivedTest(int64_t requestId, uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
}

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return true;
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest009, TestSize.Level0)
{
    // channel_manager.c interface test
    ChannelProxy proxy = { 0 };
    proxy.onBytesReceived = OnBytesReceivedTest;
    proxy.onChannelClosed = OnChannelClosedTest;
    proxy.onChannelOpened = OnChannelOpenedTest;
    int32_t res = InitChannelManager(&proxy);
    ASSERT_NE(res, HC_SUCCESS);
    DeviceAuthCallback callback = { 0 };
    CJson *jsonParams = CreateJson();
    ASSERT_NE(jsonParams, nullptr);
    ChannelType type = GetChannelType(&callback, jsonParams);
    ASSERT_EQ(type, NO_CHANNEL);
    (void)AddStringToJson(jsonParams, FIELD_CONNECT_PARAMS, TEST_CONNECT_PARAMS);
    type = GetChannelType(&callback, jsonParams);
    ASSERT_EQ(type, SOFT_BUS);
    FreeJson(jsonParams);
    jsonParams = CreateJson();
    ASSERT_NE(jsonParams, nullptr);
    callback.onTransmit = OnTransmit;
    type = GetChannelType(&callback, jsonParams);
    ASSERT_EQ(type, SERVICE_CHANNEL);
    FreeJson(jsonParams);
    res = OpenChannel(SERVICE_CHANNEL, nullptr, 123, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    jsonParams = CreateJson();
    ASSERT_NE(jsonParams, nullptr);
    int64_t returnChannelId = 0;
    res = OpenChannel(SOFT_BUS, jsonParams, 123, &returnChannelId);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddStringToJson(jsonParams, FIELD_CONNECT_PARAMS, TEST_CONNECT_PARAMS);
    res = OpenChannel(SOFT_BUS, jsonParams, 123, &returnChannelId);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(jsonParams);
    res = OpenChannel(NO_CHANNEL, nullptr, 123, &returnChannelId);
    ASSERT_NE(res, HC_SUCCESS);
    CloseChannel(SOFT_BUS, 0);
    res = HcSendMsg(SOFT_BUS, 123, 0, nullptr, TEST_TRANSMIT_DATA);
    ASSERT_NE(res, HC_SUCCESS);
    res = HcSendMsg(NO_CHANNEL, 123, 00, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = HcSendMsg(SERVICE_CHANNEL, 123, 0, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    NotifyBindResult(SOFT_BUS, 0);
    DestroyChannelManager();
}

static int32_t InitModuleTest(void)
{
    return HC_SUCCESS;
}

static int32_t InitModuleFail(void)
{
    return HC_ERROR;
}

static void DestroyModuleTest(void) {}

static int CreateTaskTest(int32_t *taskId, const CJson *in, CJson *out)
{
    (void)taskId;
    (void)in;
    (void)out;
    return HC_SUCCESS;
}

static int ProcessTaskTest(int32_t taskId, const CJson *in, CJson *out, int32_t *status)
{
    (void)taskId;
    (void)in;
    (void)out;
    (void)status;
    return HC_SUCCESS;
}

static void DestroyTaskTest(int taskId)
{
    (void)taskId;
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest010, TestSize.Level0)
{
    // dev_auth_module_manager.c interface test
    AuthModuleParams params = { DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, nullptr, 0 };
    int32_t res = UnregisterLocalIdentity(&params, ACCOUNT_MODULE);
    ASSERT_NE(res, HC_SUCCESS);
    InitModules();
    Uint8Buff authIdBuff = { (uint8_t *)TEST_AUTH_ID, strlen(TEST_AUTH_ID) };
    params.authId = &authIdBuff;
    res = UnregisterLocalIdentity(&params, DAS_MODULE);
    ASSERT_EQ(res, HC_SUCCESS);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    res = CheckMsgRepeatability(in, DAS_MODULE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = UnregisterLocalIdentity(&params, DAS_MODULE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = CheckMsgRepeatability(nullptr, DAS_MODULE);
    ASSERT_NE(res, HC_SUCCESS);
    res = CheckMsgRepeatability(in, DAS_MODULE);
    ASSERT_EQ(res, HC_SUCCESS);
    FreeJson(in);
    in = CreateJson();
    ASSERT_NE(in, nullptr);
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    int32_t taskId = 0;
    (void)CreateTask(&taskId, in, out, DAS_MODULE);
    FreeJson(in);
    FreeJson(out);
    DestroyTask(0, 0);
    (void)AddAuthModulePlugin(nullptr);
    AuthModuleBase plugin = { 0 };
    (void)AddAuthModulePlugin(&plugin);
    plugin.init = InitModuleTest;
    (void)AddAuthModulePlugin(&plugin);
    plugin.destroy = DestroyModuleTest;
    (void)AddAuthModulePlugin(&plugin);
    plugin.createTask = CreateTaskTest;
    (void)AddAuthModulePlugin(&plugin);
    plugin.processTask = ProcessTaskTest;
    (void)AddAuthModulePlugin(&plugin);
    plugin.destroyTask = DestroyTaskTest;
    (void)AddAuthModulePlugin(&plugin);
    plugin.init = InitModuleFail;
    (void)AddAuthModulePlugin(&plugin);
    plugin.init = InitModuleTest;
    res = AddAuthModulePlugin(&plugin);
    ASSERT_EQ(res, HC_SUCCESS);
    DelAuthModulePlugin(0);
    DestroyModules();
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest011, TestSize.Level0)
{
    // mbedtls_ec_adapter.c interface test
    int32_t res = MbedtlsHashToPoint25519(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    uint8_t hashVal[64] = { 0 };
    Uint8Buff hashBuff = { hashVal, 64 };
    res = MbedtlsHashToPoint25519(&hashBuff, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    uint8_t outEcPointVal[32] = { 0 };
    Uint8Buff outEcPointBuff = { outEcPointVal, 32 };
    res = MbedtlsHashToPoint25519(&hashBuff, &outEcPointBuff);
    ASSERT_NE(res, HC_SUCCESS);
    uint8_t validHashVal[32] = { 0 };
    hashBuff.val = validHashVal;
    hashBuff.length = 32;
    res = MbedtlsHashToPoint25519(&hashBuff, &outEcPointBuff);
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest012, TestSize.Level0)
{
    // account_task_main.c interface test
    int32_t taskId = 0;
    AccountTask *task = CreateAccountTaskT(&taskId, nullptr, nullptr);
    ASSERT_EQ(task, nullptr);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, MEMBER_JOIN);
    task = CreateAccountTaskT(&taskId, in, nullptr);
    ASSERT_EQ(task, nullptr);
    (void)AddIntToJson(in, FIELD_CREDENTIAL_TYPE, 0);
    task = CreateAccountTaskT(&taskId, in, nullptr);
    ASSERT_EQ(task, nullptr);
    InitVersionInfos();
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    (void)AddIntToJson(in, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED);
    task = CreateAccountTaskT(&taskId, in, nullptr);
    ASSERT_EQ(task, nullptr);
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    (void)AddIntToJson(in, FIELD_IS_CLIENT, true);
    task = CreateAccountTaskT(&taskId, in, out);
    ASSERT_EQ(task, nullptr);
    (void)AddIntToJson(in, FIELD_IS_CLIENT, false);
    task = CreateAccountTaskT(&taskId, in, out);
    ASSERT_EQ(task, nullptr);
    FreeJson(in);
    FreeJson(out);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest013, TestSize.Level0)
{
    // account_module.c interface test
    const AuthModuleBase *accountModule = GetAccountModule();
    ASSERT_NE(accountModule, nullptr);
    int32_t res = accountModule->init();
    ASSERT_EQ(res, HC_SUCCESS);
    bool isIgnored = accountModule->isMsgNeedIgnore(nullptr);
    ASSERT_EQ(isIgnored, true);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    isIgnored = accountModule->isMsgNeedIgnore(in);
    ASSERT_EQ(isIgnored, false);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, OP_BIND);
    isIgnored = accountModule->isMsgNeedIgnore(in);
    ASSERT_EQ(isIgnored, false);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, OP_UNBIND);
    isIgnored = accountModule->isMsgNeedIgnore(in);
    ASSERT_EQ(isIgnored, true);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    (void)AddIntToJson(in, FIELD_STEP, 1);
    isIgnored = accountModule->isMsgNeedIgnore(in);
    ASSERT_EQ(isIgnored, true);
    FreeJson(in);
    res = accountModule->createTask(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    int32_t taskId = 0;
    res = accountModule->createTask(&taskId, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    in = CreateJson();
    ASSERT_NE(in, nullptr);
    res = accountModule->createTask(&taskId, in, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    res = accountModule->createTask(&taskId, in, out);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    (void)AddIntToJson(in, FIELD_STEP, 0);
    res = accountModule->createTask(&taskId, in, out);
    FreeJson(in);
    FreeJson(out);
    res = accountModule->processTask(0, nullptr, nullptr, nullptr);
    accountModule->destroyTask(0);
    AccountMultiTaskManager *manager = GetAccountMultiTaskManager();
    (void)manager->addTaskToManager(nullptr);
    (void)manager->getTaskFromManager(1);
    accountModule->destroy();
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest014, TestSize.Level0)
{
    // identical_account_group.c interface test
    (void)InitDatabase();
    (void)InitBroadcastManager();
    IdenticalAccountGroup *group = (IdenticalAccountGroup *)GetIdenticalAccountGroupInstance();
    ASSERT_NE(group, nullptr);
    int32_t res = group->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *jsonParams = CreateJson();
    ASSERT_NE(jsonParams, nullptr);
    res = group->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, jsonParams);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, jsonParams);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->base.deleteGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->base.deleteGroup(DEFAULT_OS_ACCOUNT, jsonParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    char *returnJsonStr = nullptr;
    res = group->base.deleteGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->base.createGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->base.createGroup(DEFAULT_OS_ACCOUNT, jsonParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = group->base.createGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddStringToJson(jsonParams, FIELD_APP_ID, TEST_APP_ID);
    res = group->base.createGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddStringToJson(jsonParams, FIELD_USER_ID, TEST_GROUP_ID);
    res = group->base.createGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    res = group->base.deleteGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    ASSERT_EQ(res, HC_SUCCESS);
    DestroyDatabase();
    DestroyBroadcastManager();
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

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest015, TestSize.Level0)
{
    // broadcast_manager.c interface test
    int32_t res = InitBroadcastManager();
    ASSERT_EQ(res, HC_SUCCESS);
    res = AddListener(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = AddListener(TEST_APP_ID, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    DataChangeListener listener = { 0 };
    res = AddListener(TEST_APP_ID, &listener);
    ASSERT_EQ(res, HC_SUCCESS);
    res = RemoveListener(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = RemoveListener(TEST_APP_ID);
    ASSERT_EQ(res, HC_SUCCESS);
    const Broadcaster *broadcaster = GetBroadcaster();
    ASSERT_NE(broadcaster, nullptr);
    listener.onDeviceBound = OnDeviceBound;
    listener.onDeviceNotTrusted = OnDeviceNotTrusted;
    listener.onDeviceUnBound = OnDeviceUnBound;
    listener.onGroupCreated = OnGroupCreated;
    listener.onGroupDeleted = OnGroupDeleted;
    listener.onLastGroupDeleted = OnLastGroupDeleted;
    listener.onTrustedDeviceNumChanged = OnTrustedDeviceNumChanged;
    res = AddListener(TEST_APP_ID, &listener);
    ASSERT_EQ(res, HC_SUCCESS);
    broadcaster->postOnTrustedDeviceNumChanged(1);
    broadcaster->postOnLastGroupDeleted(nullptr, PEER_TO_PEER_GROUP);
    broadcaster->postOnLastGroupDeleted(TEST_AUTH_ID, PEER_TO_PEER_GROUP);
    broadcaster->postOnGroupDeleted(nullptr);
    broadcaster->postOnGroupDeleted("test");
    broadcaster->postOnGroupCreated(nullptr);
    broadcaster->postOnGroupCreated("test");
    broadcaster->postOnDeviceUnBound(nullptr, nullptr);
    broadcaster->postOnDeviceUnBound(TEST_AUTH_ID, nullptr);
    broadcaster->postOnDeviceUnBound(TEST_AUTH_ID, "test");
    broadcaster->postOnDeviceNotTrusted(nullptr);
    broadcaster->postOnDeviceNotTrusted(TEST_AUTH_ID);
    broadcaster->postOnDeviceBound(nullptr, nullptr);
    broadcaster->postOnDeviceBound(TEST_AUTH_ID, nullptr);
    broadcaster->postOnDeviceBound(TEST_AUTH_ID, "test");
    res = RemoveListener(TEST_APP_ID);
    ASSERT_EQ(res, HC_SUCCESS);
    DestroyBroadcastManager();
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest016, TestSize.Level0)
{
    // iso_protocol_common.c interface test
    int res = IsoServerGenSessionKeyAndCalToken(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    IsoBaseParams *baseParams = (IsoBaseParams *)HcMalloc(sizeof(IsoBaseParams), 0);
    baseParams->loader = GetLoaderInstance();
    res = IsoServerGenSessionKeyAndCalToken(baseParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff tokenFromPeer = { 0 };
    res = IsoServerGenSessionKeyAndCalToken(baseParams, &tokenFromPeer, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff tokenToPeer = { 0 };
    res = IsoServerGenSessionKeyAndCalToken(baseParams, &tokenFromPeer, &tokenToPeer);
    ASSERT_NE(res, HC_SUCCESS);
    res = IsoServerGenRandomAndToken(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = IsoServerGenRandomAndToken(baseParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = IsoClientGenSessionKey(nullptr, 0, nullptr, 0);
    ASSERT_NE(res, HC_SUCCESS);
    res = IsoClientGenSessionKey(baseParams, 0, nullptr, 0);
    ASSERT_NE(res, HC_SUCCESS);
    uint8_t hmacVal[256] = { 0 };
    res = IsoClientGenSessionKey(baseParams, 0, hmacVal, 256);
    ASSERT_NE(res, HC_SUCCESS);
    res = IsoClientCheckAndGenToken(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = IsoClientCheckAndGenToken(baseParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff peerToken = { 0 };
    res = IsoClientCheckAndGenToken(baseParams, &peerToken, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff selfToken = { 0 };
    res = IsoClientCheckAndGenToken(baseParams, &peerToken, &selfToken);
    ASSERT_NE(res, HC_SUCCESS);
    res = IsoClientGenRandom(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    HcFree(baseParams);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest017, TestSize.Level0)
{
    // das_lite_token_manager.c interface test
    const TokenManager *liteManager = GetLiteTokenManagerInstance();
    ASSERT_NE(liteManager, nullptr);
    Uint8Buff authIdBuff = { (uint8_t *)TEST_AUTH_ID, strlen(TEST_AUTH_ID) };
    TokenManagerParams params = {
        .osAccountId = DEFAULT_OS_ACCOUNT,
        .pkgName = { (uint8_t *)TEST_APP_ID, HcStrlen(TEST_APP_ID) },
        .serviceType = { (uint8_t *)TEST_GROUP_ID, HcStrlen(TEST_GROUP_ID) },
        .authId = authIdBuff,
        .userType = 0
    };
    int32_t res = liteManager->unregisterLocalIdentity(&params);
    ASSERT_EQ(res, HC_SUCCESS);
    // das_standard_token_manager.c interface test
    const TokenManager *standardMgr = GetStandardTokenManagerInstance();
    ASSERT_NE(standardMgr, nullptr);
    params.pkgName.val = (uint8_t *)GROUP_MANAGER_PACKAGE_NAME;
    params.pkgName.length = HcStrlen(GROUP_MANAGER_PACKAGE_NAME);
    res = standardMgr->unregisterLocalIdentity(&params);
    ASSERT_EQ(res, HC_SUCCESS);
    params.pkgName.val = (uint8_t *)TEST_APP_ID;
    params.pkgName.length = HcStrlen(TEST_APP_ID);
    res = standardMgr->deletePeerAuthInfo(&params);
    ASSERT_EQ(res, HC_SUCCESS);
    PakeParams *pakeParams = (PakeParams *)HcMalloc(sizeof(PakeParams), 0);
    pakeParams->baseParams.loader = GetLoaderInstance();
    char appId[256] = TEST_APP_ID;
    char groupId[256] = TEST_GROUP_ID;
    pakeParams->packageName = appId;
    pakeParams->serviceType = groupId;
    pakeParams->baseParams.idSelf.val = (uint8_t *)TEST_AUTH_ID;
    pakeParams->baseParams.idSelf.length = strlen(TEST_AUTH_ID);
    pakeParams->isSelfFromUpgrade = true;
    pakeParams->baseParams.idPeer.val = (uint8_t *)TEST_AUTH_ID;
    pakeParams->baseParams.idPeer.length = strlen(TEST_AUTH_ID);
    res = standardMgr->computeAndSavePsk(pakeParams);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff returnPkBuff = { 0 };
    res = standardMgr->getPublicKey(&params, &returnPkBuff);
    ASSERT_NE(res, HC_SUCCESS);
    HcFree(pakeParams);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest018, TestSize.Level0)
{
    // key_manager.c interface test
    int32_t res = GetDevicePubKey(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = DeletePseudonymPsk(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest019, TestSize.Level0)
{
    // group_auth_data_operation.c interface test
    (void)InitDatabase();
    int32_t authForm = GroupTypeToAuthForm(ACROSS_ACCOUNT_AUTHORIZE_GROUP);
    ASSERT_EQ(authForm, AUTH_FORM_ACROSS_ACCOUNT);
    authForm = GroupTypeToAuthForm(0);
    ASSERT_EQ(authForm, AUTH_FORM_INVALID_TYPE);
    int32_t groupType = AuthFormToGroupType(AUTH_FORM_ACCOUNT_UNRELATED);
    ASSERT_EQ(groupType, PEER_TO_PEER_GROUP);
    groupType = AuthFormToGroupType(AUTH_FORM_ACROSS_ACCOUNT);
    ASSERT_EQ(groupType, ACROSS_ACCOUNT_AUTHORIZE_GROUP);
    groupType = AuthFormToGroupType(-1);
    ASSERT_EQ(groupType, GROUP_TYPE_INVALID);
    int32_t res = GaGetTrustedDeviceEntryById(DEFAULT_OS_ACCOUNT, nullptr, true, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    bool isAccessiblle = GaIsGroupAccessible(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    ASSERT_EQ(isAccessiblle, false);
    isAccessiblle = GaIsGroupAccessible(DEFAULT_OS_ACCOUNT, TEST_GROUP_ID, nullptr);
    ASSERT_EQ(isAccessiblle, false);
    isAccessiblle = GaIsGroupAccessible(DEFAULT_OS_ACCOUNT, TEST_GROUP_ID, TEST_APP_ID);
    ASSERT_EQ(isAccessiblle, false);
    DestroyDatabase();
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest020, TestSize.Level0)
{
    // compatible_bind_sub_session_util.c interface test
    InformPeerProcessError(123, nullptr, nullptr, -1);
    CJson *jsonParams = CreateJson();
    ASSERT_NE(jsonParams, nullptr);
    (void)AddStringToJson(jsonParams, FIELD_CHANNEL_ID, "0");
    InformPeerProcessError(123, jsonParams, nullptr, -1);
    (void)AddStringToJson(jsonParams, FIELD_APP_ID, TEST_APP_ID);
    InformPeerProcessError(123, jsonParams, nullptr, -1);
    FreeJson(jsonParams);
    int32_t res = CombineConfirmData(MEMBER_JOIN, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = CombineConfirmData(MEMBER_INVITE, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    // compatible_bind_sub_session.c interface test
    DestroyCompatibleBindSubSession(nullptr);
    res = CreateServerBindSubSession(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    jsonParams = CreateJson();
    ASSERT_NE(jsonParams, nullptr);
    (void)AddStringToJson(jsonParams, FIELD_REQUEST_ID, "123");
    res = CreateServerBindSubSession(jsonParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_OP, MEMBER_INVITE);
    res = CreateServerBindSubSession(jsonParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(jsonParams);
    res = CreateClientBindSubSession(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    jsonParams = CreateJson();
    ASSERT_NE(jsonParams, nullptr);
    (void)AddStringToJson(jsonParams, FIELD_REQUEST_ID, "123");
    res = CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_OP, MEMBER_INVITE);
    res = CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_OP, MEMBER_JOIN);
    res = CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    res = CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    res = CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_OP, MEMBER_DELETE);
    res = CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(jsonParams);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest021, TestSize.Level0)
{
    // compatible_auth_sub_session_common.c interface test
    NotifyPeerAuthError(nullptr, nullptr);
    int32_t res = HandleAuthTaskStatus(nullptr, nullptr, IGNORE_MSG, true);
    ASSERT_EQ(res, HC_SUCCESS);
    res = HandleAuthTaskStatus(nullptr, nullptr, CONTINUE, true);
    ASSERT_NE(res, HC_SUCCESS);
    res = HandleAuthTaskStatus(nullptr, nullptr, 3, true);
    ASSERT_NE(res, HC_SUCCESS);
    // compatible_auth_sub_session_util.c interface test
    int32_t authType = GetAuthType(AUTH_FORM_ACROSS_ACCOUNT);
    ASSERT_EQ(authType, ACCOUNT_RELATED_GROUP_AUTH_TYPE);
    authType = GetAuthType(AUTH_FORM_INVALID_TYPE);
    ASSERT_EQ(authType, INVALID_GROUP_AUTH_TYPE);
    CJson *confirmJsonParams = CreateJson();
    ASSERT_NE(confirmJsonParams, nullptr);
    (void)AddIntToJson(confirmJsonParams, FIELD_OS_ACCOUNT_ID, INVALID_OS_ACCOUNT);
    res = CombineAuthConfirmData(confirmJsonParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(confirmJsonParams);
    int32_t moduleType = GetAuthModuleType(nullptr);
    ASSERT_EQ(moduleType, INVALID_MODULE_TYPE);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_INVALID_TYPE);
    moduleType = GetAuthModuleType(in);
    ASSERT_EQ(moduleType, INVALID_MODULE_TYPE);
    FreeJson(in);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest022, TestSize.Level0)
{
    // account_unrelated_group_auth.c interface test
    BaseGroupAuth *groupAuth = GetAccountUnrelatedGroupAuth();
    ASSERT_NE(groupAuth, nullptr);
    groupAuth->onFinish(123, nullptr, nullptr, nullptr);
    int32_t res = groupAuth->getAuthParamsVecForServer(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest023, TestSize.Level0)
{
    // das_task_common.c interface test
    int32_t res = GetAndCheckKeyLenOnServer(nullptr, 0);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *in = CreateJson();
    CJson *payload = CreateJson();
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    res = GetAndCheckKeyLenOnServer(in, 0);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(payload, FIELD_KEY_LENGTH, 1);
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    res = GetAndCheckKeyLenOnServer(in, 0);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(payload);
    FreeJson(in);
    res = GetAuthIdPeerFromPayload(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    in = CreateJson();
    payload = CreateJson();
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    res = GetAuthIdPeerFromPayload(in, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(payload);
    FreeJson(in);
    res = GetAndCheckAuthIdPeer(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    in = CreateJson();
    payload = CreateJson();
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    res = GetAndCheckAuthIdPeer(in, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddStringToJson(payload, FIELD_PEER_AUTH_ID, "");
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    res = GetAndCheckAuthIdPeer(in, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(payload);
    FreeJson(in);
    res = GetIdPeer(nullptr, nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    in = CreateJson();
    (void)AddStringToJson(in, FIELD_PEER_AUTH_ID, "");
    res = GetIdPeer(in, FIELD_PEER_AUTH_ID, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(in);
    res = GeneratePseudonymPskAlias(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest024, TestSize.Level0)
{
    // das_task_common.c interface test
    Uint8Buff serviceTypeBuff = { (uint8_t *)TEST_GROUP_ID, 0 };
    Uint8Buff authIdBuff = { (uint8_t *)TEST_AUTH_ID, 0 };
    uint8_t outKeyAliasVal[256] = { 0 };
    Uint8Buff outKeyAliasBuff = { outKeyAliasVal, 0 };
    int32_t res = GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    ASSERT_NE(res, HC_SUCCESS);
    serviceTypeBuff.length = HcStrlen(TEST_GROUP_ID);
    res = GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    ASSERT_NE(res, HC_SUCCESS);
    authIdBuff.length = HcStrlen(TEST_AUTH_ID);
    res = GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    ASSERT_NE(res, HC_SUCCESS);
    outKeyAliasBuff.length = 256;
    serviceTypeBuff.length = SERVICE_TYPE_MAX_LEN + 1;
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    serviceTypeBuff.length = HcStrlen(TEST_GROUP_ID);
    authIdBuff.length = AUTH_ID_MAX_LEN + 1;
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    authIdBuff.length = HcStrlen(TEST_AUTH_ID);
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    Uint8Buff pkgNameBuff = { (uint8_t *)TEST_APP_ID, 0 };
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_ACCESSOR_PK, &authIdBuff, &outKeyAliasBuff);
    pkgNameBuff.length = HcStrlen(TEST_APP_ID);
    serviceTypeBuff.length = 0;
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_ACCESSOR_PK, &authIdBuff, &outKeyAliasBuff);
    serviceTypeBuff.length = HcStrlen(TEST_GROUP_ID);
    authIdBuff.length = 0;
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_ACCESSOR_PK, &authIdBuff, &outKeyAliasBuff);
    authIdBuff.length = HcStrlen(TEST_AUTH_ID);
    outKeyAliasBuff.length = 0;
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_ACCESSOR_PK, &authIdBuff, &outKeyAliasBuff);
    outKeyAliasBuff.length = 256;
    pkgNameBuff.length = PACKAGE_NAME_MAX_LEN + 1;
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_ACCESSOR_PK, &authIdBuff, &outKeyAliasBuff);
    pkgNameBuff.length = HcStrlen(TEST_APP_ID);
    serviceTypeBuff.length = SERVICE_TYPE_MAX_LEN + 1;
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_ACCESSOR_PK, &authIdBuff, &outKeyAliasBuff);
    serviceTypeBuff.length = HcStrlen(TEST_GROUP_ID);
    authIdBuff.length = AUTH_ID_MAX_LEN + 1;
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_ACCESSOR_PK, &authIdBuff, &outKeyAliasBuff);
    authIdBuff.length = HcStrlen(TEST_AUTH_ID);
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_TYPE_END, &authIdBuff, &outKeyAliasBuff);
    (void)GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_PSK, &authIdBuff, &outKeyAliasBuff);
    res = GenerateKeyAlias(&pkgNameBuff, &serviceTypeBuff, KEY_ALIAS_AUTH_TOKEN, &authIdBuff, &outKeyAliasBuff);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest025, TestSize.Level0)
{
    // das_version_util.c interface test
    VersionStruct version = { 0 };
    PakeAlgType type = GetSupportedPakeAlg(&version, PAKE_V2);
    type = GetSupportedPakeAlg(&version, ISO);
    ProtocolType protocolType = GetPrototolType(&version, CODE_NULL);
    ASSERT_EQ(protocolType, PROTOCOL_TYPE_NONE);
    version.first = 1;
    protocolType = GetPrototolType(&version, AUTHENTICATE);
    ASSERT_EQ(protocolType, PROTOCOL_TYPE_NONE);
    protocolType = GetPrototolType(&version, OP_BIND);
    ASSERT_EQ(protocolType, PAKE_V1);
    VersionStruct versionSelf = { 0 };
    int32_t res = NegotiateVersion(nullptr, &version, &versionSelf);
    ASSERT_EQ(res, HC_SUCCESS);
    version.first = 0;
    res = NegotiateVersion(nullptr, &version, &versionSelf);
    ASSERT_NE(res, HC_SUCCESS);
    res = GetSingleVersionFromJson(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *jsonObj = CreateJson();
    res = GetSingleVersionFromJson(jsonObj, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = GetSingleVersionFromJson(jsonObj, &version);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddStringToJson(jsonObj, FIELD_GROUP_AND_MODULE_VERSION, "123");
    res = GetSingleVersionFromJson(jsonObj, &version);
    ASSERT_EQ(res, HC_SUCCESS);
    (void)AddStringToJson(jsonObj, FIELD_GROUP_AND_MODULE_VERSION, "1.2.3");
    res = GetSingleVersionFromJson(jsonObj, &version);
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest026, TestSize.Level0)
{
    // pake_v1_protocol_common.c interface test
    DestroyPakeV1BaseParams(nullptr);
    int32_t res = InitPakeV1BaseParams(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = ClientConfirmPakeV1Protocol(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    PakeBaseParams *params = (PakeBaseParams *)HcMalloc(sizeof(PakeBaseParams), 0);
    params->loader = GetLoaderInstance();
    res = ClientConfirmPakeV1Protocol(params);
    ASSERT_NE(res, HC_SUCCESS);
    res = ClientVerifyConfirmPakeV1Protocol(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = ClientVerifyConfirmPakeV1Protocol(params);
    ASSERT_NE(res, HC_SUCCESS);
    res = ServerResponsePakeV1Protocol(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = ServerResponsePakeV1Protocol(params);
    ASSERT_NE(res, HC_SUCCESS);
    res = ServerConfirmPakeV1Protocol(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = ServerConfirmPakeV1Protocol(params);
    ASSERT_NE(res, HC_SUCCESS);
    HcFree(params);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest027, TestSize.Level0)
{
    // huks_adapter.c interface test
    const AlgLoader *loader = GetLoaderInstance();
    ASSERT_NE(loader, nullptr);
    int32_t res = loader->importSymmetricKey(nullptr, nullptr, KEY_PURPOSE_SIGN_VERIFY, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    bool ret = loader->checkDlPublicKey(nullptr, nullptr);
    ASSERT_EQ(ret, false);
    Uint8Buff key = { 0 };
    ret = loader->checkDlPublicKey(&key, nullptr);
    ASSERT_EQ(ret, false);
    uint8_t keyVal[256] = { 0 };
    key.val = keyVal;
    key.length = 256;
    ret = loader->checkDlPublicKey(&key, nullptr);
    ASSERT_EQ(ret, false);
    ret = loader->checkDlPublicKey(&key, "TestPrimeHex");
    ASSERT_EQ(ret, false);
    res = loader->bigNumCompare(nullptr, nullptr);
    ASSERT_EQ(res, HC_SUCCESS);
    Uint8Buff aBuff = { 0 };
    Uint8Buff bBuff = { 0 };
    res = loader->bigNumCompare(&aBuff, &bBuff);
    ASSERT_EQ(res, HC_SUCCESS);
    res = loader->sign(nullptr, nullptr, ED25519, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = loader->generateKeyPair(ED25519, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff outPrivKey = { 0 };
    res = loader->generateKeyPair(ED25519, &outPrivKey, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    uint8_t outPrivKeyVal[256] = { 0 };
    outPrivKey.val = outPrivKeyVal;
    res = loader->generateKeyPair(ED25519, &outPrivKey, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    outPrivKey.length = 256;
    res = loader->generateKeyPair(ED25519, &outPrivKey, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff outPubKey = { 0 };
    res = loader->generateKeyPair(ED25519, &outPrivKey, &outPubKey);
    ASSERT_NE(res, HC_SUCCESS);
    uint8_t outPubKeyVal[256] = { 0 };
    outPubKey.val = outPubKeyVal;
    res = loader->generateKeyPair(ED25519, &outPrivKey, &outPubKey);
    ASSERT_NE(res, HC_SUCCESS);
    outPubKey.length = 128;
    res = loader->generateKeyPair(ED25519, &outPrivKey, &outPubKey);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest028, TestSize.Level0)
{
    // dev_session_util.c interface test
    int32_t res = AddPkInfoWithPdid(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *context = CreateJson();
    res = AddPkInfoWithPdid(context, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *credJson = CreateJson();
    res = AddPkInfoWithPdid(context, credJson, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = AddPkInfoWithPdid(context, credJson, "TestRealPkInfo");
    ASSERT_NE(res, HC_SUCCESS);
    CJson *realPkInfoJson = CreateJson();
    (void)AddStringToJson(realPkInfoJson, FIELD_USER_ID, TEST_GROUP_ID);
    (void)AddStringToJson(realPkInfoJson, FIELD_DEVICE_ID, TEST_AUTH_ID);
    char *realPkInfoStr = PackJsonToString(realPkInfoJson);
    FreeJson(realPkInfoJson);
    res = AddPkInfoWithPdid(context, credJson, realPkInfoStr);
    FreeJsonString(realPkInfoStr);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(context);
    FreeJson(credJson);
    res = GetRealPkInfoStr(DEFAULT_OS_ACCOUNT, nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    credJson = CreateJson();
    (void)AddStringToJson(credJson, FIELD_PK_INFO, "TestPkInfo");
    res = GetRealPkInfoStr(DEFAULT_OS_ACCOUNT, credJson, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *pkInfoJson = CreateJson();
    (void)AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_GROUP_ID);
    (void)AddStringToJson(pkInfoJson, FIELD_DEVICE_ID, TEST_AUTH_ID);
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    (void)AddStringToJson(credJson, FIELD_PK_INFO, pkInfoStr);
    FreeJsonString(pkInfoStr);
    res = GetRealPkInfoStr(DEFAULT_OS_ACCOUNT, credJson, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(credJson);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest029, TestSize.Level0)
{
    // pake_v2_protocol_common.c interface test
    DestroyPakeV2BaseParams(nullptr);
    int32_t res = ServerConfirmPakeV2Protocol(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    PakeBaseParams *params = (PakeBaseParams *)HcMalloc(sizeof(PakeBaseParams), 0);
    params->loader = GetLoaderInstance();
    res = ServerConfirmPakeV2Protocol(params);
    ASSERT_NE(res, HC_SUCCESS);
    res = ServerResponsePakeV2Protocol(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = ServerResponsePakeV2Protocol(params);
    ASSERT_NE(res, HC_SUCCESS);
    res = ClientVerifyConfirmPakeV2Protocol(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = ClientVerifyConfirmPakeV2Protocol(params);
    ASSERT_NE(res, HC_SUCCESS);
    res = ClientConfirmPakeV2Protocol(nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = ClientConfirmPakeV2Protocol(params);
    ASSERT_NE(res, HC_SUCCESS);
    res = InitPakeV2BaseParams(DEFAULT_OS_ACCOUNT, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    HcFree(params);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest030, TestSize.Level0)
{
    // iso_task_common.c interface test
    IsoParams *params = (IsoParams *)HcMalloc(sizeof(IsoParams), 0);
    int res = GeneratePsk(nullptr, params);
    ASSERT_NE(res, HC_SUCCESS);
    res = GenerateKeyAliasInIso(nullptr, nullptr, 0, false);
    ASSERT_NE(res, HC_SUCCESS);
    res = GenerateKeyAliasInIso(params, nullptr, 0, false);
    ASSERT_NE(res, HC_SUCCESS);
    uint8_t keyAliasVal[256] = { 0 };
    res = GenerateKeyAliasInIso(params, keyAliasVal, 0, false);
    ASSERT_NE(res, HC_SUCCESS);
    params->packageName = (char *)HcMalloc(HcStrlen(TEST_APP_ID) + 1, 0);
    (void)memcpy_s(params->packageName, HcStrlen(TEST_APP_ID) + 1, TEST_APP_ID, HcStrlen(TEST_APP_ID));
    params->serviceType = (char *)HcMalloc(HcStrlen(TEST_GROUP_ID) + 1, 0);
    (void)memcpy_s(params->serviceType, HcStrlen(TEST_GROUP_ID) + 1, TEST_GROUP_ID, HcStrlen(TEST_GROUP_ID));
    res = GenerateKeyAliasInIso(params, keyAliasVal, 256, false);
    ASSERT_NE(res, HC_SUCCESS);
    res = InitIsoParams(params, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, CODE_NULL);
    res = InitIsoParams(params, in);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    res = InitIsoParams(params, in);
    ASSERT_NE(res, HC_SUCCESS);
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
    res = InitIsoParams(params, in);
    ASSERT_NE(res, HC_SUCCESS);
    DestroyIsoParams(nullptr);
    HcFree(params);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest031, TestSize.Level0)
{
    // das_task_common.c interface test
    int res = ServerProtocolMessageOut(nullptr, 0, 0);
    ASSERT_EQ(res, HC_SUCCESS);
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    res = ServerProtocolMessageOut(out, CODE_NULL, 0);
    ASSERT_NE(res, HC_SUCCESS);
    res = ClientProtocolMessageOut(nullptr, 0, 0);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ClientProtocolMessageOut(out, CODE_NULL, 0);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(sendToPeer);
    FreeJson(out);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_MESSAGE, ERR_MESSAGE);
    uint32_t msg = ProtocolMessageIn(in);
    ASSERT_EQ(msg, ERR_MESSAGE);
    FreeJson(in);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest032, TestSize.Level0)
{
    // dev_session_util.c interface test
    int32_t res = CheckPeerPkInfoForPdid(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *context = CreateJson();
    (void)AddIntToJson(context, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    res = CheckPeerPkInfoForPdid(context, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *inputDataJson = CreateJson();
    (void)AddStringToJson(inputDataJson, FIELD_PK_INFO, "TestPkInfo");
    res = CheckPeerPkInfoForPdid(context, inputDataJson);
    ASSERT_NE(res, HC_SUCCESS);
    CJson *pkInfoJson = CreateJson();
    (void)AddStringToJson(pkInfoJson, FIELD_PSEUDONYM_ID, "TestPseudonymId");
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    (void)AddStringToJson(inputDataJson, FIELD_PK_INFO, pkInfoStr);
    FreeJsonString(pkInfoStr);
    res = CheckPeerPkInfoForPdid(context, inputDataJson);
    ASSERT_EQ(res, HC_SUCCESS);
    FreeJson(context);
    FreeJson(inputDataJson);
    res = SetPeerInfoToContext(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    inputDataJson = CreateJson();
    (void)AddStringToJson(inputDataJson, FIELD_PK_INFO, "TestPkInfo");
    res = SetPeerInfoToContext(nullptr, inputDataJson);
    ASSERT_NE(res, HC_SUCCESS);
    pkInfoJson = CreateJson();
    pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    (void)AddStringToJson(inputDataJson, FIELD_PK_INFO, pkInfoStr);
    FreeJsonString(pkInfoStr);
    res = SetPeerInfoToContext(nullptr, inputDataJson);
    ASSERT_NE(res, HC_SUCCESS);
    FreeJson(inputDataJson);
}

HWTEST_F(DeviceAuthInterfaceTest, DeviceAuthInterfaceTest033, TestSize.Level0)
{
    // huks_adapter.c interface test
    const AlgLoader *loader = GetLoaderInstance();
    ASSERT_NE(loader, nullptr);
    int32_t res = loader->agreeSharedSecretWithStorage(nullptr, nullptr, X25519, 0, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = loader->getKeyExtInfo(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    KeyParams keyParams = { { nullptr, 0, true }, true, DEFAULT_OS_ACCOUNT };
    res = loader->getKeyExtInfo(&keyParams, nullptr);
    uint8_t keyAliasVal[256] = { 0 };
    keyParams.keyBuff.key = keyAliasVal;
    keyParams.keyBuff.keyLen = 256;
    res = loader->getKeyExtInfo(&keyParams, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff outExtInfo = { 0 };
    res = loader->getKeyExtInfo(&keyParams, &outExtInfo);
    ASSERT_NE(res, HC_SUCCESS);
    keyParams.isDeStorage = false;
    res = loader->getKeyExtInfo(&keyParams, &outExtInfo);
    ASSERT_NE(res, HC_SUCCESS);
    res = loader->computePseudonymPsk(nullptr, nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    KeyParams params = { { 0 }, false, DEFAULT_OS_ACCOUNT };
    uint8_t keyValue[256] = { 0 };
    params.keyBuff.key = keyValue;
    params.keyBuff.keyLen = 256;
    params.keyBuff.isAlias = true;
    params.isDeStorage = true;
    res = loader->computePseudonymPsk(&params, nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    uint8_t pskAliasVal[256] = { 0 };
    Uint8Buff pskAlias = { pskAliasVal, 256 };
    uint8_t outPskVal[32] = { 0 };
    Uint8Buff outPsk = { outPskVal, 32 };
    res = loader->computePseudonymPsk(&params, &pskAlias, nullptr, &outPsk);
    ASSERT_NE(res, HC_SUCCESS);
    Uint8Buff extInfo = { 0 };
    res = loader->computePseudonymPsk(&params, &pskAlias, &extInfo, &outPsk);
    ASSERT_NE(res, HC_SUCCESS);
    res = loader->computeHkdf(nullptr, nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
    res = loader->computeHmacWithThreeStage(nullptr, nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
}
} // namespace