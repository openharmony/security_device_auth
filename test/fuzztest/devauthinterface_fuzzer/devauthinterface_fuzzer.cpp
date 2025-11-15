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

#include "devauthinterface_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

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
#include "ext_plugin_manager.h"
#include "channel_manager.h"
#include "soft_bus_channel.h"
#include "dev_auth_module_manager.h"
#include "mbedtls_ec_adapter.h"
#include "account_task_main.h"
#include "account_version_util.h"
#include "account_module.h"
#include "account_multi_task_manager.h"
#include "account_task_manager.h"
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
#include "base/security/device_auth/services/legacy/authenticators/src/account_unrelated/pake_task/pake_v1_task/pake_v1_protocol_task/pake_v1_protocol_task_common.c"
#include "base/security/device_auth/services/session_manager/src/session/v2/dev_session_util.c"
#include "base/security/device_auth/services/legacy/group_manager/src/group_operation/identical_account_group/identical_account_group.c"


namespace OHOS {
#define TEST_PSEUDONYM_ID "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_PSEUDONYM_CHALLENGE "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_CONNECT_PARAMS "TestConnectParams"
#define TEST_TRANSMIT_DATA "TestTransmitData"
#define TEST_APP_ID "TestAppId"
#define TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define TEST_USER_ID "testUserId"
#define TEST_DEVICE_ID "testDeviceId"
#define TEST_PK_INFO "TestPkInfo"
#define TEST_PK_INFO_SIGN "TestPkInfoSign"
#define TEST_AUTH_ID "TestAuthId"
#define TEST_KEY_LEN_1 10
#define TEST_KEY_LEN_2 40
#define TEST_KEY_LEN_3 256
#define TEST_KEY_LEN_4 128
#define TEST_KEY_LEN_5 32
#define TEST_LEN 16
#define TEST_OS_ACCOUNT_ID 0
#define TEST_DEVICE_PK "testDevicePk"
#define TEST_VERSION 0
#define TEST_RANDOM_LEN 16
#define TEST_METHOD_ID 1
#define TEST_REQ_ID 123
#define TEST_REQ_ID_STR "123"
#define TEST_VERSION_ID "1.2.3"
#define TEST_PROTOCOL_TYPE 2
#define TEST_FAULT_STATUS 3
#define TEST_TYPE_ONE 1
#define TEST_TYPE_TWO 2
static const char *EXT_INFO =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *CRED_DATA =
    "{\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *TEST_CLIENT_PK = "3059301306072A8648CE3D020106082A8648CE3D030107034200042CFE425AB037B9E6F"
    "837AED32F0CD4460D509E8C6AEC3A5D49DB25F2DDC133A87434BFDD34";
static const char *TEST_SERVER_PK = "020106082A8648CE3D030107034200042CFE425AB037B9E6F837AED32F0CD4460D509E8"
    "C6AEC3A5D49DB25F2DDC133A87434BFDD34563C2226F838D3951C0F3D";


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

static void DevAuthInterfaceTestCase001()
{
    // account_auth_plugin_proxy.c interface test
    (void)SetAccountAuthPlugin(nullptr, nullptr);
    (void)ExcuteCredMgrCmd(DEFAULT_OS_ACCOUNT, 0, nullptr, nullptr);
    (void)CreateAuthSession(0, nullptr, nullptr);
    (void)ProcessAuthSession(0, nullptr, nullptr, nullptr);
    (void)DestroyAuthSession(0);
    AccountAuthExtPlug plugin = { { 0 }, nullptr, nullptr, nullptr, nullptr };
    (void)SetAccountAuthPlugin(nullptr, &plugin);
    (void)ExcuteCredMgrCmd(DEFAULT_OS_ACCOUNT, 0, nullptr, nullptr);
    (void)CreateAuthSession(0, nullptr, nullptr);
    (void)ProcessAuthSession(0, nullptr, nullptr, nullptr);
    (void)DestroyAuthSession(0);
    plugin.createSession = CreateSessionTest;
    (void)SetAccountAuthPlugin(nullptr, &plugin);
    (void)CreateAuthSession(0, nullptr, nullptr);
    plugin.excuteCredMgrCmd = ExcuteCredMgrCmdTest;
    (void)SetAccountAuthPlugin(nullptr, &plugin);
    (void)ExcuteCredMgrCmd(DEFAULT_OS_ACCOUNT, 0, nullptr, nullptr);
    plugin.processSession = ProcessSessionTest;
    (void)SetAccountAuthPlugin(nullptr, &plugin);
    (void)ProcessAuthSession(0, nullptr, nullptr, nullptr);
    plugin.destroySession = DestroySessionTest;
    plugin.base.init = InitTest;
    (void)SetAccountAuthPlugin(nullptr, &plugin);
    (void)DestroyAuthSession(0);
    DestoryAccountAuthPlugin();
}

static void DevAuthInterfaceTestCase002()
{
    // account_auth_plugin_proxy.c interface test
    (void)SetAccountAuthPlugin(nullptr, nullptr);
    DestoryAccountAuthPlugin();
    AccountAuthExtPlug plugin = { { 0 }, nullptr, nullptr, nullptr, nullptr };
    (void)SetAccountAuthPlugin(nullptr, &plugin);
    DestoryAccountAuthPlugin();
    plugin.base.destroy = Destroy;
    (void)SetAccountAuthPlugin(nullptr, &plugin);
    DestoryAccountAuthPlugin();
}

static void DevAuthInterfaceTestCase003()
{
    // pake_protocol_dl_common.c interface test
    (void)GetPakeDlAlg();
    PakeBaseParams *baseParams = (PakeBaseParams *)HcMalloc(sizeof(PakeBaseParams), 0);
    baseParams->loader = GetLoaderInstance();
    baseParams->isClient = true;
    (void)GenerateDlPakeParams(baseParams, nullptr);
    baseParams->epkPeer.length = PAKE_DL_PRIME_LEN;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_384;
    (void)GenerateDlPakeParams(baseParams, nullptr);
    baseParams->epkPeer.length = PAKE_DL_PRIME_SMALL_LEN;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_256;
    baseParams->isClient = false;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_384;
    (void)GenerateDlPakeParams(baseParams, nullptr);
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_256;
    (void)GenerateDlPakeParams(baseParams, nullptr);
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_NONE;
    (void)GenerateDlPakeParams(baseParams, nullptr);
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_256;
    uint8_t secretVal[TEST_LEN] = { 0 };
    Uint8Buff secret = { secretVal, TEST_LEN };
    (void)GenerateDlPakeParams(baseParams, &secret);
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_NONE;
    (void)AgreeDlSharedSecret(baseParams, nullptr);
    baseParams->epkPeer.length = PAKE_DL_PRIME_LEN;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_384;
    (void)AgreeDlSharedSecret(baseParams, nullptr);
    baseParams->epkPeer.length = PAKE_DL_PRIME_SMALL_LEN;
    baseParams->supportedDlPrimeMod = DL_PRIME_MOD_256;
    (void)AgreeDlSharedSecret(baseParams, nullptr);
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

static void DevAuthInterfaceTestCase004()
{
    // pake_v1_protocol_task_common.c interface test
    DestroyDasPakeV1Params(nullptr);
    PakeParams *params = (PakeParams *)HcMalloc(sizeof(PakeParams), 0);
    params->pseudonymExtInfo.selfNextPseudonymId.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    params->pseudonymExtInfo.selfNextPseudonymChallenge.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    params->pseudonymExtInfo.peerNextPseudonymId.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    DestroyDasPakeV1Params(params);
    CJson *in = CreateJson();
    (void)InitDasPakeV1Params(params, in);
    ConstructPakeV1InParams(in);
    (void)InitDasPakeV1Params(params, in);
    (void)LoadPseudonymExtInfoIfNeed(nullptr);
    (void)LoadPseudonymExtInfoIfNeed(params);
    (void)AddPseudonymIdAndChallenge(nullptr, nullptr);
    (void)AddPseudonymIdAndChallenge(params, nullptr);
    CJson *payload = CreateJson();
    (void)AddPseudonymIdAndChallenge(params, payload);
    (void)CheckPseudonymId(nullptr, nullptr);
    (void)CheckPseudonymId(params, nullptr);
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    (void)CheckPseudonymId(params, in);
    (void)AddStringToJson(payload, FIELD_P2P_PSEUDONYM_ID, TEST_PSEUDONYM_ID);
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    (void)CheckPseudonymId(params, in);
    (void)AddStringToJson(payload, FIELD_PSEUDONYM_CHALLENGE, TEST_PSEUDONYM_CHALLENGE);
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    (void)CheckPseudonymId(params, in);
    FreeJson(in);
    FreeJson(payload);
    DestroyDasPakeV1Params(params);
    HcFree(params);
}

static void DevAuthInterfaceTestCase0041()
{
    // pake_v1_protocol_task_common.c static interface test
    PakeParams *params = (PakeParams *)HcMalloc(sizeof(PakeParams), 0);
    params->opCode = OP_UNBIND;
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_KEY_LENGTH, TEST_KEY_LEN_1);
    (void)AllocReturnKey(params, in);
    params->opCode = CODE_NULL;
    (void)AddIntToJson(in, FIELD_KEY_LENGTH, TEST_KEY_LEN_1);
    (void)AllocReturnKey(params, in);
    (void)AddIntToJson(in, FIELD_KEY_LENGTH, TEST_KEY_LEN_2);
    (void)AllocReturnKey(params, in);
    DestroyDasPakeV1Params(params);
    HcFree(params);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase0042()
{
    // pake_v1_protocol_task_common.c static interface test
    char *outStr = nullptr;
    (void)RemoveEscapeForExtInfo(EXT_INFO, &outStr);
}

static void DevAuthInterfaceTestCase0043()
{
    // pake_v1_protocol_task_common.c static interface test
    PakeParams *params = (PakeParams *)HcMalloc(sizeof(PakeParams), 0);
    params->pseudonymExtInfo.selfNextPseudonymId.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    params->pseudonymExtInfo.selfNextPseudonymChallenge.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    params->pseudonymExtInfo.peerNextPseudonymId.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    CJson *in = CreateJson();
    uint8_t *selfNextIdVal = reinterpret_cast<uint8_t *>(HcMalloc(PSEUDONYM_ID_LEN, 0));
    (void)AddByteToJson(in, FIELD_SELF_NEXT_PSEUDONYM_ID, selfNextIdVal, PSEUDONYM_ID_LEN);
    (void)FillPseudonymPskExtInfo(&params->pseudonymExtInfo, in);
    HcFree(selfNextIdVal);
    DestroyDasPakeV1Params(params);
    HcFree(params);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase0044()
{
    // pake_v1_protocol_task_common.c static interface test
    PakeParams *params = (PakeParams *)HcMalloc(sizeof(PakeParams), 0);
    CJson *in = CreateJson();
    (void)CheckPseudonymId(params, in);
    FreeJson(in);
    DestroyDasPakeV1Params(params);
    HcFree(params);
}

static void DevAuthInterfaceTestCase0045()
{
    // pake_v1_protocol_task_common.c static interface test
    PakeParams *params = (PakeParams *)HcMalloc(sizeof(PakeParams), 0);
    params->pseudonymExtInfo.selfNextPseudonymId.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    params->pseudonymExtInfo.selfNextPseudonymChallenge.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    params->pseudonymExtInfo.peerNextPseudonymId.val = (uint8_t *)HcMalloc(TEST_LEN, 0);
    (void)SaveNextPseudonymIdAndChallenge(params);
    DestroyDasPakeV1Params(params);
    HcFree(params);
}

static void DevAuthInterfaceTestCase005()
{
    // ipc_adapt.cpp interface test
    (void)InitIpcCallBackList();
    (void)InitIpcCallBackList();
    DeInitIpcCallBackList();
    DeInitIpcCallBackList();
    ResetIpcCallBackNodeByNodeId(-1);
    ResetIpcCallBackNodeByNodeId(TEST_REQ_ID);
    ResetIpcCallBackNodeByNodeId(1);
    (void)InitIpcCallBackList();
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
    (void)AddReqIdByAppId(TEST_APP_ID, TEST_REQ_ID);
    (void)InitIpcCallBackList();
    (void)AddReqIdByAppId(TEST_APP_ID, TEST_REQ_ID);
    DeInitIpcCallBackList();
    AddIpcCbObjByReqId(TEST_REQ_ID, 0, 0);
    (void)InitIpcCallBackList();
    AddIpcCbObjByReqId(TEST_REQ_ID, 0, 0);
    DeInitIpcCallBackList();
    (void)AddIpcCallBackByReqId(TEST_REQ_ID, nullptr, 0, 0);
    (void)InitIpcCallBackList();
    (void)AddIpcCallBackByReqId(TEST_REQ_ID, nullptr, 0, 0);
    DeInitIpcCallBackList();
    DelIpcCallBackByReqId(TEST_REQ_ID, 0, true);
    DelIpcCallBackByReqId(TEST_REQ_ID, 0, false);
}

static void DevAuthInterfaceTestCase006()
{
    // ipc_adapt.cpp interface test
    InitDeviceAuthCbCtx(nullptr, 0);
    DeviceAuthCallback callback = { 0 };
    InitDeviceAuthCbCtx(&callback, TEST_TYPE_ONE);
    InitDeviceAuthCbCtx(&callback, TEST_TYPE_TWO);
    InitDevAuthListenerCbCtx(nullptr);
    DataChangeListener listener = { 0 };
    InitDevAuthListenerCbCtx(&listener);
    uintptr_t ptr = 0;
    (void)CreateServiceInstance(&ptr);
    DestroyServiceInstance(ptr);
    bool isCallback = IsCallbackMethod(0);
    isCallback = IsCallbackMethod(TEST_METHOD_ID);
}

static void DevAuthInterfaceTestCase007()
{
    // mk_agree_task.c interface test
    (void)CreateMkAgreeTask(0, nullptr, nullptr);
    CJson *in = CreateJson();
    (void)CreateMkAgreeTask(0, in, nullptr);
    MkAgreeTaskBase *task = nullptr;
    (void)CreateMkAgreeTask(0, in, &task);
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
    (void)CreateMkAgreeTask(TASK_TYPE_ISO, in, &task);
    (void)CreateMkAgreeTask(TEST_PROTOCOL_TYPE, in, &task);
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

static void DevAuthInterfaceTestCase008()
{
    // ext_plugin_manager.c interface test
    (void)InitCredMgr();
    (void)ProcCred(0, DEFAULT_OS_ACCOUNT, 0, nullptr, nullptr);
    (void)AddCredPlugin(nullptr);
    CredPlugin plugin = { 0 };
    (void)AddCredPlugin(&plugin);
    plugin.init = InitCredPlugin;
    (void)AddCredPlugin(&plugin);
    plugin.destroy = DestroyCredPlugin;
    (void)AddCredPlugin(&plugin);
    plugin.procCred = ProcessCredTest;
    (void)AddCredPlugin(&plugin);
    plugin.init = InitCredPluginFail;
    (void)AddCredPlugin(&plugin);
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

static void DevAuthInterfaceTestCase009()
{
    // channel_manager.c interface test
    ChannelProxy proxy = { 0 };
    proxy.onBytesReceived = OnBytesReceivedTest;
    proxy.onChannelClosed = OnChannelClosedTest;
    proxy.onChannelOpened = OnChannelOpenedTest;
    (void)InitChannelManager(&proxy);
    DeviceAuthCallback callback = { 0 };
    CJson *jsonParams = CreateJson();
    ChannelType type = GetChannelType(&callback, jsonParams);
    (void)AddStringToJson(jsonParams, FIELD_CONNECT_PARAMS, TEST_CONNECT_PARAMS);
    type = GetChannelType(&callback, jsonParams);
    FreeJson(jsonParams);
    jsonParams = CreateJson();
    callback.onTransmit = OnTransmit;
    type = GetChannelType(&callback, jsonParams);
    FreeJson(jsonParams);
    (void)OpenChannel(SERVICE_CHANNEL, nullptr, TEST_REQ_ID, nullptr);
    jsonParams = CreateJson();
    int64_t returnChannelId = 0;
    (void)OpenChannel(SOFT_BUS, jsonParams, TEST_REQ_ID, &returnChannelId);
    (void)AddStringToJson(jsonParams, FIELD_CONNECT_PARAMS, TEST_CONNECT_PARAMS);
    (void)OpenChannel(SOFT_BUS, jsonParams, TEST_REQ_ID, &returnChannelId);
    FreeJson(jsonParams);
    (void)OpenChannel(NO_CHANNEL, nullptr, TEST_REQ_ID, &returnChannelId);
    CloseChannel(SOFT_BUS, 0);
    (void)HcSendMsg(SOFT_BUS, TEST_REQ_ID, 0, nullptr, TEST_TRANSMIT_DATA);
    (void)HcSendMsg(NO_CHANNEL, TEST_REQ_ID, 0, nullptr, nullptr);
    (void)HcSendMsg(SERVICE_CHANNEL, TEST_REQ_ID, 0, nullptr, nullptr);
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

static void DevAuthInterfaceTestCase010()
{
    // dev_auth_module_manager.c interface test
    AuthModuleParams params = { DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, nullptr, 0 };
    (void)UnregisterLocalIdentity(&params, ACCOUNT_MODULE);
    InitModules();
    Uint8Buff authIdBuff = { (uint8_t *)TEST_AUTH_ID, strlen(TEST_AUTH_ID) };
    params.authId = &authIdBuff;
    (void)UnregisterLocalIdentity(&params, DAS_MODULE);
    CJson *in = CreateJson();
    (void)CheckMsgRepeatability(in, DAS_MODULE);
    (void)UnregisterLocalIdentity(&params, DAS_MODULE);
    (void)CheckMsgRepeatability(nullptr, DAS_MODULE);
    (void)CheckMsgRepeatability(in, DAS_MODULE);
    FreeJson(in);
    in = CreateJson();
    CJson *out = CreateJson();
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
    (void)AddAuthModulePlugin(&plugin);
    DelAuthModulePlugin(0);
    DestroyModules();
}

static void DevAuthInterfaceTestCase011()
{
    // mbedtls_ec_adapter.c interface test
    (void)MbedtlsHashToPoint25519(nullptr, nullptr);
    uint8_t hashVal[64] = { 0 };
    Uint8Buff hashBuff = { hashVal, 64 };
    (void)MbedtlsHashToPoint25519(&hashBuff, nullptr);
    uint8_t outEcPointVal[TEST_KEY_LEN_5] = { 0 };
    Uint8Buff outEcPointBuff = { outEcPointVal, TEST_KEY_LEN_5 };
    (void)MbedtlsHashToPoint25519(&hashBuff, &outEcPointBuff);
    uint8_t validHashVal[TEST_KEY_LEN_5] = { 0 };
    hashBuff.val = validHashVal;
    hashBuff.length = TEST_KEY_LEN_5;
    (void)MbedtlsHashToPoint25519(&hashBuff, &outEcPointBuff);
}

static void DevAuthInterfaceTestCase012()
{
    // account_task_main.c interface test
    int32_t taskId = 0;
    AccountTask *task = CreateAccountTaskT(&taskId, nullptr, nullptr);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, MEMBER_JOIN);
    task = CreateAccountTaskT(&taskId, in, nullptr);
    (void)AddIntToJson(in, FIELD_CREDENTIAL_TYPE, 0);
    task = CreateAccountTaskT(&taskId, in, nullptr);
    InitVersionInfos();
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    (void)AddIntToJson(in, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED);
    task = CreateAccountTaskT(&taskId, in, nullptr);
    CJson *out = CreateJson();
    (void)AddIntToJson(in, FIELD_IS_CLIENT, true);
    task = CreateAccountTaskT(&taskId, in, out);
    (void)AddIntToJson(in, FIELD_IS_CLIENT, false);
    task = CreateAccountTaskT(&taskId, in, out);
    DestroyVersionInfos();
    FreeJson(in);
    FreeJson(out);
}

static void DevAuthInterfaceTestCase013()
{
    // account_module.c interface test
    const AuthModuleBase *accountModule = GetAccountModule();
    (void)accountModule->init();
    bool isIgnored = accountModule->isMsgNeedIgnore(nullptr);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    isIgnored = accountModule->isMsgNeedIgnore(in);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, OP_BIND);
    isIgnored = accountModule->isMsgNeedIgnore(in);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, OP_UNBIND);
    isIgnored = accountModule->isMsgNeedIgnore(in);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    (void)AddIntToJson(in, FIELD_STEP, 1);
    isIgnored = accountModule->isMsgNeedIgnore(in);
    FreeJson(in);
    (void)accountModule->createTask(nullptr, nullptr, nullptr);
    int32_t taskId = 0;
    (void)accountModule->createTask(&taskId, nullptr, nullptr);
    in = CreateJson();
    (void)accountModule->createTask(&taskId, in, nullptr);
    CJson *out = CreateJson();
    (void)accountModule->createTask(&taskId, in, out);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    (void)AddIntToJson(in, FIELD_STEP, 0);
    (void)accountModule->createTask(&taskId, in, out);
    FreeJson(in);
    FreeJson(out);
    (void)accountModule->processTask(0, nullptr, nullptr, nullptr);
    accountModule->destroyTask(0);
    AccountMultiTaskManager *manager = GetAccountMultiTaskManager();
    (void)manager->addTaskToManager(nullptr);
    (void)manager->getTaskFromManager(1);
    accountModule->destroy();
}

static void DevAuthInterfaceTestCase014()
{
    // identical_account_group.c interface test
    (void)InitDatabase();
    (void)InitBroadcastManager();
    IdenticalAccountGroup *group = (IdenticalAccountGroup *)GetIdenticalAccountGroupInstance();
    (void)group->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    (void)group->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr);
    CJson *jsonParams = CreateJson();
    (void)group->delMultiMembersFromGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, jsonParams);
    (void)group->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    (void)group->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr);
    (void)group->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, jsonParams);
    (void)group->base.deleteGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    (void)group->base.deleteGroup(DEFAULT_OS_ACCOUNT, jsonParams, nullptr);
    char *returnJsonStr = nullptr;
    (void)group->base.deleteGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    (void)group->base.createGroup(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    (void)group->base.createGroup(DEFAULT_OS_ACCOUNT, jsonParams, nullptr);
    (void)group->base.createGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    (void)AddStringToJson(jsonParams, FIELD_APP_ID, TEST_APP_ID);
    (void)group->base.createGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    (void)AddStringToJson(jsonParams, FIELD_USER_ID, TEST_GROUP_ID);
    (void)group->base.createGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    (void)AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    (void)group->base.deleteGroup(DEFAULT_OS_ACCOUNT, jsonParams, &returnJsonStr);
    DestroyDatabase();
    DestroyBroadcastManager();
}

static void DevAuthInterfaceTestCase0141()
{
    // identical_account_group.c static interface test
    (void)InitDatabase();
    (void)InitBroadcastManager();
    (void)GenerateGroupParams(nullptr, nullptr, nullptr);
    (void)GenerateGroupId(nullptr, nullptr);
    (void)GenerateIdenticalGroupId(nullptr, nullptr);
    CJson *in = CreateJson();
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    (void)GenerateIdenticalGroupId(in, nullptr);
    FreeJson(in);
    DestroyDatabase();
    DestroyBroadcastManager();
}

static void DevAuthInterfaceTestCase0142()
{
    // identical_account_group.c static interface test
    (void)InitDatabase();
    (void)InitBroadcastManager();
    CJson *in = CreateJson();
    (void)ImportSelfToken(TEST_OS_ACCOUNT_ID, in);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    (void)ImportSelfToken(TEST_OS_ACCOUNT_ID, in);
    (void)DelSelfToken(TEST_OS_ACCOUNT_ID, nullptr);
    FreeJson(in);
    DestroyDatabase();
    DestroyBroadcastManager();
}

static void DevAuthInterfaceTestCase0143()
{
    // identical_account_group.c static interface test
    (void)InitDatabase();
    (void)InitBroadcastManager();
    CJson *in = CreateJson();
    (void)GenerateAddTokenParams(in, in);
    (void)CheckUserIdValid(TEST_OS_ACCOUNT_ID, in, in);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    (void)GenerateAddTokenParams(in, in);
    (void)CheckUserIdValid(TEST_OS_ACCOUNT_ID, in, in);
    (void)GenerateTrustedDevParams(nullptr, nullptr, nullptr);
    (void)AddStringToJson(in, FIELD_GROUP_ID, TEST_GROUP_ID);
    (void)CheckUserIdValid(TEST_OS_ACCOUNT_ID, in, in);

    FreeJson(in);
    DestroyDatabase();
    DestroyBroadcastManager();
}

static void DevAuthInterfaceTestCase0144()
{
    // identical_account_group.c static interface test
    (void)InitDatabase();
    (void)InitBroadcastManager();
    (void)CheckPeerDeviceNotSelf(nullptr);
    CJson *in = CreateJson();
    (void)AddDeviceAndToken(TEST_OS_ACCOUNT_ID, in, in);
    (void)DelPeerDevice(TEST_OS_ACCOUNT_ID, in, in, true);
    UpdateTrustedDeviceForMetaNode(TEST_OS_ACCOUNT_ID, nullptr, nullptr);

    (void)AddStringToJson(in, FIELD_GROUP_ID, TEST_GROUP_ID);
    (void)AddDeviceAndToken(TEST_OS_ACCOUNT_ID, in, in);
    UpdateTrustedDeviceForMetaNode(TEST_OS_ACCOUNT_ID, in, nullptr);

    (void)DelPeerDevice(TEST_OS_ACCOUNT_ID, in, in, true);
    FreeJson(in);
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

static void DevAuthInterfaceTestCase015()
{
    // broadcast_manager.c interface test
    (void)InitBroadcastManager();
    (void)AddListener(nullptr, nullptr);
    (void)AddListener(TEST_APP_ID, nullptr);
    DataChangeListener listener = { 0 };
    (void)AddListener(TEST_APP_ID, &listener);
    (void)RemoveListener(nullptr);
    (void)RemoveListener(TEST_APP_ID);
    const Broadcaster *broadcaster = GetBroadcaster();
    listener.onDeviceBound = OnDeviceBound;
    listener.onDeviceNotTrusted = OnDeviceNotTrusted;
    listener.onDeviceUnBound = OnDeviceUnBound;
    listener.onGroupCreated = OnGroupCreated;
    listener.onGroupDeleted = OnGroupDeleted;
    listener.onLastGroupDeleted = OnLastGroupDeleted;
    listener.onTrustedDeviceNumChanged = OnTrustedDeviceNumChanged;
    (void)AddListener(TEST_APP_ID, &listener);
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
    (void)RemoveListener(TEST_APP_ID);
    DestroyBroadcastManager();
}

static void DevAuthInterfaceTestCase016()
{
    // iso_protocol_common.c interface test
    (void)IsoServerGenSessionKeyAndCalToken(nullptr, nullptr, nullptr);
    IsoBaseParams *baseParams = (IsoBaseParams *)HcMalloc(sizeof(IsoBaseParams), 0);
    baseParams->loader = GetLoaderInstance();
    (void)IsoServerGenSessionKeyAndCalToken(baseParams, nullptr, nullptr);
    Uint8Buff tokenFromPeer = { 0 };
    (void)IsoServerGenSessionKeyAndCalToken(baseParams, &tokenFromPeer, nullptr);
    Uint8Buff tokenToPeer = { 0 };
    (void)IsoServerGenSessionKeyAndCalToken(baseParams, &tokenFromPeer, &tokenToPeer);
    (void)IsoServerGenRandomAndToken(nullptr, nullptr);
    (void)IsoServerGenRandomAndToken(baseParams, nullptr);
    (void)IsoClientGenSessionKey(nullptr, 0, nullptr, 0);
    (void)IsoClientGenSessionKey(baseParams, 0, nullptr, 0);
    uint8_t hmacVal[TEST_KEY_LEN_5] = { 0 };
    (void)IsoClientGenSessionKey(baseParams, 0, hmacVal, TEST_KEY_LEN_5);
    (void)IsoClientCheckAndGenToken(nullptr, nullptr, nullptr);
    (void)IsoClientCheckAndGenToken(baseParams, nullptr, nullptr);
    Uint8Buff peerToken = { 0 };
    (void)IsoClientCheckAndGenToken(baseParams, &peerToken, nullptr);
    Uint8Buff selfToken = { 0 };
    (void)IsoClientCheckAndGenToken(baseParams, &peerToken, &selfToken);
    (void)IsoClientGenRandom(nullptr);
    HcFree(baseParams);
}

static void DevAuthInterfaceTestCase0161()
{
    // iso_protocol_common.c static interface test
    (void)InitIsoBaseParams(nullptr, nullptr);
    CJson *in = CreateJson();
    (void)InitIsoBaseParams(in, nullptr);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase017()
{
    // das_lite_token_manager.c interface test
    const TokenManager *liteManager = GetLiteTokenManagerInstance();
    Uint8Buff authIdBuff = { (uint8_t *)TEST_AUTH_ID, strlen(TEST_AUTH_ID) };
    TokenManagerParams params = {
        .osAccountId = DEFAULT_OS_ACCOUNT,
        .peerOsAccountId = DEFAULT_OS_ACCOUNT,
        .pkgName = { (uint8_t *)TEST_APP_ID, HcStrlen(TEST_APP_ID) },
        .serviceType = { (uint8_t *)TEST_GROUP_ID, HcStrlen(TEST_GROUP_ID) },
        .authId = authIdBuff,
        .userType = 0,
        .isDirectAuthToken = false
    };
    (void)liteManager->unregisterLocalIdentity(&params);
    // das_standard_token_manager.c interface test
    const TokenManager *standardMgr = GetStandardTokenManagerInstance();
    params.pkgName.val = (uint8_t *)GROUP_MANAGER_PACKAGE_NAME;
    params.pkgName.length = HcStrlen(GROUP_MANAGER_PACKAGE_NAME);
    (void)standardMgr->unregisterLocalIdentity(&params);
    params.pkgName.val = (uint8_t *)TEST_APP_ID;
    params.pkgName.length = HcStrlen(TEST_APP_ID);
    (void)standardMgr->deletePeerAuthInfo(&params);
    PakeParams *pakeParams = (PakeParams *)HcMalloc(sizeof(PakeParams), 0);
    pakeParams->baseParams.loader = GetLoaderInstance();
    char appId[TEST_KEY_LEN_3] = TEST_APP_ID;
    char groupId[TEST_KEY_LEN_3] = TEST_GROUP_ID;
    pakeParams->packageName = appId;
    pakeParams->serviceType = groupId;
    pakeParams->baseParams.idSelf.val = (uint8_t *)TEST_AUTH_ID;
    pakeParams->baseParams.idSelf.length = strlen(TEST_AUTH_ID);
    pakeParams->isSelfFromUpgrade = true;
    pakeParams->baseParams.idPeer.val = (uint8_t *)TEST_AUTH_ID;
    pakeParams->baseParams.idPeer.length = strlen(TEST_AUTH_ID);
    (void)standardMgr->computeAndSavePsk(pakeParams);
    Uint8Buff returnPkBuff = { 0 };
    (void)standardMgr->getPublicKey(&params, &returnPkBuff);
    HcFree(pakeParams);
}

static void DevAuthInterfaceTestCase018()
{
    // key_manager.c interface test
    (void)GetDevicePubKey(DEFAULT_OS_ACCOUNT, nullptr);
    (void)DeletePseudonymPsk(DEFAULT_OS_ACCOUNT, nullptr);
}

static void DevAuthInterfaceTestCase019()
{
    // group_auth_data_operation.c interface test
    (void)InitDatabase();
    int32_t authForm = GroupTypeToAuthForm(ACROSS_ACCOUNT_AUTHORIZE_GROUP);
    authForm = GroupTypeToAuthForm(0);
    int32_t groupType = AuthFormToGroupType(AUTH_FORM_ACCOUNT_UNRELATED);
    groupType = AuthFormToGroupType(AUTH_FORM_ACROSS_ACCOUNT);
    groupType = AuthFormToGroupType(-1);
    (void)GaGetTrustedDeviceEntryById(DEFAULT_OS_ACCOUNT, nullptr, true, nullptr, nullptr);
    bool isAccessiblle = GaIsGroupAccessible(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    isAccessiblle = GaIsGroupAccessible(DEFAULT_OS_ACCOUNT, TEST_GROUP_ID, nullptr);
    isAccessiblle = GaIsGroupAccessible(DEFAULT_OS_ACCOUNT, TEST_GROUP_ID, TEST_APP_ID);
    DestroyDatabase();
}

static void DevAuthInterfaceTestCase020()
{
    // compatible_bind_sub_session_util.c interface test
    InformPeerProcessError(TEST_REQ_ID, nullptr, nullptr, -1);
    CJson *jsonParams = CreateJson();
    (void)AddStringToJson(jsonParams, FIELD_CHANNEL_ID, "0");
    InformPeerProcessError(TEST_REQ_ID, jsonParams, nullptr, -1);
    (void)AddStringToJson(jsonParams, FIELD_APP_ID, TEST_APP_ID);
    InformPeerProcessError(TEST_REQ_ID, jsonParams, nullptr, -1);
    FreeJson(jsonParams);
    (void)CombineConfirmData(MEMBER_JOIN, nullptr, nullptr);
    (void)CombineConfirmData(MEMBER_INVITE, nullptr, nullptr);
    // compatible_bind_sub_session.c interface test
    DestroyCompatibleBindSubSession(nullptr);
    (void)CreateServerBindSubSession(nullptr, nullptr, nullptr);
    jsonParams = CreateJson();
    (void)AddStringToJson(jsonParams, FIELD_REQUEST_ID, TEST_REQ_ID_STR);
    (void)CreateServerBindSubSession(jsonParams, nullptr, nullptr);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_OP, MEMBER_INVITE);
    (void)CreateServerBindSubSession(jsonParams, nullptr, nullptr);
    FreeJson(jsonParams);
    (void)CreateClientBindSubSession(nullptr, nullptr, nullptr);
    jsonParams = CreateJson();
    (void)AddStringToJson(jsonParams, FIELD_REQUEST_ID, TEST_REQ_ID_STR);
    (void)CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_OP, MEMBER_INVITE);
    (void)CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_OP, MEMBER_JOIN);
    (void)CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    (void)CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    (void)CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    (void)AddIntToJson(jsonParams, FIELD_GROUP_OP, MEMBER_DELETE);
    (void)CreateClientBindSubSession(jsonParams, nullptr, nullptr);
    FreeJson(jsonParams);
}

static void DevAuthInterfaceTestCase021()
{
    // compatible_auth_sub_session_common.c interface test
    NotifyPeerAuthError(nullptr, nullptr);
    (void)HandleAuthTaskStatus(nullptr, nullptr, IGNORE_MSG, true);
    (void)HandleAuthTaskStatus(nullptr, nullptr, CONTINUE, true);
    (void)HandleAuthTaskStatus(nullptr, nullptr, TEST_FAULT_STATUS, true);
    // compatible_auth_sub_session_util.c interface test
    int32_t authType = GetAuthType(AUTH_FORM_ACROSS_ACCOUNT);
    authType = GetAuthType(AUTH_FORM_INVALID_TYPE);
    CJson *confirmJsonParams = CreateJson();
    (void)AddIntToJson(confirmJsonParams, FIELD_OS_ACCOUNT_ID, INVALID_OS_ACCOUNT);
    (void)CombineAuthConfirmData(confirmJsonParams, nullptr);
    FreeJson(confirmJsonParams);
    int32_t moduleType = GetAuthModuleType(nullptr);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_INVALID_TYPE);
    moduleType = GetAuthModuleType(in);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase022()
{
    // account_unrelated_group_auth.c interface test
    BaseGroupAuth *groupAuth = GetAccountUnrelatedGroupAuth();
    groupAuth->onFinish(TEST_REQ_ID, nullptr, nullptr, nullptr);
    (void)groupAuth->getAuthParamsVecForServer(nullptr, nullptr);
}

static void DevAuthInterfaceTestCase023()
{
    // das_task_common.c interface test
    (void)GetAndCheckKeyLenOnServer(nullptr, 0);
    CJson *in = CreateJson();
    CJson *payload = CreateJson();
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    (void)GetAndCheckKeyLenOnServer(in, 0);
    (void)AddIntToJson(payload, FIELD_KEY_LENGTH, 1);
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    (void)GetAndCheckKeyLenOnServer(in, 0);
    FreeJson(payload);
    FreeJson(in);
    (void)GetAuthIdPeerFromPayload(nullptr, nullptr, nullptr);
    in = CreateJson();
    payload = CreateJson();
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    (void)GetAuthIdPeerFromPayload(in, nullptr, nullptr);
    FreeJson(payload);
    FreeJson(in);

    Uint8Buff authId = { nullptr, 0 };
    (void)GetAndCheckAuthIdPeer(nullptr, nullptr, nullptr);
    in = CreateJson();
    (void)GetAndCheckAuthIdPeer(in, &authId, &authId);
    payload = CreateJson();
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    (void)GetAndCheckAuthIdPeer(in, &authId, &authId);
    (void)AddStringToJson(payload, FIELD_PEER_AUTH_ID, "");
    (void)AddObjToJson(in, FIELD_PAYLOAD, payload);
    (void)GetAndCheckAuthIdPeer(in, &authId, &authId);
    FreeJson(payload);
    FreeJson(in);
    (void)GetIdPeer(nullptr, nullptr, nullptr, nullptr);
    in = CreateJson();
    (void)AddStringToJson(in, FIELD_PEER_AUTH_ID, "");
    (void)GetIdPeer(in, FIELD_PEER_AUTH_ID, nullptr, nullptr);
    FreeJson(in);
    (void)GeneratePseudonymPskAlias(nullptr, nullptr, nullptr);
}

static void DevAuthInterfaceTestCase024()
{
    // das_task_common.c interface test
    Uint8Buff serviceTypeBuff = { (uint8_t *)TEST_GROUP_ID, 0 };
    Uint8Buff authIdBuff = { (uint8_t *)TEST_AUTH_ID, 0 };
    uint8_t outKeyAliasVal[TEST_KEY_LEN_3] = { 0 };
    Uint8Buff outKeyAliasBuff = { outKeyAliasVal, 0 };
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    serviceTypeBuff.length = HcStrlen(TEST_GROUP_ID);
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    authIdBuff.length = HcStrlen(TEST_AUTH_ID);
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    outKeyAliasBuff.length = TEST_KEY_LEN_3;
    serviceTypeBuff.length = SERVICE_TYPE_MAX_LEN + 1;
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    serviceTypeBuff.length = HcStrlen(TEST_GROUP_ID);
    authIdBuff.length = AUTH_ID_MAX_LEN + 1;
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
    authIdBuff.length = HcStrlen(TEST_AUTH_ID);
    (void)GeneratePseudonymPskAlias(&serviceTypeBuff, &authIdBuff, &outKeyAliasBuff);
}

static void DevAuthInterfaceTestCase025()
{
    // das_version_util.c interface test
    VersionStruct version = { 0 };
    PakeAlgType type = GetSupportedPakeAlg(&version, PAKE_V2);
    type = GetSupportedPakeAlg(&version, ISO);
    ProtocolType protocolType = GetPrototolType(&version, CODE_NULL);
    version.first = 1;
    protocolType = GetPrototolType(&version, AUTHENTICATE);
    protocolType = GetPrototolType(&version, OP_BIND);
    VersionStruct versionSelf = { 0 };
    (void)NegotiateVersion(nullptr, &version, &versionSelf);
    version.first = 0;
    (void)NegotiateVersion(nullptr, &version, &versionSelf);
    (void)GetSingleVersionFromJson(nullptr, nullptr);
    CJson *jsonObj = CreateJson();
    (void)GetSingleVersionFromJson(jsonObj, nullptr);
    (void)GetSingleVersionFromJson(jsonObj, &version);
    (void)AddStringToJson(jsonObj, FIELD_GROUP_AND_MODULE_VERSION, TEST_REQ_ID_STR);
    (void)GetSingleVersionFromJson(jsonObj, &version);
    (void)AddStringToJson(jsonObj, FIELD_GROUP_AND_MODULE_VERSION, TEST_VERSION_ID);
    (void)GetSingleVersionFromJson(jsonObj, &version);
}

static void DevAuthInterfaceTestCase026()
{
    // pake_v1_protocol_common.c interface test
    DestroyPakeV1BaseParams(nullptr);
    (void)InitPakeV1BaseParams(DEFAULT_OS_ACCOUNT, nullptr);
    (void)ClientConfirmPakeV1Protocol(nullptr);
    PakeBaseParams *params = (PakeBaseParams *)HcMalloc(sizeof(PakeBaseParams), 0);
    params->loader = GetLoaderInstance();
    (void)ClientConfirmPakeV1Protocol(params);
    (void)ClientVerifyConfirmPakeV1Protocol(nullptr);
    (void)ClientVerifyConfirmPakeV1Protocol(params);
    (void)ServerResponsePakeV1Protocol(nullptr);
    (void)ServerResponsePakeV1Protocol(params);
    (void)ServerConfirmPakeV1Protocol(nullptr);
    (void)ServerConfirmPakeV1Protocol(params);
    HcFree(params);
}

static void DevAuthInterfaceTestCase027()
{
    // huks_adapter.c interface test
    const AlgLoader *loader = GetLoaderInstance();
    (void)loader->importSymmetricKey(nullptr, nullptr, KEY_PURPOSE_SIGN_VERIFY, nullptr);
    bool ret = loader->checkDlPublicKey(nullptr, nullptr);
    Uint8Buff key = { 0 };
    ret = loader->checkDlPublicKey(&key, nullptr);
    uint8_t keyVal[TEST_KEY_LEN_3] = { 0 };
    key.val = keyVal;
    key.length = TEST_KEY_LEN_3;
    ret = loader->checkDlPublicKey(&key, nullptr);
    ret = loader->checkDlPublicKey(&key, "TestPrimeHex");
    (void)loader->bigNumCompare(nullptr, nullptr);
    Uint8Buff aBuff = { 0 };
    Uint8Buff bBuff = { 0 };
    (void)loader->bigNumCompare(&aBuff, &bBuff);
    (void)loader->sign(nullptr, nullptr, ED25519, nullptr);
    (void)loader->generateKeyPair(ED25519, nullptr, nullptr);
    Uint8Buff outPrivKey = { 0 };
    (void)loader->generateKeyPair(ED25519, &outPrivKey, nullptr);
    uint8_t outPrivKeyVal[TEST_KEY_LEN_3] = { 0 };
    outPrivKey.val = outPrivKeyVal;
    (void)loader->generateKeyPair(ED25519, &outPrivKey, nullptr);
    outPrivKey.length = TEST_KEY_LEN_3;
    (void)loader->generateKeyPair(ED25519, &outPrivKey, nullptr);
    Uint8Buff outPubKey = { 0 };
    (void)loader->generateKeyPair(ED25519, &outPrivKey, &outPubKey);
    uint8_t outPubKeyVal[TEST_KEY_LEN_3] = { 0 };
    outPubKey.val = outPubKeyVal;
    (void)loader->generateKeyPair(ED25519, &outPrivKey, &outPubKey);
    outPubKey.length = TEST_KEY_LEN_4;
    (void)loader->generateKeyPair(ED25519, &outPrivKey, &outPubKey);
}

static void DevAuthInterfaceTestCase028()
{
    // dev_session_util.c interface test
    (void)AddPkInfoWithPdid(nullptr, nullptr, false, nullptr);
    CJson *context = CreateJson();
    (void)AddPkInfoWithPdid(context, nullptr, false, nullptr);
    CJson *credJson = CreateJson();
    (void)AddPkInfoWithPdid(context, credJson, false, nullptr);
    (void)AddPkInfoWithPdid(context, credJson, false, "TestRealPkInfo");
    CJson *realPkInfoJson = CreateJson();
    (void)AddStringToJson(realPkInfoJson, FIELD_USER_ID, TEST_GROUP_ID);
    (void)AddStringToJson(realPkInfoJson, FIELD_DEVICE_ID, TEST_AUTH_ID);
    char *realPkInfoStr = PackJsonToString(realPkInfoJson);
    FreeJson(realPkInfoJson);
    (void)AddPkInfoWithPdid(context, credJson, false, realPkInfoStr);
    FreeJsonString(realPkInfoStr);
    FreeJson(context);
    FreeJson(credJson);
    (void)GetRealPkInfoStr(DEFAULT_OS_ACCOUNT, nullptr, nullptr, nullptr);
    credJson = CreateJson();
    (void)AddStringToJson(credJson, FIELD_PK_INFO, "TestPkInfo");
    (void)GetRealPkInfoStr(DEFAULT_OS_ACCOUNT, credJson, nullptr, nullptr);
    CJson *pkInfoJson = CreateJson();
    (void)AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_GROUP_ID);
    (void)AddStringToJson(pkInfoJson, FIELD_DEVICE_ID, TEST_AUTH_ID);
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    (void)AddStringToJson(credJson, FIELD_PK_INFO, pkInfoStr);
    FreeJsonString(pkInfoStr);
    (void)GetRealPkInfoStr(DEFAULT_OS_ACCOUNT, credJson, nullptr, nullptr);
    FreeJson(credJson);
}

static void DevAuthInterfaceTestCase0281()
{
    // dev_session_util.c static interface test
    CJson *in = CreateJson();
    TrustedDeviceEntry *entry = GetPeerDeviceEntryByContext(TEST_OS_ACCOUNT_ID, in);
    (void)AddStringToJson(in, FIELD_GROUP_ID, TEST_GROUP_ID);
    entry = GetPeerDeviceEntryByContext(TEST_OS_ACCOUNT_ID, in);
    (void)AddStringToJson(in, FIELD_PEER_AUTH_ID, TEST_AUTH_ID);
    entry = GetPeerDeviceEntryByContext(TEST_OS_ACCOUNT_ID, in);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase0282()
{
    // dev_session_util.c static interface test
    CJson *in = CreateJson();
    (void)SetPeerAuthIdByDb(in, TEST_GROUP_ID);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    (void)SetPeerAuthIdByDb(in, TEST_GROUP_ID);
    (void)AddStringToJson(in, FIELD_PEER_UDID, TEST_AUTH_ID);
    (void)SetPeerAuthIdByDb(in, TEST_GROUP_ID);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase0283()
{
    // dev_session_util.c static interface test
    CJson *in = CreateJson();
    CJson *inputData = CreateJson();
    (void)AddStringToJson(in, FIELD_PEER_AUTH_ID, TEST_AUTH_ID);
    (void)FillPeerAuthIdIfNeeded(true, in, inputData);
    FreeJson(in);
    FreeJson(inputData);
}

static void DevAuthInterfaceTestCase0284()
{
    // dev_session_util.c static interface test
    (void)BuildPeerCertInfo(nullptr, nullptr, 0, 0, nullptr);
    (void)BuildPeerCertInfo(TEST_PK_INFO, nullptr, 0, 0, nullptr);
    (void)BuildPeerCertInfo(TEST_PK_INFO, TEST_PK_INFO_SIGN, 0, 0, nullptr);
}

static void DevAuthInterfaceTestCase0285()
{
    // dev_session_util.c static interface test
    CJson *in = CreateJson();
    (void)GetPeerCertInfo(nullptr, nullptr, nullptr);
    (void)GetPeerCertInfo(in, nullptr, nullptr);
    (void)GetPeerCertInfo(in, in, nullptr);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    (void)GetPeerCertInfo(in, in, &certInfo);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase0286()
{
    // dev_session_util.c static interface test
    CJson *in = CreateJson();
    (void)AddMsgToSessionMsg(0, nullptr, nullptr);
    (void)AddMsgToSessionMsg(0, in, nullptr);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase0287()
{
    // dev_session_util.c static interface test
    (void)IsPeerSameUserId(TEST_OS_ACCOUNT_ID, nullptr);
    (void)GeneratePeerInfoJson(nullptr, nullptr);
    CJson *in = CreateJson();
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    (void)GeneratePeerInfoJson(in, nullptr);
    (void)SetPeerAuthIdByCredAuthInfo(nullptr);
    CJson *credDataJson = CreateJsonFromString(CRED_DATA);
    (void)AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credDataJson);
    FreeJson(credDataJson);
    (void)SetPeerAuthIdByCredAuthInfo(in);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase0288()
{
    // dev_session_util.c static interface test
    CJson *in = CreateJson();
    (void)GetPdidIndexByISInfo(in, nullptr);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    (void)GetPdidIndexByISInfo(in, nullptr);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase0289()
{
    // dev_session_util.c static interface test
    CJson *in = CreateJson();
    (void)BuildRealPkInfoJson(nullptr, nullptr, nullptr);
    (void)AddStringToJson(in, FIELD_DEVICE_PK, TEST_DEVICE_PK);
    (void)BuildRealPkInfoJson(in, nullptr, nullptr);
    (void)AddStringToJson(in, FIELD_VERSION, TEST_VERSION);
    (void)BuildRealPkInfoJson(in, nullptr, nullptr);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    (void)BuildRealPkInfoJson(in, in, nullptr);
    (void)AddStringToJson(in, FIELD_DEVICE_ID, TEST_DEVICE_ID);
    (void)BuildRealPkInfoJson(in, in, nullptr);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase029()
{
    // pake_v2_protocol_common.c interface test
    DestroyPakeV2BaseParams(nullptr);
    (void)ServerConfirmPakeV2Protocol(nullptr);
    PakeBaseParams *params = (PakeBaseParams *)HcMalloc(sizeof(PakeBaseParams), 0);
    params->loader = GetLoaderInstance();
    (void)ServerConfirmPakeV2Protocol(params);
    (void)ServerResponsePakeV2Protocol(nullptr);
    (void)ServerResponsePakeV2Protocol(params);
    (void)ClientVerifyConfirmPakeV2Protocol(nullptr);
    (void)ClientVerifyConfirmPakeV2Protocol(params);
    (void)ClientConfirmPakeV2Protocol(nullptr);
    (void)ClientConfirmPakeV2Protocol(params);
    (void)InitPakeV2BaseParams(DEFAULT_OS_ACCOUNT, nullptr);
    HcFree(params);
}

static void DevAuthInterfaceTestCase030()
{
    // iso_task_common.c interface test
    IsoParams *params = (IsoParams *)HcMalloc(sizeof(IsoParams), 0);
    (void)GeneratePsk(nullptr, params);
    (void)GenerateKeyAliasInIso(nullptr, nullptr, 0, false);
    (void)GenerateKeyAliasInIso(params, nullptr, 0, false);
    uint8_t keyAliasVal[TEST_KEY_LEN_3] = { 0 };
    (void)GenerateKeyAliasInIso(params, keyAliasVal, 0, false);
    params->packageName = (char *)HcMalloc(HcStrlen(TEST_APP_ID) + 1, 0);
    (void)memcpy_s(params->packageName, HcStrlen(TEST_APP_ID) + 1, TEST_APP_ID, HcStrlen(TEST_APP_ID));
    params->serviceType = (char *)HcMalloc(HcStrlen(TEST_GROUP_ID) + 1, 0);
    (void)memcpy_s(params->serviceType, HcStrlen(TEST_GROUP_ID) + 1, TEST_GROUP_ID, HcStrlen(TEST_GROUP_ID));
    (void)GenerateKeyAliasInIso(params, keyAliasVal, TEST_KEY_LEN_3, false);
    (void)InitIsoParams(params, nullptr);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, CODE_NULL);
    (void)InitIsoParams(params, in);
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, AUTHENTICATE);
    (void)InitIsoParams(params, in);
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
    (void)InitIsoParams(params, in);
    DestroyIsoParams(nullptr);
    HcFree(params);
}

static void DevAuthInterfaceTestCase031()
{
    // das_task_common.c interface test
    (void)ServerProtocolMessageOut(nullptr, 0, 0);
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    (void)ServerProtocolMessageOut(out, CODE_NULL, 0);
    (void)ClientProtocolMessageOut(nullptr, 0, 0);
    (void)ClientProtocolMessageOut(out, CODE_NULL, 0);
    FreeJson(sendToPeer);
    FreeJson(out);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_MESSAGE, ERR_MESSAGE);
    (void)ProtocolMessageIn(in);
    FreeJson(in);
}

static void DevAuthInterfaceTestCase032()
{
    // dev_session_util.c interface test
    (void)CheckPeerPkInfoForPdid(nullptr, nullptr);
    CJson *context = CreateJson();
    (void)AddIntToJson(context, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)CheckPeerPkInfoForPdid(context, nullptr);
    CJson *inputDataJson = CreateJson();
    (void)AddStringToJson(inputDataJson, FIELD_PK_INFO, "TestPkInfo");
    (void)CheckPeerPkInfoForPdid(context, inputDataJson);
    CJson *pkInfoJson = CreateJson();
    (void)AddStringToJson(pkInfoJson, FIELD_PSEUDONYM_ID, "TestPseudonymId");
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    (void)AddStringToJson(inputDataJson, FIELD_PK_INFO, pkInfoStr);
    FreeJsonString(pkInfoStr);
    (void)CheckPeerPkInfoForPdid(context, inputDataJson);
    FreeJson(context);
    FreeJson(inputDataJson);
    (void)SetPeerInfoToContext(nullptr, false, nullptr);
    inputDataJson = CreateJson();
    (void)AddStringToJson(inputDataJson, FIELD_PK_INFO, "TestPkInfo");
    (void)SetPeerInfoToContext(nullptr, false, inputDataJson);
    pkInfoJson = CreateJson();
    pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    (void)AddStringToJson(inputDataJson, FIELD_PK_INFO, pkInfoStr);
    FreeJsonString(pkInfoStr);
    (void)SetPeerInfoToContext(nullptr, false, inputDataJson);
    FreeJson(inputDataJson);
}

static void DevAuthInterfaceTestCase0321()
{
    // dev_session_util.c interface test
    (void)GetSelfUserId(DEFAULT_OS_ACCOUNT, nullptr, TEST_LEN);
    char userId[TEST_LEN];
    (void)GetSelfUserId(DEFAULT_OS_ACCOUNT, userId, TEST_LEN);
}

static void DevAuthInterfaceTestCase033()
{
    // huks_adapter.c interface test
    const AlgLoader *loader = GetLoaderInstance();
    (void)loader->agreeSharedSecretWithStorage(nullptr, nullptr, X25519, 0, nullptr);
    (void)loader->getKeyExtInfo(nullptr, nullptr);
    KeyParams keyParams = { { nullptr, 0, true }, true, DEFAULT_OS_ACCOUNT };
    (void)loader->getKeyExtInfo(&keyParams, nullptr);
    uint8_t keyAliasVal[TEST_KEY_LEN_3] = { 0 };
    keyParams.keyBuff.key = keyAliasVal;
    keyParams.keyBuff.keyLen = TEST_KEY_LEN_3;
    (void)loader->getKeyExtInfo(&keyParams, nullptr);
    Uint8Buff outExtInfo = { 0 };
    (void)loader->getKeyExtInfo(&keyParams, &outExtInfo);
    keyParams.isDeStorage = false;
    (void)loader->getKeyExtInfo(&keyParams, &outExtInfo);
    (void)loader->computePseudonymPsk(nullptr, nullptr, nullptr, nullptr);
    KeyParams params = { { 0 }, false, DEFAULT_OS_ACCOUNT };
    uint8_t keyValue[TEST_KEY_LEN_3] = { 0 };
    params.keyBuff.key = keyValue;
    params.keyBuff.keyLen = TEST_KEY_LEN_3;
    params.keyBuff.isAlias = true;
    params.isDeStorage = true;
    (void)loader->computePseudonymPsk(&params, nullptr, nullptr, nullptr);
    uint8_t pskAliasVal[TEST_KEY_LEN_3] = { 0 };
    Uint8Buff pskAlias = { pskAliasVal, TEST_KEY_LEN_3 };
    uint8_t outPskVal[TEST_KEY_LEN_5] = { 0 };
    Uint8Buff outPsk = { outPskVal, TEST_KEY_LEN_5 };
    (void)loader->computePseudonymPsk(&params, &pskAlias, nullptr, &outPsk);
    Uint8Buff extInfo = { 0 };
    (void)loader->computePseudonymPsk(&params, &pskAlias, &extInfo, &outPsk);
    (void)loader->computeHkdf(nullptr, nullptr, nullptr, nullptr);
    (void)loader->computeHmacWithThreeStage(nullptr, nullptr, nullptr);
}

static void DevAuthInterfaceTestCase034()
{
    // account_task_manager.c interface test
    DestroyAccountTaskManager();
    (void)HasAccountPlugin();
    (void)ExecuteAccountAuthCmd(DEFAULT_OS_ACCOUNT, IMPORT_SELF_CREDENTIAL, nullptr, nullptr);
    int32_t sessionId = 0;
    (void)CreateAccountAuthSession(&sessionId, nullptr, nullptr);
    (void)ProcessAccountAuthSession(&sessionId, nullptr, nullptr, nullptr);
    (void)DestroyAccountAuthSession(sessionId);
    (void)InitAccountTaskManager();
    (void)InitAccountTaskManager();
    (void)ExecuteAccountAuthCmd(DEFAULT_OS_ACCOUNT, IMPORT_SELF_CREDENTIAL, nullptr, nullptr);
    (void)CreateAccountAuthSession(&sessionId, nullptr, nullptr);
    (void)ProcessAccountAuthSession(&sessionId, nullptr, nullptr, nullptr);
    (void)DestroyAccountAuthSession(sessionId);
    DestroyAccountTaskManager();
}

static void DevAuthInterfaceTestCase035()
{
    Uint8Buff pkgNameBuff = { (uint8_t *)TEST_APP_ID, 0 };
    Uint8Buff serviceTypeBuff = { (uint8_t *)TEST_GROUP_ID, HcStrlen(TEST_GROUP_ID) };
    Uint8Buff authIdBuff = { (uint8_t *)TEST_AUTH_ID, HcStrlen(TEST_AUTH_ID) };
    uint8_t outKeyAliasVal[TEST_KEY_LEN_3] = { 0 };
    Uint8Buff outKeyAliasBuff = { outKeyAliasVal, TEST_KEY_LEN_3 };
    TokenManagerParams tokenParams = { 0 };
    tokenParams.pkgName = pkgNameBuff;
    tokenParams.serviceType = serviceTypeBuff;
    tokenParams.userType = KEY_ALIAS_ACCESSOR_PK;
    tokenParams.authId = authIdBuff;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    tokenParams.pkgName.length = HcStrlen(TEST_APP_ID);
    tokenParams.serviceType.length = 0;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    tokenParams.serviceType.length = HcStrlen(TEST_GROUP_ID);
    tokenParams.authId.length = 0;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    tokenParams.authId.length = HcStrlen(TEST_AUTH_ID);
    outKeyAliasBuff.length = 0;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    outKeyAliasBuff.length = TEST_KEY_LEN_3;
    tokenParams.pkgName.length = PACKAGE_NAME_MAX_LEN + 1;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    tokenParams.pkgName.length = HcStrlen(TEST_APP_ID);
    tokenParams.serviceType.length = SERVICE_TYPE_MAX_LEN + 1;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    tokenParams.serviceType.length = HcStrlen(TEST_GROUP_ID);
    tokenParams.authId.length = AUTH_ID_MAX_LEN + 1;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    tokenParams.authId.length = HcStrlen(TEST_AUTH_ID);
    tokenParams.userType = KEY_ALIAS_TYPE_END;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    tokenParams.userType = KEY_ALIAS_PSK;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
    tokenParams.userType = KEY_ALIAS_AUTH_TOKEN;
    (void)GenerateKeyAlias(&tokenParams, &outKeyAliasBuff);
}

static void DevAuthInterfaceTestCase036()
{
    (void)InitDeviceAuthService();
    const AccountVerifier *verifier = GetAccountVerifierInstance();
    (void)verifier->getClientSharedKey(nullptr, nullptr, nullptr, nullptr);
    (void)verifier->getClientSharedKey(TEST_SERVER_PK, nullptr, nullptr, nullptr);
    (void)verifier->getClientSharedKey(TEST_SERVER_PK, TEST_APP_ID, nullptr, nullptr);
    DataBuff sharedKeyBuff = { nullptr, 0 };
    (void)verifier->getClientSharedKey(TEST_SERVER_PK, TEST_APP_ID, &sharedKeyBuff, nullptr);
    DataBuff randomBuff = { nullptr, 0 };
    (void)verifier->getClientSharedKey(TEST_SERVER_PK, TEST_APP_ID, &sharedKeyBuff, &randomBuff);
    (void)verifier->getServerSharedKey(nullptr, nullptr, nullptr, nullptr);
    (void)verifier->getServerSharedKey(TEST_CLIENT_PK, nullptr, nullptr, nullptr);
    (void)verifier->getServerSharedKey(TEST_CLIENT_PK, TEST_APP_ID, nullptr, nullptr);
    (void)verifier->getServerSharedKey(TEST_CLIENT_PK, TEST_APP_ID, &randomBuff, nullptr);
    uint8_t randomVal[TEST_RANDOM_LEN] = { 0 };
    randomBuff.data = randomVal;
    (void)verifier->getServerSharedKey(TEST_CLIENT_PK, TEST_APP_ID, &randomBuff, nullptr);
    (void)verifier->getServerSharedKey(TEST_CLIENT_PK, TEST_APP_ID, &randomBuff, &sharedKeyBuff);
    randomBuff.length = TEST_RANDOM_LEN;
    (void)verifier->getServerSharedKey(TEST_CLIENT_PK, TEST_APP_ID, &randomBuff, &sharedKeyBuff);
    verifier->destroyDataBuff(nullptr);
    verifier->destroyDataBuff(&sharedKeyBuff);
    DestroyDeviceAuthService();
}

static void DevAuthInterfaceTestCasePart1()
{
    (void)DevAuthInterfaceTestCase001();
    (void)DevAuthInterfaceTestCase002();
    (void)DevAuthInterfaceTestCase003();
    (void)DevAuthInterfaceTestCase004();
    (void)DevAuthInterfaceTestCase0041();
    (void)DevAuthInterfaceTestCase0042();
    (void)DevAuthInterfaceTestCase0043();
    (void)DevAuthInterfaceTestCase0044();
    (void)DevAuthInterfaceTestCase0045();
    (void)DevAuthInterfaceTestCase005();
    (void)DevAuthInterfaceTestCase006();
    (void)DevAuthInterfaceTestCase007();
    (void)DevAuthInterfaceTestCase008();
    (void)DevAuthInterfaceTestCase009();
    (void)DevAuthInterfaceTestCase010();
    (void)DevAuthInterfaceTestCase011();
    (void)DevAuthInterfaceTestCase012();
    (void)DevAuthInterfaceTestCase013();
    (void)DevAuthInterfaceTestCase014();
    (void)DevAuthInterfaceTestCase0141();
    (void)DevAuthInterfaceTestCase0142();
    (void)DevAuthInterfaceTestCase0143();
    (void)DevAuthInterfaceTestCase0144();
    (void)DevAuthInterfaceTestCase015();
    (void)DevAuthInterfaceTestCase016();
    (void)DevAuthInterfaceTestCase0161();
    (void)DevAuthInterfaceTestCase017();
}

static void DevAuthInterfaceTestCasePart2()
{
    (void)DevAuthInterfaceTestCase018();
    (void)DevAuthInterfaceTestCase019();
    (void)DevAuthInterfaceTestCase020();
    (void)DevAuthInterfaceTestCase021();
    (void)DevAuthInterfaceTestCase022();
    (void)DevAuthInterfaceTestCase023();
    (void)DevAuthInterfaceTestCase024();
    (void)DevAuthInterfaceTestCase025();
    (void)DevAuthInterfaceTestCase026();
    (void)DevAuthInterfaceTestCase027();
    (void)DevAuthInterfaceTestCase028();
    (void)DevAuthInterfaceTestCase0281();
    (void)DevAuthInterfaceTestCase0282();
    (void)DevAuthInterfaceTestCase0283();
    (void)DevAuthInterfaceTestCase0284();
    (void)DevAuthInterfaceTestCase0285();
    (void)DevAuthInterfaceTestCase0286();
    (void)DevAuthInterfaceTestCase0287();
    (void)DevAuthInterfaceTestCase0288();
    (void)DevAuthInterfaceTestCase0289();
    (void)DevAuthInterfaceTestCase029();
    (void)DevAuthInterfaceTestCase030();
    (void)DevAuthInterfaceTestCase031();
    (void)DevAuthInterfaceTestCase032();
    (void)DevAuthInterfaceTestCase0321();
    (void)DevAuthInterfaceTestCase033();
    (void)DevAuthInterfaceTestCase034();
    (void)DevAuthInterfaceTestCase035();
    (void)DevAuthInterfaceTestCase036();
}

bool FuzzDoDevAuthInterfaceFuzz(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    DevAuthInterfaceTestCasePart1();
    DevAuthInterfaceTestCasePart2();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoDevAuthInterfaceFuzz(data, size);
    return 0;
}

