/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "deviceauth_standard_test.h"
#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>
#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "device_auth_ext.h"
#include "hc_dev_info_mock.h"
#include "json_utils_mock.h"
#include "json_utils.h"
#include "protocol_task_main_mock.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_REQ_ID 123
#define TEST_REQ_ID2 321
#define TEST_REQ_ID3 132
#define TEST_REQ_ID4 213
#define TEST_APP_ID "TestAppId"
#define TEST_APP_ID2 "TestAppId2"
#define TEST_GROUP_NAME "TestGroup"
#define TEST_AUTH_ID "TestAuthId"
#define TEST_AUTH_ID2 "TestAuthId2"
#define TEST_AUTH_ID3 "TestAuthId3"
#define TEST_UDID "TestUdid"
#define TEST_UDID2 "TestUdid2"
#define TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define TEST_USER_ID_AUTH "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4"
#define TEST_USER_ID "1234ABCD"
#define TEST_USER_ID2 "DCBA4321"
#define TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define TEST_GROUP_ID2 "F2AA208B1E010542B20A34B03B4B6289EA7C7F6DFE97DA2E370348B826682D3D"
#define TEST_GROUP_ID3 "1234ABCD"
#define TEST_GROUP_ID4 "6B7B805962B8EB8275D73128BFDAA7ECD755A2EC304E36543941874A277FA75F"
#define TEST_AUTH_CODE "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b"
#define TEST_AUTH_CODE2 "2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335"
#define TEST_AUTH_CODE3 "1234567812345678123456781234567812345678123456781234567812345678"
#define TEST_AUTH_TOKEN3 "10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92"
#define TEST_QUERY_PARAMS "bac"
#define TEST_PIN_CODE "123456"
#define TEST_GROUP_DATA_PATH "/data/service/el1/public/deviceauthMock"
#define TEST_HKS_MAIN_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
#define TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN 32
#define TEST_DEV_AUTH_SLEEP_TIME 50000
#define TEST_DEV_AUTH_SLEEP_TIME2 60000
static const int32_t TEST_AUTH_OS_ACCOUNT_ID = 100;
static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;
static const char *CREATE_PARAMS = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
    "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
static const char *CREATE_PARAMS2 = "{\"groupName\":\"TestPrivateGroup\",\"deviceId\":\"TestAuth"
    "Id\",\"groupType\":256,\"groupVisibility\":0,\"userType\":0,\"expireTime\":-1}";
static const char *CREATE_PARAMS3 = "{\"groupType\":1282,\"userId\":\"1234ABCD\",\"peerUserId\":\"DCBA4321\"}";
static const char *GET_REG_INFO_PARAMS =
    "{\"version\":\"1.0.0\",\"deviceId\":\"TestAuthId\",\"userId\":\"1234ABCD\"}";

enum AsyncStatus {
    ASYNC_STATUS_WAITING = 0,
    ASYNC_STATUS_TRANSMIT = 1,
    ASYNC_STATUS_FINISH = 2,
    ASYNC_STATUS_ERROR = 3
};

static AsyncStatus volatile g_asyncStatus;
static uint32_t g_transmitDataMaxLen = 2048;
static uint8_t g_transmitData[2048] = { 0 };
static uint32_t g_transmitDataLen = 0;

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    if (memcpy_s(g_transmitData, g_transmitDataMaxLen, data, dataLen) != EOK) {
        return false;
    }
    g_transmitDataLen = dataLen;
    g_asyncStatus = ASYNC_STATUS_TRANSMIT;
    return true;
}

static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
    return;
}

static void OnFinish(int64_t requestId, int operationCode, const char *authReturn)
{
    g_asyncStatus = ASYNC_STATUS_FINISH;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    g_asyncStatus = ASYNC_STATUS_ERROR;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char* reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static DeviceAuthCallback g_gmCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest
};

static void RemoveDir(const char *path)
{
    char strBuf[TEST_DEV_AUTH_BUFFER_SIZE] = {0};
    if (path == nullptr) {
        return;
    }
    if (sprintf_s(strBuf, sizeof(strBuf) - 1, "rm -rf %s", path) < 0) {
        return;
    }
    system(strBuf);
}

static void DeleteDatabase()
{
    RemoveDir(TEST_GROUP_DATA_PATH);
    RemoveDir(TEST_HKS_MAIN_DATA_PATH);
}

static bool GenerateTempKeyPair(Uint8Buff *keyAlias)
{
    int ret = GetLoaderInstance()->checkKeyExist(keyAlias, false, DEFAULT_OS_ACCOUNT);
    if (ret != HC_SUCCESS) {
        printf("Key pair not exist, start to generate\n");
        int32_t authId = 0;
        Uint8Buff authIdBuff = { reinterpret_cast<uint8_t *>(&authId), sizeof(int32_t)};
        ExtraInfo extInfo = {authIdBuff, -1, -1};
        KeyParams keyParams = { { keyAlias->val, keyAlias->length, true }, false, DEFAULT_OS_ACCOUNT };
        ret = GetLoaderInstance()->generateKeyPairWithStorage(&keyParams, TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN, P256,
            KEY_PURPOSE_SIGN_VERIFY, &extInfo);
    } else {
        printf("Server key pair already exists\n");
    }

    if (ret != HC_SUCCESS) {
        printf("Generate key pair failed\n");
        return false;
    } else {
        printf("Generate key pair for server success\n");
    }
    return true;
}

static CJson *GetAsyCredentialJson(string registerInfo)
{
    uint8_t keyAliasValue[] = "TestServerKeyPair";
    int32_t keyAliasLen = 18;
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = keyAliasLen
    };
    if (!GenerateTempKeyPair(&keyAlias)) {
        return nullptr;
    }
    uint8_t *serverPkVal = reinterpret_cast<uint8_t *>(HcMalloc(SERVER_PK_SIZE, 0));
    Uint8Buff serverPk = {
        .val = serverPkVal,
        .length = SERVER_PK_SIZE
    };

    KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, false, DEFAULT_OS_ACCOUNT };
    int32_t ret = GetLoaderInstance()->exportPublicKey(&keyAliasParams, &serverPk);
    if (ret != HC_SUCCESS) {
        printf("export PublicKey failed\n");
        HcFree(serverPkVal);
        return nullptr;
    }

    Uint8Buff messageBuff = {
        .val = reinterpret_cast<uint8_t *>(const_cast<char *>(registerInfo.c_str())),
        .length = registerInfo.length() + 1
    };
    uint8_t *signatureValue = reinterpret_cast<uint8_t *>(HcMalloc(SIGNATURE_SIZE, 0));
    Uint8Buff signature = {
        .val = signatureValue,
        .length = SIGNATURE_SIZE
    };
    ret = GetLoaderInstance()->sign(&keyAliasParams, &messageBuff, P256, &signature);
    if (ret != HC_SUCCESS) {
        printf("Sign pkInfo failed.\n");
        HcFree(serverPkVal);
        HcFree(signatureValue);
        return nullptr;
    }

    CJson *pkInfoJson = CreateJsonFromString(registerInfo.c_str());
    CJson *credentialJson = CreateJson();
    (void)AddIntToJson(credentialJson, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED);
    (void)AddByteToJson(credentialJson, FIELD_SERVER_PK, serverPkVal, serverPk.length);
    (void)AddByteToJson(credentialJson, FIELD_PK_INFO_SIGNATURE, signatureValue, signature.length);
    (void)AddObjToJson(credentialJson, FIELD_PK_INFO, pkInfoJson);
    FreeJson(pkInfoJson);
    return credentialJson;
}

static void CreateDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId, const char *createParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
}

static void CreateDemoIdenticalAccountGroup()
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(GET_REG_INFO_PARAMS, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    string registerInfo(returnData);

    CJson *credJson = GetAsyCredentialJson(registerInfo);
    ASSERT_NE(credJson, nullptr);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, TEST_USER_ID);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    gm->destroyInfo(&returnData);
    ASSERT_NE(jsonStr, nullptr);
    ret = gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
}

static void CreateDemoAcrossAccountGroup(int32_t osAccountId, int64_t reqId, const char *appId,
    const char *createParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
}

class InitDeviceAuthServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void InitDeviceAuthServiceTest::SetUpTestCase() {}
void InitDeviceAuthServiceTest::TearDownTestCase() {}
void InitDeviceAuthServiceTest::SetUp() {}
void InitDeviceAuthServiceTest::TearDown() {}

HWTEST_F(InitDeviceAuthServiceTest, InitDeviceAuthServiceTest001, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

class DestroyDeviceAuthServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DestroyDeviceAuthServiceTest::SetUpTestCase() {}
void DestroyDeviceAuthServiceTest::TearDownTestCase() {}
void DestroyDeviceAuthServiceTest::SetUp() {}
void DestroyDeviceAuthServiceTest::TearDown() {}

HWTEST_F(DestroyDeviceAuthServiceTest, DestroyDeviceAuthServiceTest001, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
    DestroyDeviceAuthService();
}

class GetGmInstanceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GetGmInstanceTest::SetUpTestCase() {}
void GetGmInstanceTest::TearDownTestCase() {}

void GetGmInstanceTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GetGmInstanceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GetGmInstanceTest, GetGmInstanceTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
}

class GetGaInstanceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GetGaInstanceTest::SetUpTestCase() {}
void GetGaInstanceTest::TearDownTestCase() {}

void GetGaInstanceTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GetGaInstanceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GetGaInstanceTest, GetGaInstanceTest001, TestSize.Level0)
{
    const GroupAuthManager *ga = GetGaInstance();
    EXPECT_NE(ga, nullptr);
}

class GmRegCallbackTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmRegCallbackTest::SetUpTestCase() {}
void GmRegCallbackTest::TearDownTestCase() {}

void GmRegCallbackTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmRegCallbackTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmRegCallbackTest, GmRegCallbackTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    DeviceAuthCallback callback;
    int32_t ret = gm->regCallback(TEST_APP_ID, &callback);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmRegCallbackTest, GmRegCallbackTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    DeviceAuthCallback callback;
    int32_t ret = gm->regCallback(TEST_APP_ID, &callback);
    ASSERT_EQ(ret, HC_SUCCESS);
    DeviceAuthCallback callback2;
    ret = gm->regCallback(TEST_APP_ID, &callback2);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmRegCallbackTest, GmRegCallbackTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    DeviceAuthCallback callback;
    int32_t ret = gm->regCallback(nullptr, &callback);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmRegCallbackTest, GmRegCallbackTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

class GmUnRegCallbackTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmUnRegCallbackTest::SetUpTestCase() {}
void GmUnRegCallbackTest::TearDownTestCase() {}

void GmUnRegCallbackTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmUnRegCallbackTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmUnRegCallbackTest, GmUnRegCallbackTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    DeviceAuthCallback callback;
    int32_t ret = gm->regCallback(TEST_APP_ID, &callback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->unRegCallback(TEST_APP_ID);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmUnRegCallbackTest, GmUnRegCallbackTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->unRegCallback(TEST_APP_ID);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmUnRegCallbackTest, GmUnRegCallbackTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->unRegCallback(nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

class GmRegDataChangeListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmRegDataChangeListenerTest::SetUpTestCase() {}
void GmRegDataChangeListenerTest::TearDownTestCase() {}

void GmRegDataChangeListenerTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmRegDataChangeListenerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmRegDataChangeListenerTest, GmRegDataChangeListenerTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    DataChangeListener listener;
    int32_t ret = gm->regDataChangeListener(TEST_APP_ID, &listener);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmRegDataChangeListenerTest, GmRegDataChangeListenerTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    DataChangeListener listener;
    int32_t ret = gm->regDataChangeListener(TEST_APP_ID, &listener);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->regDataChangeListener(TEST_APP_ID, &listener);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmRegDataChangeListenerTest, GmRegDataChangeListenerTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    DataChangeListener listener;
    int32_t ret = gm->regDataChangeListener(nullptr, &listener);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmRegDataChangeListenerTest, GmRegDataChangeListenerTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regDataChangeListener(TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

class GmUnRegDataChangeListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmUnRegDataChangeListenerTest::SetUpTestCase() {}
void GmUnRegDataChangeListenerTest::TearDownTestCase() {}

void GmUnRegDataChangeListenerTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmUnRegDataChangeListenerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmUnRegDataChangeListenerTest, GmUnRegDataChangeListenerTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    DataChangeListener listener;
    int32_t ret = gm->regDataChangeListener(TEST_APP_ID, &listener);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->unRegDataChangeListener(TEST_APP_ID);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmUnRegDataChangeListenerTest, GmUnRegDataChangeListenerTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->unRegDataChangeListener(TEST_APP_ID);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmUnRegDataChangeListenerTest, GmUnRegDataChangeListenerTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->unRegDataChangeListener(nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

class GmCreateGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmCreateGroupTest::SetUpTestCase() {}
void GmCreateGroupTest::TearDownTestCase() {}

void GmCreateGroupTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmCreateGroupTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest101, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, nullptr, CREATE_PARAMS);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest102, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest103, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest104, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest105, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest106, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest107, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"group"
        "Type\":256,\"userType\":0,\"expireTime\":-1}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest108, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"expireTime\":-1}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest109, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest110, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    int32_t invalidOsAccountId = -3;
    CreateDemoGroup(invalidOsAccountId, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest111, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest112, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":333,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest113, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-3,\"userType\":0,\"expireTime\":-1}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest114, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
    "Visibility\":-1,\"userType\":-1,\"expireTime\":-1}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest115, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *createParams = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
    "Visibility\":-1,\"userType\":0,\"expireTime\":-3}";
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest116, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_ERROR);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest117, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *createParams = "{\"groupType\":1282,\"userId\":\"1234ABCD\",\"peerUserId\":\"0CBA4321\"}";
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest118, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *createParams = "{\"groupType\":1282,\"peerUserId\":\"0CBA4321\"}";
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest119, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *createParams = "{\"groupType\":1282,\"userId\":\"1234ABCD\"}";
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest120, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *createParams = "{\"groupType\":1282,\"userId\":\"1234ABCE\",\"peerUserId\":\"DCBA4321\"}";
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest121, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *createParams = "{\"groupType\":1282,\"userId\":\"1234ABCD\",\"peerUserId\":\"1234ABCD\"}";
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest122, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *createParams = "{\"groupType\":1282,\"userId\":\"1234ABCD\",\"peerUserId\":\"DCBA4321\",\"group"
        "Visibility\":-3,\"userType\":0,\"expireTime\":-1}";
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest123, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *createParams = "{\"groupType\":1282,\"userId\":\"1234ABCD\",\"peerUserId\":\"DCBA4321\",\"group"
        "Visibility\":-1,\"userType\":-3,\"expireTime\":-1}";
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest124, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *createParams = "{\"groupType\":1282,\"userId\":\"1234ABCD\",\"peerUserId\":\"DCBA4321\",\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-3}";
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest125, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoIdenticalAccountGroup();
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmCreateGroupTest, GmCreateGroupTest126, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoAcrossAccountGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS3);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

class GmCheckAccessToGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmCheckAccessToGroupTest::SetUpTestCase()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS2);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateDemoIdenticalAccountGroup();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

void GmCheckAccessToGroupTest::TearDownTestCase()
{
    DestroyDeviceAuthService();
}

void GmCheckAccessToGroupTest::SetUp() {}

void GmCheckAccessToGroupTest::TearDown() {}

HWTEST_F(GmCheckAccessToGroupTest, GmCheckAccessToGroupTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->checkAccessToGroup(DEFAULT_OS_ACCOUNT, nullptr, TEST_GROUP_ID);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmCheckAccessToGroupTest, GmCheckAccessToGroupTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->checkAccessToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmCheckAccessToGroupTest, GmCheckAccessToGroupTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->checkAccessToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID);
    ASSERT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(GmCheckAccessToGroupTest, GmCheckAccessToGroupTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->checkAccessToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID2, TEST_GROUP_ID2);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmCheckAccessToGroupTest, GmCheckAccessToGroupTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->checkAccessToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID4);
    ASSERT_NE(ret, HC_SUCCESS);
}

class GmGetPkInfoListTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmGetPkInfoListTest::SetUpTestCase() {}
void GmGetPkInfoListTest::TearDownTestCase() {}

void GmGetPkInfoListTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmGetPkInfoListTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, nullptr, TEST_QUERY_PARAMS, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    uint32_t returnNum = 0;
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_QUERY_PARAMS, nullptr, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_QUERY_PARAMS, &returnData, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"isSelfPk\":true}";
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"udid\":\"ABCD\"}";
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest007, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"udid\":\"5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242"
        "B3930\",\"isSelfPk\":true}";
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest008, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"udid\":\"ABCD\",\"isSelfPk\":true}";
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest009, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"udid\":\"5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242"
        "B3930\",\"isSelfPk\":false}";
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetPkInfoListTest, GmGetPkInfoListTest010, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    EXPECT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"udid\":\"ABCD\",\"isSelfPk\":false}";
    int32_t ret = gm->getPkInfoList(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

class GmGetGroupInfoByIdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmGetGroupInfoByIdTest::SetUpTestCase() {}
void GmGetGroupInfoByIdTest::TearDownTestCase() {}

void GmGetGroupInfoByIdTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmGetGroupInfoByIdTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmGetGroupInfoByIdTest, GmGetGroupInfoByIdTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, nullptr, TEST_GROUP_ID, &returnData);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetGroupInfoByIdTest, GmGetGroupInfoByIdTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr, &returnData);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetGroupInfoByIdTest, GmGetGroupInfoByIdTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetGroupInfoByIdTest, GmGetGroupInfoByIdTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetGroupInfoByIdTest, GmGetGroupInfoByIdTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID2, TEST_GROUP_ID2, &returnData);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmGetGroupInfoByIdTest, GmGetGroupInfoByIdTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getGroupInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID4, &returnData);
    ASSERT_NE(ret, HC_SUCCESS);
}

class GmGetGroupInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmGetGroupInfoTest::SetUpTestCase() {}
void GmGetGroupInfoTest::TearDownTestCase() {}

void GmGetGroupInfoTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmGetGroupInfoTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmGetGroupInfoTest, GmGetGroupInfoTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, nullptr, TEST_QUERY_PARAMS, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetGroupInfoTest, GmGetGroupInfoTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetGroupInfoTest, GmGetGroupInfoTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    uint32_t returnNum = 0;
    int32_t ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_QUERY_PARAMS, nullptr, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetGroupInfoTest, GmGetGroupInfoTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_QUERY_PARAMS, &returnData, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetGroupInfoTest, GmGetGroupInfoTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"groupOwner\":\"TestAppId\"}";
    int32_t ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetGroupInfoTest, GmGetGroupInfoTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"groupOwner\":\"TestAppId2\"}";
    int32_t ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetGroupInfoTest, GmGetGroupInfoTest007, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"groupType\":0}";
    int32_t ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetGroupInfoTest, GmGetGroupInfoTest008, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    const char *queryParams = "{\"groupType\":123456}";
    int32_t ret = gm->getGroupInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, queryParams, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

class GmGetJoinedGroupsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmGetJoinedGroupsTest::SetUpTestCase() {}
void GmGetJoinedGroupsTest::TearDownTestCase() {}

void GmGetJoinedGroupsTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmGetJoinedGroupsTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmGetJoinedGroupsTest, GmGetJoinedGroupsTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, nullptr, PEER_TO_PEER_GROUP, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetJoinedGroupsTest, GmGetJoinedGroupsTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    uint32_t returnNum = 0;
    int32_t ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, PEER_TO_PEER_GROUP, nullptr, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetJoinedGroupsTest, GmGetJoinedGroupsTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, nullptr, PEER_TO_PEER_GROUP, &returnData, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetJoinedGroupsTest, GmGetJoinedGroupsTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, GROUP_TYPE_INVALID, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetJoinedGroupsTest, GmGetJoinedGroupsTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, PEER_TO_PEER_GROUP, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    ASSERT_NE(returnNum, 0);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetJoinedGroupsTest, GmGetJoinedGroupsTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getJoinedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID2, PEER_TO_PEER_GROUP, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

class GmGetRelatedGroupsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmGetRelatedGroupsTest::SetUpTestCase() {}
void GmGetRelatedGroupsTest::TearDownTestCase() {}

void GmGetRelatedGroupsTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmGetRelatedGroupsTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmGetRelatedGroupsTest, GmGetRelatedGroupsTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, nullptr, TEST_AUTH_ID, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetRelatedGroupsTest, GmGetRelatedGroupsTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetRelatedGroupsTest, GmGetRelatedGroupsTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    uint32_t returnNum = 0;
    int32_t ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, nullptr, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetRelatedGroupsTest, GmGetRelatedGroupsTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, &returnData, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetRelatedGroupsTest, GmGetRelatedGroupsTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    ASSERT_NE(returnNum, 0);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetRelatedGroupsTest, GmGetRelatedGroupsTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getRelatedGroups(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID2, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

class GmGetDeviceInfoByIdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmGetDeviceInfoByIdTest::SetUpTestCase() {}
void GmGetDeviceInfoByIdTest::TearDownTestCase() {}

void GmGetDeviceInfoByIdTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmGetDeviceInfoByIdTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmGetDeviceInfoByIdTest, GmGetDeviceInfoByIdTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, nullptr, TEST_AUTH_ID, TEST_GROUP_ID, &returnData);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetDeviceInfoByIdTest, GmGetDeviceInfoByIdTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr, TEST_GROUP_ID, &returnData);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetDeviceInfoByIdTest, GmGetDeviceInfoByIdTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, nullptr, &returnData);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetDeviceInfoByIdTest, GmGetDeviceInfoByIdTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, TEST_GROUP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetDeviceInfoByIdTest, GmGetDeviceInfoByIdTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, TEST_GROUP_ID, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetDeviceInfoByIdTest, GmGetDeviceInfoByIdTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID2, TEST_AUTH_ID, TEST_GROUP_ID2, &returnData);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmGetDeviceInfoByIdTest, GmGetDeviceInfoByIdTest007, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID, TEST_GROUP_ID4, &returnData);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmGetDeviceInfoByIdTest, GmGetDeviceInfoByIdTest008, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getDeviceInfoById(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_AUTH_ID2, TEST_GROUP_ID, &returnData);
    ASSERT_NE(ret, HC_SUCCESS);
}

class GmGetTrustedDevicesTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmGetTrustedDevicesTest::SetUpTestCase() {}
void GmGetTrustedDevicesTest::TearDownTestCase() {}

void GmGetTrustedDevicesTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmGetTrustedDevicesTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmGetTrustedDevicesTest, GmGetTrustedDevicesTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, nullptr, TEST_GROUP_ID, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetTrustedDevicesTest, GmGetTrustedDevicesTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetTrustedDevicesTest, GmGetTrustedDevicesTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    uint32_t returnNum = 0;
    int32_t ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, nullptr, &returnNum);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetTrustedDevicesTest, GmGetTrustedDevicesTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnData, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmGetTrustedDevicesTest, GmGetTrustedDevicesTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, &returnData, &returnNum);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    ASSERT_NE(returnNum, 0);
    gm->destroyInfo(&returnData);
}

HWTEST_F(GmGetTrustedDevicesTest, GmGetTrustedDevicesTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID2, TEST_GROUP_ID2, &returnData, &returnNum);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmGetTrustedDevicesTest, GmGetTrustedDevicesTest007, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    uint32_t returnNum = 0;
    int32_t ret = gm->getTrustedDevices(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID4, &returnData, &returnNum);
    ASSERT_NE(ret, HC_SUCCESS);
}

class GmIsDeviceInGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmIsDeviceInGroupTest::SetUpTestCase() {}
void GmIsDeviceInGroupTest::TearDownTestCase() {}

void GmIsDeviceInGroupTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void GmIsDeviceInGroupTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmIsDeviceInGroupTest, GmIsDeviceInGroupTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    bool ret = gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, nullptr, TEST_GROUP_ID, TEST_AUTH_ID);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GmIsDeviceInGroupTest, GmIsDeviceInGroupTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    bool ret = gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr, TEST_AUTH_ID);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GmIsDeviceInGroupTest, GmIsDeviceInGroupTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    bool ret = gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, nullptr);
    ASSERT_EQ(ret, false);
}

HWTEST_F(GmIsDeviceInGroupTest, GmIsDeviceInGroupTest004, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    bool ret = gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID, TEST_AUTH_ID);
    ASSERT_EQ(ret, true);
}

HWTEST_F(GmIsDeviceInGroupTest, GmIsDeviceInGroupTest005, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    bool ret = gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID2, TEST_GROUP_ID2, TEST_AUTH_ID);
    ASSERT_NE(ret, true);
}

HWTEST_F(GmIsDeviceInGroupTest, GmIsDeviceInGroupTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    bool ret = gm->isDeviceInGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID, TEST_GROUP_ID4, TEST_AUTH_ID);
    ASSERT_EQ(ret, false);
}
}
