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
static const char *INVALID_JSON_STR = "invalid json format";
static const char *CREATE_PARAMS = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
    "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
static const char *ADD_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\","
    "\"groupType\":256,\"pinCode\":\"123456\"}";
static const char *DELETE_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\",\"deleteId\":\"TestAuthId2\"}";
static const char *DELETE_PARAMS4 =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\",\"deleteId\":\"Test"
    "AuthId2\", \"isForceDelete\":true, \"isIgnoreChannel\":true}";

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
    (void)requestId;
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
    (void)requestId;
    (void)operationCode;
    (void)authReturn;
    g_asyncStatus = ASYNC_STATUS_FINISH;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
    g_asyncStatus = ASYNC_STATUS_ERROR;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char* reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
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

static void AddDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, ADD_PARAMS);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        uint8_t tmpTransmitData[2048] = { 0 };
        uint32_t tmpTransmitDataLen = 0;
        if (memcpy_s(tmpTransmitData, sizeof(tmpTransmitData), g_transmitData, g_transmitDataLen) != EOK) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        tmpTransmitDataLen = g_transmitDataLen;
        (void)memset_s(g_transmitData, g_transmitDataMaxLen, 0, g_transmitDataMaxLen);
        g_transmitDataLen = 0;
        if (isClient) {
            ret = gm->processData(TEST_REQ_ID, tmpTransmitData, tmpTransmitDataLen);
        } else {
            ret = gm->processData(TEST_REQ_ID2, tmpTransmitData, tmpTransmitDataLen);
        }
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME2);
    SetDeviceStatus(true);
}

static void DeleteDemoMember(int32_t osAccountId, int64_t reqId, const char *appId, const char *deleteParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->deleteMemberFromGroup(osAccountId, reqId, appId, deleteParams);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        if (isClient) {
            ret = gm->processData(TEST_REQ_ID, g_transmitData, g_transmitDataLen);
        } else {
            ret = gm->processData(TEST_REQ_ID2, g_transmitData, g_transmitDataLen);
        }
        (void)memset_s(g_transmitData, g_transmitDataMaxLen, 0, g_transmitDataMaxLen);
        g_transmitDataLen = 0;
        ASSERT_EQ(ret, HC_SUCCESS);
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    SetDeviceStatus(true);
}

class GmAddMemberToGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmAddMemberToGroupTest::SetUpTestCase() {}
void GmAddMemberToGroupTest::TearDownTestCase() {}

void GmAddMemberToGroupTest::SetUp()
{
    DeleteDatabase();
}

void GmAddMemberToGroupTest::TearDown() {}

HWTEST_F(GmAddMemberToGroupTest, GmAddMemberToGroupTest001, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, nullptr, TEST_QUERY_PARAMS);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
    DestroyDeviceAuthService();
}

HWTEST_F(GmAddMemberToGroupTest, GmAddMemberToGroupTest002, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
    DestroyDeviceAuthService();
}

HWTEST_F(GmAddMemberToGroupTest, GmAddMemberToGroupTest003, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_NE(ret, HC_SUCCESS);
    DestroyDeviceAuthService();
}

HWTEST_F(GmAddMemberToGroupTest, GmAddMemberToGroupTest004, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, INVALID_JSON_STR);
    ASSERT_NE(ret, HC_SUCCESS);
    DestroyDeviceAuthService();
}

HWTEST_F(GmAddMemberToGroupTest, GmAddMemberToGroupTest005, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
}

HWTEST_F(GmAddMemberToGroupTest, GmAddMemberToGroupTest006, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DestroyDeviceAuthService();
}

class GmDeleteMemberFromGroupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GmDeleteMemberFromGroupTest::SetUpTestCase() {}
void GmDeleteMemberFromGroupTest::TearDownTestCase() {}

void GmDeleteMemberFromGroupTest::SetUp()
{
    DeleteDatabase();
}

void GmDeleteMemberFromGroupTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest001, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->deleteMemberFromGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, nullptr, TEST_QUERY_PARAMS);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest002, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->deleteMemberFromGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest003, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->deleteMemberFromGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DELETE_PARAMS);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest004, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->deleteMemberFromGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, INVALID_JSON_STR);
    ASSERT_NE(ret, HC_SUCCESS);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest005, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DELETE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_ERROR);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest006, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DELETE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_ERROR);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest007, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DELETE_PARAMS4);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest008, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DELETE_PARAMS4);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    DeleteDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, DELETE_PARAMS4);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest009, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *deleteParams = "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C28"
        "74C230C7C21\",\"deleteId\":\"InvalidAuthId\", \"isForceDelete\":true, \"isIgnoreChannel\":true}";
    DeleteDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, deleteParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest010, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    const char *deleteParams = "{\"deleteId\":\"TestAuthId2\", \"isForceDelete\":true, \"isIgnoreChannel\":true}";
    DeleteDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, deleteParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(GmDeleteMemberFromGroupTest, GmDeleteMemberFromGroupTest011, TestSize.Level0)
{
    SetIsoSupported(true);
    SetPakeV1Supported(false);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const char *deleteParams = "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C28"
        "74C230C7C21\",\"isForceDelete\":true, \"isIgnoreChannel\":true}";
    DeleteDemoMember(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, deleteParams);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}
}
