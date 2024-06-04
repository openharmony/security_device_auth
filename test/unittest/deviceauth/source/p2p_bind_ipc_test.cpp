/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <cstring>
#include <unistd.h>
#include <gtest/gtest.h>
#include "device_auth.h"
#include "device_auth_defines.h"
#include "json_utils.h"
#include "securec.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "hc_dev_info.h"

using namespace std;
using namespace testing::ext;

namespace {
#define PROC_NAME_DEVICE_MANAGER "device_manager"
#define TEST_REQ_ID 123
#define TEST_OS_ACCOUNT_ID 100
#define TEST_APP_ID "TestAppId"
#define TEST_APP_ID2 "TestAppId2"
#define TEST_UDID "TestUdid"
#define TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define TEST_PIN_CODE "123456"

static const char* AUTH_WITH_PIN_PARAMS = "{\"osAccountId\":100,\"acquireType\":0,\"pinCode\":\"123456\"}";
static const char* AUTH_DIRECT_PARAMS =
    "{\"osAccountId\":100,\"acquireType\":0,\"serviceType\":\"service.type.import\",\"peerConnDeviceId\":"
    "\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C\"}";
#define FIELD_PUBLIC_KEY "publicKey"
#define FIELD_PIN_CODE "pinCode"
#define SERVICE_TYPE_IMPORT "service.type.import"
#define DEFAULT_SERVICE_TYPE "service.type.default"

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

static void NativeTokenSet(const char *procName)
{
    const char *acls[] = {"ACCESS_IDS"};
    const char *perms[] = {
        "ohos.permission.PLACE_CALL",
        "ohos.permission.ACCESS_IDS"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 1,
        .dcaps = NULL,
        .perms = perms,
        .acls = acls,
        .processName = procName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}

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

static char *OnAuthRequestDirectTmp(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnAuthRequestDirect(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_TYPE, SERVICE_TYPE_IMPORT);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static DeviceAuthCallback g_daTmpCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequestDirectTmp
};

static DeviceAuthCallback g_daLTCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequestDirect
};

static void CreateCredentialParamsJson(
    int32_t osAccountId, const char *deviceId, int32_t flag,
    const char *serviceType, CJson *out)
{
    AddIntToJson(out, FIELD_OS_ACCOUNT_ID, osAccountId);
    AddStringToJson(out, FIELD_DEVICE_ID, deviceId);
    AddStringToJson(out, FIELD_SERVICE_TYPE, serviceType);
    AddIntToJson(out, FIELD_ACQURIED_TYPE, P2P_BIND);

    if (flag >= 0) {
        AddIntToJson(out, FIELD_CRED_OP_FLAG, flag);
    }
    return;
}

static int32_t GetSelfUdid(char **selfUdid)
{
    printf("%s called.\n", __FUNCTION__);
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        printf("Failed to get self udid! res: %d", res);
        return res;
    }

    printf("self udid: %s\n", udid);
    *selfUdid = strdup(udid);
    return HC_SUCCESS;
}

static int32_t CreateServerKeyPair()
{
    char *selfUdid = nullptr;
    int32_t res = GetSelfUdid(&selfUdid);
    if (res != HC_SUCCESS) {
        return res;
    }
    CJson *json = CreateJson();
    if (json == nullptr) {
        printf("Failed to create json!\n");
        free(selfUdid);
        return HC_ERR_JSON_CREATE;
    }
    CreateCredentialParamsJson(TEST_OS_ACCOUNT_ID, selfUdid, RETURN_FLAG_PUBLIC_KEY,
        DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    free(selfUdid);
    if (requestParams == nullptr) {
        printf("Failed to pack json to string!\n");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    char *returnData = nullptr;

    printf("ProcessCredentialDemo: operationCode=%d\n", CRED_OP_CREATE);
    res = ProcessCredential(CRED_OP_CREATE, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        printf("returnData: %s\n", returnData);
        CJson *in = CreateJsonFromString(returnData);
        if (in == nullptr) {
            printf("CreateJsonFromString returnData failed !\n");
        } else {
            if (GetIntFromJson(in, FIELD_CRED_OP_RESULT, &res) != HC_SUCCESS) {
                printf("GetIntFromJson  result failed !\n");
                FreeJson(in);
                return HC_ERR_INVALID_PARAMS;
            }
            printf("get  result from returnData: %d\n", res);
            return res;
        }
    }

    printf("returnData is null !\n");

    return res;
}

static int32_t DeleteServerKeyPair()
{
    char *selfUdid = nullptr;
    int32_t res = GetSelfUdid(&selfUdid);
    if (res != HC_SUCCESS) {
        return res;
    }
    CJson *json = CreateJson();
    if (json == nullptr) {
        printf("Failed to create json!\n");
        free(selfUdid);
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_OS_ACCOUNT_ID, selfUdid, 1, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    free(selfUdid);
    if (requestParams == nullptr) {
        printf("Failed to pack json to string!\n");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    char *returnData = nullptr;

    printf("ProcessCredentialDemo: operationCode=%d\n", CRED_OP_DELETE);
    res = ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        printf("returnData: %s\n", returnData);
        CJson *in = CreateJsonFromString(returnData);
        if (in == nullptr) {
            printf("CreateJsonFromString returnData failed !\n");
        } else {
            if (GetIntFromJson(in, FIELD_CRED_OP_RESULT, &res) != HC_SUCCESS) {
                printf("GetIntFromJson  result failed !\n");
                FreeJson(in);
                return HC_ERR_INVALID_PARAMS;
            }
            printf("get  result from returnData: %d\n", res);
            return res;
        }
    }

    printf("returnData is null !\n");

    return res;
}

static int32_t ProcessCredentialDemo(int operationCode, const char *serviceType)
{
    int32_t flag = -1;
    if (operationCode == CRED_OP_CREATE || operationCode == CRED_OP_QUERY) {
        flag = 1;
    }
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_OS_ACCOUNT_ID, TEST_UDID, flag, serviceType, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;

    printf("ProcessCredentialDemo: operationCode=%d\n", operationCode);
    int32_t res = ProcessCredential(operationCode, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        printf("returnData: %s\n", returnData);
        CJson *in = CreateJsonFromString(returnData);
        if (in == nullptr) {
            printf("CreateJsonFromString returnData failed !\n");
        } else {
            if (GetIntFromJson(in, FIELD_CRED_OP_RESULT, &res) != HC_SUCCESS) {
                printf("GetIntFromJson  result failed !\n");
                FreeJson(in);
                return HC_ERR_INVALID_PARAMS;
            }
            printf("get  result from returnData: %d\n", res);
            return res;
        }
    }

    printf("returnData is null !\n");

    return res;
}

static int32_t ProcessCredentialDemoImport(const char *importServiceType)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_OS_ACCOUNT_ID, TEST_UDID, -1, importServiceType, json);
    AddStringToJson(json, FIELD_PUBLIC_KEY,
        "CA32A9DFACB944B1F6292C9AE10783F6376A987A9CE30C13300BC866917DFF2E");
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;

    printf("ProcessCredentialDemoImport\n");
    int32_t res = ProcessCredential(CRED_OP_IMPORT, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        CJson *in = CreateJsonFromString(returnData);
        if (in == nullptr) {
            printf("CreateJsonFromString returnData failed !\n");
        } else {
            if (GetIntFromJson(in, FIELD_CRED_OP_RESULT, &res) != HC_SUCCESS) {
                printf("GetIntFromJson  result failed !\n");
                FreeJson(in);
                return HC_ERR_INVALID_PARAMS;
            }
            printf("get  result from returnData: %d\n", res);
            return res;
        }
    }

    printf("returnData is null !\n");

    return res;
}

class DaAuthDeviceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DaAuthDeviceTest::SetUpTestCase() {}

void DaAuthDeviceTest::TearDownTestCase() {}

void DaAuthDeviceTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void DaAuthDeviceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest001, TestSize.Level0)
{
    int32_t res = StartAuthDevice(TEST_REQ_ID, AUTH_WITH_PIN_PARAMS, &g_daTmpCallback);
    ASSERT_EQ(res, HC_SUCCESS);
    res = CancelAuthRequest(TEST_REQ_ID, AUTH_WITH_PIN_PARAMS);
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest002, TestSize.Level0)
{
    int32_t res = StartAuthDevice(TEST_REQ_ID, AUTH_DIRECT_PARAMS, &g_daLTCallback);
    ASSERT_EQ(res, HC_SUCCESS);
    res = CancelAuthRequest(TEST_REQ_ID, AUTH_DIRECT_PARAMS);
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest003, TestSize.Level0)
{
    int32_t res = ProcessCredentialDemo(CRED_OP_DELETE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_CREATE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest004, TestSize.Level0)
{
    int32_t res = ProcessCredentialDemo(CRED_OP_CREATE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest005, TestSize.Level0)
{
    int32_t res = CreateServerKeyPair();
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemoImport(SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, SERVICE_TYPE_IMPORT);
    ASSERT_NE(res, HC_SUCCESS);
    res = DeleteServerKeyPair();
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest006, TestSize.Level0)
{
    int32_t res = CreateServerKeyPair();
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemoImport(SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemoImport(SERVICE_TYPE_IMPORT);
    ASSERT_NE(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, SERVICE_TYPE_IMPORT);
    ASSERT_NE(res, HC_SUCCESS);
    res = DeleteServerKeyPair();
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest007, TestSize.Level0)
{
    int32_t res = ProcessCredentialDemo(CRED_OP_CREATE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_CREATE, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
}

class ApiAccessBlockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ApiAccessBlockTest::SetUpTestCase() {}

void ApiAccessBlockTest::TearDownTestCase() {}

void ApiAccessBlockTest::SetUp()
{
    NativeTokenSet(TEST_APP_ID2);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void ApiAccessBlockTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(ApiAccessBlockTest, ApiAccessBlockTest001, TestSize.Level0)
{
    int32_t res = ProcessCredentialDemo(CRED_OP_CREATE, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
}

class ApiAccessPassTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ApiAccessPassTest::SetUpTestCase() {}

void ApiAccessPassTest::TearDownTestCase() {}

void ApiAccessPassTest::SetUp()
{
    NativeTokenSet(PROC_NAME_DEVICE_MANAGER);
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void ApiAccessPassTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(ApiAccessPassTest, ApiAccessPassTest001, TestSize.Level0)
{
    int32_t res = ProcessCredentialDemo(CRED_OP_CREATE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
}

}
