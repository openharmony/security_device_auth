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

#include <cinttypes>
#include <gtest/gtest.h>
#include <unistd.h>

#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "creds_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "device_auth_ext.h"
#include "deviceauth_standard_test.h"
#include "hc_dev_info_mock.h"
#include "json_utils.h"
#include "json_utils_mock.h"
#include "protocol_task_main_mock.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_REQ_ID 123
#define TEST_REQ_ID2 321
#define TEST_APP_ID "TestAppId"
#define TEST_UDID "TestUdid"
#define TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define TEST_PIN_CODE "123456"
#define TEST_DEV_AUTH_SLEEP_TIME 50000
static const int32_t TEST_AUTH_OS_ACCOUNT_ID = 100;

static const char *AUTH_WITH_PIN_PARAMS = "{\"osAccountId\":100,\"acquireType\":0,\"pinCode\":\"123456\"}";

static const char *AUTH_DIRECT_PARAMS =
    "{\"osAccountId\":100,\"acquireType\":0,\"serviceType\":\"service.type.import\",\"peerConnDeviceId\":"
    "\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\"}";

static const char *DEVICE_LEVEL_AUTH_PARAMS =
    "{\"peerConnDeviceId\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\",\"servicePkgName\":\"TestAppId\",\"isClient\":true, \"isDeviceLevel\":true}";

enum AsyncStatus {
    ASYNC_STATUS_WAITING = 0,
    ASYNC_STATUS_TRANSMIT = 1,
    ASYNC_STATUS_FINISH = 2,
    ASYNC_STATUS_ERROR = 3
};

static AsyncStatus volatile g_asyncStatus;
static const uint32_t TRANSMIT_DATA_MAX_LEN = 2048;
static uint8_t g_transmitData[TRANSMIT_DATA_MAX_LEN] = { 0 };
static uint32_t g_transmitDataLen = 0;

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    if (memcpy_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, data, dataLen) != EOK) {
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

static char *OnAuthRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
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

static DeviceAuthCallback g_gaCallback = { .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequest };

static DeviceAuthCallback g_daTmpCallback = { .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequestDirectTmp };

static DeviceAuthCallback g_daLTCallback = { .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequestDirect };

static void AuthDeviceDirectWithPinDemo(const char *startAuthParams, const DeviceAuthCallback *callback)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);

    int32_t ret = StartAuthDevice(TEST_REQ_ID, startAuthParams, callback);
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
        CJson *json = CreateJson();
        AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
        AddStringToJson(json, "data", (const char *)g_transmitData);
        char *autParams = PackJsonToString(json);
        FreeJson(json);
        if (isClient) {
            ret = ProcessAuthDevice(TEST_REQ_ID, autParams, callback);
        } else {
            ret = ProcessAuthDevice(TEST_REQ_ID2, autParams, callback);
        }
        FreeJsonString(autParams);
        (void)memset_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, 0, TRANSMIT_DATA_MAX_LEN);
        g_transmitDataLen = 0;
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
    SetDeviceStatus(true);
}

static void AuthDeviceDirectDemo(const char *startAuthParams, const DeviceAuthCallback *callback)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);

    int32_t ret = StartAuthDevice(TEST_REQ_ID, startAuthParams, callback);
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
        CJson *json = CreateJson();
        AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
        AddStringToJson(json, "data", (const char *)g_transmitData);
        char *autParams = PackJsonToString(json);
        FreeJson(json);
        if (isClient) {
            ret = ProcessAuthDevice(TEST_REQ_ID, autParams, callback);
        } else {
            ret = ProcessAuthDevice(TEST_REQ_ID2, autParams, callback);
        }
        FreeJsonString(autParams);
        (void)memset_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, 0, TRANSMIT_DATA_MAX_LEN);
        g_transmitDataLen = 0;
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
    SetDeviceStatus(true);
}

static void DeviceLevelAuthDemo(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    int32_t ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, DEVICE_LEVEL_AUTH_PARAMS, &g_gaCallback);
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
        if (isClient) {
            ret = ga->processData(TEST_REQ_ID, g_transmitData, g_transmitDataLen, &g_gaCallback);
        } else {
            ret = ga->processData(TEST_REQ_ID2, g_transmitData, g_transmitDataLen, &g_gaCallback);
        }
        (void)memset_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, 0, TRANSMIT_DATA_MAX_LEN);
        g_transmitDataLen = 0;
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
    SetDeviceStatus(true);
}

static void CreateCredentialParamsJson(int32_t osAccountId, const char *deviceId, int32_t flag,
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

static int32_t ProcessCredentiaCreateDemo(const int32_t osAccountId, const bool isClient, const char *udid)
{
    int32_t flag = RETURN_FLAG_PUBLIC_KEY;
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(osAccountId, udid, flag, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    SetDeviceStatus(isClient);

    int32_t res = ProcessCredential(CRED_OP_CREATE, requestParams, &returnData);
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
            SetDeviceStatus(true);
            return res;
        }
    }

    printf("returnData is null !\n");

    SetDeviceStatus(true);
    return res;
}

static int32_t ProcessCredentialQueryDemo(
    const int32_t osAccountId, const bool isClient, const char *udid, char **publicKey)
{
    int32_t flag = RETURN_FLAG_PUBLIC_KEY;

    char *returnData = nullptr;
    SetDeviceStatus(isClient);
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(osAccountId, udid, flag, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);

    int32_t res = ProcessCredential(CRED_OP_QUERY, requestParams, &returnData);
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
            *publicKey = (char *)GetStringFromJson(in, FIELD_PUBLIC_KEY);
            SetDeviceStatus(true);
            return res;
        }
    }

    printf("returnData is null !\n");

    SetDeviceStatus(true);
    return res;
}

static int32_t ProcessCredentialDemoImpPubKey(
    const int32_t osAccountId, const bool isClient, const char *udid, const char *publicKey)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(osAccountId, udid, RETURN_FLAG_INVALID, SERVICE_TYPE_IMPORT, json);
    AddStringToJson(json, FIELD_PUBLIC_KEY, publicKey);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    SetDeviceStatus(isClient);

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
            SetDeviceStatus(true);
            return res;
        }
    }

    printf("returnData is null !\n");

    SetDeviceStatus(true);
    return res;
}

static int32_t CreateServerKeyPair()
{
    SetDeviceStatus(false);
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_SERVER,
        RETURN_FLAG_PUBLIC_KEY, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;

    printf("ProcessCredentialDemo: operationCode=%d\n", CRED_OP_CREATE);
    int32_t res = ProcessCredential(CRED_OP_CREATE, requestParams, &returnData);
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

    SetDeviceStatus(true);
    return res;
}

static int32_t DeleteServerKeyPair()
{
    SetDeviceStatus(false);
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_SERVER,
        RETURN_FLAG_PUBLIC_KEY, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;

    printf("ProcessCredentialDemo: operationCode=%d\n", CRED_OP_DELETE);
    int32_t res = ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
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

    SetDeviceStatus(true);
    return res;
}

static int32_t DeleteAllCredentails()
{
    SetDeviceStatus(false);
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_SERVER,
        RETURN_FLAG_DEFAULT, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
    FreeJsonString(requestParams);

    SetDeviceStatus(true);
    json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_CLIENT,
        RETURN_FLAG_DEFAULT, DEFAULT_SERVICE_TYPE, json);
    requestParams = PackJsonToString(json);
    FreeJson(json);
    returnData = nullptr;
    ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
    FreeJsonString(requestParams);

    return HC_SUCCESS;
}

static int32_t ProcessCredentialDemo(int operationCode, const char *serviceType)
{
    int32_t flag = RETURN_FLAG_INVALID;
    if (operationCode == CRED_OP_CREATE || operationCode == CRED_OP_QUERY) {
        flag = RETURN_FLAG_PUBLIC_KEY;
    }
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID, flag, serviceType, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    bool isClient = true;
    SetDeviceStatus(isClient);

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
            SetDeviceStatus(true);
            return res;
        }
    }

    printf("returnData is null !\n");

    SetDeviceStatus(true);
    return res;
}

static int32_t ProcessCredentialDemoImport(const char *importServiceType)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID, RETURN_FLAG_INVALID, importServiceType, json);
    AddStringToJson(json, FIELD_PUBLIC_KEY,
        "CA32A9DFACB944B1F6292C9AE10783F6376A987A9CE30C13300BC866917DFF2E");
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    bool isClient = false;
    SetDeviceStatus(isClient);

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
            SetDeviceStatus(true);
            return res;
        }
    }

    printf("returnData is null !\n");

    SetDeviceStatus(true);
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
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void DaAuthDeviceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest001, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    AuthDeviceDirectWithPinDemo(AUTH_WITH_PIN_PARAMS, &g_daTmpCallback);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}
HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest002, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    AuthDeviceDirectDemo(AUTH_DIRECT_PARAMS, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest003, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
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
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

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
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
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
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    DeviceLevelAuthDemo();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest007, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"testKey\":\"testValue\"}");
    CertInfo *certInfo = (CertInfo *)HcMalloc(sizeof(CertInfo *), 0);
    IdentityInfo *identityInfo = (IdentityInfo *)HcMalloc(sizeof(IdentityInfo *), 0);

    int32_t res = GetCredInfoByPeerCert(in, certInfo, &identityInfo);

    HcFree(identityInfo);
    HcFree(certInfo);
    FreeJson(in);

    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest008, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"osAccountId\":\"100\"}");
    CertInfo *certInfo = (CertInfo *)HcMalloc(sizeof(CertInfo *), 0);
    uint8_t val[] = { 0, 0 };
    Uint8Buff sharedSecret = { val, sizeof(val) };

    int32_t res = GetSharedSecretByPeerCert(in, certInfo, ALG_EC_SPEKE, &sharedSecret);
    HcFree(certInfo);
    FreeJson(in);
    ASSERT_NE(res, HC_SUCCESS);

    res = GetSharedSecretByPeerCert(nullptr, nullptr, ALG_EC_SPEKE, &sharedSecret);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest009, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"osAccountId\":\"100\"}");
    uint8_t val[] = { 0, 0 };
    Uint8Buff sharedSecret = { val, sizeof(val) };
    Uint8Buff presharedUrl = { val, sizeof(val) };

    int32_t res = GetSharedSecretByUrl(in, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJson(in);
    ASSERT_NE(res, HC_SUCCESS);

    res = GetSharedSecretByUrl(nullptr, &presharedUrl, ALG_ISO, &sharedSecret);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest010, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"pinCode\":\"123456\",\"seed\":"
                                     "\"CA32A9DFACB944B1F6292C9AE10783F6376A987A9CE30C13300BC866917DFF2E\"}");
    uint8_t val[] = { 0, 0 };
    Uint8Buff sharedSecret = { val, sizeof(val) };
    Uint8Buff presharedUrl = { val, sizeof(val) };

    int32_t res = GetSharedSecretByUrl(in, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJson(in);
    ASSERT_EQ(res, HC_SUCCESS);

    res = GetSharedSecretByUrl(nullptr, &presharedUrl, ALG_ISO, &sharedSecret);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest011, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const AuthIdentityManager *authIdentityManager = GetAuthIdentityManager();
    ASSERT_NE(authIdentityManager, nullptr);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest012, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const AuthIdentity *authIdentity = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_INVALID);
    ASSERT_EQ(authIdentity, nullptr);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest013, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"groupId\":\"123456\",\"seed\":"
                                     "\"CA32A9DFACB944B1F6292C9AE10783F6376A987A9CE30C13300BC866917DFF2E\"}");
    uint8_t val[] = { 0, 0 };
    Uint8Buff sharedSecret = { val, sizeof(val) };
    const char *credUrl = "{\"credentialType\":0,\"keyType\":1,\"trustType\":1,\"groupId\":\"123456\"}";
    Uint8Buff presharedUrl = { (uint8_t *)credUrl, HcStrlen(credUrl) };

    int32_t res = GetSharedSecretByUrl(in, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJson(in);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest014, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    int32_t res = credentialOperator->queryCredential(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->importCredential(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest015, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    const char *reqJsonStr = "{\"deviceId\":\"123456\",\"osAccountId\":0,\"acquireType\":0}";
    char *returnData = nullptr;
    int32_t res = credentialOperator->queryCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(reqJsonStr, &returnData);
    ASSERT_EQ(res, HC_SUCCESS);

    res = credentialOperator->importCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(reqJsonStr, &returnData);
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest016, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    const char *reqJsonStr = "{\"osAccountId\":0,\"acquireType\":0}";
    char *returnData = nullptr;
    int32_t res = credentialOperator->queryCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->importCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest017, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    const char *reqJsonStr = "{\"deviceId\":\"123456\",\"acquireType\":0}";
    char *returnData = nullptr;
    int32_t res = credentialOperator->queryCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->importCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest018, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    const char *reqJsonStr = "{\"deviceId\":\"123456\",\"osAccountId\":0}";
    char *returnData = nullptr;
    int32_t res = credentialOperator->queryCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->importCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);
}

// auth with pin (Test019 ~ Test027)
HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest019, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    AuthDeviceDirectWithPinDemo(AUTH_WITH_PIN_PARAMS, nullptr);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest020, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    AuthDeviceDirectWithPinDemo(nullptr, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest021, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":100,\"acquireType\":1,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest022, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"acquireType\":0,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest023, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":-2,\"acquireType\":0,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest024, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":-1,\"acquireType\":0,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest025, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":0,\"acquireType\":0,\"pinCode\":\"654321\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest026, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":100,\"acquireType\":0}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest027, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":100,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

// auth with key-pair (Test028 ~ Test032)
HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest028, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    AuthDeviceDirectDemo(AUTH_DIRECT_PARAMS, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest029, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    AuthDeviceDirectDemo(AUTH_DIRECT_PARAMS, &g_daLTCallback);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest030, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    const char *statAuthParams =
    "{\"osAccountId\":100,\"acquireType\":0,\"serviceType\":\"service.type.import\"}";
    AuthDeviceDirectDemo(statAuthParams, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest031, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    const char *statAuthParams =
    "{\"osAccountId\":100,\"acquireType\":0,\"serviceType\":\"service.type.import\",\"peerConnDeviceId\":"
    "\"52E2706717D5C39D736E134CC1\"}";
    AuthDeviceDirectDemo(statAuthParams, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest032, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    const char *statAuthParams =
    "{\"osAccountId\":100,\"acquireType\":8,\"serviceType\":\"service.type.import\",\"peerConnDeviceId\":"
    "\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\"}";
    AuthDeviceDirectDemo(statAuthParams, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}
} // namespace
