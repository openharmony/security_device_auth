/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include <gtest/gtest.h>
#include "alg_loader.h"
#include "common_defs.h"
#include "compatible_sub_session.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "device_auth_ext.h"
#include "hc_dev_info_mock.h"
#include "json_utils_mock.h"
#include "permission_adapter.h"
#include "json_utils.h"
#include "string_util.h"
#include "protocol_task_main_mock.h"
#include "securec.h"
#include "hc_file.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "hc_log.h"
#include "hc_types.h"
#include "base/security/device_auth/services/identity_service/src/identity_operation.c"
#include "base/security/device_auth/services/identity_service/src/identity_service_impl.c"
#include "base/security/device_auth/services/identity_service/session/src/cred_session_util.c"
#include "base/security/device_auth/services/data_manager/cred_data_manager/src/credential_data_manager.c"

#include "cred_listener.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_RESULT_SUCCESS 0
#define TEST_APP_ID "TestAppId"
#define TEST_APP_ID1 "TestAppId1"
#define TEST_DEVICE_ID "TestDeviceId"
#define TEST_USER_ID "TestUserId"
#define TEST_CRED_ID "TestCredId"
#define TEST_CRED_TYPE 1
#define TEST_CRED_TYPE_1 2
#define TEST_CRED_TYPE_2 3
#define TEST_CRED_TYPE_3 4
#define TEST_REQ_ID 11111111
#define TEST_REQ_ID_S 22222222
#define TEST_REQ_ID_AUTH 12312121
#define TEST_REQ_ID_AUTH_S 4352345234534
#define TEST_OWNER_UID_1 1
#define TEST_OWNER_UID_2 2
#define TEST_CRED_INFO_ID "TestCredInfoId"
#define TEST_PIN_CODE "123456"
#define TEST_PIN_CODE_1 ""
#define QUERY_RESULT_NUM 0
#define QUERY_RESULT_NUM_2 2
#define DATA_LEN 10
#define DEFAULT_OS_ACCOUNT_ID 100
#define DEFAULT_VAL 0
#define DEFAULT_CHANNEL_TYPE 0
#define TEST_DEV_AUTH_SLEEP_TIME 50000
#define TEST_CRED_DATA_PATH "/data/service/el1/public/deviceauthMock/hccredential.dat"
static const char *TEST_DATA = "testData";
static const char *ADD_PARAMS =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *CLIENT_AUTH_PARAMS =
    "{\"credType\":2,\"keyFormat\":1,\"algorithmType\":1,\"subject\":1,"
    "\"proofType\":1,\"method\":2,\"authorizedScope\":1,"
    "\"keyValue\":\"1234567812345678123456781234567812345678123456781234567812345678\","
    "\"deviceId\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":\"0\",\"extendInfo\":\"\"}";
static const char *SERVER_AUTH_PARAMS =
    "{\"credType\":2,\"keyFormat\":1,\"algorithmType\":1,\"subject\":1,"
    "\"proofType\":1,\"method\":2,\"authorizedScope\":1,"
    "\"keyValue\":\"1234567812345678123456781234567812345678123456781234567812345678\","
    "\"deviceId\":\"5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":\"0\",\"extendInfo\":\"\"}";
static const char *ADD_PARAMS1 =
    "{\"credType\":0,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS2 =
    "{\"credType\":1,\"keyFormat\":0,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS3 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":0,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS4 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":0,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS5 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":0,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS6 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":0,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS7 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":0,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS8 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":0,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS9 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS10 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS11 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,"
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS12 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":2,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS13 =
    "{\"credType\":2,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":2,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"9A9A9A9A\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS14 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId1\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS15 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS16 =
    "{\"credId\":\"14993DDA9D\",\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"peerUserSpaceId\":\"100\",\"extendInfo\":\"\"}";
static const char *ADD_PARAMS17 =
    "{\"credType\":2,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,"
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\"}";
static const char *ADD_PARAMS18 =
    "{\"credType\":3,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId0\","
    "\"deviceId\":\"TestDeviceId0\",\"credOwner\":\"TestAppId\"}";
static const char *REQUEST_PARAMS =
    "{\"authorizedScope\":1, \"authorizedAppList\":[\"TestName1\",\"TestName2\",\"TestName3\","
    "\"TestName4\"],\"extendInfo\":\"\"}";
static const char *AGREE_PARAMS =
    "{\"credType\":2, \"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\",\"subject\":1,"
    "\"keyFormat\":2,\"proofType\":1,\"authorizedScope\":1,\"algorithmType\":3,\"peerUserSpaceId\":\"100\","
    "\"keyValue\":\"3059301306072a8648ce3d020106082a8648ce3d030107034200043bb1f8107c6306bddcdb70cd9fee0e581"
    "5bbd305184871cd2880657eb2cc88aeece1a7f076d9fff7e1114e3bc9dfa45b061b2755b46fc282ef59763b4c0288bd\"}";
static const char *BATCH_UPDATE_PARAMS =
    "{\"baseInfo\":{\"credType\":3,\"keyFormat\":2,\"algorithmType\":3,\"subject\":2,\"authorizedScope\":2,"
    "\"issuer\":1,\"proofType\":2,\"credOwner\":\"TestAppId\"},"
    "\"updateLists\":[{\"userId\":\"TestUserId\",\"deviceId\":\"TestDeviceId\"}]}";
static const char *BATCH_UPDATE_PARAMS1 =
    "{\"baseInfo\":{\"credType\":1,\"keyFormat\":2,\"algorithmType\":3,\"subject\":2,\"authorizedScope\":2,"
    "\"issuer\":1,\"proofType\":2,\"credOwner\":\"TestAppId\"},"
    "\"updateLists\":[{\"userId\":\"TestUserId\",\"deviceId\":\"TestDeviceId\"}]}";

static const char *CRED_DATA =
    "{\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *CRED_DATA_1 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *QUERY_PARAMS = "{\"deviceId\":\"TestDeviceId\"}";
static const char *QUERY_PARAMS1 = "{\"deviceId\":\"TestDeviceId1\"}";
static const char *DEL_PARAMS = "{\"credOwner\":\"TestAppId\"}";
static const char *DEL_PARAMS1 = "{\"credOwner\":\"TestAppId\",\"userIdHash\":\"12D2\",\"deviceIdHash\":\"12D2\"}";
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
static bool g_isBind = false;
static char g_clientCredId[256] = { 0 };
static char g_serverCredId[256] = { 0 };
static const char *PIN_CODE = "000000";

enum CredListenerStatus {
    CRED_LISTENER_INIT = 0,
    CRED_LISTENER_ON_ADD = 1,
    CRED_LISTENER_ON_UPDATE = 2,
    CRED_LISTENER_ON_DELETE = 3,
};

static CredListenerStatus volatile g_credListenerStatus;

static void TestOnCredAdd(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
    g_credListenerStatus = CRED_LISTENER_ON_ADD;
}

static void TestOnCredUpdate(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
    g_credListenerStatus = CRED_LISTENER_ON_UPDATE;
}

static void TestOnCredDelete(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
    g_credListenerStatus = CRED_LISTENER_ON_DELETE;
}

static CredChangeListener g_credChangeListener = {
    .onCredAdd = TestOnCredAdd,
    .onCredUpdate = TestOnCredUpdate,
    .onCredDelete = TestOnCredDelete,
};

static void DeleteDatabase()
{
    HcFileRemove(TEST_CRED_DATA_PATH);
}

static bool CompareSubject(Credential *credential, QueryCredentialParams *params)
{
    credential->subject = SUBJECT_ACCESSORY_DEVICE;
    (void)CompareIntParams(params, credential);
    credential->subject = DEFAULT_CRED_PARAM_VAL;
    (void)CompareIntParams(params, credential);
    params->subject = SUBJECT_MASTER_CONTROLLER;
    credential->subject = SUBJECT_ACCESSORY_DEVICE;
    (void)CompareIntParams(params, credential);
    credential->subject = SUBJECT_MASTER_CONTROLLER;
    bool ret = CompareIntParams(params, credential);
    params->subject = DEFAULT_CRED_PARAM_VAL;
    return ret;
}

static bool CompareIssuer(Credential *credential, QueryCredentialParams *params)
{
    credential->issuer = SYSTEM_ACCOUNT;
    (void)CompareIntParams(params, credential);
    credential->issuer = DEFAULT_CRED_PARAM_VAL;
    (void)CompareIntParams(params, credential);
    params->issuer = SYSTEM_ACCOUNT;
    credential->issuer = SYSTEM_ACCOUNT;
    (void)CompareIntParams(params, credential);
    credential->issuer = APP_ACCOUNT;
    bool ret = CompareIntParams(params, credential);
    params->issuer = DEFAULT_CRED_PARAM_VAL;
    return ret;
}

static bool CompareOwnerUid(Credential *credential, QueryCredentialParams *params)
{
    credential->ownerUid = TEST_OWNER_UID_1;
    (void)CompareIntParams(params, credential);
    credential->ownerUid = DEFAULT_CRED_PARAM_VAL;
    (void)CompareIntParams(params, credential);
    params->ownerUid = TEST_OWNER_UID_1;
    credential->ownerUid = TEST_OWNER_UID_1;
    (void)CompareIntParams(params, credential);
    credential->ownerUid = TEST_OWNER_UID_2;
    bool ret = CompareIntParams(params, credential);
    params->ownerUid = DEFAULT_CRED_PARAM_VAL;
    return ret;
}

static bool CompareAuthorziedScope(Credential *credential, QueryCredentialParams *params)
{
    credential->authorizedScope = SCOPE_DEVICE;
    (void)CompareIntParams(params, credential);
    credential->authorizedScope = DEFAULT_CRED_PARAM_VAL;
    (void)CompareIntParams(params, credential);
    params->authorizedScope = SCOPE_DEVICE;
    credential->authorizedScope = SCOPE_DEVICE;
    (void)CompareIntParams(params, credential);
    credential->authorizedScope = SCOPE_USER;
    bool ret = CompareIntParams(params, credential);
    params->authorizedScope = DEFAULT_CRED_PARAM_VAL;
    return ret;
}

static bool CompareKeyFormat(Credential *credential, QueryCredentialParams *params)
{
    credential->keyFormat = SYMMETRIC_KEY;
    (void)CompareIntParams(params, credential);
    credential->keyFormat = DEFAULT_CRED_PARAM_VAL;
    (void)CompareIntParams(params, credential);
    params->keyFormat = SYMMETRIC_KEY;
    credential->keyFormat = SYMMETRIC_KEY;
    (void)CompareIntParams(params, credential);
    credential->keyFormat = ASYMMETRIC_PUB_KEY;
    bool ret = CompareIntParams(params, credential);
    params->keyFormat = DEFAULT_CRED_PARAM_VAL;
    return ret;
}

static bool CompareAlgorithmType(Credential *credential, QueryCredentialParams *params)
{
    credential->algorithmType = ALGO_TYPE_AES_256;
    (void)CompareIntParams(params, credential);
    credential->algorithmType = DEFAULT_CRED_PARAM_VAL;
    (void)CompareIntParams(params, credential);
    params->algorithmType = ALGO_TYPE_AES_256;
    credential->algorithmType = ALGO_TYPE_AES_256;
    (void)CompareIntParams(params, credential);
    credential->algorithmType = ALGO_TYPE_AES_128;
    bool ret = CompareIntParams(params, credential);
    params->algorithmType = DEFAULT_CRED_PARAM_VAL;
    return ret;
}

static bool CompareProofType(Credential *credential, QueryCredentialParams *params)
{
    credential->proofType = PROOF_TYPE_PSK;
    (void)CompareIntParams(params, credential);
    credential->proofType = DEFAULT_CRED_PARAM_VAL;
    (void)CompareIntParams(params, credential);
    params->proofType = PROOF_TYPE_PSK;
    credential->proofType = PROOF_TYPE_PSK;
    (void)CompareIntParams(params, credential);
    credential->proofType = PROOF_TYPE_PKI;
    bool ret = CompareIntParams(params, credential);
    params->proofType = DEFAULT_CRED_PARAM_VAL;
    return ret;
}

class GetCredMgrInstanceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GetCredMgrInstanceTest::SetUpTestCase() {}
void GetCredMgrInstanceTest::TearDownTestCase() {}

void GetCredMgrInstanceTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void GetCredMgrInstanceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(GetCredMgrInstanceTest, GetCredMgrInstanceTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    EXPECT_NE(cm, nullptr);
}

HWTEST_F(GetCredMgrInstanceTest, GetCredMgrInstanceTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    EXPECT_NE(cm, nullptr);
    char *returnData = nullptr;
    cm->destroyInfo(nullptr);
    cm->destroyInfo(&returnData);
    returnData = static_cast<char *>(HcMalloc(DATA_LEN, 0));
    int32_t ret = memcpy_s(returnData, DATA_LEN, TEST_DATA, HcStrlen(TEST_DATA));
    cm->destroyInfo(&returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

class CredMgrAddCredentialTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrAddCredentialTest::SetUpTestCase() {}
void CredMgrAddCredentialTest::TearDownTestCase() {}

void CredMgrAddCredentialTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrAddCredentialTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &returnData);
    cm->destroyInfo(&returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, nullptr, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, nullptr);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS1, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest005, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS2, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest006, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS3, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest007, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS4, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest008, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS5, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest009, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS6, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest010, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS7, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest011, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS8, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest012, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS9, &returnData);
    EXPECT_EQ(ret, IS_ERR_JSON_GET);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest013, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS10, &returnData);
    EXPECT_EQ(ret, IS_ERR_JSON_GET);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest014, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS11, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest015, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS12, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest016, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS13, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest017, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS15, &returnData);
    EXPECT_EQ(ret, IS_ERR_KEYVALUE_METHOD_CONFLICT);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest018, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS16, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest019, TestSize.Level0)
{
    Credential *credential = CreateCredential();
    ASSERT_NE(credential, nullptr);
    QueryCredentialParams params = InitQueryCredentialParams();
    bool ret = CompareIntParams(&params, credential);
    EXPECT_EQ(ret, true);
    params.credType = ACCOUNT_RELATED;
    credential->credType = ACCOUNT_UNRELATED;
    ret = CompareIntParams(&params, credential);
    EXPECT_EQ(ret, false);
    params.credType = DEFAULT_CRED_PARAM_VAL;
    ret = CompareSubject(credential, &params);
    EXPECT_EQ(ret, true);
    ret = CompareIssuer(credential, &params);
    EXPECT_EQ(ret, false);
    ret = CompareOwnerUid(credential, &params);
    EXPECT_EQ(ret, false);
    ret = CompareAuthorziedScope(credential, &params);
    EXPECT_EQ(ret, false);
    ret = CompareKeyFormat(credential, &params);
    EXPECT_EQ(ret, false);
    ret = CompareAlgorithmType(credential, &params);
    EXPECT_EQ(ret, false);
    ret = CompareProofType(credential, &params);
    EXPECT_EQ(ret, false);
    DestroyCredential(credential);
}

class CredMgrExportCredentialTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void CredMgrExportCredentialTest::SetUpTestCase() {}
void CredMgrExportCredentialTest::TearDownTestCase() {}

void CredMgrExportCredentialTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrExportCredentialTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrExportCredentialTest, CredMgrExportCredentialTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->exportCredential(DEFAULT_OS_ACCOUNT, credId, &returnData);
    HcFree(credId);
    cm->destroyInfo(&returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrExportCredentialTest, CredMgrExportCredentialTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS2, &credId);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
    char *returnData = nullptr;
    ret = cm->exportCredential(DEFAULT_OS_ACCOUNT, credId, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrExportCredentialTest, CredMgrExportCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->exportCredential(DEFAULT_OS_ACCOUNT, credId, nullptr);
    HcFree(credId);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrExportCredentialTest, CredMgrExportCredentialTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->exportCredential(DEFAULT_OS_ACCOUNT, nullptr, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

class CredMgrQueryCredentialByParamsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrQueryCredentialByParamsTest::SetUpTestCase() {}
void CredMgrQueryCredentialByParamsTest::TearDownTestCase() {}

void CredMgrQueryCredentialByParamsTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrQueryCredentialByParamsTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrQueryCredentialByParamsTest, CredMgrQueryCredentialByParamsTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &returnData);
    HcFree(returnData);
    returnData = nullptr;
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS14, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *credIdList = nullptr;
    ret = cm->queryCredentialByParams(DEFAULT_OS_ACCOUNT, QUERY_PARAMS, &credIdList);
    EXPECT_EQ(ret, IS_SUCCESS);
    CJson *jsonArr = CreateJsonFromString(credIdList);
    int32_t size = GetItemNum(jsonArr);
    HcFree(credIdList);
    FreeJson(jsonArr);
    EXPECT_EQ(size, QUERY_RESULT_NUM_2);
}

HWTEST_F(CredMgrQueryCredentialByParamsTest, CredMgrQueryCredentialByParamsTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credIdList = nullptr;
    int32_t ret = cm->queryCredentialByParams(DEFAULT_OS_ACCOUNT, nullptr, &credIdList);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrQueryCredentialByParamsTest, CredMgrQueryCredentialByParamsTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->queryCredentialByParams(DEFAULT_OS_ACCOUNT, QUERY_PARAMS, nullptr);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrQueryCredentialByParamsTest, CredMgrQueryCredentialByParamsTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *credIdList = nullptr;
    ret = cm->queryCredentialByParams(DEFAULT_OS_ACCOUNT, QUERY_PARAMS1, &credIdList);
    EXPECT_EQ(ret, IS_SUCCESS);
    CJson *jsonArr = CreateJsonFromString(credIdList);
    int32_t size = GetItemNum(jsonArr);
    HcFree(credIdList);
    FreeJson(jsonArr);
    EXPECT_EQ(size, QUERY_RESULT_NUM);
}

class CredMgrQueryCredInfoByCredIdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrQueryCredInfoByCredIdTest::SetUpTestCase() {}
void CredMgrQueryCredInfoByCredIdTest::TearDownTestCase() {}

void CredMgrQueryCredInfoByCredIdTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrQueryCredInfoByCredIdTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrQueryCredInfoByCredIdTest, CredMgrQueryCredInfoByCredIdTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnCredInfo = nullptr;
    ret = cm->queryCredInfoByCredId(DEFAULT_OS_ACCOUNT, credId, &returnCredInfo);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    CJson *credInfoJson = CreateJsonFromString(returnCredInfo);
    HcFree(returnCredInfo);
    const char *deviceId = GetStringFromJson(credInfoJson, FIELD_DEVICE_ID);
    EXPECT_EQ(IsStrEqual(deviceId, TEST_DEVICE_ID), true);
    FreeJson(credInfoJson);
}

HWTEST_F(CredMgrQueryCredInfoByCredIdTest, CredMgrQueryCredInfoByCredIdTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnCredInfo = nullptr;
    int32_t ret = cm->queryCredInfoByCredId(DEFAULT_OS_ACCOUNT, nullptr, &returnCredInfo);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrQueryCredInfoByCredIdTest, CredMgrQueryCredInfoByCredIdTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS14, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->queryCredInfoByCredId(DEFAULT_OS_ACCOUNT, credId, nullptr);
    HcFree(credId);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

class CredMgrDeleteCredentialTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrDeleteCredentialTest::SetUpTestCase() {}
void CredMgrDeleteCredentialTest::TearDownTestCase() {}

void CredMgrDeleteCredentialTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrDeleteCredentialTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrDeleteCredentialTest, CredMgrDeleteCredentialTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrDeleteCredentialTest, CredMgrDeleteCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, nullptr);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

class CredMgrUpdateCredInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrUpdateCredInfoTest::SetUpTestCase() {}
void CredMgrUpdateCredInfoTest::TearDownTestCase() {}

void CredMgrUpdateCredInfoTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrUpdateCredInfoTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrUpdateCredInfoTest, CredMgrUpdateCredInfoTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, credId, REQUEST_PARAMS);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUpdateCredInfoTest, CredMgrUpdateCredInfoTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, credId, "");
    HcFree(credId);
    EXPECT_EQ(ret, IS_ERR_JSON_CREATE);
}

HWTEST_F(CredMgrUpdateCredInfoTest, CredMgrUpdateCredInfoTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, nullptr, REQUEST_PARAMS);
    HcFree(credId);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

class CredMgrRegCredListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrRegCredListenerTest::SetUpTestCase() {}
void CredMgrRegCredListenerTest::TearDownTestCase() {}

void CredMgrRegCredListenerTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrRegCredListenerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(nullptr, &listener);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, nullptr);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest005, TestSize.Level0)
{
    g_credListenerStatus = CRED_LISTENER_INIT;
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &g_credChangeListener);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *credId = nullptr;
    ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    EXPECT_EQ(g_credListenerStatus, CRED_LISTENER_ON_ADD);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest006, TestSize.Level0)
{
    g_credListenerStatus = CRED_LISTENER_INIT;
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &g_credChangeListener);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *credId = nullptr;
    ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, credId, REQUEST_PARAMS);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    EXPECT_EQ(g_credListenerStatus, CRED_LISTENER_ON_UPDATE);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest007, TestSize.Level0)
{
    g_credListenerStatus = CRED_LISTENER_INIT;
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &g_credChangeListener);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *credId = nullptr;
    ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    EXPECT_EQ(g_credListenerStatus, CRED_LISTENER_ON_DELETE);
}

class CredMgrUnRegCredListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrUnRegCredListenerTest::SetUpTestCase() {}
void CredMgrUnRegCredListenerTest::TearDownTestCase() {}

void CredMgrUnRegCredListenerTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrUnRegCredListenerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrUnRegCredListenerTest, CredMgrUnRegCredListenerTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->unregisterChangeListener(TEST_APP_ID);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUnRegCredListenerTest, CredMgrUnRegCredListenerTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->unregisterChangeListener(TEST_APP_ID);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUnRegCredListenerTest, CredMgrUnRegCredListenerTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->unregisterChangeListener(nullptr);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

class CredMgrAgreeCredentialTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrAgreeCredentialTest::SetUpTestCase() {}
void CredMgrAgreeCredentialTest::TearDownTestCase() {}

void CredMgrAgreeCredentialTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrAgreeCredentialTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrAgreeCredentialTest, CredMgrAgreeCredentialTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *selfCredId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS17, &selfCredId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->agreeCredential(DEFAULT_OS_ACCOUNT, selfCredId, AGREE_PARAMS, &returnData);
    HcFree(selfCredId);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrAgreeCredentialTest, CredMgrAgreeCredentialTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->agreeCredential(DEFAULT_OS_ACCOUNT, nullptr, AGREE_PARAMS, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAgreeCredentialTest, CredMgrAgreeCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->agreeCredential(DEFAULT_OS_ACCOUNT, TEST_CRED_ID, nullptr, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAgreeCredentialTest, CredMgrAgreeCredentialTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->agreeCredential(DEFAULT_OS_ACCOUNT, TEST_CRED_ID, AGREE_PARAMS, nullptr);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

class CredMgrBatchUpdateCredsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrBatchUpdateCredsTest::SetUpTestCase() {}
void CredMgrBatchUpdateCredsTest::TearDownTestCase() {}

void CredMgrBatchUpdateCredsTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrBatchUpdateCredsTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->batchUpdateCredentials(DEFAULT_OS_ACCOUNT, BATCH_UPDATE_PARAMS, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->batchUpdateCredentials(DEFAULT_OS_ACCOUNT, nullptr, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->batchUpdateCredentials(DEFAULT_OS_ACCOUNT, BATCH_UPDATE_PARAMS1, &returnData);
    EXPECT_EQ(ret, IS_ERR_NOT_SUPPORT);
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->batchUpdateCredentials(DEFAULT_OS_ACCOUNT, BATCH_UPDATE_PARAMS, nullptr);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrBatchUpdateCredsTest, CredMgrBatchUpdateCredsTest005, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS18, &credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->batchUpdateCredentials(DEFAULT_OS_ACCOUNT, BATCH_UPDATE_PARAMS, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

class CredMgrDelCredByParamsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredMgrDelCredByParamsTest::SetUpTestCase() {}
void CredMgrDelCredByParamsTest::TearDownTestCase() {}

void CredMgrDelCredByParamsTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredMgrDelCredByParamsTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredMgrDelCredByParamsTest, CredMgrDelCredByParamsTest001, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->deleteCredByParams(DEFAULT_OS_ACCOUNT, DEL_PARAMS, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrDelCredByParamsTest, CredMgrDelCredByParamsTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->deleteCredByParams(DEFAULT_OS_ACCOUNT, nullptr, &returnData);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrDelCredByParamsTest, CredMgrDelCredByParamsTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->deleteCredByParams(DEFAULT_OS_ACCOUNT, DEL_PARAMS, nullptr);
    EXPECT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrDelCredByParamsTest, CredMgrDelCredByParamsTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *credId = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
    HcFree(credId);
    EXPECT_EQ(ret, IS_SUCCESS);
    char *returnData = nullptr;
    ret = cm->deleteCredByParams(DEFAULT_OS_ACCOUNT, DEL_PARAMS1, &returnData);
    HcFree(returnData);
    EXPECT_EQ(ret, IS_SUCCESS);
}

class CredListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredListenerTest::SetUpTestCase() {}
void CredListenerTest::TearDownTestCase() {}

void CredListenerTest::SetUp()
{
    int32_t ret = InitCredListener();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void CredListenerTest::TearDown()
{
    DestroyCredListener();
}

HWTEST_F(CredListenerTest, CredListenerTest001, TestSize.Level0)
{
    OnCredAdd(nullptr, nullptr);
    OnCredAdd(TEST_CRED_ID, TEST_CRED_INFO_ID);
    OnCredDelete(nullptr, nullptr);
    OnCredDelete(TEST_CRED_ID, TEST_CRED_INFO_ID);
    OnCredUpdate(nullptr, nullptr);
    OnCredUpdate(TEST_CRED_ID, TEST_CRED_INFO_ID);
    int32_t ret = AddCredListener(nullptr, &g_credChangeListener);
    EXPECT_NE(ret, IS_SUCCESS);
    ret = AddCredListener(TEST_APP_ID, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredListenerTest, CredListenerTest002, TestSize.Level0)
{
    int32_t ret = RemoveCredListener(nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

class IdentityOperationTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IdentityOperationTest::SetUpTestCase() {}
void IdentityOperationTest::TearDownTestCase() {}

void IdentityOperationTest::SetUp()
{
}

void IdentityOperationTest::TearDown()
{
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest001, TestSize.Level0)
{
    int32_t ret = GetCredentialById(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest002, TestSize.Level0)
{
    char *credIdStr = nullptr;
    char *deviceId = nullptr;
    char *credOwner = nullptr;
    Uint8Buff *credIdByte = nullptr;
    int32_t ret = GenerateCredIdInner(nullptr, deviceId, credIdByte, &credIdStr);
    EXPECT_NE(ret, IS_SUCCESS);
    ret = GenerateCredIdInner(credOwner, nullptr, credIdByte, &credIdStr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest003, TestSize.Level0)
{
    Credential *credetial = CreateCredential();
    int32_t ret = SetVectorFromList(&credetial->authorizedAppList, nullptr);
    DestroyCredential(credetial);
    EXPECT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest004, TestSize.Level0)
{
    int32_t ret = SetMethodFromJson(nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest005, TestSize.Level0)
{
    int32_t ret = SetCredType(nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest006, TestSize.Level0)
{
    int32_t ret = SetKeyFormat(nullptr, nullptr, DEFAULT_VAL);
    EXPECT_NE(ret, IS_SUCCESS);
    Credential *credetial = CreateCredential();
    CJson *json = CreateJson();
    ret = AddIntToJson(json, FIELD_KEY_FORMAT, SYMMETRIC_KEY);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = SetKeyFormat(credetial, json, DEFAULT_VAL);
    EXPECT_NE(ret, IS_SUCCESS);

    ret = AddIntToJson(json, FIELD_KEY_FORMAT, ASYMMETRIC_PUB_KEY);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = SetKeyFormat(credetial, json, METHOD_GENERATE);
    EXPECT_NE(ret, IS_SUCCESS);

    ret = AddIntToJson(json, FIELD_KEY_FORMAT, ASYMMETRIC_KEY);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = SetKeyFormat(credetial, json, METHOD_IMPORT);
    EXPECT_NE(ret, IS_SUCCESS);
    DestroyCredential(credetial);
    FreeJson(json);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest007, TestSize.Level0)
{
    int32_t ret = SetAuthorizedScope(nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest008, TestSize.Level0)
{
    int32_t ret = GetCredentialById(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest009, TestSize.Level0)
{
    int32_t ret = CombineBaseCredId(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityOperationTest, IdentityOperationTest010, TestSize.Level0)
{
    int32_t ret = Sha256BaseCredId(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
#ifdef DEV_AUTH_HIVIEW_ENABLE
    LoadAllAccountsData();
    DevAuthDataBaseDump();
#endif
    LoadDataIfNotLoaded(DEFAULT_OS_ACCOUNT_ID);
    OnOsAccountUnlocked(DEFAULT_OS_ACCOUNT_ID);
    LoadDataIfNotLoaded(DEFAULT_OS_ACCOUNT_ID);
    OnOsAccountRemoved(DEFAULT_OS_ACCOUNT_ID);
}

class IdentityServiceImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IdentityServiceImplTest::SetUpTestCase() {}
void IdentityServiceImplTest::TearDownTestCase() {}

void IdentityServiceImplTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
}

void IdentityServiceImplTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest001, TestSize.Level0)
{
    int32_t ret = AddCredentialImpl(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest002, TestSize.Level0)
{
    int32_t ret = ExportCredentialImpl(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest003, TestSize.Level0)
{
    int32_t ret = QueryCredentialByParamsImpl(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest004, TestSize.Level0)
{
    int32_t ret = QueryCredInfoByCredIdImpl(DEFAULT_OS_ACCOUNT_ID, DEFAULT_VAL, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest005, TestSize.Level0)
{
    int32_t ret = DeleteCredentialImpl(DEFAULT_OS_ACCOUNT_ID, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest006, TestSize.Level0)
{
    int32_t ret = DeleteCredByParamsImpl(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest007, TestSize.Level0)
{
    int32_t ret = UpdateCredInfoImpl(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest008, TestSize.Level0)
{
    QueryCredentialParams queryParam;
    int32_t ret = AddUpdateCred(DEFAULT_OS_ACCOUNT_ID, nullptr, &queryParam);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest009, TestSize.Level0)
{
    QueryCredentialParams queryParam;
    int32_t ret = ProcessAbnormalCreds(DEFAULT_OS_ACCOUNT_ID, nullptr, &queryParam);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest010, TestSize.Level0)
{
    int32_t ret = BatchUpdateCredsImpl(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(IdentityServiceImplTest, IdentityServiceImplTest011, TestSize.Level0)
{
    int32_t ret = AgreeCredentialImpl(DEFAULT_OS_ACCOUNT_ID, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

class SessionV1Test : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SessionV1Test::SetUpTestCase() {}
void SessionV1Test::TearDownTestCase() {}

void SessionV1Test::SetUp()
{
}

void SessionV1Test::TearDown()
{
}

HWTEST_F(SessionV1Test, SessionV1Test001, TestSize.Level0)
{
    int32_t ret = CheckPermission(DEFAULT_VAL);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(SessionV1Test, SessionV1Test002, TestSize.Level0)
{
    SubSessionTypeValue subSessionType = TYPE_CLIENT_BIND_SUB_SESSION;
    int32_t ret = CreateCompatibleSubSession(subSessionType, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);

    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    DeviceAuthCallback *callback;
    CompatibleBaseSubSession *subSession;

    ret = CreateCompatibleSubSession(subSessionType, json, nullptr, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = CreateCompatibleSubSession(subSessionType, nullptr, callback, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = CreateCompatibleSubSession(subSessionType, nullptr, nullptr, &subSession);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);

    ret = CreateCompatibleSubSession(subSessionType, json, callback, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = CreateCompatibleSubSession(subSessionType, json, nullptr, &subSession);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = CreateCompatibleSubSession(subSessionType, nullptr, callback, &subSession);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);

    ret = CreateCompatibleSubSession(subSessionType, json, callback, &subSession);
    FreeJson(json);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(SessionV1Test, SessionV1Test003, TestSize.Level0)
{
    int32_t ret = ProcessCompatibleSubSession(nullptr, nullptr, nullptr, nullptr);
    DestroyCompatibleSubSession(nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession subSession;
    subSession.type = DEFAULT_VAL;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    int32_t *status = DEFAULT_VAL;

    ret = ProcessCompatibleSubSession(&subSession, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = ProcessCompatibleSubSession(&subSession, in, nullptr, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = ProcessCompatibleSubSession(&subSession, in, &out, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = ProcessCompatibleSubSession(&subSession, in, &out, status);
    DestroyCompatibleSubSession(&subSession);
    EXPECT_NE(ret, HC_SUCCESS);

    FreeJson(in);
    FreeJson(out);
}

class CredSessionUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredSessionUtilTest::SetUpTestCase() {}
void CredSessionUtilTest::TearDownTestCase() {}

void CredSessionUtilTest::SetUp() {}

void CredSessionUtilTest::TearDown() {}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest001, TestSize.Level0)
{
    int32_t ret = AddChannelInfoToContext(DEFAULT_CHANNEL_TYPE, DEFAULT_CHANNEL_ID, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    ret = AddChannelInfoToContext(DEFAULT_CHANNEL_TYPE, DEFAULT_CHANNEL_ID, in);
    EXPECT_EQ(ret, IS_SUCCESS);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest002, TestSize.Level0)
{
    int32_t ret = AddCredIdToContextIfNeeded(nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    CJson *credDataJson = CreateJsonFromString(CRED_DATA);
    (void)AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credDataJson);
    FreeJson(credDataJson);
    ret = AddCredIdToContextIfNeeded(in);
    EXPECT_NE(ret, IS_SUCCESS);

    credDataJson = CreateJsonFromString(CRED_DATA_1);
    (void)AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credDataJson);
    FreeJson(credDataJson);
    ret = AddCredIdToContextIfNeeded(in);
    EXPECT_EQ(ret, IS_SUCCESS);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest003, TestSize.Level0)
{
    int32_t ret = CheckConfirmationExist(nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_CONFIRMATION, REQUEST_REJECTED);
    ret = CheckConfirmationExist(in);
    EXPECT_EQ(ret, IS_SUCCESS);
    (void)AddIntToJson(in, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    ret = CheckConfirmationExist(in);
    EXPECT_EQ(ret, IS_SUCCESS);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest004, TestSize.Level0)
{
    const char *ret = GetAppIdByContext(nullptr);
    EXPECT_EQ(ret, nullptr);
    CJson *in = CreateJson();
    CJson *credDataJson = CreateJsonFromString(CRED_DATA);
    (void)AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credDataJson);
    FreeJson(credDataJson);
    ret = GetAppIdByContext(in);
    EXPECT_EQ(ret, nullptr);

    credDataJson = CreateJsonFromString(CRED_DATA_1);
    (void)AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credDataJson);
    FreeJson(credDataJson);
    ret = GetAppIdByContext(in);
    EXPECT_NE(ret, nullptr);

    (void)AddStringToJson(in, FIELD_PIN_CODE, TEST_PIN_CODE);
    ret = GetAppIdByContext(in);
    EXPECT_EQ(ret, nullptr);
    (void)AddStringToJson(in, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    ret = GetAppIdByContext(in);
    EXPECT_NE(ret, nullptr);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest005, TestSize.Level0)
{
    int32_t ret = AddUserIdHashHexStringToContext(nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_CRED_TYPE, TEST_CRED_TYPE_1);
    ret = AddUserIdHashHexStringToContext(nullptr, in);
    EXPECT_EQ(ret, IS_SUCCESS);
    (void)AddIntToJson(in, FIELD_CRED_TYPE, TEST_CRED_TYPE);
    ret = AddUserIdHashHexStringToContext(nullptr, in);
    EXPECT_NE(ret, IS_SUCCESS);

    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID);
    ret = AddUserIdHashHexStringToContext(nullptr, in);
    EXPECT_NE(ret, IS_SUCCESS);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest006, TestSize.Level0)
{
    int32_t ret = QueryAndAddSelfCredToContext(DEFAULT_OS_ACCOUNT_ID, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    (void)AddStringToJson(in, FIELD_CRED_ID, TEST_CRED_ID);
    ret = QueryAndAddSelfCredToContext(DEFAULT_OS_ACCOUNT_ID, in);
    EXPECT_NE(ret, IS_SUCCESS);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest007, TestSize.Level0)
{
    bool ret = CheckIsCredBind(nullptr);
    EXPECT_NE(ret, true);
    CJson *in = CreateJson();
    (void)AddStringToJson(in, FIELD_PIN_CODE, TEST_PIN_CODE_1);
    ret = CheckIsCredBind(in);
    EXPECT_NE(ret, true);

    (void)AddStringToJson(in, FIELD_PIN_CODE, TEST_PIN_CODE);
    ret = CheckIsCredBind(in);
    EXPECT_EQ(ret, true);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest008, TestSize.Level0)
{
    int32_t ret = AddAuthIdToCredContext(nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    ret = AddAuthIdToCredContext(in);
    EXPECT_EQ(ret, IS_SUCCESS);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest009, TestSize.Level0)
{
    int32_t ret = BuildClientCredBindContext(DEFAULT_OS_ACCOUNT_ID, DEFAULT_REQUEST_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    (void)AddStringToJson(in, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    const char *returnAppId = nullptr;
    ret = BuildClientCredBindContext(DEFAULT_OS_ACCOUNT_ID, DEFAULT_REQUEST_ID, in, &returnAppId);
    EXPECT_NE(ret, IS_SUCCESS);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest010, TestSize.Level0)
{
    int32_t ret = SetContextOpCode(nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_CRED_TYPE, TEST_CRED_TYPE);
    ret = SetContextOpCode(in);
    EXPECT_EQ(ret, IS_SUCCESS);
    (void)AddIntToJson(in, FIELD_CRED_TYPE, TEST_CRED_TYPE_1);
    ret = SetContextOpCode(in);
    EXPECT_EQ(ret, IS_SUCCESS);
    (void)AddIntToJson(in, FIELD_CRED_TYPE, TEST_CRED_TYPE_2);
    ret = SetContextOpCode(in);
    EXPECT_EQ(ret, IS_SUCCESS);
    (void)AddIntToJson(in, FIELD_CRED_TYPE, TEST_CRED_TYPE_3);
    ret = SetContextOpCode(in);
    EXPECT_NE(ret, IS_SUCCESS);
    FreeJson(in);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest011, TestSize.Level0)
{
    int32_t ret = BuildClientCredAuthContext(DEFAULT_OS_ACCOUNT_ID, DEFAULT_REQUEST_ID, nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
}

HWTEST_F(CredSessionUtilTest, CredSessionUtilTest012, TestSize.Level0)
{
    int32_t ret = BuildClientCredContext(DEFAULT_OS_ACCOUNT_ID, DEFAULT_REQUEST_ID,
        nullptr, nullptr);
    EXPECT_NE(ret, IS_SUCCESS);
    CJson *in = CreateJson();
    (void)AddStringToJson(in, FIELD_PIN_CODE, TEST_PIN_CODE);
    const char *returnAppId = nullptr;
    ret = BuildClientCredContext(DEFAULT_OS_ACCOUNT_ID, DEFAULT_REQUEST_ID, in, &returnAppId);
    EXPECT_NE(ret, IS_SUCCESS);
    ret = BuildServerCredBindContext(DEFAULT_REQUEST_ID, in, nullptr, &returnAppId);
    EXPECT_NE(ret, IS_SUCCESS);
    ret = BuildServerCredAuthContext(DEFAULT_REQUEST_ID, in, nullptr, &returnAppId);
    EXPECT_NE(ret, IS_SUCCESS);
    ret = BuildServerCredContext(DEFAULT_REQUEST_ID, nullptr, nullptr, &returnAppId);
    EXPECT_NE(ret, IS_SUCCESS);
    FreeJson(in);
}

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

static char *OnAuthRequest(int64_t requestId, int operationCode, const char* reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    if (g_isBind) {
        AddStringToJson(json, FIELD_PIN_CODE, PIN_CODE);
    } else {
        AddStringToJson(json, FIELD_CRED_ID, g_serverCredId);
    }
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static DeviceAuthCallback g_caCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequest
};

static const char *GenerateBindParams()
{
    CJson *json = CreateJson();
    AddStringToJson(json, FIELD_PIN_CODE, PIN_CODE);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static const char *GenerateAuthParams()
{
    CJson *json = CreateJson();
    AddStringToJson(json, FIELD_CRED_ID, g_clientCredId);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static void AuthCredDemo(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const CredAuthManager *ca = GetCredAuthInstance();
    ASSERT_NE(ca, nullptr);
    int32_t ret = ca->authCredential(DEFAULT_OS_ACCOUNT, g_isBind ? TEST_REQ_ID : TEST_REQ_ID_AUTH,
        g_isBind ? GenerateBindParams() : GenerateAuthParams(), &g_caCallback);
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
            ret = ca->processCredData(g_isBind ? TEST_REQ_ID : TEST_REQ_ID_AUTH, g_transmitData, g_transmitDataLen,
                &g_caCallback);
        } else {
            ret = ca->processCredData(g_isBind ? TEST_REQ_ID_S : TEST_REQ_ID_AUTH_S, g_transmitData, g_transmitDataLen,
                &g_caCallback);
        }
        (void)memset_s(g_transmitData, g_transmitDataMaxLen, 0, g_transmitDataMaxLen);
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

class CredAuthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredAuthTest::SetUpTestCase() {}
void CredAuthTest::TearDownTestCase() {}

void CredAuthTest::SetUp()
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void CredAuthTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredAuthTest, CredAuthTest001, TestSize.Level0)
{
    const CredAuthManager *ca = GetCredAuthInstance();
    ASSERT_NE(ca, nullptr);
    g_isBind = true;
    AuthCredDemo();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *clientReturnData = nullptr;
    char *serverReturnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, CLIENT_AUTH_PARAMS, &clientReturnData);
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->addCredential(DEFAULT_OS_ACCOUNT, SERVER_AUTH_PARAMS, &serverReturnData);
    EXPECT_EQ(ret, IS_SUCCESS);
    (void)strcpy_s(g_clientCredId, HcStrlen(clientReturnData) + 1, clientReturnData);
    (void)strcpy_s(g_serverCredId, HcStrlen(serverReturnData) + 1, serverReturnData);
    g_isBind = false;
    AuthCredDemo();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    cm->destroyInfo(&clientReturnData);
    cm->destroyInfo(&serverReturnData);
}

HWTEST_F(CredAuthTest, CredAuthTest002, TestSize.Level0)
{
    const CredAuthManager *ca = GetCredAuthInstance();
    ASSERT_NE(ca, nullptr);
    ca->authCredential(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, nullptr, nullptr);
    ca->authCredential(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, nullptr, &g_caCallback);
    ca->authCredential(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, GenerateBindParams(), nullptr);
    ca->processCredData(TEST_REQ_ID, nullptr, DATA_LEN, nullptr);
    ca->processCredData(TEST_REQ_ID, nullptr, DATA_LEN, &g_caCallback);
    ca->processCredData(TEST_REQ_ID, (const uint8_t*)GenerateBindParams(), DATA_LEN, nullptr);
}
} // namespace