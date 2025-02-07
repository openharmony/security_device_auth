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
#include "device_auth.h"
#include "device_auth_defines.h"
#include "device_auth_ext.h"
#include "hc_dev_info_mock.h"
#include "json_utils_mock.h"
#include "json_utils.h"
#include "protocol_task_main_mock.h"
#include "securec.h"
#include "hc_file.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "hc_log.h"
#include "hc_types.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_RESULT_SUCCESS 0
#define TEST_APP_ID "TestAppId"
#define TEST_APP_ID1 "TestAppId1"
#define TEST_DEVICE_ID "TestDeviceId"
#define QUERY_RESULT_NUM 0
#define QUERY_RESULT_NUM_2 2

#define TEST_CRED_DATA_PATH "/data/service/el1/public/deviceauthMock/hccredential.dat"
static const char *ADD_PARAMS =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS1 =
    "{\"credType\":0,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS2 =
    "{\"credType\":1,\"keyFormat\":0,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS3 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":0,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS4 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":0,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS5 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":0,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS6 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":0,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS7 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":0,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS8 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":0,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS9 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS10 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS11 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,"
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS12 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":2,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS13 =
    "{\"credType\":2,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":2,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"9A9A9A9A\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS14 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId1\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *REQUEST_PARAMS =
    "{\"authorizedScope\":1, \"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\","
    "\"TestName4\"],\"extendInfo\":\"\"}";

static const char *QUERY_PARAMS = "{\"deviceId\":\"TestDeviceId\"}";
static const char *QUERY_PARAMS1 = "{\"deviceId\":\"TestDeviceId1\"}";
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
    HcFree(returnData);
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
    HcFree(returnData);
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
    EXPECT_EQ(ret, IS_SUCCESS);
    ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS14, &returnData);
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
    EXPECT_EQ(strcmp(deviceId, TEST_DEVICE_ID), TEST_RESULT_SUCCESS);
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
}