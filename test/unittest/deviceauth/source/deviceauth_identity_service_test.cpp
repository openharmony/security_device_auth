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
#define TEST_APP_ID "TestAppId"

#define TEST_CRED_DATA_PATH "/data/service/el1/public/deviceauthMock"
#define TEST_HKS_MAIN_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
static const char *ADD_PARAMS =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS1 =
    "{\"credType\":0,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS2 =
    "{\"credType\":1,\"keyFormat\":0,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS3 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":0,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS4 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":0,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS5 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":0,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS6 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":0,\"method\":1,\"authorizedScope\":1,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS7 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":0,\"authorizedScope\":1,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static const char *ADD_PARAMS8 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":0,\"userId\":\"TEST_USERID\","
    "\"keyValue\":\"TEST_KEY_VAULE\",\"deviceId\":\"TEST_DEVICE_ID\",\"credOwner\":\"TEST_CRED_OWNER\","
    "\"authorizedAccoutList\":[\"TEST_NAME1\",\"TEST_NAME2\",\"TEST_NAME3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";
static void FileDirRemove(const char *path)
{
    DIR *dp;
    struct dirent *entry;
    struct stat pathStat;

    if (stat(path, &pathStat) != 0) {
        LOGE("stat");
        return;
    }
    if (!S_ISDIR(pathStat.st_mode)) {
        if (remove(path) != 0) {
            LOGE("remove");
        }
        return;
    }
    dp = opendir(path);
    if (dp == nullptr) {
        LOGE("opendir");
        return;
    }
    while ((entry = readdir(dp))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char fullPath[1024];
        if (snprintf_s(fullPath, sizeof(fullPath), sizeof(fullPath) - 1, "%s%s", path, entry->d_name) < 0) {
            return;
        }
        FileDirRemove(fullPath);
    }
    closedir(dp);

    if (rmdir(path) != 0) {
        LOGE("rmdir");
    }
}

static void DeleteDatabase()
{
    FileDirRemove(TEST_CRED_DATA_PATH);
    FileDirRemove(TEST_HKS_MAIN_DATA_PATH);
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

class GetGaInstanceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

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
    ASSERT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    ASSERT_EQ(ret, IS_SUCCESS);
    ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    ASSERT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    CredChangeListener listener;
    int32_t ret = cm->registerChangeListener(nullptr, &listener);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrRegCredListenerTest, CredMgrRegCredListenerTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->registerChangeListener(TEST_APP_ID, nullptr);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
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
    ASSERT_EQ(ret, IS_SUCCESS);
    ret = cm->unregisterChangeListener(TEST_APP_ID);
    ASSERT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUnRegCredListenerTest, CredMgrUnRegCredListenerTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->unregisterChangeListener(TEST_APP_ID);
    ASSERT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrUnRegCredListenerTest, CredMgrUnRegCredListenerTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->unregisterChangeListener(nullptr);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
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
    ASSERT_EQ(ret, IS_SUCCESS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest002, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, nullptr, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest003, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, nullptr);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest004, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS1, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest005, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS2, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest006, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS3, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest007, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS4, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest008, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS5, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest009, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS6, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest010, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS7, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}

HWTEST_F(CredMgrAddCredentialTest, CredMgrAddCredentialTest011, TestSize.Level0)
{
    const CredManager *cm = GetCredMgrInstance();
    ASSERT_NE(cm, nullptr);
    char *returnData = nullptr;
    int32_t ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS8, &returnData);
    ASSERT_EQ(ret, IS_ERR_INVALID_PARAMS);
}
}