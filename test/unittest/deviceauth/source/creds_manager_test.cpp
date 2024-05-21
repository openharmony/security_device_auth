/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "asy_token_manager.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info_mock.h"
#include "json_utils.h"
#include "securec.h"
#include "sym_token_manager.h"

using namespace std;
using namespace testing::ext;

namespace {
static const std::string TEST_SYM_USER_ID = "1234ABCD";
static const std::string TEST_SYM_DEVICE_ID = "TestAuthId";
static const std::string TEST_SYM_AUTH_CODE = "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b";
static const std::string TEST_SYM_USER_ID2 = "DCBA4321";
static const std::string TEST_SYM_DEVICE_ID2 = "TestAuthId2";
static const std::string TEST_SYM_AUTH_CODE2 = "2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335";
static const std::string TEST_SYM_USER_ID3 = "1234ABCDE";
static const std::string TEST_SYM_DEVICE_ID3 = "TestAuthId3";
static const std::string TEST_GROUP_DATA_PATH = "/data/service/el1/public/deviceauthMock";
static const std::string TEST_HKS_DATA_PATH = "/data/service/el1/public/huks_service/tmp/+0+0+0+0";

static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;

class CredsManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredsManagerTest::SetUpTestCase() {}
void CredsManagerTest::TearDownTestCase() {}

static void RemoveDir(const char *path)
{
    char strBuf[TEST_DEV_AUTH_BUFFER_SIZE] = { 0 };
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
    RemoveDir(TEST_GROUP_DATA_PATH.c_str());
    RemoveDir(TEST_HKS_DATA_PATH.c_str());
}

void CredsManagerTest::SetUp()
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void CredsManagerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredsManagerTest, CredsManagerTest001, TestSize.Level0)
{
    SymTokenManager *tokenManager = GetSymTokenManager();
    ASSERT_NE(tokenManager, nullptr);

    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    (void)AddStringToJson(json, FIELD_USER_ID, TEST_SYM_USER_ID.c_str());
    (void)AddStringToJson(json, FIELD_DEVICE_ID, TEST_SYM_DEVICE_ID.c_str());
    (void)AddStringToJson(json, FIELD_AUTH_CODE, TEST_SYM_AUTH_CODE.c_str());
    SetAccountStorageTest(true);

    int32_t ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, json);
    EXPECT_NE(ret, HC_SUCCESS);

    SetAccountStorageTest(false);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest002, TestSize.Level0)
{
    SymTokenManager *tokenManager = GetSymTokenManager();
    ASSERT_NE(tokenManager, nullptr);

    int32_t ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, nullptr);
    EXPECT_EQ(ret, HC_ERR_NULL_PTR);

    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, json);
    EXPECT_EQ(ret, HC_ERR_ALLOC_MEMORY);

    (void)AddStringToJson(json, FIELD_USER_ID, TEST_SYM_USER_ID.c_str());
    ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, json);
    EXPECT_EQ(ret, HC_ERR_ALLOC_MEMORY);

    // only add the token to vector, import key failed
    (void)AddStringToJson(json, FIELD_DEVICE_ID, TEST_SYM_DEVICE_ID.c_str());
    ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, json);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    (void)AddStringToJson(json, FIELD_AUTH_CODE, TEST_SYM_AUTH_CODE.c_str());
    ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, json);
    EXPECT_EQ(ret, HC_SUCCESS);

    // replace the existed one
    ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, json);
    EXPECT_EQ(ret, HC_SUCCESS);

    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest003, TestSize.Level0)
{
    SymTokenManager *tokenManager = GetSymTokenManager();
    ASSERT_NE(tokenManager, nullptr);

    Uint8Buff keyAlias = { nullptr, 0 };
    int32_t ret = tokenManager->generateKeyAlias(nullptr, TEST_SYM_DEVICE_ID.c_str(), &keyAlias);
    EXPECT_EQ(ret, HC_ERR_NULL_PTR);

    ret = tokenManager->generateKeyAlias(TEST_SYM_USER_ID.c_str(), nullptr, &keyAlias);
    EXPECT_EQ(ret, HC_ERR_NULL_PTR);

    ret = tokenManager->generateKeyAlias(TEST_SYM_USER_ID.c_str(), TEST_SYM_DEVICE_ID.c_str(), nullptr);
    EXPECT_EQ(ret, HC_ERR_NULL_PTR);
}

HWTEST_F(CredsManagerTest, CredsManagerTest004, TestSize.Level0)
{
    SymTokenManager *tokenManager = GetSymTokenManager();
    ASSERT_NE(tokenManager, nullptr);

    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    (void)AddStringToJson(json, FIELD_USER_ID, TEST_SYM_USER_ID.c_str());
    (void)AddStringToJson(json, FIELD_DEVICE_ID, TEST_SYM_DEVICE_ID.c_str());
    (void)AddStringToJson(json, FIELD_AUTH_CODE, TEST_SYM_AUTH_CODE.c_str());
    int32_t ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, json);
    EXPECT_EQ(ret, HC_SUCCESS);

    (void)AddStringToJson(json, FIELD_USER_ID, TEST_SYM_USER_ID2.c_str());
    (void)AddStringToJson(json, FIELD_DEVICE_ID, TEST_SYM_DEVICE_ID2.c_str());
    (void)AddStringToJson(json, FIELD_AUTH_CODE, TEST_SYM_AUTH_CODE2.c_str());
    ret = tokenManager->addToken(DEFAULT_OS_ACCOUNT, IMPORT_TRUSTED_CREDENTIALS, json);
    EXPECT_EQ(ret, HC_SUCCESS);

    // userId is null, delete failed
    ret = tokenManager->deleteToken(DEFAULT_OS_ACCOUNT, nullptr, TEST_SYM_DEVICE_ID.c_str());
    EXPECT_EQ(ret, HC_ERR_NULL_PTR);

    // deviceId is null, delete failed
    ret = tokenManager->deleteToken(DEFAULT_OS_ACCOUNT, TEST_SYM_USER_ID.c_str(), nullptr);
    EXPECT_EQ(ret, HC_ERR_NULL_PTR);

    // delete the second token first
    ret = tokenManager->deleteToken(DEFAULT_OS_ACCOUNT, TEST_SYM_USER_ID2.c_str(), TEST_SYM_DEVICE_ID2.c_str());
    EXPECT_EQ(ret, HC_SUCCESS);

    // delete non-existent token
    ret = tokenManager->deleteToken(DEFAULT_OS_ACCOUNT, TEST_SYM_USER_ID3.c_str(), TEST_SYM_DEVICE_ID3.c_str());
    EXPECT_EQ(ret, HC_ERR_NULL_PTR);

    // set account storage null, expect result: save to file failed after delete from vector
    SetAccountStorageTest(true);
    ret = tokenManager->deleteToken(DEFAULT_OS_ACCOUNT, TEST_SYM_USER_ID.c_str(), TEST_SYM_DEVICE_ID.c_str());
    SetAccountStorageTest(false);
    EXPECT_NE(ret, HC_SUCCESS);

    FreeJson(json);
}
}