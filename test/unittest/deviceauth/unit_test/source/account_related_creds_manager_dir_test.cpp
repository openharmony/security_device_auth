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
#include <unistd.h>
#include <gtest/gtest.h>

#include "asy_token_manager.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "json_utils.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {
class AsyTokenManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AsyTokenManagerTest::SetUpTestCase() {}

void AsyTokenManagerTest::TearDownTestCase() {}

void AsyTokenManagerTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void AsyTokenManagerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest001, TestSize.Level0)
{
    InitTokenManager();
    int32_t ret = GetAccountAuthTokenManager()->addToken(DEFAULT_OS_ACCOUNT, OP_BIND, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);

    CJson *in = CreateJson();
    do {
        if (in == nullptr) {
            break;
        }
        ret = GetAccountAuthTokenManager()->addToken(DEFAULT_OS_ACCOUNT, OP_BIND, in);
        EXPECT_NE(ret, HC_SUCCESS);

        ret = GetAccountAuthTokenManager()->addToken(DEFAULT_OS_ACCOUNT, OP_BIND, in);
        EXPECT_NE(ret, HC_SUCCESS);

        if (AddStringToJson(in, FIELD_USER_ID, "test_id") != HC_SUCCESS) { // For unit test.
            break;
        }
        ret = GetAccountAuthTokenManager()->addToken(DEFAULT_OS_ACCOUNT, OP_BIND, in);
        EXPECT_NE(ret, HC_SUCCESS);
    } while (0);
    FreeJson(in);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest002, TestSize.Level0)
{
    InitTokenManager();
    int32_t ret;
    AccountToken accountToken;
    do {
        ret = GetAccountAuthTokenManager()->getToken(DEFAULT_OS_ACCOUNT, nullptr, nullptr, nullptr);
        EXPECT_NE(ret, HC_SUCCESS);

        ret = GetAccountAuthTokenManager()->getToken(DEFAULT_OS_ACCOUNT, &accountToken, nullptr, nullptr);
        EXPECT_NE(ret, HC_SUCCESS);

        ret = GetAccountAuthTokenManager()->getToken(DEFAULT_OS_ACCOUNT, &accountToken, "userId", nullptr);
        EXPECT_NE(ret, HC_SUCCESS);
    } while (0);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest003, TestSize.Level0)
{
    InitTokenManager();
    int32_t ret;

    do {
        ret = GetAccountAuthTokenManager()->deleteToken(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
        EXPECT_NE(ret, HC_SUCCESS);

        ret = GetAccountAuthTokenManager()->deleteToken(DEFAULT_OS_ACCOUNT, "userId", nullptr); // For unit test.
        EXPECT_NE(ret, HC_SUCCESS);

        ret = GetAccountAuthTokenManager()->deleteToken(DEFAULT_OS_ACCOUNT, "userId", "deviceId"); // For unit test.
        EXPECT_NE(ret, HC_SUCCESS);
    } while (0);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest004, TestSize.Level0)
{
    InitTokenManager();
    int32_t ret;

    CJson *in = CreateJson();
    do {
        if (in == nullptr) {
            break;
        }
        ret = GetAccountAuthTokenManager()->getRegisterProof(nullptr, nullptr);
        EXPECT_NE(ret, HC_SUCCESS);

        ret = GetAccountAuthTokenManager()->getRegisterProof(in, nullptr);
        EXPECT_NE(ret, HC_SUCCESS);

        if (AddStringToJson(in, FIELD_USER_ID, "userId")) { // For unit test.
            break;
        }
        ret = GetAccountAuthTokenManager()->getRegisterProof(in, nullptr);
        EXPECT_NE(ret, HC_SUCCESS);

        if (AddStringToJson(in, FIELD_VERSION, "version")) { // For unit test.
            break;
        }
        ret = GetAccountAuthTokenManager()->getRegisterProof(in, nullptr);
        EXPECT_NE(ret, HC_SUCCESS);
    } while (0);
    FreeJson(in);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest005, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    (void)DestroyAccountToken(nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
}
}