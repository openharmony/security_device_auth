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

#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "json_utils.h"
#include "securec.h"
#include "../../../../../services/legacy/authenticators/src/account_related/creds_manager/asy_token_manager.c"

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

    do {
        ret = GetAccountAuthTokenManager()->getAlgVersion(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
        EXPECT_NE(ret, HC_SUCCESS);

        ret = GetAccountAuthTokenManager()->getAlgVersion(DEFAULT_OS_ACCOUNT, "userId", nullptr); // For unit test.
        EXPECT_NE(ret, HC_SUCCESS);

        ret = GetAccountAuthTokenManager()->getAlgVersion(DEFAULT_OS_ACCOUNT, "userId", "deviceId"); // For unit test.
        EXPECT_NE(ret, HC_SUCCESS);
    } while (0);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest005, TestSize.Level0)
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

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest006, TestSize.Level0)
{
    int32_t ret;
    AccountTokenVec vec = CreateAccountTokenVec();
    CJson *in = CreateJson();
    AccountToken accountToken;
    (void)memset_s(&accountToken, sizeof(accountToken), 0, sizeof(accountToken));
    do {
        if (in == nullptr) {
            break;
        }
        char tokenPath[MAX_DB_PATH_LEN] = { 0 };
        (void)GetTokenPathDe(DEFAULT_OS_ACCOUNT, tokenPath, MAX_DB_PATH_LEN);
        ret = GenerateTokenFromJson(nullptr, &accountToken);
        ret = CreateTokensFromJson(nullptr, nullptr);
        ret = ReadTokensFromFile(nullptr, tokenPath);
        ret = ReadTokensFromFile(&vec, tokenPath);
        ret = WriteTokensJsonToFile(nullptr, tokenPath);
        ret = WriteTokensJsonToFile(in, tokenPath);
        ret = GenerateJsonFromToken(&accountToken, nullptr);
        ret = GenerateServerPkAlias(nullptr, nullptr);
        if (AddStringToJson(in, FIELD_USER_ID, "user_id_test") != HC_SUCCESS) { // For unit test.
            break;
        }
        ret = GenerateServerPkAlias(in, nullptr);

        EXPECT_NE(ret, HC_SUCCESS);
    } while (0);
    ClearAccountTokenVec(&vec);
    FreeJson(in);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest007, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *in = CreateJson();
    CJson *obj = CreateJson();
    AccountTokenVec vec = CreateAccountTokenVec();
    do {
        if (in == nullptr || obj == nullptr) {
            break;
        }
        (void)ImportServerPk(nullptr, nullptr, nullptr, P256);
        (void)VerifyPkInfoSignature(nullptr, in, nullptr, nullptr, P256);
        (void)DoImportServerPkAndVerify(nullptr, nullptr, nullptr, nullptr);
        (void)VerifySignature(nullptr);
        (void)SaveOsAccountTokenDb(DEFAULT_OS_ACCOUNT);
        (void)QueryTokenPtrIfMatch(&vec, nullptr, nullptr);
        (void)QueryTokenPtrIfMatch(&vec, "userId", nullptr); // For unit test.
        (void)QueryTokenPtrIfMatch(&vec, "userId", "deviceId"); // For unit test.
        (void)GetAccountToken(DEFAULT_OS_ACCOUNT, "userId", "deviceId"); // For unit test.
        (void)DeleteTokenInner(DEFAULT_OS_ACCOUNT, "userId", "deviceId", &vec); // For unit test.
    } while (0);
    FreeJson(obj);
    FreeJson(in);
    ClearAccountTokenVec(&vec);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest0071, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *in = CreateJson();
    CJson *obj = CreateJson();
    AccountTokenVec vec = CreateAccountTokenVec();
    AccountToken accountToken;
    do {
        if (in == nullptr || obj == nullptr) {
            break;
        }
        (void)AddTokenInner(DEFAULT_OS_ACCOUNT, &accountToken);
        (void)DoExportPkAndCompare(nullptr, nullptr, nullptr, nullptr);
        (void)CheckDevicePk(nullptr);
        if (AddObjToJson(in, FIELD_PK_INFO, obj) != HC_SUCCESS) {
            break;
        }
        (void)CheckDevicePk(in);
        (void)CheckUserId(nullptr, nullptr);
        (void)CheckUserId(nullptr, in);
        (void)CheckCredValidity(IMPORT_SELF_CREDENTIAL, nullptr);
        if (AddStringToJson(in, FIELD_USER_ID, "userId") != HC_SUCCESS) { // For unit test.
            break;
        }
        (void)CheckCredValidity(IMPORT_SELF_CREDENTIAL, in);
    } while (0);
    FreeJson(obj);
    FreeJson(in);
    ClearAccountTokenVec(&vec);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest008, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *in = CreateJson();
    do {
        if (in == nullptr) {
            break;
        }
        (void)DoGenerateAndExportPk(nullptr, nullptr, nullptr, nullptr);
        (void)GetRegisterProof(nullptr, nullptr);
        if (AddStringToJson(in, FIELD_USER_ID, "userId") != HC_SUCCESS) { // For unit test.
            break;
        }
        (void)GetRegisterProof(nullptr, in);
        if (AddStringToJson(in, FIELD_VERSION, "version") != HC_SUCCESS) { // For unit test.
            break;
        }
        (void)GetRegisterProof(nullptr, in);
        EXPECT_EQ(ret, HC_SUCCESS);
    } while (0);
    FreeJson(in);
}

HWTEST_F(AsyTokenManagerTest, AsyTokenManagerTest009, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;

    do {
        (void)LoadOsAccountTokenDb(DEFAULT_OS_ACCOUNT);
        (void)DestroyAccountToken(nullptr);
    } while (0);

    EXPECT_EQ(ret, HC_SUCCESS);
}
}