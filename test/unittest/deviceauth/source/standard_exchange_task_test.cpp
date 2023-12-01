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
#include "device_auth_defines.h"
#include "securec.h"
#include "identity_defines.h"

extern "C"{
#include "common_standard_bind_exchange.h"
}

using namespace std;
using namespace testing::ext;

namespace {
static const std::string TEST_APP_ID = "TestAppId";
static const std::string TEST_GROUP_ID = "TestGroupId";
static const std::string TEST_AUTH_ID = "TestAuthId";
static const std::string TEST_SALT = "2f7562744654535564586e665467546b";

static const int AUTH_ID_LENGTH = 10;
static const int PUB_KEY_LENGTH = 128;
static const int NONCE_LENGTH = 64;
static const int INVALID_CIPHER_LENGTH = 16;
static const int VALID_CIPHER_LENGTH = 32;

class StandardExchangeTaskTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StandardExchangeTaskTest::SetUpTestCase() {}
void StandardExchangeTaskTest::TearDownTestCase() {}

void StandardExchangeTaskTest::SetUp() {}

void StandardExchangeTaskTest::TearDown() {}

HWTEST_F(StandardExchangeTaskTest, StandardExchangeTaskTest001, TestSize.Level0)
{
    int32_t ret = InitStandardBindExchangeParams(nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);

    DestroyStandardBindExchangeParams(nullptr);

    StandardBindExchangeParams params;
    DestroyStandardBindExchangeParams(&params);
}

HWTEST_F(StandardExchangeTaskTest, StandardExchangeTaskTest002, TestSize.Level0)
{
    PakeParams pakeParams;
    pakeParams.userType = KEY_ALIAS_PSK;
    pakeParams.packageName = const_cast<char *>(TEST_APP_ID.c_str());
    pakeParams.serviceType = const_cast<char *>(TEST_GROUP_ID.c_str());
    uint8_t authId[AUTH_ID_LENGTH] = { 0 };
    (void)memcpy_s(authId, AUTH_ID_LENGTH, TEST_AUTH_ID.c_str(), AUTH_ID_LENGTH);
    pakeParams.baseParams.idSelf.val = authId;
    pakeParams.baseParams.idSelf.length = AUTH_ID_LENGTH;
    pakeParams.baseParams.loader = GetLoaderInstance();

    // pubKeySelf is null, exportPubKey failed
    int32_t ret = ClientRequestStandardBindExchange(&pakeParams, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);

    uint8_t publicKey[PUB_KEY_LENGTH] = { 0 };
    StandardBindExchangeParams exchangeParams;
    exchangeParams.pubKeySelf.val = publicKey;
    exchangeParams.pubKeySelf.length = PUB_KEY_LENGTH;

    ret = ClientRequestStandardBindExchange(&pakeParams, &exchangeParams);
    EXPECT_NE(ret, HC_SUCCESS);

    uint32_t challengeLen = HcStrlen(TEST_SALT.c_str());
    uint8_t *challengeVal = static_cast<uint8_t *>(HcMalloc(challengeLen, 0));
    EXPECT_NE(challengeVal, nullptr);
    (void)memcpy_s(challengeVal, challengeLen, TEST_SALT.c_str(), challengeLen);

    pakeParams.baseParams.challengeSelf.val = challengeVal;
    pakeParams.baseParams.challengeSelf.length = challengeLen;

    ret = ClientRequestStandardBindExchange(&pakeParams, &exchangeParams);
    EXPECT_NE(ret, HC_SUCCESS);

    pakeParams.baseParams.challengePeer.val = challengeVal;
    pakeParams.baseParams.challengePeer.length = challengeLen;

    ret = ClientRequestStandardBindExchange(&pakeParams, &exchangeParams);
    EXPECT_NE(ret, HC_SUCCESS);

    uint8_t nonceVal[NONCE_LENGTH] = { 0 };
    exchangeParams.nonce.val = nonceVal;
    exchangeParams.nonce.length = NONCE_LENGTH;

    // aesGcmEncrypt failed, no sessionkey
    ret = ClientRequestStandardBindExchange(&pakeParams, &exchangeParams);
    EXPECT_NE(ret, HC_SUCCESS);

    HcFree(challengeVal);
}

HWTEST_F(StandardExchangeTaskTest, StandardExchangeTaskTest003, TestSize.Level0)
{
    PakeParams pakeParams;
    pakeParams.userType = KEY_ALIAS_PSK;
    pakeParams.packageName = const_cast<char *>(TEST_APP_ID.c_str());
    pakeParams.serviceType = const_cast<char *>(TEST_GROUP_ID.c_str());
    uint8_t authId[AUTH_ID_LENGTH] = { 0 };
    (void)memcpy_s(authId, AUTH_ID_LENGTH, TEST_AUTH_ID.c_str(), AUTH_ID_LENGTH);
    pakeParams.baseParams.idSelf.val = authId;
    pakeParams.baseParams.idSelf.length = AUTH_ID_LENGTH;
    pakeParams.baseParams.loader = GetLoaderInstance();

    StandardBindExchangeParams exchangeParams;
    exchangeParams.exInfoCipher.length = INVALID_CIPHER_LENGTH;

    int32_t ret = ServerResponseStandardBindExchange(&pakeParams, &exchangeParams);
    EXPECT_EQ(ret, HC_ERR_ALLOC_MEMORY);

    exchangeParams.exInfoCipher.length = VALID_CIPHER_LENGTH;
    ret = ServerResponseStandardBindExchange(&pakeParams, &exchangeParams);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(StandardExchangeTaskTest, StandardExchangeTaskTest004, TestSize.Level0)
{
    PakeParams pakeParams;
    pakeParams.packageName = const_cast<char *>(TEST_APP_ID.c_str());
    pakeParams.serviceType = const_cast<char *>(TEST_GROUP_ID.c_str());
    int32_t ret = ClientConfirmStandardBindExchange(&pakeParams, nullptr);
    ASSERT_NE(ret, HC_SUCCESS);
}
}