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

#include <gtest/gtest.h>
#include "securec.h"
#include "hal_error.h"
#include "clib_error.h"
#include "hks_param.h"
#include "hc_types.h"
#include "hks_type.h"
#include "account_module_defines.h"
#include "crypto_hash_to_point.h"
#include "mbedtls_ec_adapter.h"
#include "huks_adapter.h"
#include "string_util.h"
#include "alg_loader.h"

using namespace std;
using namespace testing::ext;

namespace {
static const int32_t KEY_BYTES_CURVE25519 = 32;
static const int32_t SHA_256_LENGTH = 32;
static const int32_t DEFAULT_RAND_LEN = 32;
static const int32_t EC_LEN = 64;
static const int32_t P256_PUBLIC_SIZE = 64;
static const int32_t BIGNUM_HEX_LEN = 512;

class KeyManagementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void KeyManagementTest::SetUpTestCase() {}
void KeyManagementTest::TearDownTestCase() {}
void KeyManagementTest::SetUp() {}
void KeyManagementTest::TearDown() {}

HWTEST_F(KeyManagementTest, HashToPointTest001, TestSize.Level0)
{
    uint32_t hashSize = KEY_BYTES_CURVE25519;
    uint8_t hashData[KEY_BYTES_CURVE25519] = { 0 };
    uint8_t pointData[KEY_BYTES_CURVE25519] = { 0 };
    struct HksBlob pointBlob = { hashSize, pointData };
    struct HksBlob invalidSizeBlob = { 0, hashData };
    struct HksBlob invalidDataBlob = { hashSize, nullptr };
    int32_t ret = OpensslHashToPoint(&invalidSizeBlob, &pointBlob);
    EXPECT_EQ(ret, HKS_ERROR_MALLOC_FAIL);
    ret = OpensslHashToPoint(&invalidDataBlob, &pointBlob);
    EXPECT_EQ(ret, HAL_FAILED);
    HcFree(invalidDataBlob.data);
}

HWTEST_F(KeyManagementTest, MbedtlsHashToPointTest001, TestSize.Level0)
{
    uint8_t hashData[SHA256_LEN] = { 0 };
    uint8_t pointData[EC_LEN] = { 0 };
    Uint8Buff hashBuffer = { hashData, SHA256_LEN };
    Uint8Buff pointBuffer = { pointData, EC_LEN };
    Uint8Buff invalidBuffer = { hashData, 0 };
    Uint8Buff shortPointBuffer = { hashData, EC_LEN - 1 };
    int32_t ret = MbedtlsHashToPoint(&hashBuffer, &pointBuffer);
    EXPECT_EQ(ret, HAL_SUCCESS);
    ret = MbedtlsHashToPoint(nullptr, &pointBuffer);
    EXPECT_EQ(ret, HAL_ERR_NULL_PTR);
    ret = MbedtlsHashToPoint(&hashBuffer, nullptr);
    EXPECT_EQ(ret, HAL_ERR_NULL_PTR);
    ret = MbedtlsHashToPoint(&invalidBuffer, &pointBuffer);
    EXPECT_EQ(ret, HAL_ERR_INVALID_LEN);
    ret = MbedtlsHashToPoint(&hashBuffer, &shortPointBuffer);
    EXPECT_EQ(ret, HAL_ERR_INVALID_LEN);
}

HWTEST_F(KeyManagementTest, MbedtlsSharedSecretTest001, TestSize.Level0)
{
    uint8_t keyData[P256_PUBLIC_SIZE] = { 0 };
    KeyBuff priKeyBuffer = { keyData, P256_PUBLIC_SIZE, false };
    KeyBuff pubKeyBuffer = { keyData, P256_PUBLIC_SIZE, false };
    Uint8Buff sharedKeyBuffer = { keyData, P256_PUBLIC_SIZE };
    int32_t ret = MbedtlsAgreeSharedSecret(&priKeyBuffer, &pubKeyBuffer, &sharedKeyBuffer);
    EXPECT_EQ(ret, HAL_SUCCESS);
    KeyBuff keyInvalidBuff01 = { keyData, 0, false };
    ret = MbedtlsAgreeSharedSecret(&keyInvalidBuff01, &pubKeyBuffer, &sharedKeyBuffer);
    EXPECT_EQ(ret, HAL_ERR_INVALID_LEN);
    KeyBuff keyInvalidBuff02 = { keyData, P256_PUBLIC_SIZE - 1, false };
    ret = MbedtlsAgreeSharedSecret(&priKeyBuffer, &keyInvalidBuff02, &sharedKeyBuffer);
    EXPECT_EQ(ret, HAL_FAILED);
}

HWTEST_F(KeyManagementTest, HuksAdapterTest001, TestSize.Level0)
{
    int32_t ret = GetLoaderInstance()->initAlg();
    EXPECT_EQ(ret, HAL_SUCCESS);
    uint8_t testMsgData[] = "test_message";
    uint8_t hashData[SHA_256_LENGTH] = { 0 };
    Uint8Buff msgBuff = { testMsgData, sizeof(testMsgData) };
    Uint8Buff hashBuff = { hashData, SHA_256_LENGTH };
    ret = GetLoaderInstance()->sha256(&msgBuff, &hashBuff);
    EXPECT_EQ(ret, HAL_SUCCESS);
}

HWTEST_F(KeyManagementTest, HuksAdapterTest002, TestSize.Level0)
{
    int32_t ret = GetLoaderInstance()->initAlg();
    EXPECT_EQ(ret, HAL_SUCCESS);
    uint8_t randData[DEFAULT_RAND_LEN] = { 0 };
    Uint8Buff randBuff = { randData, DEFAULT_RAND_LEN };
    ret = GetLoaderInstance()->generateRandom(&randBuff);
    EXPECT_EQ(ret, HAL_SUCCESS);
}

HWTEST_F(KeyManagementTest, HuksAdapterTest003, TestSize.Level0)
{
    int32_t ret = GetLoaderInstance()->initAlg();
    EXPECT_EQ(ret, HAL_SUCCESS);
    uint8_t keyData[P256_PUBLIC_SIZE] = { 0 };
    KeyBuff priKey = { keyData, P256_PUBLIC_SIZE, false };
    KeyBuff pubKey = { keyData, P256_PUBLIC_SIZE, false };
    Uint8Buff sharedKey = { keyData, P256_PUBLIC_SIZE };
    ret = GetLoaderInstance()->agreeSharedSecretWithStorage(&priKey, &pubKey, P256, P256_PUBLIC_SIZE, &sharedKey);
    EXPECT_EQ(ret, HAL_ERR_HUKS);
}

HWTEST_F(KeyManagementTest, HuksAdapterTest004, TestSize.Level0)
{
    int32_t ret = GetLoaderInstance()->initAlg();
    EXPECT_EQ(ret, HAL_SUCCESS);
    char bigNumHex[BIGNUM_HEX_LEN + 1] = { 0 };
    char shortNumHex[BIG_PRIME_LEN_256 + 1] = { 0 };
    char invalidCharHex[BIGNUM_HEX_LEN + 1] = { 0 };
    (void)memset_s(bigNumHex, BIGNUM_HEX_LEN, 'a', BIGNUM_HEX_LEN);
    (void)memset_s(shortNumHex, BIG_PRIME_LEN_256, 'a', BIG_PRIME_LEN_256);
    (void)memset_s(invalidCharHex, BIGNUM_HEX_LEN, 'z', BIGNUM_HEX_LEN);
    uint8_t baseData[BIGNUM_HEX_LEN] = { 0 };
    uint8_t outData[BIG_PRIME_LEN_256] = { 0 };
    Uint8Buff baseBuff = { baseData, BIGNUM_HEX_LEN };
    Uint8Buff expBuff = { baseData, BIGNUM_HEX_LEN };
    Uint8Buff outBuff = { outData, BIG_PRIME_LEN_256 };
    ret = GetLoaderInstance()->bigNumExpMod(nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = GetLoaderInstance()->bigNumExpMod(&baseBuff, &expBuff, shortNumHex, &outBuff);
    EXPECT_EQ(ret, HAL_FAILED);
    ret = GetLoaderInstance()->bigNumExpMod(&baseBuff, &expBuff, invalidCharHex, &outBuff);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
    uint32_t testLen = strlen(bigNumHex);
    EXPECT_EQ(testLen, BIGNUM_HEX_LEN);
    testLen = strlen(invalidCharHex);
    EXPECT_EQ(testLen, BIGNUM_HEX_LEN);
    ret = GetLoaderInstance()->bigNumExpMod(&baseBuff, &expBuff, bigNumHex, &outBuff);
    EXPECT_EQ(ret, HAL_SUCCESS);
}
}