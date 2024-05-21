/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "device_auth_defines.h"
#include "hc_dev_info_mock.h"
#include "mk_agree_task.h"
#include "device_auth.h"
#include "key_manager.h"
#include "string_util.h"

using namespace std;
using namespace testing::ext;

namespace {
#define PAKE_X25519_KEY_PAIR_LEN 32
#define TEST_DEVICE_ID "TestAuthId"
#define TEST_DEVICE_ID2 "TestAuthId2"
#define TEST_REAL_INFO "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b"
#define TEST_INDEX_KEY "DCBA4321"
#define TEST_DEV_PK "87364761534f454d33567a73424e794f"
#define BYTE_TO_HEX_OPER_LENGTH 2

static const std::string TEST_HKS_DATA_PATH = "/data/service/el1/public/huks_service/tmp/+0+0+0+0";
static const std::string TEST_GROUP_DATA_PATH = "/data/service/el1/public/deviceauthMock";
static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;

class MKAgreeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MKAgreeTest::SetUpTestCase() {}
void MKAgreeTest::TearDownTestCase() {}

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

void MKAgreeTest::SetUp()
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void MKAgreeTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(MKAgreeTest, GenerateDeviceKeyPairTest001, TestSize.Level0)
{
    int32_t ret = GenerateDeviceKeyPair();
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateMkTest001, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff peerPkBuff = { peerDevPkVal, peerDevPkLen };
    ret = GenerateMk(TEST_DEVICE_ID, &peerPkBuff);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = DeleteMk(TEST_DEVICE_ID);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateMkTest002, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    Uint8Buff peerPkBuff = { nullptr, peerDevPkLen };
    int32_t ret = GenerateMk(TEST_DEVICE_ID, &peerPkBuff);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateMkTest003, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff peerPkBuff = { peerDevPkVal, 0 };
    ret = GenerateMk(TEST_DEVICE_ID, &peerPkBuff);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateMkTest004, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff peerPkBuff = { peerDevPkVal, peerDevPkLen };
    ret = GenerateMk(nullptr, &peerPkBuff);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, DeleteMkTest001, TestSize.Level0)
{
    int32_t ret = DeleteMk(TEST_DEVICE_ID2);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = DeleteMk(nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = DeleteMk("");
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GeneratePseudonymPskTest001, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff salt = { peerDevPkVal, peerDevPkLen };
    ret = GeneratePseudonymPsk(TEST_DEVICE_ID, &salt);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);

    ret = DeletePseudonymPsk(TEST_DEVICE_ID);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GeneratePseudonymPskTest002, TestSize.Level0)
{
    Uint8Buff salt = { nullptr, 0 };
    int32_t ret = GeneratePseudonymPsk(TEST_DEVICE_ID, &salt);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GeneratePseudonymPskTest003, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff salt = { peerDevPkVal, peerDevPkLen };
    ret = GeneratePseudonymPsk(nullptr, &salt);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateAndSavePseudonymIdTest001, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff salt = { peerDevPkVal, peerDevPkLen };
    Uint8Buff tmpKcfData = { NULL, 0 };
    PseudonymKeyInfo info = { TEST_REAL_INFO, TEST_INDEX_KEY };
    ret = GenerateAndSavePseudonymId(DEFAULT_OS_ACCOUNT, TEST_DEVICE_ID,
        &info, &salt, &tmpKcfData);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateAndSavePseudonymIdTest002, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff salt = { peerDevPkVal, peerDevPkLen };
    Uint8Buff tmpKcfData = { NULL, 0 };
    PseudonymKeyInfo info = { TEST_REAL_INFO, TEST_INDEX_KEY };
    ret = GenerateAndSavePseudonymId(DEFAULT_OS_ACCOUNT, nullptr,
        &info, &salt, &tmpKcfData);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateAndSavePseudonymIdTest003, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff salt = { peerDevPkVal, peerDevPkLen };
    Uint8Buff tmpKcfData = { NULL, 0 };
    PseudonymKeyInfo info = { nullptr, nullptr };
    ret = GenerateAndSavePseudonymId(DEFAULT_OS_ACCOUNT, TEST_DEVICE_ID,
        &info, &salt, &tmpKcfData);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateAndSavePseudonymIdTest004, TestSize.Level0)
{
    uint32_t peerDevPkLen = HcStrlen(TEST_DEV_PK) / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t *peerDevPkVal = static_cast<uint8_t *>(HcMalloc(peerDevPkLen, 0));
    ASSERT_NE(peerDevPkVal, nullptr);
    int32_t ret = HexStringToByte(TEST_DEV_PK, peerDevPkVal, peerDevPkLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff salt = { peerDevPkVal, 0 };
    Uint8Buff tmpKcfData = { NULL, 0 };
    PseudonymKeyInfo info = { TEST_REAL_INFO, TEST_INDEX_KEY };
    ret = GenerateAndSavePseudonymId(DEFAULT_OS_ACCOUNT, TEST_DEVICE_ID,
        &info, &salt, &tmpKcfData);
    HcFree(peerDevPkVal);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GenerateAndSavePseudonymIdTest005, TestSize.Level0)
{
    Uint8Buff salt = { nullptr, 0 };
    Uint8Buff tmpKcfData = { NULL, 0 };
    PseudonymKeyInfo info = { TEST_REAL_INFO, TEST_INDEX_KEY };
    int32_t ret = GenerateAndSavePseudonymId(DEFAULT_OS_ACCOUNT, TEST_DEVICE_ID,
        &info, &salt, &tmpKcfData);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(MKAgreeTest, GetDevicePubKeyTest001, TestSize.Level0)
{
    int32_t ret = GenerateDeviceKeyPair();
    EXPECT_EQ(ret, HC_SUCCESS);
    Uint8Buff devicePk = { NULL, 0 };
    ret = InitUint8Buff(&devicePk, PAKE_X25519_KEY_PAIR_LEN);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = GetDevicePubKey(&devicePk);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeUint8Buff(&devicePk);
}

HWTEST_F(MKAgreeTest, GetDevicePubKeyTest002, TestSize.Level0)
{
    Uint8Buff devicePk = { NULL, 0 };
    int32_t ret = GetDevicePubKey(&devicePk);
    EXPECT_NE(ret, HC_SUCCESS);
}
}