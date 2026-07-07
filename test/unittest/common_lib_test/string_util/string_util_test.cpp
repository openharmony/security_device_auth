/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "string_util.h"
#include "clib_error.h"
#include "hc_types.h"
#include "securec.h"

using namespace testing::ext;

namespace {
static const uint32_t TEST_BUFFER_SIZE = 32;
static const uint32_t TEST_BUFFER_SIZE_ZERO = 0;
static const uint32_t TEST_MIN_ANONYMOUS_LEN = 6;

class StringUtilTest : public testing::Test {
};


HWTEST_F(StringUtilTest, ToUpperCaseTest001, TestSize.Level0)
{
    const char *lowerStr = "hello";
    char *upperStr = nullptr;
    int32_t ret = ToUpperCase(lowerStr, &upperStr);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_NE(upperStr, nullptr);
    const char *expected = "HELLO";
    for (uint32_t i = 0; i < HcStrlen(expected); i++) {
        EXPECT_EQ(upperStr[i], expected[i]);
    }
    HcFree(upperStr);
}

HWTEST_F(StringUtilTest, ToUpperCaseTest002, TestSize.Level0)
{
    const char *mixedStr = "HeLLo WoRLd";
    char *upperStr = nullptr;
    int32_t ret = ToUpperCase(mixedStr, &upperStr);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_NE(upperStr, nullptr);
    const char *expected = "HELLO WORLD";
    for (uint32_t i = 0; i < HcStrlen(expected); i++) {
        EXPECT_EQ(upperStr[i], expected[i]);
    }
    HcFree(upperStr);
}

HWTEST_F(StringUtilTest, ToUpperCaseTest003, TestSize.Level0)
{
    const char *upperStr = "HELLO";
    char *resultStr = nullptr;
    int32_t ret = ToUpperCase(upperStr, &resultStr);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_NE(resultStr, nullptr);
    for (uint32_t i = 0; i < HcStrlen(upperStr); i++) {
        EXPECT_EQ(resultStr[i], upperStr[i]);
    }
    HcFree(resultStr);
}

HWTEST_F(StringUtilTest, ToUpperCaseTest004, TestSize.Level0)
{
    const char *nullStr = nullptr;
    char *upperStr = nullptr;
    int32_t ret = ToUpperCase(nullStr, &upperStr);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, ToUpperCaseTest005, TestSize.Level0)
{
    const char *testStr = "hello";
    int32_t ret = ToUpperCase(testStr, nullptr);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, DeepCopyStringTest001, TestSize.Level0)
{
    const char *original = "test string";
    char *copy = nullptr;
    int32_t ret = DeepCopyString(original, &copy);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_NE(copy, nullptr);
    for (uint32_t i = 0; i < HcStrlen(original); i++) {
        EXPECT_EQ(copy[i], original[i]);
    }
    HcFree(copy);
}

HWTEST_F(StringUtilTest, DeepCopyStringTest002, TestSize.Level0)
{
    const char *nullStr = nullptr;
    char *copy = nullptr;
    int32_t ret = DeepCopyString(nullStr, &copy);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, DeepCopyStringTest003, TestSize.Level0)
{
    const char *testStr = "test";
    int32_t ret = DeepCopyString(testStr, nullptr);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, DeepCopyStringTest004, TestSize.Level0)
{
    const char *emptyStr = "";
    char *copy = nullptr;
    int32_t ret = DeepCopyString(emptyStr, &copy);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_LEN);
}

HWTEST_F(StringUtilTest, GetAnonymousStringTest001, TestSize.Level0)
{
    const char *original = "teststring";
    char anonymous[TEST_MIN_ANONYMOUS_LEN + 2] = { 0 };
    int32_t ret = GetAnonymousString(original, anonymous, TEST_MIN_ANONYMOUS_LEN + 2, true);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(anonymous[0], 't');
    EXPECT_EQ(anonymous[1], 'e');
    EXPECT_EQ(anonymous[2], 's');
    EXPECT_EQ(anonymous[3], '*');
    EXPECT_EQ(anonymous[4], '*');
    EXPECT_EQ(anonymous[5], 'i');
    EXPECT_EQ(anonymous[6], 'n');
    EXPECT_EQ(anonymous[7], 'g');
}

HWTEST_F(StringUtilTest, GetAnonymousStringTest002, TestSize.Level0)
{
    const char *original = "teststring";
    char anonymous[TEST_MIN_ANONYMOUS_LEN + 2] = { 0 };
    int32_t ret = GetAnonymousString(original, anonymous, TEST_MIN_ANONYMOUS_LEN + 2, false);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(anonymous[0], 't');
    EXPECT_EQ(anonymous[1], 'e');
    EXPECT_EQ(anonymous[2], 's');
    EXPECT_EQ(anonymous[3], 't');
    EXPECT_EQ(anonymous[4], 's');
    EXPECT_EQ(anonymous[5], 't');
    EXPECT_EQ(anonymous[6], '*');
    EXPECT_EQ(anonymous[7], '*');
}

HWTEST_F(StringUtilTest, GetAnonymousStringTest003, TestSize.Level0)
{
    const char *original = "test";
    char anonymous[TEST_MIN_ANONYMOUS_LEN + 2] = { 0 };
    int32_t ret = GetAnonymousString(original, anonymous, TEST_MIN_ANONYMOUS_LEN + 2, true);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_LEN);
}

HWTEST_F(StringUtilTest, GetAnonymousStringTest004, TestSize.Level0)
{
    const char *original = "teststring";
    int32_t ret = GetAnonymousString(original, nullptr, TEST_MIN_ANONYMOUS_LEN + 2, true);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, GetAnonymousStringTest005, TestSize.Level0)
{
    const char *nullStr = nullptr;
    char anonymous[TEST_MIN_ANONYMOUS_LEN + 2] = { 0 };
    int32_t ret = GetAnonymousString(nullStr, anonymous, TEST_MIN_ANONYMOUS_LEN + 2, true);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, GetAnonymousStringTest006, TestSize.Level0)
{
    const char *original = "teststring";
    char anonymous[TEST_MIN_ANONYMOUS_LEN] = { 0 };
    int32_t ret = GetAnonymousString(original, anonymous, TEST_MIN_ANONYMOUS_LEN, true);
    EXPECT_EQ(ret, CLIB_SUCCESS);
}

HWTEST_F(StringUtilTest, GenerateStringFromDataTest001, TestSize.Level0)
{
    const uint8_t data[] = "test data";
    char *outStr = nullptr;
    int32_t ret = GenerateStringFromData(data, sizeof(data) - 1, &outStr);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_NE(outStr, nullptr);
    for (uint32_t i = 0; i < sizeof(data) - 1; i++) {
        EXPECT_EQ(outStr[i], data[i]);
    }
    HcFree(outStr);
}

HWTEST_F(StringUtilTest, GenerateStringFromDataTest002, TestSize.Level0)
{
    const uint8_t data[] = "test";
    int32_t ret = GenerateStringFromData(data, sizeof(data) - 1, nullptr);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
}

HWTEST_F(StringUtilTest, GenerateStringFromDataTest003, TestSize.Level0)
{
    char *outStr = nullptr;
    int32_t ret = GenerateStringFromData(nullptr, TEST_BUFFER_SIZE, &outStr);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
}

HWTEST_F(StringUtilTest, GenerateStringFromDataTest004, TestSize.Level0)
{
    const uint8_t data[] = "test";
    char *outStr = nullptr;
    int32_t ret = GenerateStringFromData(data, TEST_BUFFER_SIZE_ZERO, &outStr);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
}

HWTEST_F(StringUtilTest, IsStrEqualTest001, TestSize.Level0)
{
    EXPECT_EQ(IsStrEqual(nullptr, nullptr), true);
}

HWTEST_F(StringUtilTest, IsStrEqualTest002, TestSize.Level0)
{
    EXPECT_EQ(IsStrEqual("test", nullptr), false);
}

HWTEST_F(StringUtilTest, IsStrEqualTest003, TestSize.Level0)
{
    EXPECT_EQ(IsStrEqual(nullptr, "test"), false);
}

HWTEST_F(StringUtilTest, IsStrEqualTest004, TestSize.Level0)
{
    EXPECT_EQ(IsStrEqual("test", "test"), true);
}

HWTEST_F(StringUtilTest, IsStrEqualTest005, TestSize.Level0)
{
    EXPECT_EQ(IsStrEqual("test", "Test"), false);
}

HWTEST_F(StringUtilTest, IsStrEqualTest006, TestSize.Level0)
{
    EXPECT_EQ(IsStrEqual("test", "testing"), false);
}

HWTEST_F(StringUtilTest, IsStrEqualTest007, TestSize.Level0)
{
    EXPECT_EQ(IsStrEqual("", ""), true);
}

HWTEST_F(StringUtilTest, IsStrEqualTest008, TestSize.Level0)
{
    EXPECT_EQ(IsStrEqual("", "test"), false);
}

HWTEST_F(StringUtilTest, StringToInt64Test001, TestSize.Level0)
{
    const char *numStr = "12345";
    int64_t result = StringToInt64(numStr);
    EXPECT_EQ(result, 12345);
}

HWTEST_F(StringUtilTest, StringToInt64Test002, TestSize.Level0)
{
    const char *numStr = "-12345";
    int64_t result = StringToInt64(numStr);
    EXPECT_EQ(result, -12345);
}

HWTEST_F(StringUtilTest, StringToInt64Test003, TestSize.Level0)
{
    int64_t result = StringToInt64(nullptr);
    EXPECT_EQ(result, 0);
}

HWTEST_F(StringUtilTest, StringToInt64Test004, TestSize.Level0)
{
    const char *numStr = "0";
    int64_t result = StringToInt64(numStr);
    EXPECT_EQ(result, 0);
}

HWTEST_F(StringUtilTest, ByteToHexStringTest001, TestSize.Level0)
{
    uint8_t byte[] = {0x01, 0x0A, 0xFF};
    char hexStr[7] = {0};
    int32_t ret = ByteToHexString(byte, sizeof(byte), hexStr, sizeof(hexStr));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_STREQ(hexStr, "010AFF");
}

HWTEST_F(StringUtilTest, ByteToHexStringTest002, TestSize.Level0)
{
    char hexStr[7] = {0};
    int32_t ret = ByteToHexString(NULL, 3, hexStr, 7);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, ByteToHexStringTest003, TestSize.Level0)
{
    uint8_t byte[] = {0x01};
    int32_t ret = ByteToHexString(byte, 1, NULL, 3);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, ByteToHexStringTest004, TestSize.Level0)
{
    uint8_t byte[] = {0x01, 0x0A, 0xFF};
    char hexStr[7] = {0};
    int32_t ret = ByteToHexString(byte, sizeof(byte), hexStr, 6);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_LEN);
}

HWTEST_F(StringUtilTest, ByteToHexStringTest005, TestSize.Level0)
{
    uint8_t byte[] = {0x00, 0x01, 0x09, 0x0A, 0x0F, 0x10, 0x1A, 0x1F, 0xFF};
    char hexStr[19] = {0};
    int32_t ret = ByteToHexString(byte, sizeof(byte), hexStr, sizeof(hexStr));
    EXPECT_EQ(ret, CLIB_SUCCESS);
}

HWTEST_F(StringUtilTest, ByteToHexStringTest006, TestSize.Level0)
{
    uint8_t byte[] = {0};
    char hexStr[3] = {0};
    int32_t ret = ByteToHexString(byte, 0, hexStr, sizeof(hexStr));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_STREQ(hexStr, "");
}

HWTEST_F(StringUtilTest, HexStringToByteTest001, TestSize.Level0)
{
    const char *hexStr = "010aff";
    uint8_t byte[3] = {0};
    int32_t ret = HexStringToByte(hexStr, byte, sizeof(byte));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(byte[0], 0x01);
    EXPECT_EQ(byte[1], 0x0A);
    EXPECT_EQ(byte[2], 0xFF);
}

HWTEST_F(StringUtilTest, HexStringToByteTest002, TestSize.Level0)
{
    uint8_t byte[3] = {0};
    int32_t ret = HexStringToByte(NULL, byte, sizeof(byte));
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, HexStringToByteTest003, TestSize.Level0)
{
    const char *hexStr = "010aff";
    int32_t ret = HexStringToByte(hexStr, NULL, 3);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(StringUtilTest, HexStringToByteTest004, TestSize.Level0)
{
    const char *hexStr = "abc";
    uint8_t byte[2] = {0};
    int32_t ret = HexStringToByte(hexStr, byte, sizeof(byte));
    EXPECT_EQ(ret, CLIB_ERR_INVALID_LEN);
}

HWTEST_F(StringUtilTest, HexStringToByteTest005, TestSize.Level0)
{
    const char *hexStr = "010aff";
    uint8_t byte[2] = {0};
    int32_t ret = HexStringToByte(hexStr, byte, 2);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_LEN);
}

HWTEST_F(StringUtilTest, HexStringToByteTest006, TestSize.Level0)
{
    const char *hexStr = "0A1BXY";
    uint8_t byte[3] = {0};
    int32_t ret = HexStringToByte(hexStr, byte, sizeof(byte));
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
}

HWTEST_F(StringUtilTest, HexStringToByteTest007, TestSize.Level0)
{
    const char *hexStr = "0A1B2C";
    uint8_t byte[3] = {0};
    int32_t ret = HexStringToByte(hexStr, byte, sizeof(byte));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(byte[0], 0x0A);
    EXPECT_EQ(byte[1], 0x1B);
    EXPECT_EQ(byte[2], 0x2C);
}

HWTEST_F(StringUtilTest, HexStringToByteTest008, TestSize.Level0)
{
    const char *hexStr = "0a1b2c";
    uint8_t byte[3] = {0};
    int32_t ret = HexStringToByte(hexStr, byte, sizeof(byte));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(byte[0], 0x0A);
    EXPECT_EQ(byte[1], 0x1B);
    EXPECT_EQ(byte[2], 0x2C);
}

HWTEST_F(StringUtilTest, HexStringToByteTest009, TestSize.Level0)
{
    const char *hexStr = "0112";
    uint8_t byte[2] = {0};
    int32_t ret = HexStringToByte(hexStr, byte, sizeof(byte));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(byte[0], 0x01);
    EXPECT_EQ(byte[1], 0x12);
}

HWTEST_F(StringUtilTest, PrintBufferTest001, TestSize.Level0)
{
    uint8_t msg[] = {0x01, 0x02, 0x03, 0x04};
    PrintBuffer(msg, sizeof(msg), "TestTag");
}

HWTEST_F(StringUtilTest, PrintBufferTest002, TestSize.Level0)
{
    uint8_t msg[] = {0};
    PrintBuffer(msg, 0, "TestTag");
}

HWTEST_F(StringUtilTest, PrintBufferTest003, TestSize.Level0)
{
    PrintBuffer(NULL, 0, "TestTag");
}
}
