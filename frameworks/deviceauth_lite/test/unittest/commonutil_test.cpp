/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "commonutil_test.h"
#include "hichain.h"

using namespace testing::ext;

namespace {
class HexStringToByteTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HexStringToByteTest::SetUpTestCase(void) {}

void HexStringToByteTest::TearDownTestCase(void) {}

void HexStringToByteTest::SetUp(void) {}

void HexStringToByteTest::TearDown(void) {}


// 测试正常情况 - 小写字母
HWTEST_F(HexStringToByteTest, NormalCaseLowerCase, TestSize.Level0) {
    const char* input = "1a2b3c";
    uint8_t output[3];
    int32_t result = hex_string_to_byte(input, 6, output, 3);
    EXPECT_EQ(result, HC_OK);
    EXPECT_EQ(output[0], 0x1A);
    EXPECT_EQ(output[1], 0x2B);
    EXPECT_EQ(output[2], 0x3C);
}

// 测试正常情况 - 大写字母
HWTEST_F(HexStringToByteTest, NormalCaseUpperCase, TestSize.Level0) {
    const char* input = "1A2B3C";
    uint8_t output[3];
    int32_t result = hex_string_to_byte(input, 6, output, 3);
    EXPECT_EQ(result, HC_OK);
    EXPECT_EQ(output[0], 0x1A);
    EXPECT_EQ(output[1], 0x2B);
    EXPECT_EQ(output[2], 0x3C);
}

// 测试边界情况 - 最小长度
HWTEST_F(HexStringToByteTest, MinLength, TestSize.Level0) {
    const char* input = "1A";
    uint8_t output[1];
    int32_t result = hex_string_to_byte(input, 2, output, 1);
    EXPECT_EQ(result, HC_OK);
    EXPECT_EQ(output[0], 0x1A);
}

// 测试错误情况 - 奇数长度
HWTEST_F(HexStringToByteTest, OddLength, TestSize.Level0) {
    const char* input = "1A2";
    uint8_t output[2];
    int32_t result = hex_string_to_byte(input, 3, output, 2);
    EXPECT_EQ(result, HC_INPUT_ERROR);
}

// 测试错误情况 - 长度不匹配
HWTEST_F(HexStringToByteTest, LengthMismatch, TestSize.Level0) {
    const char* input = "1A2B";
    uint8_t output[3];
    int32_t result = hex_string_to_byte(input, 4, output, 3);
    EXPECT_EQ(result, HC_INPUT_ERROR);
}

// 测试错误情况 - 非法字符
HWTEST_F(HexStringToByteTest, InvalidCharacter, TestSize.Level0) {
    const char* input = "1X2B";
    uint8_t output[2];
    int32_t result = hex_string_to_byte(input, 4, output, 2);
    EXPECT_EQ(result, HC_INPUT_ERROR);
}

// 测试边界情况 - 全零
HWTEST_F(HexStringToByteTest, AllZero, TestSize.Level0) {
    const char* input = "0000";
    uint8_t output[2];
    int32_t result = hex_string_to_byte(input, 4, output, 2);
    EXPECT_EQ(result, HC_OK);
    EXPECT_EQ(output[0], 0x00);
    EXPECT_EQ(output[1], 0x00);
}

// 测试边界情况 - 全F
HWTEST_F(HexStringToByteTest, AllF, TestSize.Level0) {
    const char* input = "FFFF";
    uint8_t output[2];
    int32_t result = hex_string_to_byte(input, 4, output, 2);
    EXPECT_EQ(result, HC_OK);
    EXPECT_EQ(output[0], 0xFF);
    EXPECT_EQ(output[1], 0xFF);
}
}