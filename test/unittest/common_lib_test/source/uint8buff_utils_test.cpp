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

#include <gtest/gtest.h>
#include "uint8buff_utils.h"
#include "clib_error.h"
#include "hc_types.h"
#include "securec.h"

using namespace testing::ext;

namespace {
static const uint32_t TEST_BUFFER_SIZE = 16;
static const uint32_t TEST_BUFFER_SIZE_LARGE = 256;
static const uint32_t TEST_BUFFER_SIZE_ZERO = 0;
static const uint32_t TEST_MAX_LEN = 255;
}

class Uint8BuffUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Uint8BuffUtilsTest::SetUpTestCase() {}
void Uint8BuffUtilsTest::TearDownTestCase() {}
void Uint8BuffUtilsTest::SetUp() {}
void Uint8BuffUtilsTest::TearDown() {}

HWTEST_F(Uint8BuffUtilsTest, InitUint8BuffTest001, TestSize.Level0)
{
    Uint8Buff buff;
    int32_t ret = InitUint8Buff(&buff, TEST_BUFFER_SIZE);
    EXPECT_EQ(ret,     CLIB_SUCCESS);
    EXPECT_NE(buff.val, nullptr);
    EXPECT_EQ(buff.length, TEST_BUFFER_SIZE);
    FreeUint8Buff(&buff);
}

HWTEST_F(Uint8BuffUtilsTest, InitUint8BuffTest002, TestSize.Level0)
{
    int32_t ret = InitUint8Buff(nullptr, TEST_BUFFER_SIZE);
    EXPECT_EQ(ret,     CLIB_ERR_NULL_PTR);
}

HWTEST_F(Uint8BuffUtilsTest, InitUint8BuffTest003, TestSize.Level0)
{
    Uint8Buff buff;
    int32_t ret = InitUint8Buff(&buff, TEST_BUFFER_SIZE_ZERO);
    EXPECT_EQ(ret,     CLIB_ERR_INVALID_LEN);
}

HWTEST_F(Uint8BuffUtilsTest, DeepCopyUint8BuffTest001, TestSize.Level0)
{
    Uint8Buff srcBuff;
    Uint8Buff dstBuff;
    int32_t ret = InitUint8Buff(&srcBuff, TEST_BUFFER_SIZE);
    EXPECT_EQ(ret,     CLIB_SUCCESS);
    
    for (uint32_t i = 0; i < srcBuff.length; i++) {
        srcBuff.val[i] = static_cast<uint8_t>(i);
    }
    
    ret = DeepCopyUint8Buff(&srcBuff, &dstBuff);
    EXPECT_EQ(ret,     CLIB_SUCCESS);
    EXPECT_NE(dstBuff.val, nullptr);
    EXPECT_EQ(dstBuff.length, srcBuff.length);
    
    for (uint32_t i = 0; i < srcBuff.length; i++) {
        EXPECT_EQ(dstBuff.val[i], srcBuff.val[i]);
    }
    
    FreeUint8Buff(&srcBuff);
    FreeUint8Buff(&dstBuff);
}

HWTEST_F(Uint8BuffUtilsTest, DeepCopyUint8BuffTest002, TestSize.Level0)
{
    Uint8Buff srcBuff;
    int32_t ret = DeepCopyUint8Buff(nullptr, &srcBuff);
    EXPECT_EQ(ret,     CLIB_ERR_NULL_PTR);
}

HWTEST_F(Uint8BuffUtilsTest, DeepCopyUint8BuffTest003, TestSize.Level0)
{
    Uint8Buff srcBuff;
    int32_t ret = DeepCopyUint8Buff(&srcBuff, nullptr);
    EXPECT_EQ(ret,     CLIB_ERR_NULL_PTR);
}

HWTEST_F(Uint8BuffUtilsTest, DeepCopyUint8BuffTest004, TestSize.Level0)
{
    Uint8Buff srcBuff = { nullptr, 0 };
    Uint8Buff dstBuff;
    int32_t ret = DeepCopyUint8Buff(&srcBuff, &dstBuff);
    EXPECT_EQ(ret,     CLIB_ERR_NULL_PTR);
}

HWTEST_F(Uint8BuffUtilsTest, FreeUint8BuffTest001, TestSize.Level0)
{
    Uint8Buff buff;
    InitUint8Buff(&buff, TEST_BUFFER_SIZE);
    FreeUint8Buff(&buff);
    EXPECT_EQ(buff.val, nullptr);
    EXPECT_EQ(buff.length, 0);
}

HWTEST_F(Uint8BuffUtilsTest, FreeUint8BuffTest002, TestSize.Level0)
{
    FreeUint8Buff(nullptr);
}

HWTEST_F(Uint8BuffUtilsTest, FreeUint8BuffTest003, TestSize.Level0)
{
    Uint8Buff buff = { nullptr, 0 };
    FreeUint8Buff(&buff);
}

HWTEST_F(Uint8BuffUtilsTest, ClearFreeUint8BuffTest001, TestSize.Level0)
{
    Uint8Buff buff;
    InitUint8Buff(&buff, TEST_BUFFER_SIZE);
    
    for (uint32_t i = 0; i < buff.length; i++) {
        buff.val[i] = 0xAA;
    }
    
    ClearFreeUint8Buff(&buff);
    EXPECT_EQ(buff.val, nullptr);
    EXPECT_EQ(buff.length, 0);
}

HWTEST_F(Uint8BuffUtilsTest, ClearFreeUint8BuffTest002, TestSize.Level0)
{
    ClearFreeUint8Buff(nullptr);
}

HWTEST_F(Uint8BuffUtilsTest, ClearFreeUint8BuffTest003, TestSize.Level0)
{
    Uint8Buff buff = { nullptr, 0 };
    ClearFreeUint8Buff(&buff);
}

HWTEST_F(Uint8BuffUtilsTest, IsUint8BuffValidTest001, TestSize.Level0)
{
    Uint8Buff buff;
    InitUint8Buff(&buff, TEST_BUFFER_SIZE);
    
    bool valid = IsUint8BuffValid(&buff, TEST_MAX_LEN);
    EXPECT_EQ(valid, true);
    
    FreeUint8Buff(&buff);
}

HWTEST_F(Uint8BuffUtilsTest, IsUint8BuffValidTest002, TestSize.Level0)
{
    bool valid = IsUint8BuffValid(nullptr, TEST_MAX_LEN);
    EXPECT_EQ(valid, false);
}

HWTEST_F(Uint8BuffUtilsTest, IsUint8BuffValidTest003, TestSize.Level0)
{
    Uint8Buff buff = { nullptr, 0 };
    bool valid = IsUint8BuffValid(&buff, TEST_MAX_LEN);
    EXPECT_EQ(valid, false);
}

HWTEST_F(Uint8BuffUtilsTest, IsUint8BuffValidTest004, TestSize.Level0)
{
    Uint8Buff buff;
    InitUint8Buff(&buff, TEST_BUFFER_SIZE_LARGE);
    
    bool valid = IsUint8BuffValid(&buff, TEST_MAX_LEN);
    EXPECT_EQ(valid, false);
    
    FreeUint8Buff(&buff);
}

HWTEST_F(Uint8BuffUtilsTest, ToLowerCaseTest001, TestSize.Level0)
{
    Uint8Buff buff;
    InitUint8Buff(&buff, TEST_BUFFER_SIZE);
    
    const char *testStr = "HELLO WORLD";
    (void)memcpy_s(buff.val, buff.length, testStr, HcStrlen(testStr));
    
    int32_t ret = ToLowerCase(&buff);
    EXPECT_EQ(ret,     CLIB_SUCCESS);
    
    const char *expected = "hello world";
    for (uint32_t i = 0; i < HcStrlen(expected); i++) {
        EXPECT_EQ(buff.val[i], expected[i]);
    }
    
    FreeUint8Buff(&buff);
}

HWTEST_F(Uint8BuffUtilsTest, ToLowerCaseTest002, TestSize.Level0)
{
    Uint8Buff buff;
    InitUint8Buff(&buff, TEST_BUFFER_SIZE);
    
    const char *testStr = "hello world";
    (void)memcpy_s(buff.val, buff.length, testStr, HcStrlen(testStr));
    
    int32_t ret = ToLowerCase(&buff);
    EXPECT_EQ(ret,     CLIB_SUCCESS);
    
    const char *expected = "hello world";
    for (uint32_t i = 0; i < HcStrlen(expected); i++) {
        EXPECT_EQ(buff.val[i], expected[i]);
    }
    
    FreeUint8Buff(&buff);
}

HWTEST_F(Uint8BuffUtilsTest, ToLowerCaseTest003, TestSize.Level0)
{
    Uint8Buff buff;
    InitUint8Buff(&buff, TEST_BUFFER_SIZE);
    
    const char *testStr = "HeLLo WoRLd";
    (void)memcpy_s(buff.val, buff.length, testStr, HcStrlen(testStr));
    
    int32_t ret = ToLowerCase(&buff);
    EXPECT_EQ(ret,     CLIB_SUCCESS);
    
    const char *expected = "hello world";
    for (uint32_t i = 0; i < HcStrlen(expected); i++) {
        EXPECT_EQ(buff.val[i], expected[i]);
    }
    
    FreeUint8Buff(&buff);
}
