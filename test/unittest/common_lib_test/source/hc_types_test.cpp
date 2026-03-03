/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "hc_types.h"
#include "securec.h"

using namespace testing::ext;

namespace {
static const uint32_t TEST_MALLOC_SIZE = 16;
static const uint32_t TEST_MALLOC_SIZE_LARGE = 1024;
static const uint32_t TEST_MALLOC_SIZE_ZERO = 0;
static const char TEST_MALLOC_VAL = 0xAA;
static const char TEST_MALLOC_VAL_ZERO = 0x00;

class HcTypesTest : public testing::Test {
public:
};

HWTEST_F(HcTypesTest, HcMallocTest001, TestSize.Level0)
{
    void *ptr = HcMalloc(TEST_MALLOC_SIZE, TEST_MALLOC_VAL);
    ASSERT_NE(ptr, nullptr);
    uint8_t *bytePtr = static_cast<uint8_t *>(ptr);
    for (uint32_t i = 0; i < TEST_MALLOC_SIZE; i++) {
        EXPECT_EQ(bytePtr[i], TEST_MALLOC_VAL);
    }
    HcFree(ptr);
}

HWTEST_F(HcTypesTest, HcMallocTest002, TestSize.Level0)
{
    void *ptr = HcMalloc(TEST_MALLOC_SIZE_LARGE, TEST_MALLOC_VAL_ZERO);
    ASSERT_NE(ptr, nullptr);
    uint8_t *bytePtr = static_cast<uint8_t *>(ptr);
    for (uint32_t i = 0; i < TEST_MALLOC_SIZE_LARGE; i++) {
        EXPECT_EQ(bytePtr[i], TEST_MALLOC_VAL_ZERO);
    }
    HcFree(ptr);
}

HWTEST_F(HcTypesTest, HcMallocTest003, TestSize.Level0)
{
    void *ptr = HcMalloc(TEST_MALLOC_SIZE_ZERO, TEST_MALLOC_VAL);
    EXPECT_EQ(ptr, nullptr);
}

HWTEST_F(HcTypesTest, HcFreeTest001, TestSize.Level0)
{
    HcFree(nullptr);
}

HWTEST_F(HcTypesTest, HcFreeTest002, TestSize.Level0)
{
    void *ptr = HcMalloc(TEST_MALLOC_SIZE, TEST_MALLOC_VAL);
    ASSERT_NE(ptr, nullptr);
    HcFree(ptr);
}

HWTEST_F(HcTypesTest, HcStrlenTest001, TestSize.Level0)
{
    const char *emptyStr = "";
    uint32_t len = HcStrlen(emptyStr);
    EXPECT_EQ(len, 0);
}

HWTEST_F(HcTypesTest, HcStrlenTest002, TestSize.Level0)
{
    const char *nullStr = nullptr;
    uint32_t len = HcStrlen(nullStr);
    EXPECT_EQ(len, 0);
}

HWTEST_F(HcTypesTest, HcStrlenTest003, TestSize.Level0)
{
    const char *shortStr = "hello";
    uint32_t len = HcStrlen(shortStr);
    EXPECT_EQ(len, 5);
}

HWTEST_F(HcTypesTest, HcStrlenTest004, TestSize.Level0)
{
    const char *longStr = "This is a longer string for testing purposes";
    uint32_t len = HcStrlen(longStr);
    EXPECT_EQ(len, 44);
}

HWTEST_F(HcTypesTest, HcStrlenTest005, TestSize.Level0)
{
    char buffer[256];
    (void)memset_s(buffer, sizeof(buffer), 'A', sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    uint32_t len = HcStrlen(buffer);
    EXPECT_EQ(len, 255);
}

HWTEST_F(HcTypesTest, HcStrlenTest006, TestSize.Level0)
{
    char buffer[512 * 1024];
    (void)memset_s(buffer, sizeof(buffer), 'B', sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    uint32_t len = HcStrlen(buffer);
    EXPECT_EQ(len, 512 * 1024 - 1);
}

HWTEST_F(HcTypesTest, HcStrlenTest007, TestSize.Level0)
{
    const char *strWithSpaces = "hello world";
    uint32_t len = HcStrlen(strWithSpaces);
    EXPECT_EQ(len, 11);
}

HWTEST_F(HcTypesTest, HcStrlenTest008, TestSize.Level0)
{
    const char *strWithSpecialChars = "test\nstring\twith\rchars";
    uint32_t len = HcStrlen(strWithSpecialChars);
    EXPECT_EQ(len, 22);
}
}