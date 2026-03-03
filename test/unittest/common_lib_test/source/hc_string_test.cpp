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
#include "hc_string.h"
#include "hc_types.h"

using namespace testing::ext;

namespace {
class HcStringTest : public testing::Test {
};

HWTEST_F(HcStringTest, StringAppendTest001, TestSize.Level0)
{
    HcString str = CreateString();
    HcString appendStr = CreateString();
    HcBool ret = StringSetPointer(&appendStr, "hello");
    EXPECT_EQ(ret, HC_TRUE);
    ret = StringAppend(&str, appendStr);
    EXPECT_EQ(ret, HC_TRUE);
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    for (uint32_t i = 0; i < HcStrlen("hello"); i++) {
        EXPECT_EQ(result[i], "hello"[i]);
    }
    DeleteString(&str);
    DeleteString(&appendStr);
}

HWTEST_F(HcStringTest, StringAppendTest002, TestSize.Level0)
{
    HcString str = CreateString();
    HcString emptyStr = CreateString();
    HcBool ret = StringAppend(&str, emptyStr);
    EXPECT_EQ(ret, HC_TRUE);
    DeleteString(&str);
    DeleteString(&emptyStr);
}

HWTEST_F(HcStringTest, StringAppendTest003, TestSize.Level0)
{
    HcString str = CreateString();
    HcString appendStr = CreateString();
    HcBool ret = StringAppend(nullptr, appendStr);
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringAppend(&str, appendStr);
    EXPECT_EQ(ret, HC_TRUE);
    DeleteString(&str);
    DeleteString(&appendStr);
}

HWTEST_F(HcStringTest, StringAppendPointerTest001, TestSize.Level0)
{
    HcString str = CreateString();
    HcBool ret = StringAppendPointer(&str, "hello");
    EXPECT_EQ(ret, HC_TRUE);
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    for (uint32_t i = 0; i < HcStrlen("hello"); i++) {
        EXPECT_EQ(result[i], "hello"[i]);
    }
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringAppendPointerTest002, TestSize.Level0)
{
    HcString str = CreateString();
    HcBool ret = StringAppendPointer(nullptr, "hello");
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringAppendPointer(&str, nullptr);
    EXPECT_EQ(ret, HC_FALSE);
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringAppendPointerTest003, TestSize.Level0)
{
    HcString str = CreateString();
    HcBool ret = StringAppendPointer(&str, "");
    EXPECT_EQ(ret, HC_TRUE);
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringAppendCharTest001, TestSize.Level0)
{
    HcString str = CreateString();
    HcBool ret = StringAppendChar(&str, 'A');
    EXPECT_EQ(ret, HC_TRUE);
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result[0], 'A');
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringAppendCharTest002, TestSize.Level0)
{
    HcString str = CreateString();
    HcBool ret = StringAppendChar(nullptr, 'A');
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringAppendChar(&str, '\0');
    EXPECT_EQ(ret, HC_FALSE);
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringAppendCharTest003, TestSize.Level0)
{
    HcString str = CreateString();
    StringAppendChar(&str, 'H');
    StringAppendChar(&str, 'e');
    StringAppendChar(&str, 'l');
    StringAppendChar(&str, 'l');
    StringAppendChar(&str, 'o');
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    for (uint32_t i = 0; i < HcStrlen("Hello"); i++) {
        EXPECT_EQ(result[i], "Hello"[i]);
    }
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringSetTest001, TestSize.Level0)
{
    HcString str = CreateString();
    HcString srcStr = CreateString();
    StringSetPointer(&srcStr, "hello");
    HcBool ret = StringSet(&str, srcStr);
    EXPECT_EQ(ret, HC_TRUE);
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    for (uint32_t i = 0; i < HcStrlen("hello"); i++) {
        EXPECT_EQ(result[i], "hello"[i]);
    }
    DeleteString(&str);
    DeleteString(&srcStr);
}

HWTEST_F(HcStringTest, StringSetTest002, TestSize.Level0)
{
    HcString srcStr = CreateString();
    HcBool ret = StringSet(nullptr, srcStr);
    EXPECT_EQ(ret, HC_FALSE);
    DeleteString(&srcStr);
}

HWTEST_F(HcStringTest, StringSetPointerTest001, TestSize.Level0)
{
    HcString str = CreateString();
    HcBool ret = StringSetPointer(&str, "hello");
    EXPECT_EQ(ret, HC_TRUE);
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    for (uint32_t i = 0; i < HcStrlen("hello"); i++) {
        EXPECT_EQ(result[i], "hello"[i]);
    }
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringSetPointerTest002, TestSize.Level0)
{
    HcString str = CreateString();
    HcBool ret = StringSetPointer(nullptr, "hello");
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringSetPointer(&str, nullptr);
    EXPECT_EQ(ret, HC_FALSE);
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringGetTest001, TestSize.Level0)
{
    HcString str = CreateString();
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringGetTest002, TestSize.Level0)
{
    const char *result = StringGet(nullptr);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(HcStringTest, StringLengthTest001, TestSize.Level0)
{
    HcString str = CreateString();
    uint32_t len = StringLength(&str);
    EXPECT_EQ(len, 0);
    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringLengthTest002, TestSize.Level0)
{
    HcString str = CreateString();
    StringSetPointer(&str, "hello");
    uint32_t len = StringLength(&str);
    EXPECT_EQ(len, 5);

    DeleteString(&str);
}

HWTEST_F(HcStringTest, StringLengthTest003, TestSize.Level0)
{
    uint32_t len = StringLength(nullptr);
    EXPECT_EQ(len, 0);
}

HWTEST_F(HcStringTest, CreateStringTest001, TestSize.Level0)
{
    HcString str = CreateString();
    const char *result = StringGet(&str);
    EXPECT_NE(result, nullptr);
    uint32_t len = StringLength(&str);
    EXPECT_EQ(len, 0);
    DeleteString(&str);
}

HWTEST_F(HcStringTest, DeleteStringTest001, TestSize.Level0)
{
    HcString str = CreateString();
    StringSetPointer(&str, "hello");

    DeleteString(&str);

    uint32_t len = StringLength(&str);
    EXPECT_EQ(len, 0);
}

HWTEST_F(HcStringTest, DeleteStringTest002, TestSize.Level0)
{
    DeleteString(nullptr);
}
}
