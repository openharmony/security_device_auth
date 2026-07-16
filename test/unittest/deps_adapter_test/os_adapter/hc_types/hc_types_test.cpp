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
#include "hc_types.h"

using namespace testing::ext;

class HcTypesTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(HcTypesTest, HcMallocTest001, TestSize.Level0)
{
    void *ptr = HcMalloc(100, 0);
    EXPECT_NE(ptr, nullptr);
    HcFree(ptr);
}

HWTEST_F(HcTypesTest, HcMallocTest002, TestSize.Level0)
{
    void *ptr = HcMalloc(100, 0xFF);
    EXPECT_NE(ptr, nullptr);
    unsigned char *buf = (unsigned char *)ptr;
    for (int i = 0; i < 100; i++) {
        EXPECT_EQ(buf[i], 0xFF);
    }
    HcFree(ptr);
}

HWTEST_F(HcTypesTest, HcMallocTest003, TestSize.Level0)
{
    void *ptr = HcMalloc(0, 0);
    EXPECT_EQ(ptr, nullptr);
}

HWTEST_F(HcTypesTest, HcFreeTest001, TestSize.Level0)
{
    void *ptr = HcMalloc(100, 0);
    EXPECT_NE(ptr, nullptr);
    HcFree(ptr);
}

HWTEST_F(HcTypesTest, HcFreeTest002, TestSize.Level0)
{
    HcFree(nullptr);
    SUCCEED();
}

HWTEST_F(HcTypesTest, HcStrlenTest001, TestSize.Level0)
{
    EXPECT_EQ(HcStrlen("hello"), 5u);
}

HWTEST_F(HcTypesTest, HcStrlenTest002, TestSize.Level0)
{
    EXPECT_EQ(HcStrlen(""), 0u);
}

HWTEST_F(HcTypesTest, HcStrlenTest003, TestSize.Level0)
{
    EXPECT_EQ(HcStrlen(nullptr), 0u);
}

HWTEST_F(HcTypesTest, HcMallocFreeCycleTest001, TestSize.Level0)
{
    for (int i = 0; i < 100; i++) {
        void *ptr = HcMalloc(256, 0);
        EXPECT_NE(ptr, nullptr);
        HcFree(ptr);
    }
}
