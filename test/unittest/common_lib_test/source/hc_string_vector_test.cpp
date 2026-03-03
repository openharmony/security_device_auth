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
#include <cstdint>
#include <cstring>
#include "base/security/device_auth/common_lib/interfaces/hc_string_vector.h"
#include "base/security/device_auth/common_lib/interfaces/hc_string.h"

using namespace std;
using namespace testing::ext;
namespace {
class HcStringVectorTest : public testing::Test {};

HWTEST_F(HcStringVectorTest, CreateStrVectorTest001, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    EXPECT_NE(vec.size, nullptr);
    EXPECT_NE(vec.pushBack, nullptr);
    EXPECT_NE(vec.get, nullptr);
    EXPECT_NE(vec.eraseElement, nullptr);

    uint32_t size = vec.size(&vec);
    EXPECT_EQ(size, 0);

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, DestroyStrVectorTest001, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    HcString str1 = CreateString();
    HcString str2 = CreateString();

    EXPECT_EQ(StringSetPointer(&str1, "hello"), HC_TRUE);
    EXPECT_EQ(StringSetPointer(&str2, "world"), HC_TRUE);

    vec.pushBack(&vec, &str1);
    vec.pushBack(&vec, &str2);

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, DestroyStrVectorTest002, TestSize.Level0)
{
    StringVector *vec = nullptr;
    DestroyStrVector(vec);
    EXPECT_EQ(vec, nullptr);
}

HWTEST_F(HcStringVectorTest, DestroyStrVectorTest003, TestSize.Level0)
{
    StringVector vec = CreateStrVector();
    StringVector *vecPtr = &vec;
    DestroyStrVector(&vec);
    EXPECT_EQ(vecPtr, nullptr);
}

HWTEST_F(HcStringVectorTest, StringVectorPushBackTest001, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    HcString str = CreateString();
    StringSetPointer(&str, "hello");

    HcString *result = vec.pushBack(&vec, &str);
    EXPECT_NE(result, nullptr);

    uint32_t size = vec.size(&vec);
    EXPECT_EQ(size, 1);

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, StringVectorPushBackTest002, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    HcString str1 = CreateString();
    HcString str2 = CreateString();
    HcString str3 = CreateString();

    StringSetPointer(&str1, "first");
    StringSetPointer(&str2, "second");
    StringSetPointer(&str3, "third");

    vec.pushBack(&vec, &str1);
    vec.pushBack(&vec, &str2);
    vec.pushBack(&vec, &str3);

    uint32_t size = vec.size(&vec);
    EXPECT_EQ(size, 3);

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, StringVectorGetByIndexTest001, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    HcString str = CreateString();
    StringSetPointer(&str, "hello");
    vec.pushBack(&vec, &str);

    HcString *strPtr = vec.getp(&vec, 0);
    EXPECT_NE(strPtr, nullptr);

    const char *content = StringGet(strPtr);
    EXPECT_NE(content, nullptr);

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, StringVectorGetByIndexTest002, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    HcString *strPtr = vec.getp(&vec, 0);
    EXPECT_EQ(strPtr, nullptr);

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, StringVectorGetByIndexTest003, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    HcString str = CreateString();
    StringSetPointer(&str, "hello");
    vec.pushBack(&vec, &str);

    HcString *strPtr = vec.getp(&vec, 10);
    EXPECT_EQ(strPtr, nullptr);

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, StringVectorRemoveByIndexTest001, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    HcString str1 = CreateString();
    HcString str2 = CreateString();
    HcString str3 = CreateString();

    StringSetPointer(&str1, "first");
    StringSetPointer(&str2, "second");
    StringSetPointer(&str3, "third");

    vec.pushBack(&vec, &str1);
    vec.pushBack(&vec, &str2);
    vec.pushBack(&vec, &str3);

    vec.eraseElement(&vec, &str2, 1);

    uint32_t size = vec.size(&vec);
    EXPECT_EQ(size, 2);

    HcString *strPtr = vec.getp(&vec, 1);
    EXPECT_NE(strPtr, nullptr);

    const char *content = StringGet(strPtr);
    EXPECT_NE(content, nullptr);

    for (uint32_t i = 0; i < HcStrlen("third"); i++) {
        EXPECT_EQ(content[i], "third"[i]);
    }

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, StringVectorRemoveByIndexTest002, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    HcString str = CreateString();
    StringSetPointer(&str, "hello");
    vec.pushBack(&vec, &str);

    vec.eraseElement(&vec, &str, 0);

    uint32_t size = vec.size(&vec);
    EXPECT_EQ(size, 0);

    DestroyStrVector(&vec);
}

HWTEST_F(HcStringVectorTest, StringVectorSizeTest001, TestSize.Level0)
{
    StringVector vec = CreateStrVector();

    uint32_t size = vec.size(&vec);
    EXPECT_EQ(size, 0);

    HcString str = CreateString();
    StringSetPointer(&str, "hello");
    vec.pushBack(&vec, &str);

    size = vec.size(&vec);
    EXPECT_EQ(size, 1);

    DestroyStrVector(&vec);
}
}