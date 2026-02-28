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
#include "hc_parcel.h"
#include "hc_types.h"
#include "securec.h"
#include "hc_string.h"

using namespace testing::ext;

namespace {
static const uint32_t TEST_BUFFER_SIZE = 32;
static const uint32_t TEST_BUFFER_SIZE_LARGE = 256;

class HcParcelTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HcParcelTest::SetUpTestCase() {}
void HcParcelTest::TearDownTestCase() {}
void HcParcelTest::SetUp() {}
void HcParcelTest::TearDown() {}



HWTEST_F(HcParcelTest, ParcelReadWriteTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    int32_t srcInt32 = 12345;
    HcBool ret = ParcelWriteInt32(&parcel, srcInt32);
    EXPECT_EQ(ret, HC_TRUE);
    
    int32_t dstInt32 = 0;
    ret = ParcelReadInt32(&parcel, &dstInt32);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstInt32, srcInt32);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteTest002, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t srcUint32 = 0xFFFFFFFF;
    HcBool ret = ParcelWriteUint32(&parcel, srcUint32);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint32_t dstUint32 = 0;
    ret = ParcelReadUint32(&parcel, &dstUint32);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstUint32, srcUint32);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteTest003, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    int16_t srcInt16 = 1234;
    HcBool ret = ParcelWriteInt16(&parcel, srcInt16);
    EXPECT_EQ(ret, HC_TRUE);
    
    int16_t dstInt16 = 0;
    ret = ParcelReadInt16(&parcel, &dstInt16);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstInt16, srcInt16);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteTest004, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint16_t srcUint16 = 0xFFFF;
    HcBool ret = ParcelWriteUint16(&parcel, srcUint16);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint16_t dstUint16 = 0;
    ret = ParcelReadUint16(&parcel, &dstUint16);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstUint16, srcUint16);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteTest005, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    char srcInt8 = 123;
    HcBool ret = ParcelWriteInt8(&parcel, srcInt8);
    EXPECT_EQ(ret,  HC_TRUE);
    
    char dstInt8 = 0;
    ret = ParcelReadInt8(&parcel, &dstInt8);
    EXPECT_EQ(ret,  HC_TRUE);
    EXPECT_EQ(dstInt8, srcInt8);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteTest006, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint8_t srcUint8 = 0xFF;
    HcBool ret = ParcelWriteUint8(&parcel, srcUint8);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint8_t dstUint8 = 0;
    ret = ParcelReadUint8(&parcel, &dstUint8);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstUint8, srcUint8);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteTest007, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    int64_t srcInt64 = 1234567890LL;
    HcBool ret = ParcelWriteInt64(&parcel, srcInt64);
    EXPECT_EQ(ret, HC_TRUE);
    
    int64_t dstInt64 = 0;
    ret = ParcelReadInt64(&parcel, &dstInt64);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstInt64, srcInt64);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteTest008, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint64_t srcUint64 = 0xFFFFFFFFFFFFFFFFULL;
    HcBool ret = ParcelWriteUint64(&parcel, srcUint64);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint64_t dstUint64 = 0;
    ret = ParcelReadUint64(&parcel, &dstUint64);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstUint64, srcUint64);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteRevertTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    int32_t srcInt32 = 12345;
    HcBool ret = ParcelWriteInt32Revert(&parcel, srcInt32);
    EXPECT_EQ(ret, HC_TRUE);
    
    int32_t dstInt32 = 0;
    ret = ParcelReadInt32Revert(&parcel, &dstInt32);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstInt32, srcInt32);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteRevertTest002, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t srcUint32 = 0x12345678;
    HcBool ret = ParcelWriteUint32Revert(&parcel, srcUint32);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint32_t dstUint32 = 0;
    ret = ParcelReadUint32Revert(&parcel, &dstUint32);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstUint32, srcUint32);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteRevertTest003, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    int64_t srcInt64 = 1234567890123456LL;
    HcBool ret = ParcelWriteInt64Revert(&parcel, srcInt64);
    EXPECT_EQ(ret, HC_TRUE);
    
    int64_t dstInt64 = 0;
    ret = ParcelReadInt64Revert(&parcel, &dstInt64);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstInt64, srcInt64);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelReadWriteRevertTest004, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint64_t srcUint64 = 0x123456789ABCDEF0ULL;
    HcBool ret = ParcelWriteUint64Revert(&parcel, srcUint64);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint64_t dstUint64 = 0;
    ret = ParcelReadUint64Revert(&parcel, &dstUint64);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(dstUint64, srcUint64);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, DataRevertTest001, TestSize.Level0)
{
    uint32_t data = 0x12345678;
    DataRevert(&data, sizeof(data));
    EXPECT_EQ(data, 0x78563412);
}

HWTEST_F(HcParcelTest, DataRevertTest002, TestSize.Level0)
{
    uint16_t data = 0x1234;
    DataRevert(&data, sizeof(data));
    EXPECT_EQ(data, 0x3412);
}

HWTEST_F(HcParcelTest, DataRevertTest003, TestSize.Level0)
{
    uint64_t data = 0x123456789ABCDEF0ULL;
    DataRevert(&data, sizeof(data));
    EXPECT_EQ(data, 0xF0DEBC9A78563412ULL);
}

HWTEST_F(HcParcelTest, DataRevertTest004, TestSize.Level0)
{
    DataRevert(nullptr, 0);
}

HWTEST_F(HcParcelTest, ParcelEraseBlockTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t data1 = 0x11111111;
    uint32_t data2 = 0x22222222;
    uint32_t data3 = 0x33333333;
    
    ParcelWriteUint32(&parcel, data1);
    ParcelWriteUint32(&parcel, data2);
    ParcelWriteUint32(&parcel, data3);
    
    uint32_t erasedData = 0;
    HcBool ret = ParcelEraseBlock(&parcel, sizeof(uint32_t), sizeof(uint32_t), &erasedData);
    EXPECT_EQ(ret, HC_TRUE);
    EXPECT_EQ(erasedData, data2);
    
    uint32_t readData1 = 0;
    ParcelReadUint32(&parcel, &readData1);
    EXPECT_EQ(readData1, data1);
    
    uint32_t readData3 = 0;
    ParcelReadUint32(&parcel, &readData3);
    EXPECT_EQ(readData3, data3);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelEraseBlockTest002, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    uint32_t data = 0;
    
    HcBool ret = ParcelEraseBlock(nullptr, 0, sizeof(data), &data);
    EXPECT_EQ(ret, HC_FALSE);
    
    ret = ParcelEraseBlock(&parcel, 0, sizeof(data), nullptr);
    EXPECT_EQ(ret, HC_FALSE);
    
    ret = ParcelEraseBlock(&parcel, 0, 0, &data);
    EXPECT_EQ(ret, HC_FALSE);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelCopyTest001, TestSize.Level0)
{
    HcParcel srcParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel dstParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t data = 0x12345678;
    ParcelWriteUint32(&srcParcel, data);
    
    HcBool ret = ParcelCopy(&srcParcel, &dstParcel);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint32_t readData = 0;
    ParcelReadUint32(&dstParcel, &readData);
    EXPECT_EQ(readData, data);
    
    DeleteParcel(&srcParcel);
    DeleteParcel(&dstParcel);
}

HWTEST_F(HcParcelTest, ParcelCopyTest002, TestSize.Level0)
{
    HcParcel srcParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel dstParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    HcBool ret = ParcelCopy(nullptr, &dstParcel);
    EXPECT_EQ(ret, HC_FALSE);
    
    ret = ParcelCopy(&srcParcel, nullptr);
    EXPECT_EQ(ret,  HC_FALSE);
    
    DeleteParcel(&srcParcel);
    DeleteParcel(&dstParcel);
}

HWTEST_F(HcParcelTest, ParcelCopyTest003, TestSize.Level0)
{
    HcParcel srcParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel dstParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    HcBool ret = ParcelCopy(&srcParcel, &dstParcel);
    EXPECT_EQ(ret, HC_TRUE);
    
    DeleteParcel(&srcParcel);
    DeleteParcel(&dstParcel);
}

HWTEST_F(HcParcelTest, ParcelReadParcelTest001, TestSize.Level0)
{
    HcParcel srcParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel dstParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t data = 0x12345678;
    ParcelWriteUint32(&srcParcel, data);
    
    HcBool ret = ParcelReadParcel(&srcParcel, &dstParcel, sizeof(data), HC_TRUE);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint32_t readData = 0;
    ParcelReadUint32(&dstParcel, &readData);
    EXPECT_EQ(readData, data);
    
    DeleteParcel(&srcParcel);
    DeleteParcel(&dstParcel);
}

HWTEST_F(HcParcelTest, ParcelReadParcelTest002, TestSize.Level0)
{
    HcParcel srcParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel dstParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t data = 0x12345678;
    ParcelWriteUint32(&srcParcel, data);
    
    HcBool ret = ParcelReadParcel(&srcParcel, &dstParcel, sizeof(data), HC_FALSE);
    EXPECT_EQ(ret, HC_TRUE);
    
    uint32_t readData = 0;
    ParcelReadUint32(&dstParcel, &readData);
    EXPECT_EQ(readData, data);
    
    uint32_t srcDataSize = GetParcelDataSize(&srcParcel);
    EXPECT_EQ(srcDataSize, 0);
    
    DeleteParcel(&srcParcel);
    DeleteParcel(&dstParcel);
}

HWTEST_F(HcParcelTest, ParcelReadParcelTest003, TestSize.Level0)
{
    HcParcel srcParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel dstParcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    HcBool ret = ParcelReadParcel(nullptr, &dstParcel, sizeof(uint32_t), HC_TRUE);
    EXPECT_EQ(ret, HC_FALSE);
    
    ret = ParcelReadParcel(&srcParcel, nullptr, sizeof(uint32_t), HC_TRUE);
    EXPECT_EQ(ret, HC_FALSE);
    
    DeleteParcel(&srcParcel);
    DeleteParcel(&dstParcel);
}

HWTEST_F(HcParcelTest, ParcelPopBackTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t data1 = 0x11111111;
    uint32_t data2 = 0x22222222;
    ParcelWriteUint32(&parcel, data1);
    ParcelWriteUint32(&parcel, data2);
    
    HcBool ret = ParcelPopBack(&parcel, sizeof(uint32_t));
    EXPECT_EQ(ret, HC_TRUE);
    
    uint32_t readData = 0;
    ParcelReadUint32(&parcel, &readData);
    EXPECT_EQ(readData, data1);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelPopBackTest002, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    HcBool ret = ParcelPopBack(nullptr, sizeof(uint32_t));
    EXPECT_EQ(ret, HC_FALSE);
    
    ret = ParcelPopBack(&parcel, 0);
    EXPECT_EQ(ret, HC_FALSE);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelPopFrontTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t data1 = 0x11111111;
    uint32_t data2 = 0x22222222;
    ParcelWriteUint32(&parcel, data1);
    ParcelWriteUint32(&parcel, data2);
    
    HcBool ret = ParcelPopFront(&parcel, sizeof(uint32_t));
    EXPECT_EQ(ret, HC_TRUE);
    
    uint32_t readData = 0;
    ParcelReadUint32(&parcel, &readData);
    EXPECT_EQ(readData, data2);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ParcelPopFrontTest002, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    HcBool ret = ParcelPopFront(nullptr, sizeof(uint32_t));
    EXPECT_EQ(ret, HC_FALSE);
    
    ret = ParcelPopFront(&parcel, 0);
    EXPECT_EQ(ret, HC_FALSE);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, GetParcelDataSizeTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t size = GetParcelDataSize(&parcel);
    EXPECT_EQ(size, 0);
    
    uint32_t data = 0x12345678;
    ParcelWriteUint32(&parcel, data);
    
    size = GetParcelDataSize(&parcel);
    EXPECT_EQ(size, sizeof(uint32_t));
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, GetParcelDataSizeTest002, TestSize.Level0)
{
    uint32_t size = GetParcelDataSize(nullptr);
    EXPECT_EQ(size, 0);
}

HWTEST_F(HcParcelTest, GetParcelDataTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    const char *data = GetParcelData(&parcel);
    EXPECT_NE(data, nullptr);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, GetParcelDataTest002, TestSize.Level0)
{
    const char *data = GetParcelData(nullptr);
    EXPECT_EQ(data, nullptr);
}

HWTEST_F(HcParcelTest, GetParcelLastCharTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    const char *lastChar = GetParcelLastChar(&parcel);
    EXPECT_EQ(lastChar, nullptr);
    
    uint32_t data = 0x12345678;
    ParcelWriteUint32(&parcel, data);
    
    lastChar = GetParcelLastChar(&parcel);
    EXPECT_NE(lastChar, nullptr);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, GetParcelLastCharTest002, TestSize.Level0)
{
    const char *lastChar = GetParcelLastChar(nullptr);
    EXPECT_EQ(lastChar, nullptr);
}

HWTEST_F(HcParcelTest, ClearParcelTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t data = 0x12345678;
    ParcelWriteUint32(&parcel, data);
    
    ClearParcel(&parcel);
    
    uint32_t size = GetParcelDataSize(&parcel);
    EXPECT_EQ(size, 0);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ClearParcelTest002, TestSize.Level0)
{
    ClearParcel(nullptr);
}

HWTEST_F(HcParcelTest, ResetParcelTest001, TestSize.Level0)
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    
    uint32_t data = 0x12345678;
    ParcelWriteUint32(&parcel, data);
    
    ResetParcel(&parcel, TEST_BUFFER_SIZE_LARGE, TEST_BUFFER_SIZE_LARGE);
    
    uint32_t size = GetParcelDataSize(&parcel);
    EXPECT_EQ(size, 0);
    
    DeleteParcel(&parcel);
}

HWTEST_F(HcParcelTest, ResetParcelTest002, TestSize.Level0)
{
    ResetParcel(nullptr, TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
}
}
