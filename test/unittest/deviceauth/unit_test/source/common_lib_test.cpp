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

#include "common_lib_test.h"
#include <gtest/gtest.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {
static const uint32_t TEST_BUFFER_SIZE = 16;
static const uint32_t TEST_INVALID_BUFFER_SIZE = 0;
static const uint32_t TEST_LENGTH_ZERO = 0;
static const uint32_t TEST_SRC_DATA = 4;
static const uint32_t TEST_UINT32_SIZE = 4;
static const uint32_t MAX_TLV_LENGTH = 32768;
const uint32_t PARCEL_UINT_MAX = 0xffffffffU;
static const char *TEST_JSON_STR = "{\"name\":\"test_name\", \"age\":18}";
static const char *TEST_JSON_STR_ARR = "[{\"name\":\"Tom1\",\"age\":18},{\"name\":\"Tom2\",\"age\":19}]";
static const char *TEST_STR = "test_str";
static const char TEST_CHAR = '0';

class CommonLibTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CommonLibTest::SetUpTestCase() {}
void CommonLibTest::TearDownTestCase() {}
void CommonLibTest::SetUp() {}
void CommonLibTest::TearDown() {}

HWTEST_F(CommonLibTest, HcParcelCreateTest001, TestSize.Level0)
{
    HcParcel parcelNullData = CreateParcel(TEST_INVALID_BUFFER_SIZE, PARCEL_DEFAULT_ALLOC_UNIT);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, PARCEL_DEFAULT_ALLOC_UNIT);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    uint32_t invalidLength = GetParcelDataSize(nullptr);
    EXPECT_EQ(invalidLength, TEST_LENGTH_ZERO);
    uint32_t validLength = GetParcelDataSize(&parcelWithData);
    EXPECT_EQ(validLength, TEST_UINT32_SIZE);
    const char *invalidData = GetParcelData(nullptr);
    EXPECT_EQ(invalidData, nullptr);
    const char *validData = GetParcelData(&parcelWithData);
    EXPECT_NE(validData, nullptr);
    const char *invalidLastChar = GetParcelLastChar(nullptr);
    EXPECT_EQ(invalidLastChar, nullptr);
    const char *validLastChar = GetParcelLastChar(&parcelWithData);
    EXPECT_NE(validLastChar, nullptr);
    ClearParcel(&parcelWithData);
    ResetParcel(&parcelWithData, TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    DeleteParcel(nullptr);
    DeleteParcel(&parcelNullData);
    DeleteParcel(&parcelWithData);
}

HWTEST_F(CommonLibTest, HcParcelReadTest001, TestSize.Level0)
{
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    HcBool ret = ParcelReadWithoutPopData(&parcelWithData, &num, uintDataSize);
    EXPECT_EQ(ret, HC_TRUE);
    ret = ParcelRead(nullptr, nullptr, uintDataSize);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelRead(&parcelWithData, &num, uintDataSize);
    EXPECT_EQ(ret, HC_TRUE);
    parcelWithData.beginPos = PARCEL_UINT_MAX - uintDataSize;
    ret = ParcelRead(&parcelWithData, &num, uintDataSize);
    parcelWithData.beginPos = 0;
    parcelWithData.endPos = 0;
    ret = ParcelRead(&parcelWithData, &num, uintDataSize);
    EXPECT_EQ(ret, HC_FALSE);
    DeleteParcel(&parcelWithData);
}

HWTEST_F(CommonLibTest, HcParcelEraseBlockTest001, TestSize.Level0)
{
    uint32_t start = 0;
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    HcBool ret = ParcelEraseBlock(nullptr, start, uintDataSize, &num);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelEraseBlock(&parcelWithData, PARCEL_UINT_MAX, uintDataSize, &num);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelEraseBlock(&parcelWithData, PARCEL_UINT_MAX - uintDataSize, uintDataSize, &num);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelEraseBlock(&parcelWithData, start, uintDataSize, &num);
    EXPECT_EQ(ret, HC_TRUE);
    DeleteParcel(&parcelWithData);
}

HWTEST_F(CommonLibTest, HcParcelRevertTest001, TestSize.Level0)
{
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    HcBool ret = ParcelReadRevert(&parcelWithData, &num, TEST_LENGTH_ZERO);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelReadRevert(&parcelWithData, &num, uintDataSize);
    EXPECT_EQ(ret, HC_TRUE);
    ret = ParcelWriteRevert(nullptr, &num, uintDataSize);
    DeleteParcel(&parcelWithData);
}

HWTEST_F(CommonLibTest, HcParcelReadWrite001, TestSize.Level0)
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    int32_t srcInt = 0;
    int32_t dstInt = 0;
    HcBool ret = ParcelWriteInt32(&parcelWithData, srcInt);
    ret = ParcelReadInt32(&parcelWithData, &dstInt);
    EXPECT_EQ(ret, HC_TRUE);
    uint32_t srcUint32 = 0;
    uint32_t dstUint32 = 0;
    ret = ParcelWriteUint32(&parcelWithData, srcUint32);
    ret = ParcelReadUint32(&parcelWithData, &dstUint32);
    EXPECT_EQ(ret, HC_TRUE);
    short srcInt16 = 0;
    short dstInt16 = 0;
    ret = ParcelWriteInt16(&parcelWithData, srcInt16);
    ret = ParcelReadInt16(&parcelWithData, &dstInt16);
    EXPECT_EQ(ret, HC_TRUE);
    uint16_t srcUint16 = 0;
    uint16_t dstUint16 = 0;
    ret = ParcelWriteUint16(&parcelWithData, srcUint16);
    ret = ParcelReadUint16(&parcelWithData, &dstUint16);
    EXPECT_EQ(ret, HC_TRUE);
    char srcInt8 = 0;
    char dstInt8 = 0;
    ret = ParcelWriteInt8(&parcelWithData, srcInt8);
    ret = ParcelReadInt8(&parcelWithData, &dstInt8);
    EXPECT_EQ(ret, HC_TRUE);
    uint8_t srcUint8 = 0;
    uint8_t dstUint8 = 0;
    ret = ParcelWriteUint8(&parcelWithData, srcUint8);
    ret = ParcelReadUint8(&parcelWithData, &dstUint8);
    EXPECT_EQ(ret, HC_TRUE);
    int64_t srcInt64 = 0;
    int64_t dstInt64 = 0;
    ret = ParcelWriteInt64(&parcelWithData, srcInt64);
    ret = ParcelReadInt64(&parcelWithData, &dstInt64);
    EXPECT_EQ(ret, HC_TRUE);
    uint64_t srcUint64 = 0;
    uint64_t dstUint64 = 0;
    ret = ParcelWriteUint64(&parcelWithData, srcUint64);
    ret = ParcelReadUint64(&parcelWithData, &dstUint64);
    EXPECT_EQ(ret, HC_TRUE);
    DeleteParcel(&parcelWithData);
}

HWTEST_F(CommonLibTest, HcParcelRealloc001, TestSize.Level0)
{
    HcParcel parcelSrc = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel parcelDst = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcBool ret = ParcelWriteInt32(&parcelSrc, TEST_SRC_DATA);
    EXPECT_EQ(ret, HC_TRUE);
    uint32_t data01 = 0;
    uint64_t data02 = 0;
    uint32_t validLen = sizeof(data01);
    uint32_t invalidLen = sizeof(data02);
    ret = ParcelReadParcel(nullptr, nullptr, validLen, HC_FALSE);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelReadParcel(&parcelSrc, &parcelDst, invalidLen, HC_FALSE);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelReadParcel(&parcelSrc, &parcelDst, TEST_LENGTH_ZERO, HC_FALSE);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelReadParcel(&parcelSrc, &parcelDst, validLen, HC_FALSE);
    EXPECT_EQ(ret, HC_TRUE);
    DeleteParcel(&parcelSrc);
    DeleteParcel(&parcelDst);
}

HWTEST_F(CommonLibTest, HcParcelCopy001, TestSize.Level0)
{
    HcParcel parcelSrc = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel parcelDst = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcBool ret = ParcelCopy(nullptr, nullptr);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelCopy(&parcelSrc, &parcelDst);
    EXPECT_EQ(ret, HC_TRUE);
    ret = ParcelWriteInt32(&parcelSrc, TEST_SRC_DATA);
    EXPECT_EQ(ret, HC_TRUE);
    ret = ParcelCopy(&parcelSrc, &parcelDst);
    EXPECT_EQ(ret, HC_TRUE);
    DeleteParcel(&parcelSrc);
    DeleteParcel(&parcelDst);
}

HWTEST_F(CommonLibTest, HcParcelReadWriteRevert001, TestSize.Level0)
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    int32_t srcInt = 0;
    int32_t dstInt = 0;
    HcBool ret = ParcelWriteInt32Revert(&parcelWithData, srcInt);
    ret = ParcelReadInt32Revert(&parcelWithData, &dstInt);
    EXPECT_EQ(ret, HC_TRUE);
    uint32_t srcUint32 = 0;
    uint32_t dstUint32 = 0;
    ret = ParcelWriteUint32Revert(&parcelWithData, srcUint32);
    ret = ParcelReadUint32Revert(&parcelWithData, &dstUint32);
    EXPECT_EQ(ret, HC_TRUE);
    short srcInt16 = 0;
    short dstInt16 = 0;
    ret = ParcelWriteInt16Revert(&parcelWithData, srcInt16);
    ret = ParcelReadInt16Revert(&parcelWithData, &dstInt16);
    EXPECT_EQ(ret, HC_TRUE);
    uint16_t srcUint16 = 0;
    uint16_t dstUint16 = 0;
    ret = ParcelWriteUint16Revert(&parcelWithData, srcUint16);
    ret = ParcelReadUint16Revert(&parcelWithData, &dstUint16);
    EXPECT_EQ(ret, HC_TRUE);
    char srcInt8 = 0;
    char dstInt8 = 0;
    ret = ParcelWriteInt8Revert(&parcelWithData, srcInt8);
    ret = ParcelReadInt8Revert(&parcelWithData, &dstInt8);
    EXPECT_EQ(ret, HC_TRUE);
    uint8_t srcUint8 = 0;
    uint8_t dstUint8 = 0;
    ret = ParcelWriteUint8Revert(&parcelWithData, srcUint8);
    ret = ParcelReadUint8Revert(&parcelWithData, &dstUint8);
    EXPECT_EQ(ret, HC_TRUE);
    int64_t srcInt64 = 0;
    int64_t dstInt64 = 0;
    ret = ParcelWriteInt64Revert(&parcelWithData, srcInt64);
    ret = ParcelReadInt64Revert(&parcelWithData, &dstInt64);
    EXPECT_EQ(ret, HC_TRUE);
    uint64_t srcUint64 = 0;
    uint64_t dstUint64 = 0;
    ret = ParcelWriteUint64Revert(&parcelWithData, srcUint64);
    ret = ParcelReadUint64Revert(&parcelWithData, &dstUint64);
    EXPECT_EQ(ret, HC_TRUE);
    DeleteParcel(&parcelWithData);
}

HWTEST_F(CommonLibTest, HcParcelPop001, TestSize.Level0)
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcBool ret = ParcelWriteInt32(&parcelWithData, TEST_SRC_DATA);
    EXPECT_EQ(ret, HC_TRUE);
    ret = ParcelPopBack(&parcelWithData, sizeof(uint32_t));
    EXPECT_EQ(ret, HC_TRUE);
    ret = ParcelPopBack(&parcelWithData, sizeof(uint32_t));
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParcelWriteInt32(&parcelWithData, TEST_SRC_DATA);
    EXPECT_EQ(ret, HC_TRUE);
    ret = ParcelPopFront(&parcelWithData, sizeof(uint32_t));
    EXPECT_EQ(ret, HC_TRUE);
    ret = ParcelPopFront(&parcelWithData, sizeof(uint32_t));
    EXPECT_EQ(ret, HC_FALSE);
    DeleteParcel(&parcelWithData);
}

HWTEST_F(CommonLibTest, HcStringTest001, TestSize.Level0)
{
    HcString selfStr = CreateString();
    HcString srcStr = CreateString();
    HcBool ret = StringSetPointer(&srcStr, TEST_STR);
    EXPECT_EQ(ret, HC_TRUE);
    ret = StringAppend(nullptr, srcStr);
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringAppend(&selfStr, srcStr);
    EXPECT_EQ(ret, HC_TRUE);
    ret = StringAppendPointer(nullptr, TEST_STR);
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringAppendPointer(&selfStr, TEST_STR);
    EXPECT_EQ(ret, HC_TRUE);
    ret = StringAppendChar(nullptr, TEST_CHAR);
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringAppendChar(&selfStr, TEST_CHAR);
    EXPECT_EQ(ret, HC_TRUE);
    ret = StringSet(nullptr, srcStr);
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringSet(&selfStr, srcStr);
    EXPECT_EQ(ret, HC_TRUE);
    ret = StringSetPointer(nullptr, TEST_STR);
    EXPECT_EQ(ret, HC_FALSE);
    ret = StringSetPointer(&selfStr, TEST_STR);
    EXPECT_EQ(ret, HC_TRUE);
    const char *retStr = StringGet(nullptr);
    EXPECT_EQ(retStr, nullptr);
    retStr = StringGet(&selfStr);
    EXPECT_NE(retStr, nullptr);
    uint32_t retLen = StringLength(nullptr);
    EXPECT_EQ(retLen, 0);
    retLen = StringLength(&selfStr);
    EXPECT_NE(retLen, 0);
    DeleteString(&selfStr);
    retLen = StringLength(&selfStr);
    EXPECT_EQ(retLen, 0);
    DeleteString(&srcStr);
}

HWTEST_F(CommonLibTest, HcCreateJsonTest001, TestSize.Level0)
{
    CJson *invalidJson = CreateJsonFromString(nullptr);
    EXPECT_EQ(invalidJson, nullptr);
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(validJson, nullptr);
    invalidJson = DuplicateJson(nullptr);
    EXPECT_EQ(invalidJson, nullptr);
    FreeJson(validJson);
}

HWTEST_F(CommonLibTest, HcDeleteJsonTest001, TestSize.Level0)
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(validJson, nullptr);
    CJson *jsonItem = DetachItemFromJson(nullptr, "age");
    EXPECT_EQ(jsonItem, nullptr);
    jsonItem = DetachItemFromJson(validJson, "age");
    EXPECT_NE(jsonItem, nullptr);
    DeleteItemFromJson(nullptr, "name");
    DeleteItemFromJson(validJson, "name");
    DeleteAllItemExceptOne(nullptr, "name");
    DeleteAllItemExceptOne(validJson, "name");
    DeleteAllItem(nullptr);
    DeleteAllItem(validJson);
    FreeJson(validJson);
}

HWTEST_F(CommonLibTest, HcJsonGetTest001, TestSize.Level0)
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(validJson, nullptr);
    char *jsonStr = PackJsonToString(nullptr);
    EXPECT_EQ(jsonStr, nullptr);
    jsonStr = PackJsonToString(validJson);
    EXPECT_NE(jsonStr, nullptr);
    FreeJsonString(jsonStr);
    int32_t itemNum = GetItemNum(nullptr);
    EXPECT_EQ(itemNum, 0);
    itemNum = GetItemNum(validJson);
    EXPECT_NE(itemNum, 0);
    const char *itemKey = GetItemKey(nullptr);
    EXPECT_EQ(itemKey, nullptr);
    itemKey = GetItemKey(validJson);
    EXPECT_EQ(itemKey, nullptr);
    CJson *jsonObj = GetObjFromJson(nullptr, "name");
    EXPECT_EQ(jsonObj, nullptr);
    jsonObj = GetObjFromJson(validJson, "name");
    EXPECT_NE(jsonObj, nullptr);
    jsonObj = GetItemFromArray(nullptr, 0);
    EXPECT_EQ(jsonObj, nullptr);
    jsonObj = GetItemFromArray(validJson, 0);
    EXPECT_NE(jsonObj, nullptr);
    FreeJson(validJson);
}

HWTEST_F(CommonLibTest, HcJsonGetTest002, TestSize.Level0)
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(validJson, nullptr);
    const char *strObj = GetStringFromJson(nullptr, "name");
    EXPECT_EQ(strObj, nullptr);
    strObj = GetStringFromJson(validJson, "name");
    EXPECT_NE(strObj, nullptr);
    char byteData[] = "test_byte";
    int32_t ret = GetByteFromJson(nullptr, "name", nullptr, sizeof(byteData));
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = GetByteFromJson(validJson, "gender", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    EXPECT_EQ(ret, CLIB_ERR_JSON_GET);
    ret = GetByteFromJson(validJson, "name", reinterpret_cast<uint8_t *>(byteData), TEST_LENGTH_ZERO);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_LEN);
    int32_t valueInt32 = 0;
    ret = GetIntFromJson(nullptr, "age", &valueInt32);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    uint32_t valueUint32 = 0;
    ret = GetUnsignedIntFromJson(nullptr, "age", &valueUint32);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    int64_t valueInt64 = 0;
    ret = GetInt64FromJson(nullptr, "age", &valueInt64);
    EXPECT_EQ(ret, CLIB_ERR_JSON_GET);
    bool valueBool = false;
    ret = GetBoolFromJson(nullptr, "age", &valueBool);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    CJson *jsonObj = GetObjFromJson(validJson, "name");
    char *valueStr = GetStringValue(jsonObj);
    EXPECT_NE(valueStr, nullptr);
    FreeJson(validJson);
}

HWTEST_F(CommonLibTest, HcJsonAddTest001, TestSize.Level0)
{
    CJson *jsonArr = CreateJsonFromString(TEST_JSON_STR_ARR);
    EXPECT_NE(jsonArr, nullptr);
    CJson *childObj = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(childObj, nullptr);
    int32_t ret = AddObjToJson(nullptr, "name", nullptr);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = AddObjToJson(jsonArr, "gender", childObj);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddObjToJson(jsonArr, "name", childObj);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddObjToArray(nullptr, childObj);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = AddObjToArray(childObj, jsonArr);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
    ret = AddObjToArray(jsonArr, childObj);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddStringToArray(nullptr, TEST_STR);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = AddStringToArray(childObj, TEST_STR);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
    ret = AddStringToArray(jsonArr, TEST_STR);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddStringToJson(nullptr, "name", TEST_STR);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = AddStringToJson(childObj, "gender", TEST_STR);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddStringToJson(childObj, "name", TEST_STR);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    FreeJson(jsonArr);
}

HWTEST_F(CommonLibTest, HcJsonAddTest002, TestSize.Level0)
{
    CJson *childObj = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(childObj, nullptr);
    char byteData[] = "test_byte";
    int32_t ret = AddByteToJson(nullptr, "name", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = AddByteToJson(childObj, "gender", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddByteToJson(childObj, "name", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddBoolToJson(nullptr, "name", false);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = AddBoolToJson(childObj, "gender", false);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddBoolToJson(childObj, "name", false);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    int32_t valueInt32 = 0;
    ret = AddIntToJson(nullptr, "name", valueInt32);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = AddIntToJson(childObj, "gender", valueInt32);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    ret = AddIntToJson(childObj, "name", valueInt32);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    int64_t valueInt64 = 0;
    ret = AddInt64StringToJson(nullptr, "name", valueInt64);
    EXPECT_EQ(ret, CLIB_ERR_JSON_ADD);
    ret = AddInt64StringToJson(childObj, "name", valueInt64);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    const char *const strArr[] = {"first test data", "second test data"};
    ret = AddStringArrayToJson(nullptr, "name", strArr, sizeof(strArr) / sizeof(strArr[0]));
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = AddStringArrayToJson(childObj, "name", strArr, sizeof(strArr) / sizeof(strArr[0]));
    EXPECT_EQ(ret, CLIB_SUCCESS);
}

HWTEST_F(CommonLibTest, HcClearJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(jsonObj, nullptr);
    ClearSensitiveStringInJson(nullptr, "name");
    ClearSensitiveStringInJson(jsonObj, "gender");
    ClearSensitiveStringInJson(jsonObj, "name");
    FreeJson(jsonObj);
}

HWTEST_F(CommonLibTest, HcStringUtilTest001, TestSize.Level0)
{
    const uint8_t byteData[] = "1234";
    const char hexData[] = "ABCD";
    const char invalidData[] = "GHJK";
    uint32_t byteSize = sizeof(byteData);
    char hexStr[TEST_BUFFER_SIZE] = { 0 };
    int32_t ret = ByteToHexString(nullptr, byteSize, hexStr, TEST_BUFFER_SIZE);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = ByteToHexString(byteData, byteSize, hexStr, TEST_LENGTH_ZERO);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_LEN);
    ret = ByteToHexString(byteData, byteSize, hexStr, TEST_BUFFER_SIZE);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    uint8_t byteStr[TEST_BUFFER_SIZE] = { 0 };
    ret = HexStringToByte(nullptr, byteStr, TEST_BUFFER_SIZE);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    ret = HexStringToByte(hexData, byteStr, TEST_LENGTH_ZERO);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_LEN);
    ret = HexStringToByte(invalidData, byteStr, TEST_BUFFER_SIZE);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
    ret = HexStringToByte(hexData, byteStr, TEST_BUFFER_SIZE);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    const char intStr[] = "10";
    int64_t int64Res = StringToInt64(intStr);
    EXPECT_EQ(ret, 0);
    int64Res = StringToInt64(intStr);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CommonLibTest, ParseTlvHeadTest001, TestSize.Level0)
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    TlvBase tlvBase = {
        .tag = 0,
        .length = 0,
        .checkTag = 1,
    };
    HcBool ret = ParseTlvHead(&tlvBase, nullptr);
    EXPECT_EQ(ret, HC_FALSE);
    ret = ParseTlvHead(&tlvBase, &parcelWithData);
    EXPECT_EQ(ret, HC_FALSE);
    parcelWithData.beginPos = PARCEL_UINT_MAX;
    tlvBase.checkTag = tlvBase.length;
    ret = ParseTlvHead(&tlvBase, &parcelWithData);
    EXPECT_EQ(ret, HC_FALSE);
    parcelWithData.beginPos = 0;
    tlvBase.length = MAX_TLV_LENGTH + 1;
    ret = ParseTlvHead(&tlvBase, &parcelWithData);
    EXPECT_EQ(ret, HC_FALSE);
    tlvBase.length = 0;
    ret = ParseTlvHead(&tlvBase, &parcelWithData);
    EXPECT_EQ(ret, HC_FALSE);
    DeleteParcel(&parcelWithData);
}

HWTEST_F(CommonLibTest, ParseTlvNodeTest001, TestSize.Level0)
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    TlvBase tlvBase = {
        .tag = 0,
        .length = GetParcelDataSize(&parcelWithData) + 1,
        .checkTag = 1,
    };
    int32_t ret = ParseTlvNode(nullptr, &parcelWithData, true);
    EXPECT_EQ(ret, TLV_FAIL);
    ret = ParseTlvNode(&tlvBase, &parcelWithData, true);
    EXPECT_EQ(ret, TLV_FAIL);
    DeleteParcel(&parcelWithData);
}
}