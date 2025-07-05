/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "commonlib_fuzzer.h"

#include "clib_error.h"
#include "hc_string.h"
#include "json_utils.h"
#include "string_util.h"
#include "hc_tlv_parser.h"
#include "account_module_defines.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include "securec.h"
#include "base/security/device_auth/common_lib/impl/src/hc_parcel.c"

namespace OHOS {
static const uint32_t TEST_BUFFER_SIZE = 16;
static const uint32_t TEST_MIN_ANONYMOUS_LEN = 12;
static const uint32_t TEST_LEN_TWO = 2;
static const uint32_t TEST_INVALID_BUFFER_SIZE = 0;
static const uint32_t TEST_LENGTH_ZERO = 0;
static const uint32_t TEST_SRC_DATA = 4;
static const uint32_t MAX_TLV_LENGTH = 32768;
static const uint32_t PARCEL_POS_0 = 0;
static const uint32_t PARCEL_POS_1 = 1;
const uint32_t PARCEL_UINT_MAX = 0xffffffffU;
static const char *TEST_JSON_STR = "{\"name\":\"test_name\", \"age\":18}";
static const char *TEST_JSON_STR_1 =
    "{\"name\":\"test_name\", \"age\":18, \"useBigIntArr\":[\"userId\"], \"userId\":\"12343215234\"}";
static const char *TEST_JSON_STR_ARR = "[{\"name\":\"Tom1\",\"age\":18},{\"name\":\"Tom2\",\"age\":19}]";
static const char *TEST_STR = "test_str";
static const char TEST_CHAR = '0';

static void HcParcelNullPtrTest001()
{
    HcParcel *parcelNull = nullptr;
    ClearParcel(parcelNull);
    ResetParcel(parcelNull, 1, 1);
    HcParcel parcel;
    void *dstNull = nullptr;
    (void)ParcelEraseBlock(&parcel, 1, 1, dstNull);
    (void)ParcelIncrease(parcelNull, 1);
    (void)ParcelIncrease(&parcel, 0);
    ParcelRecycle(parcelNull);
    const void *srcNull = nullptr;
    (void)ParcelWrite(&parcel, srcNull, 1);
    (void)ParcelPopBack(parcelNull, 1);
    (void)ParcelPopBack(&parcel, 0);
    (void)ParcelPopFront(parcelNull, 1);
    (void)ParcelPopFront(&parcel, 0);
    DataRevert(parcelNull, 0);
    (void)ParcelCopy(&parcel, parcelNull);
    (void)ParcelReadParcel(&parcel, parcelNull, 0, HC_TRUE);
}

static void HcParcelNullPtrTest002()
{
    HcParcel *parcelNull = nullptr;
    HcParcel parcel;
    (void)GetParcelIncreaseSize(parcelNull, 1);
    parcel.allocUnit = 0;
    (void)GetParcelIncreaseSize(&parcel, 1);
}

static void HcParcelInValidDataSizeTest001()
{
    HcParcel parcel;
    parcel.beginPos = PARCEL_POS_1;
    parcel.endPos = PARCEL_POS_0;
    (void)GetParcelDataSize(&parcel);
    (void)GetParcelLastChar(&parcel);
    parcel.beginPos = PARCEL_POS_0;
    parcel.endPos = PARCEL_POS_1;
    parcel.allocUnit = 0;
    ParcelRecycle(&parcel);
}

static void HcParcelInValidDataSizeTest002()
{
    HcParcel parcel;
    uint32_t data = 1;
    (void)ParcelEraseBlock(&parcel, 1, 0, &data);
    (void)ParcelWriteRevert(&parcel, &data, 0);
    parcel.length = 1;
    (void)ParcelRealloc(&parcel, 0);
    parcel.data = nullptr;
    (void)ParcelIncrease(&parcel, 1);
}

static void HcParcelReadRevertTest001()
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel *parcelNull = nullptr;
    int32_t int32Dst = 0;
    uint32_t uint32Dst = 0;
    int16_t int16Dst = 0;
    uint16_t uint16Dst = 0;
    uint16_t *uint16DstNull = nullptr;
    int64_t int64Dst = 0;
    uint64_t uint64Dst = 0;
    (void)ParcelReadInt32Revert(&parcel, &int32Dst);
    (void)ParcelReadUint32Revert(&parcel, &uint32Dst);
    (void)ParcelReadInt16Revert(&parcel, &int16Dst);
    (void)ParcelReadUint16Revert(&parcel, &uint16Dst);
    (void)ParcelReadUint16Revert(&parcel, uint16DstNull);
    (void)ParcelReadUint16Revert(parcelNull, &uint16Dst);
    (void)ParcelReadUint16Revert(&parcel, &uint16Dst);
    (void)ParcelReadInt64Revert(&parcel, &int64Dst);
    (void)ParcelReadUint64Revert(&parcel, &uint64Dst);
    DeleteParcel(&parcel);
}

static void HcParcelCreateTest001()
{
    HcParcel parcelNullData = CreateParcel(TEST_INVALID_BUFFER_SIZE, PARCEL_DEFAULT_ALLOC_UNIT);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, PARCEL_DEFAULT_ALLOC_UNIT);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    (void)GetParcelDataSize(nullptr);
    (void)GetParcelDataSize(&parcelWithData);
    (void)GetParcelData(nullptr);
    (void)GetParcelData(&parcelWithData);
    (void)GetParcelLastChar(nullptr);
    (void)GetParcelLastChar(&parcelWithData);
    ClearParcel(&parcelWithData);
    ResetParcel(&parcelWithData, TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    DeleteParcel(nullptr);
    DeleteParcel(&parcelNullData);
    DeleteParcel(&parcelWithData);
}

static void HcParcelReadTest001()
{
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelReadWithoutPopData(&parcelWithData, &num, uintDataSize);
    (void)ParcelRead(nullptr, nullptr, uintDataSize);
    (void)ParcelRead(&parcelWithData, &num, uintDataSize);
    parcelWithData.beginPos = PARCEL_UINT_MAX - uintDataSize;
    (void)ParcelRead(&parcelWithData, &num, uintDataSize);
    parcelWithData.beginPos = 0;
    parcelWithData.endPos = 0;
    (void)ParcelRead(&parcelWithData, &num, uintDataSize);
    DeleteParcel(&parcelWithData);
}

static void HcParcelEraseBlockTest001()
{
    uint32_t start = 0;
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelEraseBlock(nullptr, start, uintDataSize, &num);
    (void)ParcelEraseBlock(&parcelWithData, PARCEL_UINT_MAX, uintDataSize, &num);
    (void)ParcelEraseBlock(&parcelWithData, PARCEL_UINT_MAX - uintDataSize, uintDataSize, &num);
    (void)ParcelEraseBlock(&parcelWithData, start, uintDataSize, &num);
    DeleteParcel(&parcelWithData);
}

static void HcParcelRevertTest001()
{
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelReadRevert(&parcelWithData, &num, TEST_LENGTH_ZERO);
    (void)ParcelReadRevert(&parcelWithData, &num, uintDataSize);
    (void)ParcelWriteRevert(nullptr, &num, uintDataSize);
    DeleteParcel(&parcelWithData);
}

static void HcParcelReadWrite001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    int32_t srcInt = 0;
    int32_t dstInt = 0;
    (void)ParcelWriteInt32(&parcelWithData, srcInt);
    (void)ParcelReadInt32(&parcelWithData, &dstInt);
    uint32_t srcUint32 = 0;
    uint32_t dstUint32 = 0;
    (void)ParcelWriteUint32(&parcelWithData, srcUint32);
    (void)ParcelReadUint32(&parcelWithData, &dstUint32);
    short srcInt16 = 0;
    short dstInt16 = 0;
    (void)ParcelWriteInt16(&parcelWithData, srcInt16);
    (void)ParcelReadInt16(&parcelWithData, &dstInt16);
    uint16_t srcUint16 = 0;
    uint16_t dstUint16 = 0;
    (void)ParcelWriteUint16(&parcelWithData, srcUint16);
    (void)ParcelReadUint16(&parcelWithData, &dstUint16);
    char srcInt8 = 0;
    char dstInt8 = 0;
    (void)ParcelWriteInt8(&parcelWithData, srcInt8);
    (void)ParcelReadInt8(&parcelWithData, &dstInt8);
    uint8_t srcUint8 = 0;
    uint8_t dstUint8 = 0;
    (void)ParcelWriteUint8(&parcelWithData, srcUint8);
    (void)ParcelReadUint8(&parcelWithData, &dstUint8);
    int64_t srcInt64 = 0;
    int64_t dstInt64 = 0;
    (void)ParcelWriteInt64(&parcelWithData, srcInt64);
    (void)ParcelReadInt64(&parcelWithData, &dstInt64);
    uint64_t srcUint64 = 0;
    uint64_t dstUint64 = 0;
    (void)ParcelWriteUint64(&parcelWithData, srcUint64);
    (void)ParcelReadUint64(&parcelWithData, &dstUint64);
    DeleteParcel(&parcelWithData);
}

static void HcParcelRealloc001()
{
    HcParcel parcelSrc = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel parcelDst = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)ParcelWriteInt32(&parcelSrc, TEST_SRC_DATA);
    uint32_t data01 = 0;
    uint64_t data02 = 0;
    uint32_t validLen = sizeof(data01);
    uint32_t invalidLen = sizeof(data02);
    (void)ParcelReadParcel(nullptr, nullptr, validLen, HC_FALSE);
    (void)ParcelReadParcel(&parcelSrc, &parcelDst, invalidLen, HC_FALSE);
    (void)ParcelReadParcel(&parcelSrc, &parcelDst, TEST_LENGTH_ZERO, HC_FALSE);
    (void)ParcelReadParcel(&parcelSrc, &parcelDst, validLen, HC_FALSE);
    DeleteParcel(&parcelSrc);
    DeleteParcel(&parcelDst);
}

static void HcParcelCopy001()
{
    HcParcel parcelSrc = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel parcelDst = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)ParcelCopy(nullptr, nullptr);
    (void)ParcelCopy(&parcelSrc, &parcelDst);
    (void)ParcelWriteInt32(&parcelSrc, TEST_SRC_DATA);
    (void)ParcelCopy(&parcelSrc, &parcelDst);
    DeleteParcel(&parcelSrc);
    DeleteParcel(&parcelDst);
}

static void HcParcelReadWriteRevert001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    int32_t srcInt = 0;
    int32_t dstInt = 0;
    (void)ParcelWriteInt32Revert(&parcelWithData, srcInt);
    (void)ParcelReadInt32Revert(&parcelWithData, &dstInt);
    uint32_t srcUint32 = 0;
    uint32_t dstUint32 = 0;
    (void)ParcelWriteUint32Revert(&parcelWithData, srcUint32);
    (void)ParcelReadUint32Revert(&parcelWithData, &dstUint32);
    short srcInt16 = 0;
    short dstInt16 = 0;
    (void)ParcelWriteInt16Revert(&parcelWithData, srcInt16);
    (void)ParcelReadInt16Revert(&parcelWithData, &dstInt16);
    uint16_t srcUint16 = 0;
    uint16_t dstUint16 = 0;
    (void)ParcelWriteUint16Revert(&parcelWithData, srcUint16);
    (void)ParcelReadUint16Revert(&parcelWithData, &dstUint16);
    char srcInt8 = 0;
    char dstInt8 = 0;
    (void)ParcelWriteInt8Revert(&parcelWithData, srcInt8);
    (void)ParcelReadInt8Revert(&parcelWithData, &dstInt8);
    uint8_t srcUint8 = 0;
    uint8_t dstUint8 = 0;
    (void)ParcelWriteUint8Revert(&parcelWithData, srcUint8);
    (void)ParcelReadUint8Revert(&parcelWithData, &dstUint8);
    int64_t srcInt64 = 0;
    int64_t dstInt64 = 0;
    (void)ParcelWriteInt64Revert(&parcelWithData, srcInt64);
    (void)ParcelReadInt64Revert(&parcelWithData, &dstInt64);
    uint64_t srcUint64 = 0;
    uint64_t dstUint64 = 0;
    (void)ParcelWriteUint64Revert(&parcelWithData, srcUint64);
    (void)ParcelReadUint64Revert(&parcelWithData, &dstUint64);
    DeleteParcel(&parcelWithData);
}

static void HcParcelPop001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)ParcelWriteInt32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelPopBack(&parcelWithData, sizeof(uint32_t));
    (void)ParcelPopBack(&parcelWithData, sizeof(uint32_t));
    (void)ParcelWriteInt32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelPopFront(&parcelWithData, sizeof(uint32_t));
    (void)ParcelPopFront(&parcelWithData, sizeof(uint32_t));
    DeleteParcel(&parcelWithData);
}

static void HcStringTest001()
{
    HcString selfStr = CreateString();
    HcString srcStr = CreateString();
    (void)StringSetPointer(&srcStr, TEST_STR);
    (void)StringAppend(nullptr, srcStr);
    (void)StringAppend(&selfStr, srcStr);
    (void)StringAppendPointer(nullptr, TEST_STR);
    (void)StringAppendPointer(&selfStr, TEST_STR);
    (void)StringAppendChar(nullptr, TEST_CHAR);
    (void)StringAppendChar(&selfStr, TEST_CHAR);
    (void)StringSet(nullptr, srcStr);
    (void)StringSet(&selfStr, srcStr);
    (void)StringSetPointer(nullptr, TEST_STR);
    (void)StringSetPointer(&selfStr, TEST_STR);
    const char *retStr = StringGet(nullptr);
    retStr = StringGet(&selfStr);
    uint32_t retLen = StringLength(nullptr);
    retLen = StringLength(&selfStr);
    DeleteString(&selfStr);
    retLen = StringLength(&selfStr);
    DeleteString(&srcStr);
}

static void HcCreateJsonTest001()
{
    CJson *invalidJson = CreateJsonFromString(nullptr);
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    invalidJson = DuplicateJson(nullptr);
    FreeJson(validJson);
}

static void HcDeleteJsonTest001()
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    CJson *jsonItem = DetachItemFromJson(nullptr, "age");
    jsonItem = DetachItemFromJson(validJson, "age");
    DeleteItemFromJson(nullptr, "name");
    DeleteItemFromJson(validJson, "name");
    DeleteAllItemExceptOne(nullptr, "name");
    DeleteAllItemExceptOne(validJson, "name");
    DeleteAllItem(nullptr);
    DeleteAllItem(validJson);
    FreeJson(validJson);
}

static void HcJsonGetTest001()
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    char *jsonStr = PackJsonToString(nullptr);
    jsonStr = PackJsonToString(validJson);
    FreeJsonString(jsonStr);
    int32_t itemNum = GetItemNum(nullptr);
    itemNum = GetItemNum(validJson);
    const char *itemKey = GetItemKey(nullptr);
    itemKey = GetItemKey(validJson);
    CJson *jsonObj = GetObjFromJson(nullptr, "name");
    jsonObj = GetObjFromJson(validJson, "name");
    jsonObj = GetItemFromArray(nullptr, 0);
    jsonObj = GetItemFromArray(validJson, 0);
    FreeJson(validJson);
}

static void HcJsonGetTest002()
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    const char *strObj = GetStringFromJson(nullptr, "name");
    strObj = GetStringFromJson(validJson, "name");
    char byteData[] = "test_byte";
    (void)GetByteFromJson(nullptr, "name", nullptr, sizeof(byteData));
    (void)GetByteFromJson(validJson, "gender", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)GetByteFromJson(validJson, "name", reinterpret_cast<uint8_t *>(byteData), TEST_LENGTH_ZERO);
    int32_t valueInt32 = 0;
    (void)GetIntFromJson(nullptr, "age", &valueInt32);
    uint32_t valueUint32 = 0;
    (void)GetUnsignedIntFromJson(nullptr, "age", &valueUint32);
    int64_t valueInt64 = 0;
    (void)GetInt64FromJson(nullptr, "age", &valueInt64);
    bool valueBool = false;
    (void)GetBoolFromJson(nullptr, "age", &valueBool);
    CJson *jsonObj = GetObjFromJson(validJson, "name");
    (void)GetStringValue(jsonObj);
    FreeJson(validJson);
}

static void HcJsonGetTest003()
{
    CJson *jsonObj = CreateJson();
    int data = 1;
    uint8_t value = 0;
    (void)AddIntToJson(jsonObj, "name", data);
    (void)GetUint8FromJson(nullptr, "name", &value);
    (void)GetUint8FromJson(jsonObj, nullptr, &value);
    (void)GetUint8FromJson(jsonObj, "name", nullptr);
    (void)GetUint8FromJson(jsonObj, "name", &value);
    DeleteItemFromJson(jsonObj, "name");
    (void)GetUint8FromJson(jsonObj, "name", &value);
    (void)GetBoolFromJson(jsonObj, nullptr, nullptr);
    (void)GetBoolFromJson(jsonObj, "name", nullptr);
    (void)GetUnsignedIntFromJson(jsonObj, nullptr, nullptr);
    (void)GetUnsignedIntFromJson(jsonObj, "name", nullptr);
    (void)GetIntFromJson(jsonObj, nullptr, nullptr);
    (void)GetIntFromJson(jsonObj, "name", nullptr);
    (void)GetByteFromJson(jsonObj, nullptr, nullptr, TEST_BUFFER_SIZE);
    (void)GetByteFromJson(jsonObj, "name", nullptr, TEST_BUFFER_SIZE);
    (void)GetStringFromJson(jsonObj, nullptr);
    FreeJsonString(nullptr);
    CJson *retJson = DetachItemFromJson(jsonObj, nullptr);
    retJson = GetObjFromJson(jsonObj, nullptr);
    DeleteAllItemExceptOne(jsonObj, nullptr);
    DeleteItemFromJson(jsonObj, nullptr);
    retJson = DuplicateJson(nullptr);
    FreeJson(jsonObj);
}

static void HcJsonGetTest004()
{
    CJson *jsonObj = CreateJson();
    uint32_t byteLen = 0;
    char byteData[] = "test_byte";
    (void)AddByteToJson(jsonObj, "name", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)GetByteLenFromJson(nullptr, "name", &byteLen);
    (void)GetByteLenFromJson(jsonObj, nullptr, &byteLen);
    (void)GetByteLenFromJson(jsonObj, "name", nullptr);
    (void)GetByteLenFromJson(jsonObj, "name", &byteLen);
    (void)GetByteLenFromJson(jsonObj, "test", &byteLen);
    FreeJson(jsonObj);
}

static void HcJsonAddTest001()
{
    CJson *jsonArr = CreateJsonFromString(TEST_JSON_STR_ARR);
    CJson *childObj = CreateJsonFromString(TEST_JSON_STR);
    (void)AddObjToJson(nullptr, "name", nullptr);
    (void)AddObjToJson(jsonArr, "gender", childObj);
    (void)AddObjToJson(jsonArr, "name", childObj);
    (void)AddObjToArray(nullptr, childObj);
    (void)AddObjToArray(childObj, jsonArr);
    (void)AddObjToArray(jsonArr, childObj);
    (void)AddStringToArray(nullptr, TEST_STR);
    (void)AddStringToArray(childObj, TEST_STR);
    (void)AddStringToArray(jsonArr, TEST_STR);
    (void)AddStringToJson(nullptr, "name", TEST_STR);
    (void)AddStringToJson(childObj, "gender", TEST_STR);
    (void)AddStringToJson(childObj, "name", TEST_STR);
    FreeJson(jsonArr);
}

static void HcJsonAddTest002()
{
    CJson *childObj = CreateJsonFromString(TEST_JSON_STR);
    char byteData[] = "test_byte";
    (void)AddByteToJson(nullptr, "name", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)AddByteToJson(childObj, "gender", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)AddByteToJson(childObj, "name", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)AddBoolToJson(nullptr, "name", false);
    (void)AddBoolToJson(childObj, "gender", false);
    (void)AddBoolToJson(childObj, "name", false);
    int32_t valueInt32 = 0;
    (void)AddIntToJson(nullptr, "name", valueInt32);
    (void)AddIntToJson(childObj, "gender", valueInt32);
    (void)AddIntToJson(childObj, "name", valueInt32);
    int64_t valueInt64 = 0;
    (void)AddInt64StringToJson(nullptr, "name", valueInt64);
    (void)AddInt64StringToJson(childObj, "name", valueInt64);
    const char *const strArr[] = {"first test data", "second test data"};
    (void)AddStringArrayToJson(nullptr, "name", strArr, sizeof(strArr) / sizeof(strArr[0]));
    (void)AddStringArrayToJson(childObj, "name", strArr, sizeof(strArr) / sizeof(strArr[0]));
}

static void HcJsonAddTest003()
{
    CJson *jsonObj = CreateJson();
    (void)AddBoolToJson(jsonObj, nullptr, false);
    (void)AddByteToJson(jsonObj, nullptr, nullptr, TEST_BUFFER_SIZE);
    (void)AddByteToJson(jsonObj, "name", nullptr, TEST_BUFFER_SIZE);
    (void)AddIntToJson(jsonObj, nullptr, 0);
    (void)AddStringArrayToJson(jsonObj, nullptr, nullptr, TEST_BUFFER_SIZE);
    (void)AddStringArrayToJson(jsonObj, "name", nullptr, TEST_BUFFER_SIZE);
    (void)AddStringToJson(jsonObj, nullptr, nullptr);
    (void)AddStringToJson(jsonObj, "name", nullptr);
    (void)AddStringToArray(jsonObj, nullptr);
    (void)AddObjToArray(jsonObj, nullptr);
    (void)AddObjToJson(jsonObj, nullptr, nullptr);
    (void)AddObjToJson(jsonObj, "name", nullptr);
    FreeJson(jsonObj);
}

static void HcClearJsonTest001()
{
    CJson *jsonObj = CreateJsonFromString(TEST_JSON_STR);
    ClearSensitiveStringInJson(nullptr, "name");
    ClearSensitiveStringInJson(jsonObj, "gender");
    ClearSensitiveStringInJson(jsonObj, "name");
    ClearSensitiveStringInJson(jsonObj, nullptr);
    FreeJson(jsonObj);
}

static void HcClearJsonTest002()
{
    CJson *jsonObj = CreateJsonFromString(TEST_JSON_STR);
    char *jsonStr = PackJsonToString(jsonObj);
    ClearAndFreeJsonString(nullptr);
    ClearAndFreeJsonString(jsonStr);
    FreeJson(jsonObj);
}

static void HcClearJsonTest003()
{
    CJson *jsonObj = CreateJsonFromString(TEST_JSON_STR_1);
    char *jsonStr = PackJsonToString(jsonObj);
    ClearAndFreeJsonString(nullptr);
    ClearAndFreeJsonString(jsonStr);
    FreeJson(jsonObj);
}

static void HcStringUtilTest001()
{
    const uint8_t byteData[] = "1234";
    const char hexData[] = "ABCD";
    const char invalidData[] = "GHJK";
    const char inValidLenData[] = "ABC";
    uint32_t byteSize = sizeof(byteData);
    char hexStr[TEST_BUFFER_SIZE] = { 0 };
    (void)ByteToHexString(nullptr, byteSize, hexStr, TEST_BUFFER_SIZE);
    (void)ByteToHexString(byteData, byteSize, nullptr, TEST_BUFFER_SIZE);
    (void)ByteToHexString(byteData, byteSize, hexStr, TEST_LENGTH_ZERO);
    (void)ByteToHexString(byteData, byteSize, hexStr, TEST_BUFFER_SIZE);
    uint8_t byteStr[TEST_BUFFER_SIZE] = { 0 };
    (void)HexStringToByte(nullptr, byteStr, TEST_BUFFER_SIZE);
    (void)HexStringToByte(hexData, nullptr, TEST_BUFFER_SIZE);
    (void)HexStringToByte(inValidLenData, byteStr, TEST_BUFFER_SIZE);
    (void)HexStringToByte(hexData, byteStr, TEST_LENGTH_ZERO);
    (void)HexStringToByte(invalidData, byteStr, TEST_BUFFER_SIZE);
    (void)HexStringToByte(hexData, byteStr, TEST_BUFFER_SIZE);
    const char intStr[] = "10";
    int64_t int64Res = StringToInt64(intStr);
    int64Res = StringToInt64(nullptr);
}

static void HcStringUtilTest002()
{
    const char oriData[] = "abcd";
    const char inValidData[] = "";
    char *desData = nullptr;
    (void)ToUpperCase(nullptr, &desData);
    (void)ToUpperCase(oriData, nullptr);
    (void)DeepCopyString(nullptr, &desData);
    (void)DeepCopyString(inValidData, &desData);
}

static void HcStringUtilTest003()
{
    const uint8_t byteData[] = "1234";
    uint32_t byteSize = sizeof(byteData);
    const char tag[] = "TEST";
    PrintBuffer(byteData, byteSize, tag);
}

static void HcStringUtilTest004()
{
    const char oriData[] = "abcd";
    char anonymousData[TEST_MIN_ANONYMOUS_LEN + TEST_LEN_TWO] = { 0 };
    (void)GetAnonymousString(oriData, nullptr, TEST_MIN_ANONYMOUS_LEN + 1);
    (void)GetAnonymousString(oriData, anonymousData, TEST_MIN_ANONYMOUS_LEN - 1);
    (void)GetAnonymousString(oriData, anonymousData, TEST_MIN_ANONYMOUS_LEN + 1);
    (void)GetAnonymousString(oriData, anonymousData, TEST_MIN_ANONYMOUS_LEN + TEST_LEN_TWO);
}

static void ParseTlvHeadTest001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    TlvBase tlvBase = {
        .tag = 0,
        .length = 0,
        .checkTag = 1,
    };
    (void)ParseTlvHead(&tlvBase, nullptr);
    (void)ParseTlvHead(&tlvBase, &parcelWithData);
    parcelWithData.beginPos = PARCEL_UINT_MAX;
    tlvBase.checkTag = tlvBase.length;
    (void)ParseTlvHead(&tlvBase, &parcelWithData);
    parcelWithData.beginPos = 0;
    tlvBase.length = MAX_TLV_LENGTH + 1;
    (void)ParseTlvHead(&tlvBase, &parcelWithData);
    tlvBase.length = 0;
    (void)ParseTlvHead(&tlvBase, &parcelWithData);
    DeleteParcel(&parcelWithData);
}


static void ParseTlvNodeTest001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    TlvBase tlvBase = {
        .tag = 0,
        .length = GetParcelDataSize(&parcelWithData) + 1,
        .checkTag = 1,
    };
    (void)ParseTlvNode(nullptr, &parcelWithData, true);
    (void)ParseTlvNode(&tlvBase, &parcelWithData, true);
    DeleteParcel(&parcelWithData);
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    HcParcelNullPtrTest001();
    HcParcelNullPtrTest002();
    HcParcelInValidDataSizeTest001();
    HcParcelInValidDataSizeTest002();
    HcParcelReadRevertTest001();
    HcParcelCreateTest001();
    HcParcelReadTest001();
    HcParcelEraseBlockTest001();
    HcParcelRevertTest001();
    HcParcelReadWrite001();
    HcParcelRealloc001();
    HcParcelCopy001();
    HcParcelReadWriteRevert001();
    HcParcelPop001();
    HcStringTest001();
    HcCreateJsonTest001();
    HcDeleteJsonTest001();
    HcJsonGetTest001();
    HcJsonGetTest002();
    HcJsonGetTest003();
    HcJsonGetTest004();
    HcJsonAddTest001();
    HcJsonAddTest002();
    HcJsonAddTest003();
    HcClearJsonTest001();
    HcClearJsonTest002();
    HcClearJsonTest003();
    HcStringUtilTest001();
    HcStringUtilTest002();
    HcStringUtilTest003();
    HcStringUtilTest004();
    ParseTlvHeadTest001();
    ParseTlvNodeTest001();
    return true;
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoCallback(data, size);
    return 0;
}

