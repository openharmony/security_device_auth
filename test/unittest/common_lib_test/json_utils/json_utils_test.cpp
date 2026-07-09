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
#include "json_utils.h"
#include "clib_error.h"
#include "hc_types.h"

using namespace testing::ext;

namespace {
static const char *TEST_JSON_STR = "{\"name\":\"test\",\"value\":123}";
static const char *TEST_JSON_ARR = "[1,2,3]";
static const uint8_t TEST_DATA[] = "{\"key\":\"value\"}";


class JsonUtilsTest : public testing::Test {};

HWTEST_F(JsonUtilsTest, CreateJsonFromDataTest001, TestSize.Level0)
{
    CJson *json = nullptr;
    int32_t ret = CreateJsonFromData(TEST_DATA, sizeof(TEST_DATA) - 1, &json);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_NE(json, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, CreateJsonFromDataTest002, TestSize.Level0)
{
    CJson *json = nullptr;
    int32_t ret = CreateJsonFromData(nullptr, sizeof(TEST_DATA), &json);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
}

HWTEST_F(JsonUtilsTest, CreateJsonFromDataTest003, TestSize.Level0)
{
    CJson *json = nullptr;
    int32_t ret = CreateJsonFromData(TEST_DATA, 0, &json);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
}

HWTEST_F(JsonUtilsTest, CreateJsonFromDataTest004, TestSize.Level0)
{
    CJson *json = nullptr;
    int32_t ret = CreateJsonFromData(TEST_DATA, sizeof(TEST_DATA) - 1, &json);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_NE(json, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, CreateJsonFromStringTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, CreateJsonFromStringTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(nullptr);
    EXPECT_EQ(json, nullptr);
}

HWTEST_F(JsonUtilsTest, CreateJsonFromStringTest003, TestSize.Level0)
{
    CJson *json = CreateJsonFromString("invalid json");
    EXPECT_EQ(json, nullptr);
}

HWTEST_F(JsonUtilsTest, CreateJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, CreateJsonArrayTest001, TestSize.Level0)
{
    CJson *json = CreateJsonArray();
    EXPECT_NE(json, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, DuplicateJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    CJson *dup = DuplicateJson(json);
    EXPECT_NE(dup, nullptr);
    FreeJson(json);
    FreeJson(dup);
}

HWTEST_F(JsonUtilsTest, DuplicateJsonTest002, TestSize.Level0)
{
    CJson *dup = DuplicateJson(nullptr);
    EXPECT_EQ(dup, nullptr);
}

HWTEST_F(JsonUtilsTest, DeleteItemFromJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    DeleteItemFromJson(json, "name");
    const char *name = GetStringFromJson(json, "name");
    EXPECT_EQ(name, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, DeleteItemFromJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    DeleteItemFromJson(nullptr, "name");
    DeleteItemFromJson(json, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, DeleteAllItemExceptOneTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    DeleteAllItemExceptOne(json, "name");
    const char *name = GetStringFromJson(json, "name");
    EXPECT_NE(name, nullptr);
    int32_t value = 0;
    int32_t ret = GetIntFromJson(json, "value", &value);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, DeleteAllItemExceptOneTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    DeleteAllItemExceptOne(nullptr, "name");
    DeleteAllItemExceptOne(json, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, DeleteAllItemTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    DeleteAllItem(json);
    int32_t num = GetItemNum(json);
    EXPECT_EQ(num, 0);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, DeleteAllItemTest002, TestSize.Level0)
{
    CJson *json = nullptr;
    DeleteAllItem(json);
    EXPECT_EQ(json, nullptr);
}

HWTEST_F(JsonUtilsTest, DetachItemFromJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    CJson *item = DetachItemFromJson(json, "name");
    EXPECT_NE(item, nullptr);
    const char *name = GetStringFromJson(json, "name");
    EXPECT_EQ(name, nullptr);
    FreeJson(item);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, DetachItemFromJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    CJson *item = DetachItemFromJson(nullptr, "name");
    EXPECT_EQ(item, nullptr);
    item = DetachItemFromJson(json, nullptr);
    EXPECT_EQ(item, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, PackJsonToStringTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    char *str = PackJsonToString(json);
    EXPECT_NE(str, nullptr);
    FreeJsonString(str);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, PackJsonToStringTest002, TestSize.Level0)
{
    char *str = PackJsonToString(nullptr);
    EXPECT_EQ(str, nullptr);
}

HWTEST_F(JsonUtilsTest, GetItemNumTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    int32_t num = GetItemNum(json);
    EXPECT_GT(num, 0);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetItemNumTest002, TestSize.Level0)
{
    int32_t num = GetItemNum(nullptr);
    EXPECT_EQ(num, 0);
}

HWTEST_F(JsonUtilsTest, GetItemKeyTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    const char *key = GetItemKey(json);
    EXPECT_EQ(key, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetObjFromJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString("{\"obj\":{\"key\":\"value\"}}");
    EXPECT_NE(json, nullptr);
    CJson *obj = GetObjFromJson(json, "obj");
    EXPECT_NE(obj, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetObjFromJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    CJson *obj = GetObjFromJson(nullptr, "name");
    EXPECT_EQ(obj, nullptr);
    obj = GetObjFromJson(json, nullptr);
    EXPECT_EQ(obj, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetItemFromArrayTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_ARR);
    EXPECT_NE(json, nullptr);
    CJson *item = GetItemFromArray(json, 0);
    EXPECT_NE(item, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetItemFromArrayTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_ARR);
    EXPECT_NE(json, nullptr);
    CJson *item = GetItemFromArray(nullptr, 0);
    EXPECT_EQ(item, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetStringFromJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    const char *str = GetStringFromJson(json, "name");
    EXPECT_NE(str, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetStringFromJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    const char *str = GetStringFromJson(nullptr, "name");
    EXPECT_EQ(str, nullptr);
    str = GetStringFromJson(json, nullptr);
    EXPECT_EQ(str, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetIntFromJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    int32_t value = 0;
    int32_t ret = GetIntFromJson(json, "value", &value);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(value, 123);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, GetIntFromJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    int32_t value = 0;
    int32_t ret = GetIntFromJson(nullptr, "value", &value);
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = GetIntFromJson(json, nullptr, &value);
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = GetIntFromJson(json, "value", nullptr);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddObjToJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    CJson *obj = CreateJson();
    EXPECT_NE(obj, nullptr);
    int32_t ret = AddObjToJson(json, "obj", obj);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddObjToJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    int32_t ret = AddObjToJson(nullptr, "obj", json);
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = AddObjToJson(json, nullptr, json);
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = AddObjToJson(json, "obj", nullptr);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddStringToJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    int32_t ret = AddStringToJson(json, "name", "test");
    EXPECT_EQ(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddStringToJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    int32_t ret = AddStringToJson(nullptr, "name", "test");
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = AddStringToJson(json, nullptr, "test");
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = AddStringToJson(json, "name", nullptr);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddIntToJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    int32_t ret = AddIntToJson(json, "value", 123);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    int32_t value = 0;
    ret = GetIntFromJson(json, "value", &value);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(value, 123);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddIntToJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    int32_t ret = AddIntToJson(nullptr, "value", 123);
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = AddIntToJson(json, nullptr, 123);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddBoolToJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    int32_t ret = AddBoolToJson(json, "flag", true);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    bool flag = false;
    ret = GetBoolFromJson(json, "flag", &flag);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(flag, true);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddBoolToJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    int32_t ret = AddBoolToJson(nullptr, "flag", true);
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = AddBoolToJson(json, nullptr, true);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddByteToJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    uint8_t data[] = {0x01, 0x02, 0x03};
    int32_t ret = AddByteToJson(json, "data", data, sizeof(data));
    EXPECT_EQ(ret, CLIB_SUCCESS);
    uint8_t outData[sizeof(data)] = {0};
    uint32_t outLen = sizeof(outData);
    ret = GetByteFromJson(json, "data", outData, outLen);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(outLen, sizeof(data));
    EXPECT_EQ(memcmp(data, outData, sizeof(data)), 0);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, AddByteToJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJson();
    EXPECT_NE(json, nullptr);
    uint8_t data[] = {0x01, 0x02, 0x03};
    int32_t ret = AddByteToJson(nullptr, "data", data, sizeof(data));
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = AddByteToJson(json, nullptr, data, sizeof(data));
    EXPECT_NE(ret, CLIB_SUCCESS);
    ret = AddByteToJson(json, "data", nullptr, sizeof(data));
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, ClearSensitiveStringInJsonTest001, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    ClearSensitiveStringInJson(json, "name");
    const char *name = GetStringFromJson(json, "name");
    EXPECT_EQ(HcStrlen(name), 0);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, ClearSensitiveStringInJsonTest002, TestSize.Level0)
{
    CJson *json = CreateJsonFromString(TEST_JSON_STR);
    EXPECT_NE(json, nullptr);
    ClearSensitiveStringInJson(nullptr, "name");
    ClearSensitiveStringInJson(json, nullptr);
    FreeJson(json);
}

HWTEST_F(JsonUtilsTest, ClearAndFreeJsonStringTest001, TestSize.Level0)
{
    char *str = static_cast<char *>(HcMalloc(10, 0));
    EXPECT_NE(str, nullptr);
    ClearAndFreeJsonString(str);
}

HWTEST_F(JsonUtilsTest, ClearAndFreeJsonStringTest002, TestSize.Level0)
{
    char *str = nullptr;
    ClearAndFreeJsonString(str);
    EXPECT_EQ(str, nullptr);
}

HWTEST_F(JsonUtilsTest, AddObjToArrayTest001, TestSize.Level0)
{
    CJson *jsonArr = CreateJsonArray();
    CJson *item = CreateJson();
    AddStringToJson(item, "key", "value");
    int32_t ret = AddObjToArray(jsonArr, item);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(GetItemNum(jsonArr), 1);
    FreeJson(jsonArr);
}

HWTEST_F(JsonUtilsTest, AddObjToArrayNullTest001, TestSize.Level0)
{
    CJson *item = CreateJson();
    int32_t ret = AddObjToArray(NULL, item);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    FreeJson(item);
}

HWTEST_F(JsonUtilsTest, AddObjToArrayNullTest002, TestSize.Level0)
{
    CJson *jsonArr = CreateJsonArray();
    int32_t ret = AddObjToArray(jsonArr, NULL);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    FreeJson(jsonArr);
}

HWTEST_F(JsonUtilsTest, AddObjToArrayNonArrayTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddStringToJson(jsonObj, "key", "value");
    CJson *item = CreateJson();
    int32_t ret = AddObjToArray(jsonObj, item);
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
    FreeJson(jsonObj);
    FreeJson(item);
}

HWTEST_F(JsonUtilsTest, AddStringToArrayTest001, TestSize.Level0)
{
    CJson *jsonArr = CreateJsonArray();
    int32_t ret = AddStringToArray(jsonArr, "hello");
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(GetItemNum(jsonArr), 1);
    FreeJson(jsonArr);
}

HWTEST_F(JsonUtilsTest, AddStringToArrayNullTest001, TestSize.Level0)
{
    int32_t ret = AddStringToArray(NULL, "hello");
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(JsonUtilsTest, AddStringToArrayNullTest002, TestSize.Level0)
{
    CJson *jsonArr = CreateJsonArray();
    int32_t ret = AddStringToArray(jsonArr, NULL);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
    FreeJson(jsonArr);
}

HWTEST_F(JsonUtilsTest, AddStringToArrayNonArrayTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    int32_t ret = AddStringToArray(jsonObj, "hello");
    EXPECT_EQ(ret, CLIB_ERR_INVALID_PARAM);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, AddInt64StringToJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    int32_t ret = AddInt64StringToJson(jsonObj, "int64key", 123456789012LL);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    const char *str = GetStringFromJson(jsonObj, "int64key");
    EXPECT_NE(str, nullptr);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, AddInt64StringToJsonTest002, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    int32_t ret = AddInt64StringToJson(jsonObj, "negkey", -12345LL);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, AddStringArrayToJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    const char *strs[] = {"hello", "world"};
    int32_t ret = AddStringArrayToJson(jsonObj, "arrkey", strs, 2);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, AddStringArrayToJsonNullTest001, TestSize.Level0)
{
    int32_t ret = AddStringArrayToJson(NULL, "key", nullptr, 0);
    EXPECT_EQ(ret, CLIB_ERR_NULL_PTR);
}

HWTEST_F(JsonUtilsTest, GetUnsignedIntFromJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddIntToJson(jsonObj, "uintkey", 123);
    uint32_t val = 0;
    int32_t ret = GetUnsignedIntFromJson(jsonObj, "uintkey", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, 123u);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetUnsignedIntFromJsonTest002, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddIntToJson(jsonObj, "negkey", -5);
    uint32_t val = 0;
    int32_t ret = GetUnsignedIntFromJson(jsonObj, "negkey", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetUnsignedIntFromJsonRecurseTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"outer\":{\"inner\":{\"uintkey\":42}}}");
    EXPECT_NE(jsonObj, nullptr);
    uint32_t val = 0;
    int32_t ret = GetUnsignedIntFromJson(jsonObj, "uintkey", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, 42u);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetUint8FromJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddIntToJson(jsonObj, "u8key", 200);
    uint8_t val = 0;
    int32_t ret = GetUint8FromJson(jsonObj, "u8key", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, 200);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetUint8FromJsonTest002, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddIntToJson(jsonObj, "negkey", -1);
    uint8_t val = 0;
    int32_t ret = GetUint8FromJson(jsonObj, "negkey", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetByteLenFromJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddStringToJson(jsonObj, "hexkey", "0102ff");
    uint32_t len = 0;
    int32_t ret = GetByteLenFromJson(jsonObj, "hexkey", &len);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(len, 3u);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetStringValueTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddStringToJson(jsonObj, "strkey", "hello");
    CJson *item = GetObjFromJson(jsonObj, "strkey");
    const char *val = GetStringValue(item);
    EXPECT_NE(val, nullptr);
    EXPECT_STREQ(val, "hello");
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetStringValueNullTest001, TestSize.Level0)
{
    const char *val = GetStringValue(NULL);
    EXPECT_EQ(val, nullptr);
}

HWTEST_F(JsonUtilsTest, ReplaceStringInJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddStringToJson(jsonObj, "key", "first");
    EXPECT_STREQ(GetStringFromJson(jsonObj, "key"), "first");
    int32_t ret = AddStringToJson(jsonObj, "key", "second");
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_STREQ(GetStringFromJson(jsonObj, "key"), "second");
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, ReplaceBoolInJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddBoolToJson(jsonObj, "flag", false);
    bool val = true;
    GetBoolFromJson(jsonObj, "flag", &val);
    EXPECT_EQ(val, false);
    int32_t ret = AddBoolToJson(jsonObj, "flag", true);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    GetBoolFromJson(jsonObj, "flag", &val);
    EXPECT_EQ(val, true);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, ReplaceIntInJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddIntToJson(jsonObj, "num", 10);
    int32_t val = 0;
    GetIntFromJson(jsonObj, "num", &val);
    EXPECT_EQ(val, 10);
    int32_t ret = AddIntToJson(jsonObj, "num", 20);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    GetIntFromJson(jsonObj, "num", &val);
    EXPECT_EQ(val, 20);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, ReplaceObjInJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    CJson *obj1 = CreateJson();
    AddStringToJson(obj1, "inner", "v1");
    AddObjToJson(jsonObj, "obj", obj1);
    FreeJson(obj1);
    CJson *obj2 = CreateJson();
    AddStringToJson(obj2, "inner", "v2");
    int32_t ret = AddObjToJson(jsonObj, "obj", obj2);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    FreeJson(obj2);
    CJson *found = GetObjFromJson(jsonObj, "obj");
    EXPECT_NE(found, nullptr);
    EXPECT_STREQ(GetStringFromJson(found, "inner"), "v2");
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetStringFromJsonRecurseTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"outer\":{\"inner\":{\"name\":\"deepval\"}}}");
    EXPECT_NE(jsonObj, nullptr);
    const char *str = GetStringFromJson(jsonObj, "name");
    EXPECT_NE(str, nullptr);
    EXPECT_STREQ(str, "deepval");
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetIntFromJsonRecurseTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"outer\":{\"inner\":{\"value\":456}}}");
    EXPECT_NE(jsonObj, nullptr);
    int32_t val = 0;
    int32_t ret = GetIntFromJson(jsonObj, "value", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, 456);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetBoolFromJsonRecurseTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"outer\":{\"inner\":{\"flag\":true}}}");
    EXPECT_NE(jsonObj, nullptr);
    bool val = false;
    int32_t ret = GetBoolFromJson(jsonObj, "flag", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, true);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetObjFromJsonRecurseTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"outer\":{\"inner\":{\"target\":{\"key\":\"val\"}}}}");
    EXPECT_NE(jsonObj, nullptr);
    CJson *obj = GetObjFromJson(jsonObj, "target");
    EXPECT_NE(obj, nullptr);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetInt64FromJsonTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddInt64StringToJson(jsonObj, "bigval", 123456789012LL);
    int64_t val = 0;
    int32_t ret = GetInt64FromJson(jsonObj, "bigval", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, 123456789012LL);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetInt64FromJsonNullKeyTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    int64_t val = 0;
    int32_t ret = GetInt64FromJson(jsonObj, NULL, &val);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetInt64FromJsonNullValueTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    AddInt64StringToJson(jsonObj, "bigval", 123456789012LL);
    int64_t val = 0;
    int32_t ret = GetInt64FromJson(jsonObj, "bigval", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, 123456789012LL);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetInt64FromJsonNotFoundTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    int64_t val = 0;
    int32_t ret = GetInt64FromJson(jsonObj, "nonexistent", &val);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetBoolFromJsonTrueTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"flag\":true}");
    EXPECT_NE(jsonObj, nullptr);
    bool val = false;
    int32_t ret = GetBoolFromJson(jsonObj, "flag", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, true);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetBoolFromJsonFalseTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"flag\":false}");
    EXPECT_NE(jsonObj, nullptr);
    bool val = true;
    int32_t ret = GetBoolFromJson(jsonObj, "flag", &val);
    EXPECT_EQ(ret, CLIB_SUCCESS);
    EXPECT_EQ(val, false);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetBoolFromJsonNullKeyTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJson();
    bool val = false;
    int32_t ret = GetBoolFromJson(jsonObj, NULL, &val);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, GetBoolFromJsonNullValueTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"flag\":true}");
    EXPECT_NE(jsonObj, nullptr);
    int32_t ret = GetBoolFromJson(jsonObj, "flag", NULL);
    EXPECT_NE(ret, CLIB_SUCCESS);
    FreeJson(jsonObj);
}

HWTEST_F(JsonUtilsTest, ClearSensitiveStringInJsonNullStrTest001, TestSize.Level0)
{
    CJson *jsonObj = CreateJsonFromString("{\"secret\":\"sensitive\"}");
    EXPECT_NE(jsonObj, nullptr);
    ClearSensitiveStringInJson(jsonObj, "nonexistent");
    FreeJson(jsonObj);
}
}