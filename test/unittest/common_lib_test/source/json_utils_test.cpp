/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http: //www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OFkt ANY KIND, either express or implied.
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
}