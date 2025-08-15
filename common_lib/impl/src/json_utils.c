/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "json_utils.h"
#include <inttypes.h>
#include <string.h>
#include "securec.h"
#include "clib_error.h"
#include "hc_types.h"
#include "string_util.h"
#include "hc_log.h"

#define RECURSE_FLAG_TRUE 1
#define MAX_DEPTH 10
#define MAX_LEN 5
#define BIG_INT_ARR "bigIntArr"
#define SPLIT_LEN_ONE 1
#define SPLIT_LEN_TWO 2

static int32_t GetCjsonMaxDepth(const char *jsonStr)
{
    int32_t max = 0;
    uint32_t len = HcStrlen(jsonStr);
    int32_t cnt = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (jsonStr[i] == '{' || jsonStr[i] == '[') {
            cnt++;
            if (cnt > max) {
                max = cnt;
            }
        } else if (jsonStr[i] == '}' || jsonStr[i] == ']') {
            cnt--;
        }
    }
    return max;
}

CJson *CreateJsonFromString(const char *jsonStr)
{
    if (jsonStr == NULL) {
        return NULL;
    }
    int32_t depth = GetCjsonMaxDepth(jsonStr);
    if (depth > MAX_DEPTH) {
        LOGE("jsonStr depth %" LOG_PUB "d over 10", depth);
        return NULL;
    }
    return cJSON_Parse(jsonStr);
}

CJson *CreateJson(void)
{
    return cJSON_CreateObject();
}

CJson *CreateJsonArray(void)
{
    return cJSON_CreateArray();
}

CJson *DuplicateJson(const CJson *jsonObj)
{
    if (jsonObj == NULL) {
        return NULL;
    }
    return cJSON_Duplicate(jsonObj, RECURSE_FLAG_TRUE);
}

void FreeJson(CJson *jsonObj)
{
    cJSON_Delete(jsonObj);
}

void DeleteItemFromJson(CJson *jsonObj, const char *key)
{
    if (jsonObj == NULL || key == NULL) {
        return;
    }
    cJSON_DeleteItemFromObjectCaseSensitive(jsonObj, key);
}

void DeleteAllItemExceptOne(CJson *jsonObj, const char *key)
{
    if (jsonObj == NULL || key == NULL) {
        return;
    }

    CJson *curItem = jsonObj->child;
    CJson *nextItem = NULL;
    while (curItem != NULL) {
        nextItem = curItem->next;
        if (!IsStrEqual(key, curItem->string)) {
            cJSON_Delete(cJSON_DetachItemViaPointer(jsonObj, curItem));
        }
        curItem = nextItem;
    }
}

void DeleteAllItem(CJson *jsonObj)
{
    if (jsonObj == NULL) {
        return;
    }

    CJson *curItem = jsonObj->child;
    CJson *nextItem = NULL;
    while (curItem != NULL) {
        nextItem = curItem->next;
        cJSON_Delete(cJSON_DetachItemViaPointer(jsonObj, curItem));
        curItem = nextItem;
    }
}

CJson *DetachItemFromJson(CJson *jsonObj, const char *key)
{
    if (jsonObj == NULL || key == NULL) {
        return NULL;
    }

    return cJSON_DetachItemFromObjectCaseSensitive(jsonObj, key);
}

static void ReplaceStringToInt(char *input, const char *keyName)
{
    if (keyName == NULL) {
        LOGE("input keyName is NULL.");
        return;
    }
    uint32_t keywordLen = SPLIT_LEN_ONE + HcStrlen(keyName) + SPLIT_LEN_TWO;
    char keyword[keywordLen + 1];
    keyword[0] = '"';
    if (strcpy_s(&keyword[1], HcStrlen(keyName) + 1, keyName) != EOK) {
        LOGE("failed to copy keyword to buffer.");
        return;
    }
    keyword[keywordLen - SPLIT_LEN_TWO] = '"';
    keyword[keywordLen - SPLIT_LEN_ONE] = ':';
    keyword[keywordLen] = '\0';
    const char * const pos1 = strstr(input, keyword);
    if (pos1 == NULL) {
        LOGW("keyword not found.");
        return;
    }
    const char * const pos2 = strstr(pos1 + keywordLen + 1, "\"");
    if (pos2 == NULL) {
        LOGW("json key format parse error.");
        return;
    }
    uint32_t startOffset = pos1 - input + keywordLen;
    uint32_t endOffset = pos2 - input;

    bool shouldReplace = true;
    for (uint32_t i = startOffset + 1; i < endOffset; i++) {
        // only replace if the content is only composed of digits
        shouldReplace &= input[i] >= '0' && input[i] <= '9';
    }

    if (shouldReplace) {
        uint32_t readI = startOffset + SPLIT_LEN_ONE;
        uint32_t writeI = startOffset;
        while (input[readI]) {
            input[writeI] = input[readI];
            readI++;
            writeI++;
            if (readI == endOffset) {
                readI++;
            }
        }
        input[writeI] = '\0';
    }
}

static char **CreateKeyList(CJson *arr)
{
    int keyListSize = GetItemNum(arr);
    char **keyList = HcMalloc(keyListSize, sizeof(char *));
    if (keyList == NULL) {
        LOGE("Malloc keyList failed.");
        return NULL;
    }
    for (int i = 0; i < keyListSize; i++) {
        const char *str = GetStringValue(GetItemFromArray(arr, i));
        if (str == NULL) {
            keyList[i] = NULL;
        } else {
            keyList[i] = strdup(str);
        }
    }
    return keyList;
}

static void DestroyKeyList(int size, char **keyList)
{
    for (int i = 0; i < size; i++) {
        HcFree(keyList[i]);
    }
    HcFree(keyList);
}

static char *PackJsonWithBigIntArrToString(const CJson *jsonObj, CJson *arr)
{
    int keyListSize = GetItemNum(arr);
    char **keyList = CreateKeyList(arr);
    if (keyList == NULL) {
        return NULL;
    }
    CJson *dupJson = cJSON_Duplicate(jsonObj, RECURSE_FLAG_TRUE);
    if (dupJson == NULL) {
        DestroyKeyList(keyListSize, keyList);
        LOGE("duplicate json failed.");
        return NULL;
    }
    cJSON_DeleteItemFromObject(dupJson, BIG_INT_ARR);

    char *jsonStr = NULL;
    do {
        jsonStr = cJSON_PrintUnformatted(dupJson);
        if (jsonStr == NULL) {
            LOGE("dup json to str failed.");
            break;
        }
        for (int i = 0; i < keyListSize; i++) {
            if (keyList[i] != NULL) {
                ReplaceStringToInt(jsonStr, keyList[i]);
            }
        }
    } while (0);
    cJSON_free(dupJson);
    DestroyKeyList(keyListSize, keyList);
    return jsonStr;
}

char *PackJsonToString(const CJson *jsonObj)
{
    if (jsonObj == NULL) {
        return NULL;
    }
    CJson *arr = GetObjFromJson(jsonObj, BIG_INT_ARR);
    if (arr == NULL) {
        return cJSON_PrintUnformatted(jsonObj);
    }
    return PackJsonWithBigIntArrToString(jsonObj, arr);
}

void FreeJsonString(char *jsonStr)
{
    if (jsonStr != NULL) {
        cJSON_free(jsonStr);
    }
}

int GetItemNum(const CJson *jsonObj)
{
    if (jsonObj == NULL) {
        return 0;
    }
    return cJSON_GetArraySize(jsonObj);
}

const char *GetItemKey(const CJson *item)
{
    if (item == NULL) {
        return NULL;
    }
    return item->string;
}

CJson *GetObjFromJson(const CJson *jsonObj, const char *key)
{
    if (jsonObj == NULL || key == NULL) {
        return NULL;
    }

    cJSON *objValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (objValue != NULL) {
        return objValue;
    }

    int len = cJSON_GetArraySize(jsonObj);
    for (int i = 0; i < len; i++) {
        cJSON *item = cJSON_GetArrayItem(jsonObj, i);
        if (cJSON_IsObject(item)) {
            cJSON *obj = GetObjFromJson(item, key);
            if (obj != NULL) {
                return obj;
            }
        }
    }

    return NULL;
}

CJson *GetItemFromArray(const CJson *jsonArr, int index)
{
    if (jsonArr == NULL) {
        return NULL;
    }
    return cJSON_GetArrayItem(jsonArr, index);
}

const char *GetStringFromJson(const CJson *jsonObj, const char *key)
{
    if (jsonObj == NULL || key == NULL) {
        return NULL;
    }

    cJSON *jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (jsonObjTmp != NULL && cJSON_IsString(jsonObjTmp)) {
        return cJSON_GetStringValue(jsonObjTmp);
    }

    int len = cJSON_GetArraySize(jsonObj);
    for (int i = 0; i < len; i++) {
        cJSON *item = cJSON_GetArrayItem(jsonObj, i);
        if (cJSON_IsObject(item)) {
            const char *resValue = GetStringFromJson(item, key);
            if (resValue != NULL) {
                return resValue;
            }
        }
    }

    return NULL;
}

int32_t GetByteLenFromJson(const CJson *jsonObj, const char *key, uint32_t *byteLen)
{
    if (jsonObj == NULL || key == NULL || byteLen == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    const char *valueStr = GetStringFromJson(jsonObj, key);
    if (valueStr == NULL) {
        return CLIB_ERR_JSON_GET;
    }
    *byteLen = HcStrlen(valueStr) / BYTE_TO_HEX_OPER_LENGTH;
    return CLIB_SUCCESS;
}

int32_t GetByteFromJson(const CJson *jsonObj, const char *key, uint8_t *byte, uint32_t len)
{
    if (jsonObj == NULL || key == NULL || byte == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    const char *valueStr = GetStringFromJson(jsonObj, key);
    if (valueStr == NULL) {
        return CLIB_ERR_JSON_GET;
    }
    if (len < HcStrlen(valueStr) / BYTE_TO_HEX_OPER_LENGTH) {
        return CLIB_ERR_INVALID_LEN;
    }
    return HexStringToByte(valueStr, byte, len);
}

int32_t GetIntFromJson(const CJson *jsonObj, const char *key, int32_t *value)
{
    if (jsonObj == NULL || key == NULL || value == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (jsonObjTmp != NULL && cJSON_IsNumber(jsonObjTmp)) {
        *value = (int)cJSON_GetNumberValue(jsonObjTmp);
        return CLIB_SUCCESS;
    }

    int len = cJSON_GetArraySize(jsonObj);
    for (int i = 0; i < len; i++) {
        cJSON *item = cJSON_GetArrayItem(jsonObj, i);
        if (cJSON_IsObject(item)) {
            int32_t ret = GetIntFromJson(item, key, value);
            if (ret == CLIB_SUCCESS) {
                return ret;
            }
        }
    }

    return CLIB_ERR_JSON_GET;
}

int32_t GetUnsignedIntFromJson(const CJson *jsonObj, const char *key, uint32_t *value)
{
    if (jsonObj == NULL || key == NULL || value == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (jsonObjTmp != NULL && cJSON_IsNumber(jsonObjTmp)) {
        double realValue = cJSON_GetNumberValue(jsonObjTmp);
        if (realValue < 0) {
            int32_t tmpValue = (int32_t)realValue;
            *value = (uint32_t)tmpValue;
        } else {
            *value = (uint32_t)realValue;
        }
        return CLIB_SUCCESS;
    }

    int len = cJSON_GetArraySize(jsonObj);
    for (int i = 0; i < len; i++) {
        cJSON *item = cJSON_GetArrayItem(jsonObj, i);
        if (cJSON_IsObject(item)) {
            int32_t ret = GetUnsignedIntFromJson(item, key, value);
            if (ret == CLIB_SUCCESS) {
                return ret;
            }
        }
    }

    return CLIB_ERR_JSON_GET;
}

int32_t GetUint8FromJson(const CJson *jsonObj, const char *key, uint8_t *value)
{
    if (jsonObj == NULL || key == NULL || value == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (jsonObjTmp != NULL && cJSON_IsNumber(jsonObjTmp)) {
        double realValue = cJSON_GetNumberValue(jsonObjTmp);
        if (realValue < 0) {
            int8_t tmpValue = (int8_t)realValue;
            *value = (uint8_t)tmpValue;
        } else {
            *value = (uint8_t)realValue;
        }
        return CLIB_SUCCESS;
    }

    int len = cJSON_GetArraySize(jsonObj);
    for (int i = 0; i < len; i++) {
        cJSON *item = cJSON_GetArrayItem(jsonObj, i);
        if (cJSON_IsObject(item)) {
            int8_t ret = GetUint8FromJson(item, key, value);
            if (ret == CLIB_SUCCESS) {
                return ret;
            }
        }
    }

    return CLIB_ERR_JSON_GET;
}

int32_t GetInt64FromJson(const CJson *jsonObj, const char *key, int64_t *value)
{
    const char *str = GetStringFromJson(jsonObj, key);
    if (str == NULL) {
        return CLIB_ERR_JSON_GET;
    }
    *value = StringToInt64(str);
    return CLIB_SUCCESS;
}

int32_t GetBoolFromJson(const CJson *jsonObj, const char *key, bool *value)
{
    if (jsonObj == NULL || key == NULL || value == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (jsonObjTmp != NULL && cJSON_IsBool(jsonObjTmp)) {
        *value = cJSON_IsTrue(jsonObjTmp) ? true : false;
        return CLIB_SUCCESS;
    }

    int len = cJSON_GetArraySize(jsonObj);
    for (int i = 0; i < len; i++) {
        cJSON *item = cJSON_GetArrayItem(jsonObj, i);
        if (cJSON_IsObject(item)) {
            int32_t ret = GetBoolFromJson(item, key, value);
            if (ret == CLIB_SUCCESS) {
                return ret;
            }
        }
    }

    return CLIB_ERR_JSON_GET;
}

char *GetStringValue(const CJson *item)
{
    if (item == NULL) {
        return NULL;
    }
    return cJSON_GetStringValue(item);
}

int32_t AddObjToJson(CJson *jsonObj, const char *key, const CJson *childObj)
{
    if (jsonObj == NULL || key == NULL || childObj == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *tmpObj = cJSON_Duplicate(childObj, RECURSE_FLAG_TRUE);
    if (tmpObj == NULL) {
        return CLIB_ERR_JSON_DUPLICATE;
    }

    cJSON *objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (objInJson == NULL) {
        if (cJSON_AddItemToObject(jsonObj, key, tmpObj) == false) {
            cJSON_Delete(tmpObj);
            return CLIB_ERR_JSON_ADD;
        }
    } else {
        if (cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key, tmpObj) == false) {
            cJSON_Delete(tmpObj);
            return CLIB_ERR_JSON_REPLACE;
        }
    }

    return CLIB_SUCCESS;
}

int32_t AddObjToArray(CJson *jsonArr, CJson *item)
{
    if (jsonArr == NULL || item == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    if (cJSON_IsArray(jsonArr) == false) {
        return CLIB_ERR_INVALID_PARAM;
    }

    bool ret = cJSON_AddItemToArray(jsonArr, item);
    if (ret == false) {
        return CLIB_ERR_JSON_ADD;
    }

    return CLIB_SUCCESS;
}

int32_t AddStringToArray(CJson *jsonArr, const char *string)
{
    if (jsonArr == NULL || string == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    if (cJSON_IsArray(jsonArr) == false) {
        return CLIB_ERR_INVALID_PARAM;
    }

    cJSON *strObj = cJSON_CreateString(string);
    if (strObj == NULL) {
        return CLIB_ERR_BAD_ALLOC;
    }
    bool ret = cJSON_AddItemToArray(jsonArr, strObj);
    if (ret == false) {
        cJSON_Delete(strObj);
        return CLIB_ERR_JSON_ADD;
    }

    return CLIB_SUCCESS;
}

int32_t AddStringToJson(CJson *jsonObj, const char *key, const char *value)
{
    if (jsonObj == NULL || key == NULL || value == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (objInJson == NULL) {
        if (cJSON_AddStringToObject(jsonObj, key, value) == NULL) {
            return CLIB_ERR_JSON_GET;
        }
    } else {
        cJSON *tmp = cJSON_CreateString(value);
        if (tmp == NULL) {
            LOGE("The operation of cJSON_CreateString failed.");
            return CLIB_ERR_BAD_ALLOC;
        }
        if (cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key, tmp) == false) {
            cJSON_Delete(tmp);
            return CLIB_ERR_JSON_REPLACE;
        }
    }

    return CLIB_SUCCESS;
}

int32_t AddByteToJson(CJson *jsonObj, const char *key, const uint8_t *byte, uint32_t len)
{
    if (jsonObj == NULL || key == NULL || byte == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    uint32_t hexLen = len * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *hexStr = (char *)HcMalloc(hexLen, 0);
    if (hexStr == NULL) {
        return CLIB_ERR_BAD_ALLOC;
    }
    int32_t ret = ByteToHexString(byte, len, hexStr, hexLen);
    if (ret != CLIB_SUCCESS) {
        HcFree(hexStr);
        return ret;
    }

    ret = AddStringToJson(jsonObj, key, hexStr);
    if (ret != CLIB_SUCCESS) {
        HcFree(hexStr);
        return ret;
    }

    HcFree(hexStr);
    return CLIB_SUCCESS;
}

int32_t AddBoolToJson(CJson *jsonObj, const char *key, bool value)
{
    if (jsonObj == NULL || key == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (objInJson == NULL) {
        if (cJSON_AddBoolToObject(jsonObj, key, value) == NULL) {
            return CLIB_ERR_JSON_GET;
        }
    } else {
        cJSON *tmp = cJSON_CreateBool(value);
        if (tmp == NULL) {
            LOGE("cJSON_CreateString failed.");
            return CLIB_ERR_BAD_ALLOC;
        }
        if (cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key, tmp) == false) {
            cJSON_Delete(tmp);
            return CLIB_ERR_JSON_REPLACE;
        }
    }

    return CLIB_SUCCESS;
}

int32_t AddIntToJson(CJson *jsonObj, const char *key, int value)
{
    if (jsonObj == NULL || key == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key);
    if (objInJson == NULL) {
        if (cJSON_AddNumberToObject(jsonObj, key, value) == NULL) {
            return CLIB_ERR_JSON_GET;
        }
    } else {
        cJSON *tmp = cJSON_CreateNumber(value);
        if (tmp == NULL) {
            return CLIB_ERR_BAD_ALLOC;
        }
        if (cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key, tmp) == false) {
            cJSON_Delete(tmp);
            return CLIB_ERR_JSON_REPLACE;
        }
    }

    return CLIB_SUCCESS;
}

int32_t AddInt64StringToJson(CJson *jsonObj, const char *key, int64_t value)
{
    char buffer[65] = { 0 };
    if (sprintf_s(buffer, sizeof(buffer), "%" PRId64, value) <= 0) {
        return CLIB_FAILED;
    }
    if (AddStringToJson(jsonObj, key, buffer) != CLIB_SUCCESS) {
        return CLIB_ERR_JSON_ADD;
    }
    return CLIB_SUCCESS;
}

int32_t AddStringArrayToJson(CJson *jsonObj, const char *key, const char * const *stringArray, uint32_t arrayLen)
{
    if (jsonObj == NULL || key == NULL || stringArray == NULL) {
        return CLIB_ERR_NULL_PTR;
    }

    cJSON *strArrayObj = cJSON_CreateStringArray(stringArray, arrayLen);
    if (strArrayObj == NULL) {
        return CLIB_ERR_BAD_ALLOC;
    }
    if (cJSON_AddItemToObject(jsonObj, key, strArrayObj) == false) {
        cJSON_Delete(strArrayObj);
        return CLIB_ERR_JSON_ADD;
    }
    return CLIB_SUCCESS;
}

void ClearSensitiveStringInJson(CJson *jsonObj, const char *key)
{
    if (jsonObj == NULL || key == NULL) {
        return;
    }
    char *str = (char *)GetStringFromJson(jsonObj, key);
    if (str == NULL) {
        return;
    }
    (void)memset_s(str, HcStrlen(str), 0, HcStrlen(str));
}

void ClearAndFreeJsonString(char *jsonStr)
{
    if (jsonStr == NULL) {
        return;
    }
    (void)memset_s(jsonStr, HcStrlen(jsonStr), 0, HcStrlen(jsonStr));
    FreeJsonString(jsonStr);
}
