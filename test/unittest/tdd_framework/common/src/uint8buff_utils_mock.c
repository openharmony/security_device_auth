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

#include "uint8buff_utils.h"

#include "securec.h"
#include "clib_error.h"
#include "hc_types.h"
#include "ctype.h"
#include "string_util.h"

#define ERROR_MOCK "error"

int32_t InitUint8Buff(Uint8Buff *buff, uint32_t buffLen)
{
    if (buff == NULL) {
        return CLIB_ERR_NULL_PTR;
    }
    if (buffLen == 0) {
        return CLIB_ERR_INVALID_LEN;
    }
    buff->val = (uint8_t *)HcMalloc(buffLen, 0);
    if (buff->val == NULL) {
        return CLIB_ERR_BAD_ALLOC;
    }
    buff->length = buffLen;
    return CLIB_SUCCESS;
}

int32_t DeepCopyUint8Buff(const Uint8Buff *buff, Uint8Buff *newBuff)
{
    if (buff == NULL || buff->val == NULL || newBuff == NULL) {
        return CLIB_ERR_NULL_PTR;
    }
    if (IsStrEqual((char *)buff->val, ERROR_MOCK)) {
        return CLIB_ERR_NULL_PTR;
    }
    if (buff->length == 0) {
        return CLIB_ERR_INVALID_LEN;
    }
    uint8_t *val = (uint8_t *)HcMalloc(buff->length, 0);
    if (val == NULL) {
        return CLIB_ERR_BAD_ALLOC;
    }
    (void)memcpy_s(val, buff->length, buff->val, buff->length);
    newBuff->val = val;
    newBuff->length = buff->length;
    return CLIB_SUCCESS;
}

void FreeUint8Buff(Uint8Buff *buff)
{
    if (buff == NULL || buff->val == NULL || buff->length == 0) {
        return;
    }
    HcFree(buff->val);
    buff->val = NULL;
    buff->length = 0;
}

void ClearFreeUint8Buff(Uint8Buff *buff)
{
    if (buff == NULL || buff->val == NULL || buff->length == 0) {
        return;
    }
    (void)memset_s(buff->val, buff->length, 0, buff->length);
    HcFree(buff->val);
    buff->val = NULL;
    buff->length = 0;
}

bool IsUint8BuffValid(const Uint8Buff *buff, uint32_t maxLen)
{
    return ((buff != NULL) && (buff->val != NULL) && (0 < buff->length) && (buff->length <= maxLen));
}

int32_t ToLowerCase(Uint8Buff *buff)
{
    uint32_t buffLen = buff->length;
    char *buffStr = (char *)HcMalloc(buffLen + 1, 0);
    if (buffStr == NULL) {
        return CLIB_ERR_BAD_ALLOC;
    }
    if (memcpy_s(buffStr, buffLen + 1, buff->val, buffLen) != EOK) {
        HcFree(buffStr);
        return CLIB_FAILED;
    }
    for (uint32_t i = 0; i < buffLen; i++) {
        buffStr[i] = tolower(buffStr[i]);
    }
    if (memcpy_s(buff->val, buffLen, buffStr, buffLen) != EOK) {
        HcFree(buffStr);
        return CLIB_FAILED;
    }
    HcFree(buffStr);
    return CLIB_SUCCESS;
}
