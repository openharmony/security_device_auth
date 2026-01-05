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

#include "hc_log.h"

#include <inttypes.h>
#include <stdlib.h>
#include "securec.h"
#include "hc_types.h"

#define LOG_PRINT_MAX_LEN 1024

static bool RemoveSubString(const char *fmt, char outStr[LOG_PRINT_MAX_LEN], char *subStr)
{
    char *pos;
    uint32_t fmtLen = strlen(fmt);
    uint32_t subStrLen = strlen(subStr);
    if ((fmtLen == 0) || (subStrLen == 0)) {
        return true;
    }
    uint32_t i = 0;
    uint32_t j = 0;
    pos = strstr(fmt, subStr);
    while (pos != NULL) {
        if (memcpy_s(outStr + i, LOG_PRINT_MAX_LEN - i - 1, fmt + j, pos - fmt - j) != EOK) {
            return false;
        }
        i += pos - fmt - j;
        j = pos - fmt + subStrLen;
        if (j >= fmtLen) {
            break;
        }
        pos = strstr(fmt + j, subStr);
    }
    while (j < fmtLen && i < LOG_PRINT_MAX_LEN - 1) {
        outStr[i++] = *(fmt + j);
        j++;
    }
    outStr[i] = '\0';
    return true;
}

void LogAndRecordError(const char *funName, uint32_t lineNum, const char *fmt, ...)
{
    if ((funName == NULL) || (fmt == NULL)) {
        return;
    }
    int32_t ulPos = 0;
    char outStr[LOG_PRINT_MAX_LEN] = {0};
    char newFmt[LOG_PRINT_MAX_LEN] = {0};
    int32_t ret = sprintf_s(outStr, sizeof(outStr), "%s[%u]: ", funName, lineNum);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "%" LOG_PUB "s[%" LOG_PUB "u] unknown", funName, lineNum);
        return;
    }
    if (!RemoveSubString(fmt, newFmt, LOG_PUB)) {
        HILOG_ERROR(LOG_CORE, "%" LOG_PUB "s unknown", outStr);
        return;
    }
    ulPos = strlen(outStr);
    va_list arg;
    va_start(arg, fmt);
    RECORD_ERR_TRACE(funName, lineNum, newFmt, arg);
    ret = vsprintf_s(&outStr[ulPos], sizeof(outStr) - ulPos, newFmt, arg);
    va_end(arg);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "%s unknown", outStr);
        return;
    }
    HILOG_ERROR(LOG_CORE, "%" LOG_PUB "s", outStr);
}
