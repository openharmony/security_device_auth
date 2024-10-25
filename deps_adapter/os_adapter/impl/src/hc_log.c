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
#include "securec.h"
#include "hc_types.h"

#define LOG_PRINT_MAX_LEN 2048

static const char *SENSITIVE_WORDS[] = { "droid" };

#ifdef DEV_AUTH_DEBUG_PRINTF

#include <stdio.h>
#include <stdlib.h>

#define DEV_AUTH_LOG_DEBUG(buf) printf("[D][DEVAUTH]: %s\n", buf)
#define DEV_AUTH_LOG_INFO(buf) printf("[I][DEVAUTH]: %s\n", buf)
#define DEV_AUTH_LOG_WARN(buf) printf("[W][DEVAUTH]: %s\n", buf)
#define DEV_AUTH_LOG_ERROR(buf) printf("[E][DEVAUTH]: %s\n", buf)

#else

#include "hilog/log.h"

#define DEV_AUTH_LOG_DEBUG(buf) HILOG_DEBUG(LOG_CORE, "%{public}s", buf)
#define DEV_AUTH_LOG_INFO(buf) HILOG_INFO(LOG_CORE, "%{public}s", buf)
#define DEV_AUTH_LOG_WARN(buf) HILOG_WARN(LOG_CORE, "%{public}s", buf)
#define DEV_AUTH_LOG_ERROR(buf) HILOG_ERROR(LOG_CORE, "%{public}s", buf)

#endif

static __thread int32_t g_logMode = 0;
static __thread int64_t g_traceId = 0;

static void DevAuthOutPrint(const char *buf, DevAuthLogLevel level)
{
    switch (level) {
        case DEV_AUTH_LOG_LEVEL_DEBUG:
            DEV_AUTH_LOG_DEBUG(buf);
            break;
        case DEV_AUTH_LOG_LEVEL_INFO:
            DEV_AUTH_LOG_INFO(buf);
            break;
        case DEV_AUTH_LOG_LEVEL_WARN:
            DEV_AUTH_LOG_WARN(buf);
            break;
        case DEV_AUTH_LOG_LEVEL_ERROR:
            DEV_AUTH_LOG_ERROR(buf);
            break;
        default:
            break;
    }
}

static void ReplaceSensitiveWord(char *msg, const char *sensitiveWord)
{
    uint32_t len = HcStrlen(sensitiveWord);
    char *ptr = strstr(msg, sensitiveWord);
    while (ptr != NULL) {
        (void)memset_s(ptr, len, '*', len);
        ptr = strstr(ptr + 1, sensitiveWord);
    }
}

static void DesensitizeLogMsg(char *msg)
{
    for (uint32_t i = 0; i < sizeof(SENSITIVE_WORDS) / sizeof(SENSITIVE_WORDS[0]); i++) {
        ReplaceSensitiveWord(msg, SENSITIVE_WORDS[i]);
    }
}

void DevAuthLogPrint(DevAuthLogLevel level, const char *funName, const char *fmt, ...)
{
    int32_t ulPos = 0;
    char outStr[LOG_PRINT_MAX_LEN] = {0};
    int32_t res;
    if (g_logMode == TRACE_MODE) {
        res = sprintf_s(outStr, sizeof(outStr), "<%" PRId64 ">%s: ", g_traceId, funName);
    } else {
        res = sprintf_s(outStr, sizeof(outStr), "%s: ", funName);
    }
    if (res < 0) {
        return;
    }
    ulPos = (int32_t)HcStrlen(outStr);
    va_list arg;
    va_start(arg, fmt);
    res = vsprintf_s(&outStr[ulPos], sizeof(outStr) - ulPos, fmt, arg);
    va_end(arg);
    if (res < 0) {
        return;
    }
    DesensitizeLogMsg(outStr);
    DevAuthOutPrint(outStr, level);
}

void SetLogMode(LogMode mode)
{
    g_logMode = mode;
    g_traceId = 0;
}

void SetTraceId(int64_t traceId)
{
    g_traceId = traceId;
}
