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

#include "hc_err_trace.h"

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include "securec.h"

#define MAX_TRACE_INFO_SIZE 128

#define MAX_ERROR_TRACE_LEN 768
#define MAX_FULL_ERROR_TRACE_LEN 512

#define INTERVAL_STR " < "
#define INTERVAL_STR_LEN 3

static __thread int32_t g_logMode = 0;
static __thread int64_t g_traceId = 0;
static __thread char g_traceInfo[MAX_TRACE_INFO_SIZE] = {0};

static __thread uint32_t g_errTraceLen = 0;
static __thread char g_errTrace[MAX_ERROR_TRACE_LEN + 1] = {0};
static __thread bool g_isErrTraceOn = false;

void SetLogModeAndErrTrace(LogMode mode, bool isErrTraceOn)
{
    g_logMode = mode;
    g_traceId = 0;
    g_isErrTraceOn = isErrTraceOn;
    ClearErrTrace();
}

void SetTraceId(int64_t traceId)
{
    g_traceId = traceId;
}

static const char *GetTraceInfo(const char* funcName)
{
    if (funcName == NULL) {
        return UNKNOWN_ERROR_TRACE;
    }

    if (g_logMode != TRACE_MODE) {
        return funcName;
    }

    if (sprintf_s(g_traceInfo, MAX_TRACE_INFO_SIZE - 1,
        "[%" PRId64 "]%s", g_traceId, funcName) <= 0) {
        return funcName;
    }
    return g_traceInfo;
}

void RecordErrTrace(const char *funName, uint32_t lineNum, const char *fmt, va_list args)
{
    if ((funName == NULL) || (fmt == NULL) || (!g_isErrTraceOn)) {
        return;
    }
    if (g_errTraceLen != 0) {
        if (memcpy_s(g_errTrace + g_errTraceLen, MAX_ERROR_TRACE_LEN - g_errTraceLen,
            INTERVAL_STR, INTERVAL_STR_LEN) != EOK) {
            return;
        }
        g_errTraceLen += INTERVAL_STR_LEN;
    }

    int32_t offset = sprintf_s(g_errTrace + g_errTraceLen, MAX_ERROR_TRACE_LEN - g_errTraceLen,
        "%s[%u] ", GetTraceInfo(funName), lineNum);
    if (offset <= 0) {
        return;
    }
    g_errTraceLen += (uint32_t)offset;

    if (g_errTraceLen < MAX_FULL_ERROR_TRACE_LEN) {
        va_list ap;
        va_copy(ap, args);
        char buff[MAX_FULL_ERROR_TRACE_LEN] = {0};
        offset = vsprintf_s(buff, MAX_FULL_ERROR_TRACE_LEN, fmt, ap);
        va_end(ap);
        if (offset < 0) {
            return;
        }
        if ((uint32_t)offset + g_errTraceLen > MAX_ERROR_TRACE_LEN) {
            return;
        }
        if (memcpy_s(g_errTrace + g_errTraceLen, MAX_ERROR_TRACE_LEN - g_errTraceLen, buff, (uint32_t)offset) != EOK) {
            return;
        }
        g_errTraceLen += (uint32_t)offset;
    }
}
 
uint32_t GetErrTraceLen()
{
    return g_errTraceLen;
}

const char *GetErrTrace()
{
    return g_errTrace;
}

void ClearErrTrace()
{
    (void)memset_s(g_errTrace, MAX_ERROR_TRACE_LEN + 1, 0, MAX_ERROR_TRACE_LEN + 1);
    g_errTraceLen = 0;
}
