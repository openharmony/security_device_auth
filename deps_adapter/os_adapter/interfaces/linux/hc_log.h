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

#ifndef HC_LOG_H
#define HC_LOG_H

typedef enum {
    NORMAL_MODE = 0,
    TRACE_MODE = 1,
} LogMode;

#define DESENSITIZATION_LEN 12
#define DEV_AUTH_ZERO 0
#define DEV_AUTH_ONE 1
#define DEV_AUTH_TWO 2
#define DEV_AUTH_THREE 3

#define PRINT_SENSITIVE_DATA(tag, str) \
    do { \
        if (HcStrlen((str)) < DESENSITIZATION_LEN) { \
            LOGW("[" tag "]: sensitive str is too short."); \
        } else { \
            LOGI("[" tag "]: %c%c%c%c****", (str)[DEV_AUTH_ZERO], (str)[DEV_AUTH_ONE], \
                (str)[DEV_AUTH_TWO], (str)[DEV_AUTH_THREE]); \
        } \
    } while (0)

#ifdef HILOG_ENABLE

#include <stdint.h>
#include <inttypes.h>

typedef enum {
    DEV_AUTH_LOG_LEVEL_DEBUG = 0,
    DEV_AUTH_LOG_LEVEL_INFO,
    DEV_AUTH_LOG_LEVEL_WARN,
    DEV_AUTH_LOG_LEVEL_ERROR
} DevAuthLogLevel;

#ifndef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F03 /* Security subsystem's domain id */
#endif

#ifndef LOG_TAG
#define LOG_TAG "[DEVAUTH]"
#endif

#define LOGD(fmt, ...) (DevAuthLogPrint(DEV_AUTH_LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__))
#define LOGI(fmt, ...) (DevAuthLogPrint(DEV_AUTH_LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__))
#define LOGW(fmt, ...) (DevAuthLogPrint(DEV_AUTH_LOG_LEVEL_WARN, __FUNCTION__, fmt, ##__VA_ARGS__))
#define LOGE(fmt, ...) (DevAuthLogPrint(DEV_AUTH_LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__))

#define SET_LOG_MODE(mode) SetLogMode(mode)
#define SET_TRACE_ID(traceId) SetTraceId(traceId)

#ifdef __cplusplus
extern "C" {
#endif

void DevAuthLogPrint(DevAuthLogLevel level, const char *funName, const char *fmt, ...);
void SetLogMode(LogMode mode);
void SetTraceId(int64_t traceId);

#ifdef __cplusplus
}
#endif

#else

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define LOGD(fmt, ...) printf("[D][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGI(fmt, ...) printf("[I][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGW(fmt, ...) printf("[W][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[E][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)

#define SET_LOG_MODE(mode)
#define SET_TRACE_ID(traceId)

#endif

#endif
