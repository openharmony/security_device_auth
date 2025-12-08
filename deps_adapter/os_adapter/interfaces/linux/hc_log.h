/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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
            LOGI("[" tag "]: %" LOG_PUB "c%" LOG_PUB "c%" LOG_PUB "c%" LOG_PUB "c****", (str)[DEV_AUTH_ZERO], \
                (str)[DEV_AUTH_ONE], (str)[DEV_AUTH_TWO], (str)[DEV_AUTH_THREE]); \
        } \
    } while (0)

#define PRINT_SENSITIVE_BYTE(tag, byte, len) \
    do { \
        if ((len) < DESENSITIZATION_LEN) { \
            LOGW("[" tag "]: sensitive str is too short."); \
        } else { \
            LOGI("[" tag "]: %" LOG_PUB ".2x%" LOG_PUB ".2x****%" LOG_PUB ".2x%" LOG_PUB ".2x", (byte)[DEV_AUTH_ZERO], \
                (byte)[DEV_AUTH_ONE], (byte)[(len) - DEV_AUTH_TWO], (byte)[(len) - DEV_AUTH_ONE]); \
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

#ifdef DEV_AUTH_DEBUG_PRINTF

#include <stdio.h>
#include <stdlib.h>

#define LOG_PUB ""

#define LOGD(fmt, ...) printf("[D][DEVAUTH]: %s" fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGI(fmt, ...) printf("[I][DEVAUTH]: %s" fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGW(fmt, ...) printf("[W][DEVAUTH]: %s" fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[E][DEVAUTH]: %s" fmt "\n", __FUNCTION__, ##__VA_ARGS__)

#else

#include "hilog/log.h"
#include "hc_err_trace.h"

#define LOG_PUB "{public}"

#define LOGD(fmt, ...) HILOG_DEBUG(LOG_CORE, "%" LOG_PUB "s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define LOGI(fmt, ...) HILOG_INFO(LOG_CORE, "%" LOG_PUB "s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define LOGW(fmt, ...) HILOG_WARN(LOG_CORE, "%" LOG_PUB "s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define LOGE(fmt, ...) LogAndRecordError(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#define PRINT_ERR_TRACE() HILOG_ERROR(LOG_CORE, "%" LOG_PUB "s: <errtrace> %" LOG_PUB "s", \
    GetTraceInfo(__FUNCTION__), GET_ERR_TRACE())

#endif

#ifdef __cplusplus
extern "C" {
#endif

void LogAndRecordError(const char *funName, uint32_t lineNum, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#else

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define LOG_PUB ""

#define LOGD(fmt, ...) printf("[D][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGI(fmt, ...) printf("[I][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGW(fmt, ...) printf("[W][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[E][DEVAUTH]%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)

#endif

#endif
