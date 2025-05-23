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

#ifndef HC_LOG_H
#define HC_LOG_H

#include <inttypes.h>
#include "log.h"

#define LOGD(fmt, ...) HILOG_DEBUG(HILOG_MODULE_SCY, fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) HILOG_INFO(HILOG_MODULE_SCY, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) HILOG_WARN(HILOG_MODULE_SCY, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) HILOG_ERROR(HILOG_MODULE_SCY, fmt, ##__VA_ARGS__)

typedef enum {
    NORMAL_MODE = 0,
    TRACE_MODE = 1,
} LogMode;

#define LOG_PUB ""

#define SET_LOG_MODE(mode)
#define SET_TRACE_ID(traceId)

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

#endif
