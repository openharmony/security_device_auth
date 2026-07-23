/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "hc_time.h"
#include <time.h>
#include <stdint.h>

#define SEC_TO_MILLI 1000
#define NANO_TO_MILLI 1000000
#define FORCE_TIMEOUT_INTERVAL 301

static int32_t g_forceTimeout = 0;

void SetForceTimeout(int32_t force)
{
    g_forceTimeout = force;
}

int64_t HcGetCurTime(void)
{
    struct timespec start;
    int res = clock_gettime(CLOCK_MONOTONIC, &start);
    if (res != 0) {
        return -1;
    }
    return start.tv_sec;
}

int64_t HcGetCurTimeInMillis(void)
{
    struct timespec start;
    int res = clock_gettime(CLOCK_MONOTONIC, &start);
    if (res != 0) {
        return -1;
    }
    return start.tv_sec * SEC_TO_MILLI + start.tv_nsec / NANO_TO_MILLI;
}

int64_t HcGetIntervalTime(int64_t startTime)
{
    if (startTime < 0) {
        return -1;
    }
    if (g_forceTimeout) {
        return FORCE_TIMEOUT_INTERVAL;
    }
    struct timespec end;
    int res = clock_gettime(CLOCK_MONOTONIC, &end);
    if (res != 0) {
        return -1;
    }
    if (end.tv_sec < startTime) {
        return -1;
    }
    return (end.tv_sec - startTime);
}

int64_t HcGetRealTime(void)
{
    struct timespec start;
    int res = clock_gettime(CLOCK_REALTIME, &start);
    if (res != 0) {
        return -1;
    }
    return start.tv_sec;
}
