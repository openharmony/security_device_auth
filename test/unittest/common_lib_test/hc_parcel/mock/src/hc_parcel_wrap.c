/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "securec.h"

static bool g_hcMallocFail = false;
static bool g_memmoveFail = false;

void SetHcMallocFail(bool shouldFail)
{
    g_hcMallocFail = shouldFail;
}

bool GetHcMallocFail(void)
{
    return g_hcMallocFail;
}

void ResetHcMallocFail(void)
{
    g_hcMallocFail = false;
}

void SetMemmoveFail(bool shouldFail)
{
    g_memmoveFail = shouldFail;
}

bool GetMemmoveFail(void)
{
    return g_memmoveFail;
}

void ResetMemmoveFail(void)
{
    g_memmoveFail = false;
}

void *__real_HcMalloc(uint32_t size, uint32_t maxLen);
errno_t __real_memmove_s(void *dest, uint32_t destMax, const void *src, uint32_t count);
errno_t __real_memcpy_s(void *dest, uint32_t destMax, const void *src, uint32_t count);

void *__wrap_HcMalloc(uint32_t size, uint32_t maxLen)
{
    if (GetHcMallocFail()) {
        return NULL;
    }
    return __real_HcMalloc(size, maxLen);
}

errno_t __wrap_memmove_s(void *dest, uint32_t destMax, const void *src, uint32_t count)
{
    if (GetMemmoveFail()) {
        return 1; // Return error code
    }
    return __real_memmove_s(dest, destMax, src, count);
}

errno_t __wrap_memcpy_s(void *dest, uint32_t destMax, const void *src, uint32_t count)
{
    if (GetMemmoveFail()) {
        return 1; // Return error code
    }
    return __real_memcpy_s(dest, destMax, src, count);
}
