/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "memory_mock.h"
#include "hc_types.h"

#include <securec.h>
#include "exception_controller.h"
#include "memory_monitor.h"

void *MockMalloc(uint32_t size, char val, const char *strFile, int nLine)
{
    if (size == 0) {
        return NULL;
    }
    if (IsNeedThrowException()) {
        AddCallNum();
        return NULL;
    } else {
        AddCallNum();
    }
    void* addr = malloc(size);
    if (addr != NULL) {
        (void)memset_s(addr, size, val, size);
        HcMonitorMalloc(addr, size, strFile, nLine);
    }
    return addr;
}

void MockFree(void *addr)
{
    if (addr != NULL) {
        HcMonitorFree(addr);
        free(addr);
    }
}

void *MockMallocForJson(size_t size)
{
    return MockMalloc((uint32_t)size, 0, __FILE__, __LINE__);
}

uint32_t HcStrlen(const char *str)
{
    if (str == NULL) {
        return 0;
    }
    const char *p = str;
    while (*p++ != '\0') {}
    return p - str - 1;
}
