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

#include "hc_types.h"
#include "hc_log.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_STR_LEN (512 * 1024)

void* HcMalloc(uint32_t size, char val)
{
    if (size == 0) {
        LOGE("Malloc size is invalid.");
        return NULL;
    }
    void* addr = malloc(size);
    if (addr == NULL) {
        LOGE("[OS]: malloc fail. [Size]: %" LOG_PUB "u", size);
        return NULL;
    }
    (void)memset_s(addr, size, val, size);
    return addr;
}

void HcFree(void* addr)
{
    if (addr != NULL) {
        free(addr);
    }
}

uint32_t HcStrlen(const char *str)
{
    if (str == NULL) {
        LOGE("Invalid param!");
        return 0;
    }
    const char *p = str;
    while (*p++ != '\0' && (p - str - 1) < MAX_STR_LEN) {}
    return p - str - 1;
}

#ifdef __cplusplus
}
#endif
