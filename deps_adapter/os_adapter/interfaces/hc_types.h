/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef HC_TYPES_H
#define HC_TYPES_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "securec.h"

typedef uint32_t HcBool;
#define HC_TRUE 1
#define HC_FALSE 0

#ifndef NULL
#define NULL 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEV_AUTH_MEMORY_DEBUG

#define HcMalloc(size, val) MockMalloc(size, val, __FILE__, __LINE__)
#define HcFree(addr) MockFree(addr)
void *MockMalloc(uint32_t size, char val, const char *strFile, int nLine);
void MockFree(void *addr);

#else

void* HcMalloc(uint32_t size, char val);
void HcFree(void* addr);

#endif

uint32_t HcStrlen(const char *str);

#ifdef __cplusplus
}
#endif

#endif