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

#ifndef DEV_AUTH_MEMORY_MOCK_H
#define DEV_AUTH_MEMORY_MOCK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *MockMalloc(uint32_t size, char val, const char *strFile, int nLine);
void MockFree(void *addr);
void *MockMallocForJson(uint32_t size);
uint32_t HcStrlen(const char *str);

#ifdef __cplusplus
}
#endif
#endif
