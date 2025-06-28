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

#ifndef CRITICAL_HANDLER_H
#define CRITICAL_HANDLER_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADD_ONE 1
#define ADD_TWO 2

void NotifyProcessIsActive(void);
void NotifyProcessIsStop(void);
void IncreaseCriticalCnt(int addCnt);
void DecreaseCriticalCnt(void);
int32_t GetCriticalCnt(void);

#ifdef __cplusplus
}
#endif
#endif
