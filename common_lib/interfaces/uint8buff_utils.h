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

#ifndef UINT8BUFF_UTILS_H
#define UINT8BUFF_UTILS_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t *val;
    uint32_t length;
} Uint8Buff;

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitUint8Buff(Uint8Buff *buff, uint32_t buffLen);
int32_t DeepCopyUint8Buff(const Uint8Buff *buff, Uint8Buff *newBuff);
void FreeUint8Buff(Uint8Buff *buff);
void ClearFreeUint8Buff(Uint8Buff *buff);
bool IsUint8BuffValid(const Uint8Buff *buff, uint32_t maxLen);

#ifdef __cplusplus
}
#endif
#endif