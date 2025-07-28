/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef ACCOUNT_TASK_MANAGER_H
#define ACCOUNT_TASK_MANAGER_H

#include <stdint.h>

#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitAccountTaskManager(void);
void DestroyAccountTaskManager(void);
bool HasAccountPlugin(void);
int32_t ExecuteAccountAuthCmd(int32_t osAccountId, int32_t cmdId, const CJson *in, CJson *out);
int32_t CreateAccountAuthSession(int32_t *sessionId, const CJson *in, CJson *out);
int32_t ProcessAccountAuthSession(int32_t *sessionId, const CJson *in, CJson *out, int32_t *status);
int32_t DestroyAccountAuthSession(int32_t sessionId);
void IncreaseLoadCount(void);
void DecreaseLoadCount(void);

#ifdef __cplusplus
}
#endif
#endif