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

#ifndef DEV_AUTH_DEV_SESSION_MANAGER_H
#define DEV_AUTH_DEV_SESSION_MANAGER_H

#include "dev_session_fwk.h"
#include "json_utils.h"
#include "string_util.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitDevSessionManager(void);
void DestroyDevSessionManager(void);

int32_t OpenDevSession(int64_t sessionId, const char *appId, SessionInitParams *params);
int32_t StartDevSession(int64_t sessionId);
int32_t ProcessDevSession(int64_t sessionId, const CJson *receviedMsg, bool *isFinish);
void CloseDevSession(int64_t sessionId);
bool IsSessionExist(int64_t sessionId);
void CancelDevSession(int64_t sessionId, const char *appId);

#ifdef __cplusplus
}
#endif
#endif
