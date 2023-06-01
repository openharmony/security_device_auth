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

#ifndef COMPATIBLE_SUB_SESSION_H
#define COMPATIBLE_SUB_SESSION_H

#include "compatible_sub_session_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateCompatibleSubSession(SubSessionTypeValue sessionType, CJson *jsonParams,
    const DeviceAuthCallback *callback, CompatibleBaseSubSession **session);
int32_t ProcessCompatibleSubSession(CompatibleBaseSubSession *session, CJson *in, CJson **out, int32_t *status);
void DestroyCompatibleSubSession(CompatibleBaseSubSession *session);

#ifdef __cplusplus
}
#endif

#endif
