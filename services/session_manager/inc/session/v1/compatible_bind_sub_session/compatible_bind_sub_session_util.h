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

#ifndef COMPATIBLE_BIND_SUB_SESSION_UTIL_H
#define COMPATIBLE_BIND_SUB_SESSION_UTIL_H

#include "compatible_bind_sub_session_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateAndProcessBindTask(CompatibleBindSubSession *session, const CJson *in, CJson *out, int32_t *status);
int32_t TransmitBindSessionData(const CompatibleBindSubSession *session, const CJson *sendData);
int32_t CombineConfirmData(int operationCode, const CJson *returnData, CJson *jsonParams);
void InformPeerGroupErrorIfNeeded(bool isNeedInform, int32_t errorCode, const CompatibleBindSubSession *session);
void InformPeerProcessError(int64_t requestId, const CJson *jsonParams, const DeviceAuthCallback *callback,
    int32_t errorCode);

#ifdef __cplusplus
}
#endif

#endif