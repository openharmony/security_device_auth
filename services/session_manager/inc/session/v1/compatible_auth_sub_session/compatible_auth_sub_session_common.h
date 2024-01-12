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

#ifndef COMPATIBLE_AUTH_SUB_SESSION_COMMON_H
#define COMPATIBLE_AUTH_SUB_SESSION_COMMON_H

#include "compatible_auth_sub_session_defines.h"

#define MIN_KEY_LENGTH 16
#define MAX_KEY_LENGTH 1024

#ifdef __cplusplus
extern "C" {
#endif

void CreateAuthParamsList(ParamsVecForAuth *vec);
void DestroyAuthParamsList(ParamsVecForAuth *vec);
int32_t GetAuthParamsVec(int32_t osAccountId, const CJson *param, ParamsVecForAuth *authParamsVec);
int32_t CreateAndProcessAuthTask(CompatibleAuthSubSession *session, CJson *paramInSession, CJson *out,
    int32_t *status);
void ClearCachedData(CJson *paramInSession);
int32_t ProcessClientAuthError(CompatibleAuthSubSession *session, const CJson *out);
void ProcessServerAuthError(CompatibleAuthSubSession *session, const CJson *out);
int32_t AddGroupAuthTransmitData(const CompatibleAuthSubSession *session, bool isClientFirst, CJson *sendToPeer);
int32_t HandleAuthTaskStatus(const CompatibleAuthSubSession *session, CJson *out, int32_t status);
void NotifyPeerAuthError(const CJson *authParam, const DeviceAuthCallback *callback);
int32_t AuthOnNextGroupIfExist(CompatibleAuthSubSession *session);

#ifdef __cplusplus
}
#endif

#endif