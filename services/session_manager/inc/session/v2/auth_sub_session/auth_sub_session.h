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

#ifndef AUTH_SUB_SESSION_H
#define AUTH_SUB_SESSION_H

#include "json_utils.h"
#include "string_util.h"

typedef enum {
    AUTH_STATE_INIT = 0,
    AUTH_STATE_RUNNING = 1,
    AUTH_STATE_FINISH = 2,
} AuthState;

typedef struct AuthSubSession AuthSubSession;
struct AuthSubSession {
    int32_t protocolType;
    int32_t state;
    int32_t (*start)(AuthSubSession *self, CJson **returnSendMsg);
    int32_t (*process)(AuthSubSession *self, const CJson *receviedMsg, CJson **returnSendMsg);
    int32_t (*setPsk)(AuthSubSession *self, const Uint8Buff *psk);
    int32_t (*setSelfProtectedMsg)(AuthSubSession *self, const Uint8Buff *selfMsg);
    int32_t (*setPeerProtectedMsg)(AuthSubSession *self, const Uint8Buff *peerMsg);
    int32_t (*getSessionKey)(AuthSubSession *self, Uint8Buff *returnSessionKey);
    void (*destroy)(AuthSubSession *self);
};

#ifdef __cplusplus
extern "C" {
#endif

bool IsProtocolSupport(int32_t protocolType);
int32_t CreateAuthSubSession(int32_t protocolType, void *params, bool isClient, AuthSubSession **returnObj);

#ifdef __cplusplus
}
#endif
#endif
