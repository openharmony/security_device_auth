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

#ifndef BASE_PROTOCOL_H
#define BASE_PROTOCOL_H

#include "json_utils.h"
#include "string_util.h"

#define PROTECTED_MSG_MAX_LEN 1024

typedef struct {
    Uint8Buff selfMsg;
    Uint8Buff peerMsg;
} ProtectedMsg;

typedef struct BaseProtocol BaseProtocol;
struct BaseProtocol {
    int32_t name;
    int32_t curState;
    int32_t beginState;
    int32_t finishState;
    int32_t failState;
    Uint8Buff sessionKey;
    ProtectedMsg protectedMsg;
    int32_t (*start)(BaseProtocol *, CJson **);
    int32_t (*process)(BaseProtocol *, const CJson *, CJson **);
    int32_t (*setPsk)(BaseProtocol *, const Uint8Buff *);
    int32_t (*setSelfProtectedMsg)(BaseProtocol *, const Uint8Buff *);
    int32_t (*setPeerProtectedMsg)(BaseProtocol *, const Uint8Buff *);
    int32_t (*getSessionKey)(BaseProtocol *, Uint8Buff *);
    void (*destroy)(BaseProtocol *);
};

typedef enum {
    START_AUTH_EVENT = 0,
    CLEINT_START_REQ_EVENT,
    SERVER_START_RSP_EVENT,
    CLEINT_FINISH_REQ_EVENT,
    SERVER_FINISH_RSP_EVENT,
    FAIL_EVENT,
    UNKNOWN_EVENT,
} ProtocolEventEnum;

typedef enum {
    CREATE_AS_CLIENT_STATE = 0,
    CREATE_AS_SERVER_STATE,
    CLIENT_REQ_STATE,
    SERVER_RSP_STATE,
    CLIENT_FINISH_REQ_STATE,
    /* FINISH STATE */
    SERVER_FINISH_STATE,
    CLIENT_FINISH_STATE,
    /* FAIL STATE */
    FAIL_STATE
} ProtocolStateEnum;

#endif
