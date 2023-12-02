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

#ifndef DEV_AUTH_DEV_SESSION_DEF_H
#define DEV_AUTH_DEV_SESSION_DEF_H

#include "auth_sub_session.h"
#include "compatible_sub_session.h"
#include "expand_sub_session.h"
#include "identity_defines.h"
#include "dev_session_fwk.h"
#include "hc_vector.h"

typedef struct {
    int32_t type;
    const CJson *data;
} SessionEvent;

DECLARE_HC_VECTOR(EventList, SessionEvent)
DECLARE_HC_VECTOR(AuthSubSessionList, AuthSubSession *)

typedef struct {
    DevSession base;
    bool isClient;
    int32_t opCode;
    int32_t channelType;
    int64_t channelId;
    CJson *context;
    int32_t curState;
    int32_t restartState;
    uint32_t credCurIndex;
    uint32_t credTotalNum;
    Uint8Buff salt;
    Uint8Buff sessionKey;
    EventList eventList;
    IdentityInfoVec credList;
    ProtocolEntity protocolEntity;
    AuthSubSessionList authSubSessionList;
    ExpandSubSession *expandSubSession;
    CompatibleBaseSubSession *compatibleSubSession;
} SessionImpl;

#endif
