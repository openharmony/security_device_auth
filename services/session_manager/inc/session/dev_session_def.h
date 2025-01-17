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

#define FIELD_DATA "data"
#define FIELD_VR "vr"
#define FIELD_INDEX "index"
#define FIELD_TOTAL "total"
#define FIELD_CRED_URL "credUrl"
#define FIELD_PROTOCOL "protocol"
#define FIELD_CMDS "cmds"
#define FIELD_AUTH_MSG "authMsg"
#define FIELD_AUTH_DATA "authData"
#define FIELD_ABILITY "ability"
#define FIELD_TYPE "type"
#define FIELD_MSG "msg"

#define FIELD_HAND_SHAKE "handshake"
#define FIELD_AUTH_EVENT "authEvent"
#define FIELD_ID "id"
#define FIELD_TD_CMDS "tdCmds"
#define FIELD_SP_CMDS "spCmds"
#define FIELD_CMD_EVENT "cmdEvent"
#define FIELD_SESSION_FAIL_EVENT "failEvent"

#define DEV_SESSION_SALT_LEN 32

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
    bool isCredAuth;
} SessionImpl;

#endif
