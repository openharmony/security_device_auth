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

#ifndef DEV_AUTH_DEV_SESSION_V2_H
#define DEV_AUTH_DEV_SESSION_V2_H

#include "dev_session_def.h"

typedef enum {
    JUMP_TO_NEXT_STATE,
    STAY_STATE,
    RESTART_STATE,
    JUMP_TO_FINISH_STATE
} JumpPolicy;

typedef enum {
    INIT_CLIENT_STATE = 0,
    INIT_SERVER_STATE,
    HAND_SHAKE_REQ_STATE,
    HAND_SHAKE_RSP_STATE,
    AUTH_STATE,
    EXPAND_STATE,
    SESSION_FINISH_STATE,
    SESSION_FAIL_STATE,
} SessionStateEnum;

typedef enum {
    START_EVENT,
    HAND_SHAKE_EVENT,
    HAND_SHAKE_RSP_EVENT,
    AUTH_EVENT,
    EXPAND_EVENT,
    SESSION_FAIL_EVENT,
    SESSION_UNKNOWN_EVENT,
} SessionEventType;

#ifdef __cplusplus
extern "C" {
#endif

bool IsSupportSessionV2(void);
AuthSubSessionList CreateAuthSubSessionList(void);
void DestroyAuthSubSessionList(AuthSubSessionList *list);
EventList CreateEventList(void);
void DestroyEventList(EventList *list);
int32_t SessionSwitchState(SessionImpl *impl, SessionEvent *event, CJson *sessionMsg);

#ifdef __cplusplus
}
#endif
#endif
