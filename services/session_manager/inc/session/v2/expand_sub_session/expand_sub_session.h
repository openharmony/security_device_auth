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

#ifndef EXPAND_SUB_SESSION_H
#define EXPAND_SUB_SESSION_H

#include "base_cmd.h"

typedef enum {
    EXPAND_STATE_INIT = 0,
    EXPAND_STATE_RUNNING = 1,
    EXPAND_STATE_FINISH = 2,
} ExpandStatus;

typedef struct ExpandSubSession ExpandSubSession;
struct ExpandSubSession {
    int32_t state;
    int32_t (*addCmd)(ExpandSubSession *self, int32_t cmdType,
        void *params, bool isClient, int32_t strategy);
    int32_t (*start)(ExpandSubSession *self, CJson **returnSendMsg);
    int32_t (*process)(ExpandSubSession *self, const CJson *receviedMsg, CJson **returnSendMsg);
    void (*destroy)(ExpandSubSession *self);
};

#ifdef __cplusplus
extern "C" {
#endif

bool IsCmdSupport(int32_t cmdId);
int32_t CreateExpandSubSession(const Uint8Buff *nonce, const Uint8Buff *encKey, ExpandSubSession **returnObj);

#ifdef __cplusplus
}
#endif
#endif
