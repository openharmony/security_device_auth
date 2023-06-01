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

#ifndef DEV_AUTH_DEV_SESSION_FWK_H
#define DEV_AUTH_DEV_SESSION_FWK_H

#include "device_auth.h"
#include "json_utils.h"
#include "string_util.h"

typedef struct {
    const CJson *context;
    const DeviceAuthCallback callback;
} SessionInitParams;

typedef struct DevSession DevSession;
struct DevSession {
    int64_t id;
    char *appId;
    int32_t opCode;
    DeviceAuthCallback callback;
    int32_t (*start)(DevSession *self);
    int32_t (*process)(DevSession *self, const CJson *receviedMsg, bool *isFinish);
    void (*destroy)(DevSession *self);
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateDevSession(int64_t sessionId, const char *appId, SessionInitParams *params, DevSession **returnObj);

#ifdef __cplusplus
}
#endif
#endif
