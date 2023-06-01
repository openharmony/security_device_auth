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

#ifndef COMPATIBLE_SUB_SESSION_DEFINES_H
#define COMPATIBLE_SUB_SESSION_DEFINES_H

#include "common_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STATUS_INITIAL = 1,
    STATUS_PROCESSING
} SubSessionStatusValue;

typedef struct {
    int type;
    char *appId;
    int32_t curTaskId;
    SubSessionStatusValue status;
    const DeviceAuthCallback *callback;
} CompatibleBaseSubSession;

typedef enum {
    TYPE_CLIENT_BIND_SUB_SESSION = 1,
    TYPE_SERVER_BIND_SUB_SESSION,
    TYPE_CLIENT_AUTH_SUB_SESSION,
    TYPE_SERVER_AUTH_SUB_SESSION
} SubSessionTypeValue;

#ifdef __cplusplus
}
#endif

#endif
