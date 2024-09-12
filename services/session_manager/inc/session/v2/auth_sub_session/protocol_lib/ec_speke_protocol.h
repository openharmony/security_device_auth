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

#ifndef DEV_AUTH_EC_SPEKE_PROTOCOL_H
#define DEV_AUTH_EC_SPEKE_PROTOCOL_H

#include "base_protocol.h"

#define PROTOCOL_TYPE_EC_SPEKE 1

typedef enum {
    CURVE_TYPE_256 = 1,
    CURVE_TYPE_25519 = 2,
} EcSpekeCurveType;

typedef struct {
    int32_t curveType;
    Uint8Buff authId;
    int32_t osAccountId;
} EcSpekeInitParams;

#ifdef ENABLE_EC_SPEKE

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateEcSpekeProtocol(const void *baseParams, bool isClient, BaseProtocol **returnObj);

#ifdef __cplusplus
}
#endif

#endif

#endif
