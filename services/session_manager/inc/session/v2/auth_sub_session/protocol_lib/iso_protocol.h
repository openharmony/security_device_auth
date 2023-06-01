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

#ifndef ISO_PROTOCOL_H
#define ISO_PROTOCOL_H

#include "base_protocol.h"

#define PROTOCOL_TYPE_ISO 4

typedef struct {
    Uint8Buff authId;
} IsoInitParams;

#ifdef ENABLE_ISO

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateIsoProtocol(const void *baseParams, bool isClient, BaseProtocol **returnObj);

#ifdef __cplusplus
}
#endif

#endif

#endif
