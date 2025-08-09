/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef LIGHT_SESSION_MANAGER_H
#define LIGHT_SESSION_MANAGER_H

#include <stdbool.h>
#include "hc_string.h"
#include "hc_string_vector.h"
#include "hc_tlv_parser.h"
#include "hc_vector.h"
#include "json_utils.h"
#include "device_auth.h"

typedef struct {
    int64_t requestId;
    int32_t osAccountId;
    char *serviceId;
    uint8_t *randomVal;
    uint32_t randomLen;
} LightSession;

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitLightSessionManager(void);

void DestroyLightSessionManager(void);

int32_t QueryLightSession(int64_t requestId, int32_t osAccountId, uint8_t **randomVal, char **serviceId);

int32_t AddLightSession(int64_t requestId, int32_t osAccountId, const char *serviceId, DataBuff randomBuff);

int32_t DeleteLightSession(int64_t requestId, int32_t osAccountId);

#ifdef __cplusplus
}
#endif
#endif
