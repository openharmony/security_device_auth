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

#include "hc_log.h"
#include "hc_vector.h"
#include "device_auth_defines.h"

typedef struct {
    int64_t requestId;
    int32_t osAccountId;
    char *serviceId;
    uint8_t *randomVal;
} LightSession;

int32_t InitLightSessionManager(void)
{
    return HC_SUCCESS;
}

void DestroyLightSessionManager(void)
{
    return;
}

int32_t QueryLightSession(int64_t requestId, int32_t osAccountId, LightSession **lightSession)
{
    (void)requestId;
    (void)osAccountId;
    (void)lightSession;
    return HC_SUCCESS;
}

int32_t AddLightSession(int64_t requestId, int32_t osAccountId, const char *serviceId, uint8_t *randomVal)
{
    (void)requestId;
    (void)osAccountId;
    (void)serviceId;
    (void)randomVal;
    return HC_SUCCESS;
}

int32_t DeleteLightSession(int64_t requestId, int32_t osAccountId)
{
    (void)requestId;
    (void)osAccountId;
    return HC_SUCCESS;
}