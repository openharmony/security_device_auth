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

#ifndef PSEUDONYM_MANAGER_H
#define PSEUDONYM_MANAGER_H

#include <stdint.h>
#include "common_defs.h"
#include "string_util.h"

typedef struct {
    void (*loadPseudonymData)(void);
    int32_t (*getRealInfo)(int32_t osAccountId, const char *pseudonymId, char **realInfo);
    int32_t (*getPseudonymId)(int32_t osAccountId, const char *indexKey, char **pseudonymId);
    int32_t (*savePseudonymId)(int32_t osAccountId, const char *pseudonymId, const char *realInfo,
        const char *deviceId, const char *indexKey);
    int32_t (*deleteAllPseudonymId)(int32_t osAccountId, const char *deviceId);
    int32_t (*deletePseudonymId)(int32_t osAccountId, const char *indexKey);
    bool (*isNeedRefreshPseudonymId)(int32_t osAccountId, const char *indexKey);
} PseudonymManager;

#ifdef __cplusplus
extern "C" {
#endif

PseudonymManager *GetPseudonymInstance(void);
void DestroyPseudonymManager(void);

#ifdef __cplusplus
}
#endif
#endif
