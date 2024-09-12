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

#ifndef DAS_TOKEN_MANAGER_H
#define DAS_TOKEN_MANAGER_H

#include "common_defs.h"
#include "pake_base_cur_task.h"

typedef struct {
    int32_t osAccountId;
    Uint8Buff pkgName;
    Uint8Buff serviceType;
    Uint8Buff authId;
    int userType;
} TokenManagerParams;


typedef struct TokenManagerT {
    int32_t (*registerLocalIdentity)(const TokenManagerParams *);
    int32_t (*unregisterLocalIdentity)(const TokenManagerParams *);
    int32_t (*deletePeerAuthInfo)(const TokenManagerParams *);
    int32_t (*computeAndSavePsk)(const PakeParams *);
    int32_t (*getPublicKey)(const TokenManagerParams *, Uint8Buff *);
} TokenManager;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif
#endif