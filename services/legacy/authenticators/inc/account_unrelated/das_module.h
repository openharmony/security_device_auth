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

#ifndef DAS_MODULE_H
#define DAS_MODULE_H

#include "common_defs.h"
#include "string_util.h"
#include "dev_auth_module_manager.h"
#include "das_token_manager.h"

typedef struct DasAuthModuleT {
    AuthModuleBase base;
    int32_t (*registerLocalIdentity)(const TokenManagerParams *);
    int32_t (*unregisterLocalIdentity)(const TokenManagerParams *);
    int32_t (*deletePeerAuthInfo)(const TokenManagerParams *);
    int32_t (*getPublicKey)(const TokenManagerParams *, Uint8Buff *);
} DasAuthModule;

#ifdef __cplusplus
extern "C" {
#endif

const AuthModuleBase *GetDasModule(void);

#ifdef __cplusplus
}
#endif
#endif
