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

#ifndef COMPATIBLE_BIND_SUB_SESSION_COMMON_H
#define COMPATIBLE_BIND_SUB_SESSION_COMMON_H

#include "compatible_bind_sub_session_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

bool IsCreateGroupNeeded(int isClient, int operationCode);
int32_t GenerateBaseBindParams(int32_t osAccountId, int isClient, const CJson *jsonParams,
    CompatibleBindSubSession *session);
int32_t GenerateBaseModuleParams(bool isClient, CompatibleBindSubSession *session, CJson *moduleParams);
int32_t AddInfoToBindData(bool isNeedCompatibleInfo, const CompatibleBindSubSession *session, CJson *data);

#ifdef __cplusplus
}
#endif

#endif