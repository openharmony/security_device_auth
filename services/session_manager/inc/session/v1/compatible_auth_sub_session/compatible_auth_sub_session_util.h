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

#ifndef COMPATIBLE_AUTH_SUB_SESSION_UTIL_H
#define COMPATIBLE_AUTH_SUB_SESSION_UTIL_H

#include "base_group_auth.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetAuthModuleType(const CJson *in);
char *GetDuplicatePkgName(const CJson *params);
int32_t CombineAuthConfirmData(const CJson *confirmationJson, CJson *dataFromClient);
int32_t GetAuthType(int32_t authForm);
BaseGroupAuth *GetGroupAuth(int32_t groupAuthType);

#ifdef __cplusplus
}
#endif

#endif