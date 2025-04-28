/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_ADAPTER_H
#define PERMISSION_ADAPTER_H

#include <stdint.h>

#define CRED_AUTH_PERMISSION "ohos.permission.ACCESS_DEVAUTH_CRED_AUTH"
#define CRED_MGR_PERMISSION "ohos.permission.ACCESS_DEVAUTH_CRED_MGR"
#define CRED_PRIVILEGE_PERMISSION "ohos.permission.ACCESS_DEVAUTH_CRED_PRIVILEGE"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CheckInterfacePermission(const char *permission);
int32_t CheckPermission(int32_t methodId);
int32_t GetCallingUid(void);

#ifdef __cplusplus
}
#endif

#endif
