/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include "device_auth_defines.h"

static int32_t g_checkPermissionResult = HC_SUCCESS;

void SetCheckPermissionResult(int32_t result)
{
    g_checkPermissionResult = result;
}

extern "C" {

int32_t CheckPermission(int32_t methodId)
{
    (void)methodId;
    return g_checkPermissionResult;
}

int32_t CheckInterfacePermission(const char *permission)
{
    (void)permission;
    return g_checkPermissionResult;
}

int32_t GetCallingUid(void)
{
    return 0;
}

int32_t CheckRestoreCallPermission(void)
{
    return g_checkPermissionResult;
}

}
