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


#include "plugin_adapter.h"

#include <los_ld_elflib.h>
#include "hal_error.h"
#include "hc_log.h"

void *DevAuthDlopen(const char *filePath)
{
    return LOS_SoLoad(filePath);
}

void *DevAuthDlsym(void *handle, const char *funcName)
{
    return LOS_FindSymByName(handle, funcName);
}

void DevAuthDlclose(void *handle)
{
    (void)LOS_ModuleUnload(handle);
}
