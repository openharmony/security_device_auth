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

#ifndef EXT_PART_PROXY_H
#define EXT_PART_PROXY_H

#include <stdint.h>
#include "device_auth_ext.h"

typedef struct ExtPartProxy {
    int32_t (*initExtPartFunc)(const cJSON *params, ExtPart *extPart);
    ExtPluginList (*getPluginListFunc)(ExtPart *extPart);
    void (*destroyExtPartFunc)(ExtPart *extPart);
} ExtPartProxy;

#ifdef __cplusplus
extern "C" {
#endif
int32_t AddExtPlugin(const ExtPartProxy *pluginProxy);
void DestroyExt(ExtPartProxy *pluginProxy);

#ifdef __cplusplus
}
#endif

#endif