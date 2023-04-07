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

#ifndef PLUGIN_ADAPTER_H
#define PLUGIN_ADAPTER_H

#ifndef DEV_AUTH_PLUGIN_ENABLE

#define DEV_AUTH_LOAD_PLUGIN()
#define DEV_AUTH_UNLOAD_PLUGIN()

#else

#include <stdint.h>

#define DEV_AUTH_LOAD_PLUGIN() LoadExtendPlugin()
#define DEV_AUTH_UNLOAD_PLUGIN() UnloadExtendPlugin()

#ifdef __cplusplus
extern "C" {
#endif

void LoadExtendPlugin(void);
void UnloadExtendPlugin(void);

#ifdef __cplusplus
}
#endif

#endif

#endif
