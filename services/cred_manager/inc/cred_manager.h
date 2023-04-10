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

#ifndef CRED_MANAGER_H
#define CRED_MANAGER_H

#include "cred_plugin_def.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitCredMgr(void);
void DestroyCredMgr(void);
int32_t AddCredPlugin(const CredPlugin *plugin);
void DelCredPlugin(int32_t pluginName);
int32_t ProcCred(int32_t pluginName, int32_t osAccountId, int32_t cmdId, CJson *in, CJson *out);

#ifdef __cplusplus
}
#endif

#endif
