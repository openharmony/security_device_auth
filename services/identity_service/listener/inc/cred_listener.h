/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef CRED_LISTENER_H
#define CRED_LISTENER_H

#include "device_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitCredListener(void);
void DestroyCredListener(void);

void OnCredAdd(const char *credId, const char *credInfo);
void OnCredDelete(const char *credId, const char *credInfo);
void OnCredUpdate(const char *credId, const char *credInfo);
bool IsCredListenerSupported(void);

int32_t AddCredListener(const char *appId, const CredChangeListener *listener);
int32_t RemoveCredListener(const char *appId);

#ifdef __cplusplus
}
#endif
#endif
