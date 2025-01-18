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

#ifndef IDENTITY_SERVICE_H
#define IDENTITY_SERVICE_H

#include "cred_listener.h"

int32_t AddCredential(int32_t osAccountId, const char *requestParams, char **returnData);

int32_t ExportCredential(int32_t osAccountId, const char *credId, char **returnData);

int32_t QueryCredentialByParams(int32_t osAccountId, const char *requestParams, char **returnData);

int32_t QueryCredInfoByCredId(int32_t osAccountId, const char *credId, char **returnData);

int32_t DeleteCredential(int32_t osAccountId, const char *appId, const char *credId);

int32_t UpdateCredInfo(int32_t osAccountId, const char *appId, const char *credId, const char *requestParams);

int32_t RegisterChangeListener(const char *appId, CredChangeListener *listener);

int32_t UnregisterChangeListener(const char *appId);

void DestroyInfo(char **returnData);

int32_t InitIdentityService(void);

void DestroyIdentityService(void);

#endif // IDENTITY_SERVICE_H