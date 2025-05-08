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

#ifndef IDENTITY_SERVICE_IMPL_H
#define IDENTITY_SERVICE_IMPL_H

#include "cred_listener.h"

int32_t AddCredentialImpl(int32_t osAccountId, const char *requestParams, char **returnData);

int32_t ExportCredentialImpl(int32_t osAccountId, const char *credId, char **returnData);

int32_t QueryCredentialByParamsImpl(int32_t osAccountId, const char *requestParams, char **returnData);

int32_t QueryCredInfoByCredIdImpl(int32_t osAccountId, int32_t uid, const char *credId, char **returnData);

int32_t DeleteCredentialImpl(int32_t osAccountId, const char *credId);

int32_t DeleteCredByParamsImpl(int32_t osAccountId, const char *requestParams, char **returnData);

int32_t UpdateCredInfoImpl(int32_t osAccountId, const char *credId, const char *requestParams);

int32_t BatchUpdateCredsImpl(int32_t osAccountId, const char *requestParams, char **returnData);

int32_t AgreeCredentialImpl(int32_t osAccountId, const char *selfCredId, const char *requestParams, char **returnData);

int32_t RegCredListener(const char *appId, const CredChangeListener *listener);

int32_t UnRegCredListener(const char *appId);

#endif // IDENTITY_SERVICE_IMPL_H