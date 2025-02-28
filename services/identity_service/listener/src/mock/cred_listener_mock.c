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

#include "cred_listener.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_types.h"
#include "securec.h"

void OnCredAdd(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
}

void OnCredDelete(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
}

void OnCredUpdate(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
}

bool IsCredListenerSupported(void)
{
    return false;
}

int32_t InitCredListener(void)
{
    return IS_ERR_NOT_SUPPORT;
}

void DestroyCredListener(void)
{
    return;
}

int32_t AddCredListener(const char *appId, const CredChangeListener *listener)
{
    (void)appId;
    (void)listener;
    return IS_ERR_NOT_SUPPORT;
}

int32_t RemoveCredListener(const char *appId)
{
    (void)appId;
    return IS_ERR_NOT_SUPPORT;
}
