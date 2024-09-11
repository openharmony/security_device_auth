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

#include "key_manager.h"
#include "device_auth_defines.h"

int32_t GenerateDeviceKeyPair(int32_t osAccountId)
{
    (void)osAccountId;
    return HC_ERR_NOT_SUPPORT;
}

int32_t GenerateMk(int32_t osAccountId, const char *peerDeviceId, const Uint8Buff *peerPubKey)
{
    (void)osAccountId;
    (void)peerDeviceId;
    (void)peerPubKey;
    return HC_ERR_NOT_SUPPORT;
}

int32_t DeleteMk(int32_t osAccountId, const char *peerDeviceId)
{
    (void)osAccountId;
    (void)peerDeviceId;
    return HC_ERR_NOT_SUPPORT;
}

int32_t GeneratePseudonymPsk(int32_t osAccountId, const char *peerDeviceId, const Uint8Buff *salt)
{
    (void)osAccountId;
    (void)peerDeviceId;
    (void)salt;
    return HC_ERR_NOT_SUPPORT;
}

int32_t DeletePseudonymPsk(int32_t osAccountId, const char *peerDeviceId)
{
    (void)osAccountId;
    (void)peerDeviceId;
    return HC_ERR_NOT_SUPPORT;
}

int32_t GenerateAndSavePseudonymId(int32_t osAccountId, const char *peerDeviceId, const PseudonymKeyInfo *info,
    const Uint8Buff *saltBuff, Uint8Buff *returnHmac)
{
    (void)osAccountId;
    (void)peerDeviceId;
    (void)info;
    (void)saltBuff;
    (void)returnHmac;
    return HC_ERR_NOT_SUPPORT;
}

int32_t GetDevicePubKey(int32_t osAccountId, Uint8Buff *devicePk)
{
    (void)osAccountId;
    (void)devicePk;
    return HC_ERR_NOT_SUPPORT;
}