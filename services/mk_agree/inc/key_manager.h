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

#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include "string_util.h"

typedef struct {
    const char *peerInfo;
    const char *pdidIndex;
} PseudonymKeyInfo;

#ifdef __cplusplus
extern "C" {
#endif

int32_t GenerateDeviceKeyPair(void);
int32_t GenerateMk(const char *peerDeviceId, const Uint8Buff *peerPubKey);
int32_t DeleteMk(const char *peerDeviceId);
int32_t GeneratePseudonymPsk(const char *peerDeviceId, const Uint8Buff *salt);
int32_t DeletePseudonymPsk(const char *peerDeviceId);
int32_t GenerateAndSavePseudonymId(int32_t osAccountId, const char *peerDeviceId, const PseudonymKeyInfo *info,
    const Uint8Buff *salt, Uint8Buff *returnKey);
int32_t GetDevicePubKey(Uint8Buff *devicePk);

#ifdef __cplusplus
}
#endif
#endif