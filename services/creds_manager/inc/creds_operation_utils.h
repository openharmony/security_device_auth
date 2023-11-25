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

#ifndef CREDS_OPERATION_UTILS_H
#define CREDS_OPERATION_UTILS_H

#include "creds_manager_defines.h"
#include "data_manager.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetSelfDeviceEntry(int32_t osAccountId, const char *groupId, TrustedDeviceEntry *deviceEntry);
const char *GetPeerDevIdFromJson(const CJson *in, bool *isUdid);
int32_t GetPeerDeviceEntry(int32_t osAccountId, const CJson *in, const char *groupId,
    TrustedDeviceEntry *returnDeviceEntry);
int32_t GetIdentityInfoForPinType(const CJson *in, IdentityInfo *info);
int32_t GetIdentityInfoByType(int32_t keyType, int32_t trustType, const char *groupId, IdentityInfo *info);
void FreeBuffData(Uint8Buff *buff);

IdentityInfo *CreateIdentityInfo(void);
void DestroyIdentityInfo(IdentityInfo *info);

IdentityInfoVec CreateIdentityInfoVec(void);
void ClearIdentityInfoVec(IdentityInfoVec *vec);

ProtocolEntityVec CreateProtocolEntityVec(void);
void ClearProtocolEntityVec(ProtocolEntityVec *vec);

#ifdef __cplusplus
}
#endif

#endif