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

#ifndef DEV_SESSION_UTIL_H
#define DEV_SESSION_UTIL_H

#include "identity_defines.h"
#include "data_manager.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t FillPeerAuthIdIfNeeded(bool isClient, const CJson *context, CJson *inputData);
int32_t SetPeerAuthIdToContextIfNeeded(CJson *context, const IdentityInfo *info);
bool IsP2pAuth(const IdentityInfo *info);
int32_t SetPeerInfoToContext(CJson *context, const CJson *inputData);
int32_t ReplaceAuthIdWithRandom(CJson *authData);
int32_t CheckPeerPkInfoForPdid(const CJson *context, const CJson *inputData);
int32_t GetRealPkInfoStr(int32_t osAccountId, const CJson *credInfo, char **returnPkInfoStr, bool *isPseudonym);
int32_t AddPkInfoWithPdid(const CJson *context, CJson *credInfo, const char *realPkInfoStr);
TrustedDeviceEntry *GetDeviceEntryById(int32_t osAccountId, const char *deviceId, bool isUdid,
    const char *groupId);

#ifdef __cplusplus
}
#endif
#endif
