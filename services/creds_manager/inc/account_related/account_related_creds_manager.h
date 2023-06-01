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

#ifndef ACCOUNT_RELATED_CREDS_MANAGER_H
#define ACCOUNT_RELATED_CREDS_MANAGER_H

#include "creds_manager_defines.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetAccountRelatedCredInfo(int32_t osAccountId, const char *groupId, const char *deviceId,
    bool isUdid, IdentityInfo *info);
int32_t GetAccountAsymSharedSecret(int32_t osAccountId, const CertInfo *peerCertInfo, Uint8Buff *sharedSecret);
int32_t GetAccountSymSharedSecret(const CJson *in, const CJson *urlJson, Uint8Buff *sharedSecret);
int32_t GetAccountAsymCredInfo(int32_t osAccountId, const CertInfo *certInfo, IdentityInfo **returnInfo);
int32_t GetAccountSymCredInfoByPeerUrl(const CJson *in, const CJson *urlJson, IdentityInfo *info);

#ifdef __cplusplus
}
#endif

#endif