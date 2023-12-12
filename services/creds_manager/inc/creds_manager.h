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

#ifndef CREDS_MANAGER_H
#define CREDS_MANAGER_H

#include "identity_manager.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t AddCertInfoToJson(const CertInfo *certInfo, CJson *out);
int32_t GetCredInfosByPeerIdentity(CJson *in, IdentityInfoVec *vec);
int32_t GetCredInfoByPeerUrl(const CJson *in, const Uint8Buff *presharedUrl, IdentityInfo **returnInfo);
int32_t GetSharedSecretByUrl(
    const CJson *in, const Uint8Buff *presharedUrl, ProtocolAlgType protocolType, Uint8Buff *sharedSecret);
int32_t GetCredInfoByPeerCert(const CJson *in, const CertInfo *certInfo, IdentityInfo **returnInfo);
int32_t GetSharedSecretByPeerCert(
    const CJson *in, const CertInfo *peerCertInfo, ProtocolAlgType protocolType, Uint8Buff *sharedSecret);

#ifdef __cplusplus
}
#endif

#endif