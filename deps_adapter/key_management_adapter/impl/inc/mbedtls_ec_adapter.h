/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef MBEDTLS_EC_ADAPTER_H
#define MBEDTLS_EC_ADAPTER_H

#include <stdint.h>
#include "string_util.h"
#include "alg_defs.h"

#define HASH2POINT_PARA_PREPRO 0xc0
#define BYTE_LENGTH_CURVE_25519 32

#ifdef __cplusplus
extern "C" {
#endif

int32_t MbedtlsHashToPoint(const Uint8Buff *hash, Uint8Buff *outEcPoint);
int32_t MbedtlsHashToPoint25519(const Uint8Buff *hash, Uint8Buff *outEcPoint);
int32_t MbedtlsAgreeSharedSecret(const KeyBuff *priKey, const KeyBuff *pubKey, Uint8Buff *sharedKey);
int32_t MbedtlsBase64Encode(const uint8_t *byte, uint32_t byteLen, char *base64Str, uint32_t strLen, uint32_t *outLen);
int32_t MbedtlsBase64Decode(const char *base64Str, uint32_t strLen, uint8_t *byte, uint32_t byteLen, uint32_t *outLen);
bool MbedtlsIsP256PublicKeyValid(const Uint8Buff *pubKey);
bool MbedtlsIsX25519PublicKeyValid(const Uint8Buff *pubKey);

#ifdef __cplusplus
}
#endif
#endif
