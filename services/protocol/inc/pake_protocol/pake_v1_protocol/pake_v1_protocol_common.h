/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef PAKE_V1_PROTOCOL_COMMON_H
#define PAKE_V1_PROTOCOL_COMMON_H

#include "hc_types.h"
#include "pake_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitPakeV1BaseParams(int32_t osAccountId, PakeBaseParams *params);
void DestroyPakeV1BaseParams(PakeBaseParams *params);

int32_t ClientConfirmPakeV1Protocol(PakeBaseParams *params);
int32_t ClientVerifyConfirmPakeV1Protocol(PakeBaseParams *params);

int32_t ServerResponsePakeV1Protocol(PakeBaseParams *params);
int32_t ServerConfirmPakeV1Protocol(PakeBaseParams *params);
#ifdef __cplusplus
}
#endif
#endif
