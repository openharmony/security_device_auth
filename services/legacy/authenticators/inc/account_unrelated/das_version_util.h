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

#ifndef DAS_VERSION_UTIL_H
#define DAS_VERSION_UTIL_H

#include "pake_defs.h"
#include "common_defs.h"
#include "protocol_common.h"

#define ALG_OFFSET_FOR_PAKE_V1 0
#define ALG_OFFSET_FOR_PAKE_V2 5

#define MAJOR_VERSION_NO 2
#define TMP_VERSION_STR_LEN 15

typedef enum {
    UNSUPPORTED_ALG = 0x0000,
    DL_PAKE_V1 = 0x0001, // 0001
    EC_PAKE_V1 = 0x0002, // 0010
    STS_ALG = 0x0004, // 0100
    PSK_SPEKE = 0x0008, // 1000
    ISO_ALG = 0x0010, // 0001 0000
    DL_PAKE_V2 = 0x0020, // 0010 0000
    EC_PAKE_V2 = 0x0040, // 0100 0000
} DasAlgType;

typedef enum {
    INITIAL,
    VERSION_CONFIRM,
    VERSION_DECIDED,
} VersionAgreementStatus;

typedef struct {
    uint32_t first;
    uint32_t second;
    uint32_t third;
} VersionStruct;

typedef struct VersionInfoT {
    int32_t opCode;
    VersionAgreementStatus versionStatus;
    VersionStruct minVersion;
    VersionStruct curVersion;
} VersionInfo;

#ifdef __cplusplus
extern "C" {
#endif

int32_t VersionToString(const VersionStruct *version, char *verStr, uint32_t len);
int32_t StringToVersion(const char* verStr, VersionStruct* version);

int32_t AddSingleVersionToJson(CJson *jsonObj, const VersionStruct *version);
int32_t GetSingleVersionFromJson(const CJson* jsonObj, VersionStruct *version);
void InitGroupAndModuleVersion(VersionStruct *version);

int32_t GetVersionFromJson(const CJson *jsonObj, VersionStruct *minVer, VersionStruct *maxVer);
int32_t AddVersionToJson(CJson *jsonObj, const VersionStruct *minVer, const VersionStruct *maxVer);

bool IsVersionEqual(VersionStruct *src, VersionStruct *des);
int32_t NegotiateVersion(VersionStruct *minVersionPeer, VersionStruct *curVersionPeer,
    VersionStruct *curVersionSelf);

ProtocolType GetPrototolType(VersionStruct *curVersion, OperationCode opCode);
PakeAlgType GetSupportedPakeAlg(VersionStruct *curVersion, ProtocolType protocolType);
bool IsSupportedPsk(VersionStruct *curVersion);

#ifdef __cplusplus
}
#endif
#endif
