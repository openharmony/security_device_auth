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

#ifndef OPERATION_DATA_MANAGER_H
#define OPERATION_DATA_MANAGER_H

#include <stdint.h>
#include "hc_string.h"
#include "hc_tlv_parser.h"
#include "hc_vector.h"
#include "json_utils.h"

#define FIELD_OPERATION_RECORD "operationRecord"
#define FIELD_COMMON_EVENT_RECORD "commonEventRecord"

#define DEFAULT_RECORD_OPERATION_SIZE 180

#ifdef LITE_DEVICE
#define MAX_RECENT_OPERATION_CNT 30
#define DEFAULT_RECENT_OPERATION_CNT 15
#define DEFAULT_COMMON_EVENT_CNT 0
#else
#define MAX_RECENT_OPERATION_CNT 150
#define DEFAULT_RECENT_OPERATION_CNT 20
#define DEFAULT_COMMON_EVENT_CNT 5
#endif

typedef struct {
    HcString caller;
    HcString function;
    HcString operationInfo; // （credId/groupId，deviceId）
    uint32_t operationType;
    uint64_t operationTime;
} OperationRecord;
DECLARE_HC_VECTOR(OperationVec, OperationRecord*)

typedef enum DevAuthOperationType {
    OPERATION_COMMON_EVENT        = 1,
    OPERATION_GROUP               = 2,
    OPERATION_IDENTITY_SERVICE    = 4,
    OPERATION_ANY                 = 0xFFFFFFFF
} DevAuthOperationType;

#ifdef __cplusplus
extern "C" {
#endif

void CopyHcStringForcibly(HcString *self, const char *str);
void SetAnonymousField(const char *str, const char *field, CJson *operationInfo);
int32_t RecordOperationData(int32_t osAccountId, const OperationRecord *operation);
int32_t GetOperationDataRecently(int32_t osAccountId, uint32_t types, char *record,
    uint32_t recordSize, uint32_t maxOperationCnt);

int32_t InitOperationDataManager(void);
void DestroyOperationDataManager(void);
OperationRecord *CreateOperationRecord(void);
OperationRecord *DeepCopyOperationRecord(const OperationRecord *entry);
void DestroyOperationRecord(OperationRecord *operation);
void ClearOperationVec(OperationVec *vec);

#ifdef __cplusplus
}
#endif
#endif