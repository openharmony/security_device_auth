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

#define FIELD_OPERATION_RECORD "operationRecord"

#define DEFAULT_RECORD_OPERATION_SIZE 128
#define DEFAULT_RECENT_OPERATION_CNT 20

#ifdef LITE_DEVICE
#define MAX_RECENT_OPERATION_CNT 30
#else
#define MAX_RECENT_OPERATION_CNT 150
#endif

typedef struct {
    HcString caller;
    HcString function;
    HcString operationInfo; // （credId/groupId，deviceId）
    uint32_t operationType;
    int64_t operationTime;
} Operation;
DECLARE_HC_VECTOR(OperationVec, Operation*)

typedef enum DevAuthOperationType {
    OPERATION_CREDENTIAL = 0,                  //0
    OPERATION_COMMON_EVENT,                    //1
    OPERATION_GROUP,                           //2
    OPERATION_IDENTITY_SERVICE,                //3
    OPERATION_ANY = 100,                       //100
} DevAuthOperationType;

#ifdef __cplusplus
extern "C" {
#endif

int32_t RecordOperationData(int32_t osAccountId, const Operation *operation);
int32_t GetOperationDataRecently(int32_t osAccountId, DevAuthOperationType type, char *record,
    uint32_t recordSize, uint32_t maxOperationCnt);

int32_t InitOperationDataManager(void);
void DestroyOperationDataManager(void);
Operation *CreateOperationRecord(void);
Operation *DeepCopyOperationRecord(const Operation *entry);
void DestroyOperationRecord(Operation *operation);
void ClearOperationVec(OperationVec *vec);

#ifdef __cplusplus
}
#endif
#endif