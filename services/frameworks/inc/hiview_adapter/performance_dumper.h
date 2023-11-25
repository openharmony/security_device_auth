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

#ifndef PERFORMANCE_DUMPER_H
#define PERFORMANCE_DUMPER_H

#include <stdbool.h>
#include "hc_vector.h"

typedef enum {
    PERFORM_DATA_STATUS_BEGIN = 0,
    PERFORM_DATA_STATUS_FINISH
} PerformDataStatus;

typedef enum {
    FIRST_START_TIME = 0,
    FIRST_TRANSMIT_TIME,
    SECOND_START_TIME,
    SECOND_TRANSMIT_TIME,
    THIRD_START_TIME,
    THIRD_TRANSMIT_TIME,
    FOURTH_START_TIME,
    FOURTH_TRANSMIT_TIME,
    ON_SESSION_KEY_RETURN_TIME,
    ON_FINISH_TIME
} PerformTimeIndex;

typedef struct {
    int64_t reqId;
    bool isBind;
    bool isClient;
    PerformTimeIndex selfIndex;
    PerformDataStatus status;
    int64_t firstStartTime;
    int64_t firstTransmitTime;
    int64_t secondStartTime;
    int64_t secondTransmitTime;
    int64_t thirdStartTime;
    int64_t thirdTransmitTime;
    int64_t fourthStartTime;
    int64_t fourthTransmitTime;
    int64_t onSessionKeyReturnTime;
    int64_t onFinishTime;
    int64_t firstConsumeTime;
    int64_t secondConsumeTime;
    int64_t thirdConsumeTime;
    int64_t fourthConsumeTime;
    int64_t innerConsumeTime;
    int64_t totalConsumeTime;
} PerformData;
DECLARE_HC_VECTOR(PerformDataVec, PerformData*)

#ifndef DEV_AUTH_HIVIEW_ENABLE

#define ADD_PERFORM_DATA(reqId, isBind, isClient, startTime)
#define RESET_PERFORM_DATA(reqId)
#define UPDATE_PERFORM_DATA_BY_INPUT_INDEX(reqId, timeIndex, time)
#define UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, time)
#define INIT_PERFORMANCE_DUMPER()
#define DESTROY_PERFORMANCE_DUMPER()

#else

#define ADD_PERFORM_DATA(reqId, isBind, isClient, startTime) AddPerformData(reqId, isBind, isClient, startTime)
#define RESET_PERFORM_DATA(reqId) ResetPerformData(reqId)
#define UPDATE_PERFORM_DATA_BY_INPUT_INDEX(reqId, timeIndex, time) \
    UpdatePerformDataByInputIndex(reqId, timeIndex, time)
#define UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, time) UpdatePerformDataBySelfIndex(reqId, time)
#define INIT_PERFORMANCE_DUMPER() InitPerformanceDumper()
#define DESTROY_PERFORMANCE_DUMPER() DestroyPerformanceDumper()

#ifdef __cplusplus
extern "C" {
#endif

void AddPerformData(int64_t reqId, bool isBind, bool isClient, int64_t startTime);
void ResetPerformData(int64_t reqId);
void UpdatePerformDataByInputIndex(int64_t reqId, PerformTimeIndex timeIndex, int64_t time);
void UpdatePerformDataBySelfIndex(int64_t reqId, int64_t time);
void InitPerformanceDumper(void);
void DestroyPerformanceDumper(void);

#ifdef __cplusplus
}
#endif
#endif
#endif
