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

#include "performance_dumper.h"

#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_time.h"
#include "hc_types.h"
#include "hidump_adapter.h"

#define ENABLE_PERFORMANCE_DUMPER "--enable"
#define DISABLE_PERFORMANCE_DUMPER "--disable"
#define MAX_REQUEST_ID_LEN 128
#define MAX_DUMP_SESSION_NUM 10
#define MIN_ARGS_NUM 1
#define MAX_ARGS_NUM 2

IMPLEMENT_HC_VECTOR(PerformDataVec, PerformData*, 1)

static bool g_isInit = false;
static HcMutex *g_performDataMutex = NULL;
static PerformDataVec g_performDataVec;
static bool g_isPerformDumpEnabled = false;
static uint32_t g_bindClientSessionNum = 0;
static uint32_t g_bindServerSessionNum = 0;
static uint32_t g_authClientSessionNum = 0;
static uint32_t g_authServerSessionNum = 0;

static PerformData *CreatePerformData(void)
{
    PerformData *performData = (PerformData *)HcMalloc(sizeof(PerformData), 0);
    if (performData == NULL) {
        LOGE("Failed to alloc memory for perform data!");
        return NULL;
    }
    return performData;
}

static void DestroyPerformData(PerformData *performData)
{
    HcFree(performData);
}

static void ClearPerformDataVec(void)
{
    uint32_t index;
    PerformData **performData;
    FOR_EACH_HC_VECTOR(g_performDataVec, index, performData) {
        PerformData *popData;
        HC_VECTOR_POPELEMENT(&g_performDataVec, &popData, index);
        DestroyPerformData(popData);
    }
    g_bindClientSessionNum = 0;
    g_bindServerSessionNum = 0;
    g_authClientSessionNum = 0;
    g_authServerSessionNum = 0;
}

static void DecreaseSessionNum(PerformData *data)
{
    if (data->isBind) {
        if (data->isClient) {
            g_bindClientSessionNum--;
        } else {
            g_bindServerSessionNum--;
        }
    } else {
        if (data->isClient) {
            g_authClientSessionNum--;
        } else {
            g_authServerSessionNum--;
        }
    }
}

static void RemovePerformDataIfExist(int64_t reqId)
{
    uint32_t index;
    PerformData **performData;
    FOR_EACH_HC_VECTOR(g_performDataVec, index, performData) {
        if ((*performData)->reqId == reqId) {
            PerformData *popData;
            HC_VECTOR_POPELEMENT(&g_performDataVec, &popData, index);
            DecreaseSessionNum(popData);
            DestroyPerformData(popData);
            return;
        }
    }
}

static void UpdateDataBySelfIndex(PerformData *performData, int64_t time)
{
    switch (performData->selfIndex) {
        case FIRST_START_TIME:
            performData->firstTransmitTime = time;
            performData->selfIndex = FIRST_TRANSMIT_TIME;
            break;
        case FIRST_TRANSMIT_TIME:
            performData->secondStartTime = time;
            performData->selfIndex = SECOND_START_TIME;
            break;
        case SECOND_START_TIME:
            performData->secondTransmitTime = time;
            performData->selfIndex = SECOND_TRANSMIT_TIME;
            break;
        case SECOND_TRANSMIT_TIME:
            performData->thirdStartTime = time;
            performData->selfIndex = THIRD_START_TIME;
            break;
        case THIRD_START_TIME:
            performData->thirdTransmitTime = time;
            performData->selfIndex = THIRD_TRANSMIT_TIME;
            break;
        case THIRD_TRANSMIT_TIME:
            performData->fourthStartTime = time;
            performData->selfIndex = FOURTH_START_TIME;
            break;
        case FOURTH_START_TIME:
            performData->fourthTransmitTime = time;
            performData->selfIndex = FOURTH_TRANSMIT_TIME;
            break;
        default:
            LOGE("Invalid timeIndex!");
            break;
    }
}

static void UpdateDataByInputIndex(PerformData *performData, PerformTimeIndex timeIndex, int64_t time)
{
    if (timeIndex == ON_SESSION_KEY_RETURN_TIME) {
        performData->onSessionKeyReturnTime = time;
    } else if (timeIndex == ON_FINISH_TIME) {
        performData->onFinishTime = time;
        performData->status = PERFORM_DATA_STATUS_FINISH;
    } else {
        LOGE("Invalid timeIndex!");
    }
}

static int64_t GetConsumeTimeByIndex(PerformData *performData, PerformTimeIndex index)
{
    switch (index) {
        case FIRST_START_TIME:
            if (performData->firstTransmitTime != 0) {
                return performData->firstTransmitTime - performData->firstStartTime;
            } else {
                return performData->onSessionKeyReturnTime - performData->firstStartTime;
            }
        case SECOND_START_TIME:
            if (performData->secondTransmitTime != 0) {
                return performData->secondTransmitTime - performData->secondStartTime;
            } else {
                return performData->onSessionKeyReturnTime - performData->secondStartTime;
            }
        case THIRD_START_TIME:
            if (performData->thirdTransmitTime != 0) {
                return performData->thirdTransmitTime - performData->thirdStartTime;
            } else {
                return performData->onSessionKeyReturnTime - performData->thirdStartTime;
            }
        case FOURTH_START_TIME:
            if (performData->fourthTransmitTime != 0) {
                return performData->fourthTransmitTime - performData->fourthStartTime;
            } else {
                return performData->onSessionKeyReturnTime - performData->fourthStartTime;
            }
        default:
            return 0;
    }
}

static const char *GetOperationTag(bool isBind)
{
    if (isBind) {
        return "bind";
    } else {
        return "auth";
    }
}

static const char *GetIsClientTag(bool isClient)
{
    if (isClient) {
        return "true";
    } else {
        return "false";
    }
}

static void DumpPerformData(int fd, PerformData *performData)
{
    int64_t firstConsume = 0;
    if (performData->firstStartTime != 0) {
        firstConsume = GetConsumeTimeByIndex(performData, FIRST_START_TIME);
    }
    int64_t secondConsume = 0;
    if (performData->secondStartTime != 0) {
        secondConsume = GetConsumeTimeByIndex(performData, SECOND_START_TIME);
    }
    int64_t thirdConsume = 0;
    if (performData->thirdStartTime != 0) {
        thirdConsume = GetConsumeTimeByIndex(performData, THIRD_START_TIME);
    }
    int64_t fourthConsume = 0;
    if (performData->fourthStartTime != 0) {
        fourthConsume = GetConsumeTimeByIndex(performData, FOURTH_START_TIME);
    }
    int64_t innerConsume = firstConsume + secondConsume + thirdConsume + fourthConsume;
    int64_t totalTime = performData->onFinishTime - performData->firstStartTime;
    char reqIdStr[MAX_REQUEST_ID_LEN] = { 0 };
    if (sprintf_s(reqIdStr, MAX_REQUEST_ID_LEN, "%lld", performData->reqId) <= 0) {
        LOGE("Failed to get requestId string!");
        return;
    }
    performData->firstConsumeTime = firstConsume;
    performData->secondConsumeTime = secondConsume;
    performData->thirdConsumeTime = thirdConsume;
    performData->fourthConsumeTime = fourthConsume;
    performData->innerConsumeTime = innerConsume;
    performData->totalConsumeTime = totalTime;
    const char *operationTag = GetOperationTag(performData->isBind);
    const char *isClientTag = GetIsClientTag(performData->isClient);
    dprintf(fd, "|%-10s|%-9s|%-10.8s|%-6lld|%-7lld|%-6lld|%-7lld|%-10lld|%-9lld|\n", operationTag, isClientTag,
        reqIdStr, firstConsume, secondConsume, thirdConsume, fourthConsume, innerConsume, totalTime);
    dprintf(fd, "|----------------------------------------------------------------------------------|\n");
}

static const char *GetAverageTimeTag(bool isBind, bool isClient)
{
    if (isBind) {
        if (isClient) {
            return "bind client average";
        } else {
            return "bind server average";
        }
    } else {
        if (isClient) {
            return "auth client average";
        } else {
            return "auth server average";
        }
    }
}

static void DumpAverageConsumeTime(int fd, bool isBind, bool isClient)
{
    uint32_t sessionSize = 0;
    int64_t totalFirstConsume = 0;
    int64_t totalSecondConsume = 0;
    int64_t totalThirdConsume = 0;
    int64_t totalFourthConsume = 0;
    int64_t totalInnerConsume = 0;
    int64_t totalConsume = 0;
    uint32_t index;
    PerformData **peformData;
    FOR_EACH_HC_VECTOR(g_performDataVec, index, peformData) {
        if ((*peformData)->status != PERFORM_DATA_STATUS_FINISH) {
            continue;
        }
        if ((*peformData)->isBind == isBind && (*peformData)->isClient == isClient) {
            sessionSize++;
            totalFirstConsume += (*peformData)->firstConsumeTime;
            totalSecondConsume += (*peformData)->secondConsumeTime;
            totalThirdConsume += (*peformData)->thirdConsumeTime;
            totalFourthConsume += (*peformData)->fourthConsumeTime;
            totalInnerConsume += (*peformData)->innerConsumeTime;
            totalConsume += (*peformData)->totalConsumeTime;
        }
    }
    int64_t firstAverage = 0;
    int64_t secondAverage = 0;
    int64_t thirdAverage = 0;
    int64_t fourthAverage = 0;
    int64_t innerAverage = 0;
    int64_t totalAverage = 0;
    if (sessionSize != 0) {
        firstAverage = totalFirstConsume / sessionSize;
        secondAverage = totalSecondConsume / sessionSize;
        thirdAverage = totalThirdConsume / sessionSize;
        fourthAverage = totalFourthConsume / sessionSize;
        innerAverage = totalInnerConsume / sessionSize;
        totalAverage = totalConsume / sessionSize;
    }
    const char *averageTimeTag = GetAverageTimeTag(isBind, isClient);
    dprintf(fd, "|%-31s|%-6lld|%-7lld|%-6lld|%-7lld|%-10lld|%-9lld|\n", averageTimeTag, firstAverage,
        secondAverage, thirdAverage, fourthAverage, innerAverage, totalAverage);
}

static void DumpDevAuthPerformData(int fd)
{
    if (!g_isPerformDumpEnabled) {
        dprintf(fd, "performance dumper is not enabled, input the following command to enable it:\n"
            "hidumper -s 4701 -a \"performance --enable\"\n");
        return;
    }
    dprintf(fd, "|---------------------------------PerformanceData----------------------------------|\n");
    dprintf(fd, "|%-10s|%-9s|%-10s|%-6s|%-7s|%-6s|%-7s|%-10s|%-9s|\n", "operation", "isClient", "requestId", "first",
        "second", "third", "fourth", "innerTime", "totalTime");
    dprintf(fd, "|----------------------------------------------------------------------------------|\n");
    uint32_t index;
    PerformData **peformData;
    FOR_EACH_HC_VECTOR(g_performDataVec, index, peformData) {
        if ((*peformData)->status != PERFORM_DATA_STATUS_FINISH) {
            continue;
        }
        DumpPerformData(fd, *peformData);
    }
    DumpAverageConsumeTime(fd, true, true);
    dprintf(fd, "|----------------------------------------------------------------------------------|\n");
    DumpAverageConsumeTime(fd, true, false);
    dprintf(fd, "|----------------------------------------------------------------------------------|\n");
    DumpAverageConsumeTime(fd, false, true);
    dprintf(fd, "|----------------------------------------------------------------------------------|\n");
    DumpAverageConsumeTime(fd, false, false);
    dprintf(fd, "|---------------------------------PerformanceData----------------------------------|\n");
}

static void PerformanceDump(int fd, StringVector *strArgVec)
{
    if (!g_isInit) {
        LOGE("Not initialized!");
        return;
    }
    g_performDataMutex->lock(g_performDataMutex);
    uint32_t argSize = strArgVec->size(strArgVec);
    if (argSize == MIN_ARGS_NUM) {
        DumpDevAuthPerformData(fd);
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    if (argSize != MAX_ARGS_NUM) {
        dprintf(fd, "Invalid arguments number!\n");
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    HcString strArg = strArgVec->get(strArgVec, 1);
    if (strcmp(StringGet(&strArg), ENABLE_PERFORMANCE_DUMPER) == 0) {
        g_isPerformDumpEnabled = true;
        dprintf(fd, "performance dumper is enabled!\n");
    } else if (strcmp(StringGet(&strArg), DISABLE_PERFORMANCE_DUMPER) == 0) {
        ClearPerformDataVec();
        g_isPerformDumpEnabled = false;
        dprintf(fd, "performance dumper is disabled!\n");
    } else {
        dprintf(fd, "Invalid arguments!\n");
    }
    g_performDataMutex->unlock(g_performDataMutex);
}

static bool IsSessionNumExceeded(bool isBind, bool isClient)
{
    if (isBind) {
        if (isClient) {
            return g_bindClientSessionNum == MAX_DUMP_SESSION_NUM;
        } else {
            return g_bindServerSessionNum == MAX_DUMP_SESSION_NUM;
        }
    } else {
        if (isClient) {
            return g_authClientSessionNum == MAX_DUMP_SESSION_NUM;
        } else {
            return g_authServerSessionNum == MAX_DUMP_SESSION_NUM;
        }
    }
}

static void IncreaseSessionNum(PerformData *data)
{
    if (data->isBind) {
        if (data->isClient) {
            g_bindClientSessionNum++;
        } else {
            g_bindServerSessionNum++;
        }
    } else {
        if (data->isClient) {
            g_authClientSessionNum++;
        } else {
            g_authServerSessionNum++;
        }
    }
}

void AddPerformData(int64_t reqId, bool isBind, bool isClient, int64_t startTime)
{
    if (!g_isInit) {
        return;
    }
    g_performDataMutex->lock(g_performDataMutex);
    if (!g_isPerformDumpEnabled) {
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    RemovePerformDataIfExist(reqId);
    if (IsSessionNumExceeded(isBind, isClient)) {
        LOGE("session number exceeded, requestId: %lld", reqId);
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    PerformData *performData = CreatePerformData();
    if (performData == NULL) {
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    performData->reqId = reqId;
    performData->isBind = isBind;
    performData->isClient = isClient;
    performData->firstStartTime = startTime;
    performData->selfIndex = FIRST_START_TIME;
    performData->status = PERFORM_DATA_STATUS_BEGIN;
    if (g_performDataVec.pushBackT(&g_performDataVec, performData) == NULL) {
        LOGE("Failed to push perform data to vec!");
        DestroyPerformData(performData);
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    IncreaseSessionNum(performData);
    g_performDataMutex->unlock(g_performDataMutex);
}

void ResetPerformData(int64_t reqId)
{
    if (!g_isInit) {
        return;
    }
    g_performDataMutex->lock(g_performDataMutex);
    if (!g_isPerformDumpEnabled) {
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    uint32_t index;
    PerformData **performData;
    FOR_EACH_HC_VECTOR(g_performDataVec, index, performData) {
        if ((*performData)->reqId == reqId) {
            (*performData)->selfIndex = FIRST_START_TIME;
            (*performData)->status = PERFORM_DATA_STATUS_BEGIN;
            (*performData)->firstStartTime = HcGetCurTimeInMillis();
            (*performData)->firstTransmitTime = 0;
            (*performData)->secondStartTime = 0;
            (*performData)->secondTransmitTime = 0;
            (*performData)->thirdStartTime = 0;
            (*performData)->thirdTransmitTime = 0;
            (*performData)->fourthStartTime = 0;
            (*performData)->fourthTransmitTime = 0;
            (*performData)->onSessionKeyReturnTime = 0;
            (*performData)->onFinishTime = 0;
            (*performData)->firstConsumeTime = 0;
            (*performData)->secondConsumeTime = 0;
            (*performData)->thirdConsumeTime = 0;
            (*performData)->fourthConsumeTime = 0;
            (*performData)->innerConsumeTime = 0;
            (*performData)->totalConsumeTime = 0;
            g_performDataMutex->unlock(g_performDataMutex);
            return;
        }
    }
    g_performDataMutex->unlock(g_performDataMutex);
}

void UpdatePerformDataBySelfIndex(int64_t reqId, int64_t time)
{
    if (!g_isInit) {
        return;
    }
    g_performDataMutex->lock(g_performDataMutex);
    if (!g_isPerformDumpEnabled) {
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    uint32_t index;
    PerformData **performData;
    FOR_EACH_HC_VECTOR(g_performDataVec, index, performData) {
        if ((*performData)->reqId == reqId) {
            UpdateDataBySelfIndex(*performData, time);
            g_performDataMutex->unlock(g_performDataMutex);
            return;
        }
    }
    g_performDataMutex->unlock(g_performDataMutex);
}

void UpdatePerformDataByInputIndex(int64_t reqId, PerformTimeIndex timeIndex, int64_t time)
{
    if (!g_isInit) {
        return;
    }
    g_performDataMutex->lock(g_performDataMutex);
    if (!g_isPerformDumpEnabled) {
        g_performDataMutex->unlock(g_performDataMutex);
        return;
    }
    uint32_t index;
    PerformData **performData;
    FOR_EACH_HC_VECTOR(g_performDataVec, index, performData) {
        if ((*performData)->reqId == reqId) {
            UpdateDataByInputIndex(*performData, timeIndex, time);
            g_performDataMutex->unlock(g_performDataMutex);
            return;
        }
    }
    g_performDataMutex->unlock(g_performDataMutex);
}

void InitPerformanceDumper(void)
{
    if (g_isInit) {
        return;
    }
    if (g_performDataMutex == NULL) {
        g_performDataMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_performDataMutex == NULL) {
            LOGE("Alloc databaseMutex failed");
            return;
        }
        if (InitHcMutex(g_performDataMutex) != HC_SUCCESS) {
            LOGE("[DB]: Init mutex failed");
            HcFree(g_performDataMutex);
            g_performDataMutex = NULL;
            return;
        }
    }
    g_performDataMutex->lock(g_performDataMutex);
    g_performDataVec = CREATE_HC_VECTOR(PerformDataVec);
    g_performDataMutex->unlock(g_performDataMutex);
    DEV_AUTH_REG_PERFORM_DUMP_FUNC(PerformanceDump);
    g_isInit = true;
}

void DestroyPerformanceDumper(void)
{
    if (!g_isInit) {
        return;
    }
    g_isInit = false;
    g_performDataMutex->lock(g_performDataMutex);
    g_isPerformDumpEnabled = false;
    ClearPerformDataVec();
    DESTROY_HC_VECTOR(PerformDataVec, &g_performDataVec);
    g_performDataMutex->unlock(g_performDataMutex);
    DestroyHcMutex(g_performDataMutex);
    HcFree(g_performDataMutex);
    g_performDataMutex = NULL;
}