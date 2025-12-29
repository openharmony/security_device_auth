/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hiviewadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "device_auth_defines.h"
#include "hc_time.h"
#include "hidump_adapter.h"
#include "performance_dumper.h"

namespace OHOS {
#define TEST_REQ_ID 123
#define TEST_REQ_ID1 124
#define TEST_REQ_ID2 125
#define TEST_REQ_ID3 126
#define TEST_TIME_INTERVAL1 1
#define TEST_TIME_INTERVAL2 2
#define TEST_TIME_INTERVAL3 3
#define TEST_TIME_INTERVAL4 4
#define TEST_TIME_INTERVAL5 5
#define TEST_TIME_INTERVAL6 6
#define TEST_TIME_INTERVAL7 7
#define TEST_TIME_INTERVAL8 8
#define TEST_TIME_INTERVAL9 9
#define TEST_TIME_INTERVAL10 10
#define MAX_SESSION_NUM 10
#define COUNT_TWO_NUM 2
#define COUNT_THREE_NUM 3
#define COUNT_FOUR_NUM 4
#define ENABLE_PERFORMANCE_DUMPER "--enable"
#define DISABLE_PERFORMANCE_DUMPER "--disable"
#define INVALID_DUMPER_ARG "--test"

static void EnablePerformDumper(void)
{
    StringVector strArgVec = CreateStrVector();
    HcString strArg1 = CreateString();
    (void)StringSetPointer(&strArg1, PERFORM_DUMP_ARG);
    (void)strArgVec.pushBackT(&strArgVec, strArg1);
    HcString strArg2 = CreateString();
    (void)StringSetPointer(&strArg2, ENABLE_PERFORMANCE_DUMPER);
    (void)strArgVec.pushBackT(&strArgVec, strArg2);
    DEV_AUTH_DUMP(0, &strArgVec);
    DestroyStrVector(&strArgVec);
}

static void DumpByInvalidArg(void)
{
    StringVector strArgVec = CreateStrVector();
    HcString strArg1 = CreateString();
    (void)StringSetPointer(&strArg1, PERFORM_DUMP_ARG);
    (void)strArgVec.pushBackT(&strArgVec, strArg1);
    HcString strArg2 = CreateString();
    (void)StringSetPointer(&strArg2, INVALID_DUMPER_ARG);
    (void)strArgVec.pushBackT(&strArgVec, strArg2);
    DEV_AUTH_DUMP(0, &strArgVec);
    DestroyStrVector(&strArgVec);
}

static void DumpByInvalidArgNum(void)
{
    StringVector strArgVec = CreateStrVector();
    HcString strArg1 = CreateString();
    (void)StringSetPointer(&strArg1, PERFORM_DUMP_ARG);
    (void)strArgVec.pushBackT(&strArgVec, strArg1);
    HcString strArg2 = CreateString();
    (void)StringSetPointer(&strArg2, ENABLE_PERFORMANCE_DUMPER);
    (void)strArgVec.pushBackT(&strArgVec, strArg2);
    HcString strArg3 = CreateString();
    (void)StringSetPointer(&strArg3, ENABLE_PERFORMANCE_DUMPER);
    (void)strArgVec.pushBackT(&strArgVec, strArg3);
    DEV_AUTH_DUMP(0, &strArgVec);
    DestroyStrVector(&strArgVec);
}

static void DisablePerformDumper(void)
{
    StringVector strArgVec = CreateStrVector();
    HcString strArg1 = CreateString();
    (void)StringSetPointer(&strArg1, PERFORM_DUMP_ARG);
    (void)strArgVec.pushBackT(&strArgVec, strArg1);
    HcString strArg2 = CreateString();
    (void)StringSetPointer(&strArg2, DISABLE_PERFORMANCE_DUMPER);
    (void)strArgVec.pushBackT(&strArgVec, strArg2);
    DEV_AUTH_DUMP(0, &strArgVec);
    DestroyStrVector(&strArgVec);
}

static void DumpPerformData(void)
{
    StringVector strArgVec = CreateStrVector();
    HcString strArg = CreateString();
    (void)StringSetPointer(&strArg, PERFORM_DUMP_ARG);
    (void)strArgVec.pushBackT(&strArgVec, strArg);
    DEV_AUTH_DUMP(0, &strArgVec);
    DestroyStrVector(&strArgVec);
}

static void TestAddUpdatePerformData(int64_t reqId, bool isBind, bool isClient)
{
    int64_t curTimeInMillis = HcGetCurTimeInMillis();
    ADD_PERFORM_DATA(reqId, isBind, isClient, curTimeInMillis);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, curTimeInMillis + TEST_TIME_INTERVAL1);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, curTimeInMillis + TEST_TIME_INTERVAL2);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, curTimeInMillis + TEST_TIME_INTERVAL3);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, curTimeInMillis + TEST_TIME_INTERVAL4);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, curTimeInMillis + TEST_TIME_INTERVAL5);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, curTimeInMillis + TEST_TIME_INTERVAL6);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(reqId, curTimeInMillis + TEST_TIME_INTERVAL7);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(reqId, ON_SESSION_KEY_RETURN_TIME, curTimeInMillis + TEST_TIME_INTERVAL8);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(reqId, ON_FINISH_TIME, curTimeInMillis + TEST_TIME_INTERVAL9);
}

static void HiviewAdapterTest01(void)
{
    // has not been initialized
    int64_t curTimeInMillis = HcGetCurTimeInMillis();
    ADD_PERFORM_DATA(TEST_REQ_ID, true, true, curTimeInMillis);
    RESET_PERFORM_DATA(TEST_REQ_ID);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(TEST_REQ_ID, ON_SESSION_KEY_RETURN_TIME, curTimeInMillis);

    INIT_PERFORMANCE_DUMPER();
    INIT_PERFORMANCE_DUMPER(); // has been initialized

    // dump by invalid args
    DumpByInvalidArg();
    DumpByInvalidArgNum();

    // dump not enabled
    DumpPerformData();
    ADD_PERFORM_DATA(TEST_REQ_ID, true, true, curTimeInMillis);
    RESET_PERFORM_DATA(TEST_REQ_ID);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(TEST_REQ_ID, ON_SESSION_KEY_RETURN_TIME, curTimeInMillis);

    EnablePerformDumper();
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis + TEST_TIME_INTERVAL1);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis + TEST_TIME_INTERVAL2);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis + TEST_TIME_INTERVAL3);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis + TEST_TIME_INTERVAL4);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis + TEST_TIME_INTERVAL5);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis + TEST_TIME_INTERVAL6);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis + TEST_TIME_INTERVAL7);
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(TEST_REQ_ID, curTimeInMillis + TEST_TIME_INTERVAL8);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(TEST_REQ_ID, ON_SESSION_KEY_RETURN_TIME, curTimeInMillis + TEST_TIME_INTERVAL9);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(TEST_REQ_ID, ON_FINISH_TIME, curTimeInMillis + TEST_TIME_INTERVAL10);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(TEST_REQ_ID, FIRST_START_TIME, curTimeInMillis + TEST_TIME_INTERVAL10);
    DumpPerformData();
    RESET_PERFORM_DATA(TEST_REQ_ID);
    DisablePerformDumper();

    DESTROY_PERFORMANCE_DUMPER();
    DESTROY_PERFORMANCE_DUMPER(); // has been deinitialized
}

static void HiviewAdapterTest02(void)
{
    INIT_PERFORMANCE_DUMPER();
    EnablePerformDumper();

    DumpPerformData();

    DisablePerformDumper();
    DESTROY_PERFORMANCE_DUMPER();
}

static void HiviewAdapterTest03(void)
{
    INIT_PERFORMANCE_DUMPER();
    EnablePerformDumper();

    TestAddUpdatePerformData(TEST_REQ_ID, true, false);
    TestAddUpdatePerformData(TEST_REQ_ID1, false, true);
    TestAddUpdatePerformData(TEST_REQ_ID2, false, false);

    DumpPerformData();

    DisablePerformDumper();
    DESTROY_PERFORMANCE_DUMPER();
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)HiviewAdapterTest01();
    (void)HiviewAdapterTest02();
    (void)HiviewAdapterTest03();
    DestroyPerformanceDumper();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoCallback(data, size);
    return 0;
}

