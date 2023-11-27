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

#include <gtest/gtest.h>
#include "device_auth_defines.h"
#include "hc_time.h"
#include "hidump_adapter.h"
#include "performance_dumper.h"

using namespace std;
using namespace testing::ext;

namespace {
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

class PerformDumperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PerformDumperTest::SetUpTestCase() {}
void PerformDumperTest::TearDownTestCase() {}

void PerformDumperTest::SetUp() {}

void PerformDumperTest::TearDown() {}

HWTEST_F(PerformDumperTest, PerformDumperTest001, TestSize.Level0)
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
    ADD_PERFORM_DATA(TEST_REQ_ID, true, true, curTimeInMillis);
    ADD_PERFORM_DATA(TEST_REQ_ID, true, true, curTimeInMillis); // remove existed request
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
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(TEST_REQ_ID, FIRST_START_TIME, curTimeInMillis + 10);
    ADD_PERFORM_DATA(TEST_REQ_ID1, true, false, curTimeInMillis);
    ADD_PERFORM_DATA(TEST_REQ_ID1, true, false, curTimeInMillis); // remove existed request
    ADD_PERFORM_DATA(TEST_REQ_ID2, false, true, curTimeInMillis);
    ADD_PERFORM_DATA(TEST_REQ_ID2, false, true, curTimeInMillis); // remove existed request
    ADD_PERFORM_DATA(TEST_REQ_ID3, false, false, curTimeInMillis);
    ADD_PERFORM_DATA(TEST_REQ_ID3, false, false, curTimeInMillis); // remove existed request
    DumpPerformData();
    RESET_PERFORM_DATA(TEST_REQ_ID);
    DisablePerformDumper();

    DESTROY_PERFORMANCE_DUMPER();
    DESTROY_PERFORMANCE_DUMPER(); // has been deinitialized
    int32_t res = HC_SUCCESS;
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(PerformDumperTest, PerformDumperTest002, TestSize.Level0)
{
    INIT_PERFORMANCE_DUMPER();
    EnablePerformDumper();

    int64_t curTimeInMillis = HcGetCurTimeInMillis();
    for (uint32_t i = 0; i <= MAX_SESSION_NUM; i++) {
        ADD_PERFORM_DATA(i, true, true, curTimeInMillis + i);
    }

    for (uint32_t i = MAX_SESSION_NUM; i <= MAX_SESSION_NUM * 2; i++) {
        ADD_PERFORM_DATA(i, true, false, curTimeInMillis + i);
    }

    for (uint32_t i = MAX_SESSION_NUM * 2; i <= MAX_SESSION_NUM * 3; i++) {
        ADD_PERFORM_DATA(i, false, true, curTimeInMillis + i);
    }

    for (uint32_t i = MAX_SESSION_NUM * 3; i <= MAX_SESSION_NUM * 4; i++) {
        ADD_PERFORM_DATA(i, false, false, curTimeInMillis + i);
    }

    DumpPerformData();

    DisablePerformDumper();
    DESTROY_PERFORMANCE_DUMPER();
    int32_t res = HC_SUCCESS;
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(PerformDumperTest, PerformDumperTest003, TestSize.Level0)
{
    INIT_PERFORMANCE_DUMPER();
    EnablePerformDumper();

    TestAddUpdatePerformData(TEST_REQ_ID, true, false);
    TestAddUpdatePerformData(TEST_REQ_ID1, false, true);
    TestAddUpdatePerformData(TEST_REQ_ID2, false, false);

    DumpPerformData();

    DisablePerformDumper();
    DESTROY_PERFORMANCE_DUMPER();
    int32_t res = HC_SUCCESS;
    ASSERT_EQ(res, HC_SUCCESS);
}
}