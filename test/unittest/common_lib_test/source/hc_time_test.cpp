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
 * limitations under theater License.
 */

#include <gtest/gtest.h>
#include "hc_time.h"
#include <unistd.h>

using namespace testing::ext;

namespace {
static const int64_t TEST_SLEEP_TIME_MS = 100;
static const int64_t TEST_SLEEP_TIME_SEC = 1;
}

class HcTimeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HcTimeTest::SetUpTestCase() {}
void HcTimeTest::TearDownTestCase() {}
void HcTimeTest::SetUp() {}
void HcTimeTest::TearDown() {}

HWTEST_F(HcTimeTest, HcGetCurTimeTest001, TestSize.Level0)
{
    int64_t time1 = HcGetCurTime();
    EXPECT_GT(time1, 0);
    
    usleep(TEST_SLEEP_TIME_MS * 1000);
    
    int64_t time2 = HcGetCurTime();
    EXPECT_GT(time2, 0);
    EXPECT_GE(time2, time1);
}

HWTEST_F(HcTimeTest, HcGetCurTimeInMillisTest001, TestSize.Level0)
{
    int64_t time1 = HcGetCurTimeInMillis();
    EXPECT_GT(time1, 0);
    
    usleep(TEST_SLEEP_TIME_MS * 1000);
    
    int64_t time2 = HcGetCurTimeInMillis();
    EXPECT_GT(time2, 0);
    EXPECT_GE(time2, time1);
    EXPECT_GE(time2 - time1, TEST_SLEEP_TIME_MS);
}

HWTEST_F(HcTimeTest, HcGetIntervalTimeTest001, TestSize.Level0)
{
    int64_t startTime = HcGetCurTime();
    EXPECT_GT(startTime, 0);
    
    sleep(TEST_SLEEP_TIME_SEC);
    
    int64_t interval = HcGetIntervalTime(startTime);
    EXPECT_GE(interval, TEST_SLEEP_TIME_SEC);
}

HWTEST_F(HcTimeTest, HcGetIntervalTimeTest002, TestSize.Level0)
{
    int64_t invalidTime = -1;
    int64_t interval = HcGetIntervalTime(invalidTime);
    EXPECT_EQ(interval, -1);
}

HWTEST_F(HcTimeTest, HcGetIntervalTimeTest003, TestSize.Level0)
{
    int64_t startTime = HcGetCurTime();
    
    int64_t interval = HcGetIntervalTime(startTime);
    EXPECT_GE(interval, 0);
}

HWTEST_F(HcTimeTest, HcGetRealTimeTest001, TestSize.Level0)
{
    int64_t time1 = HcGetRealTime();
    EXPECT_GT(time1, 0);
    
    sleep(TEST_SLEEP_TIME_SEC);
    
    int64_t time2 = HcGetRealTime();
    EXPECT_GT(time2, 0);
    EXPECT_GE(time2, time1);
}

HWTEST_F(HcTimeTest, HcGetRealTimeTest002, TestSize.Level0)
{
    int64_t time1 = HcGetRealTime();
    int64_t time2 = HcGetRealTime();
    
    EXPECT_GE(time2, time1);
    EXPECT_LE(time2 - time1, 1);
}
