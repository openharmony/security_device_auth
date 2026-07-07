/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <unistd.h>
#include "hc_thread.h"
#include "hc_dev_info.h"

using namespace std;
using namespace testing::ext;
namespace {
static int g_threadRunCount = 0;
static const int32_t TEST_WAIT_TIME_US = 50000;

static int TestThreadFunc(void *args)
{
    g_threadRunCount++;
    return 0;
}

static int TestThreadFuncForNotify(void *args)
{
    HcThread *thread = static_cast<HcThread *>(args);
    usleep(TEST_WAIT_TIME_US);
    thread->notify(thread);
    return 0;
}

class HcThreadTest : public testing::Test {
public:
    void SetUp() override
    {
        g_threadRunCount = 0;
    }
};

HWTEST_F(HcThreadTest, InitThreadNullTest001, TestSize.Level0)
{
    int32_t res = InitThread(NULL, TestThreadFunc, 0, "test");
    EXPECT_EQ(res, -1);
}

HWTEST_F(HcThreadTest, InitThreadValidTest001, TestSize.Level0)
{
    HcThread thread;
    int32_t res = InitThread(&thread, TestThreadFunc, 0, "testThread");
    EXPECT_EQ(res, 0);
    DestroyThread(&thread);
}

HWTEST_F(HcThreadTest, InitThreadWithStackSizeTest001, TestSize.Level0)
{
    HcThread thread;
    int32_t res = InitThread(&thread, TestThreadFunc, 8192, "stackThread");
    EXPECT_EQ(res, 0);
    DestroyThread(&thread);
}

HWTEST_F(HcThreadTest, DestroyThreadNullTest001, TestSize.Level0)
{
    DestroyThread(NULL);
}

HWTEST_F(HcThreadTest, StartAndJoinTest001, TestSize.Level0)
{
    HcThread thread;
    int32_t res = InitThread(&thread, TestThreadFunc, 0, "startJoinThread");
    EXPECT_EQ(res, 0);

    res = thread.start(&thread);
    EXPECT_EQ(res, 0);

    thread.join(&thread);
    EXPECT_EQ(g_threadRunCount, 1);
    DestroyThread(&thread);
}

HWTEST_F(HcThreadTest, StartAlreadyRunningTest001, TestSize.Level0)
{
    HcThread thread;
    int32_t res = InitThread(&thread, TestThreadFunc, 0, "runningThread");
    EXPECT_EQ(res, 0);

    res = thread.start(&thread);
    EXPECT_EQ(res, 0);

    int res2 = thread.start(&thread);
    EXPECT_EQ(res2, 0);

    thread.join(&thread);
    EXPECT_EQ(g_threadRunCount, 1);
    DestroyThread(&thread);
}

HWTEST_F(HcThreadTest, BizNotifyAndWaitTest001, TestSize.Level0)
{
    HcThread thread;
    int32_t res = InitThread(&thread, TestThreadFuncForNotify, 0, "bizNotifyThread");
    EXPECT_EQ(res, 0);

    res = thread.start(&thread);
    EXPECT_EQ(res, 0);

    thread.wait(&thread);
    thread.join(&thread);
    DestroyThread(&thread);
}
}
