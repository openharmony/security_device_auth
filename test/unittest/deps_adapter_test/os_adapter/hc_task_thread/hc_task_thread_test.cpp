/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <unistd.h>
#include "hc_task_thread.h"
#include "hc_dev_info.h"

using namespace std;
using namespace testing::ext;
namespace {
static volatile int g_taskActionCount = 0;

static void TestTaskDoAction(HcTaskBase *task)
{
    g_taskActionCount++;
}

static void TestTaskDestroy(HcTaskBase *task)
{
}

static HcTaskBase *CreateTestTask()
{
    HcTaskBase *task = (HcTaskBase *)HcMalloc(sizeof(HcTaskBase), 0);
    if (task != NULL) {
        task->doAction = TestTaskDoAction;
        task->destroy = TestTaskDestroy;
    }
    return task;
}

class HcTaskThreadTest : public testing::Test {
public:
    void SetUp() override
    {
        g_taskActionCount = 0;
    }
};

HWTEST_F(HcTaskThreadTest, InitHcTaskThreadNullTest001, TestSize.Level0)
{
    int32_t res = InitHcTaskThread(NULL, 0, "test");
    EXPECT_EQ(res, -1);
}

HWTEST_F(HcTaskThreadTest, InitHcTaskThreadValidTest001, TestSize.Level0)
{
    HcTaskThread thread;
    int32_t res = InitHcTaskThread(&thread, 0, "taskThread");
    EXPECT_EQ(res, 0);
    DestroyHcTaskThread(&thread);
}

HWTEST_F(HcTaskThreadTest, PushAndExecuteTaskTest001, TestSize.Level0)
{
    HcTaskThread thread;
    int32_t res = InitHcTaskThread(&thread, 0, "pushTaskThread");
    EXPECT_EQ(res, 0);

    res = thread.startThread(&thread);
    EXPECT_EQ(res, 0);

    HcTaskBase *task = CreateTestTask();
    EXPECT_NE(task, nullptr);
    thread.pushTask(&thread, task);

    usleep(100000);
    EXPECT_EQ(g_taskActionCount, 1);

    thread.stopAndClear(&thread);
    DestroyHcTaskThread(&thread);
}

HWTEST_F(HcTaskThreadTest, PushNullTaskTest001, TestSize.Level0)
{
    HcTaskThread thread;
    int32_t res = InitHcTaskThread(&thread, 0, "nullTaskThread");
    EXPECT_EQ(res, 0);

    thread.pushTask(&thread, NULL);
    thread.pushTask(NULL, CreateTestTask());

    DestroyHcTaskThread(&thread);
}

HWTEST_F(HcTaskThreadTest, ClearTest001, TestSize.Level0)
{
    HcTaskThread thread;
    int32_t res = InitHcTaskThread(&thread, 0, "clearThread");
    EXPECT_EQ(res, 0);

    HcTaskBase *task1 = CreateTestTask();
    HcTaskBase *task2 = CreateTestTask();
    thread.pushTask(&thread, task1);
    thread.pushTask(&thread, task2);

    thread.clear(&thread);
    DestroyHcTaskThread(&thread);
}

HWTEST_F(HcTaskThreadTest, StopAndClearNullTest001, TestSize.Level0)
{
    HcTaskThread thread;
    int32_t res = InitHcTaskThread(&thread, 0, "stopNullThread");
    EXPECT_EQ(res, 0);

    DestroyHcTaskThread(&thread);
}
}
