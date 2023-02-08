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

#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>
#include "../../../../../services/group_manager/src/session/bind_session/bind_session_client.c"

#ifdef __cpluscplus
extern "C"
{
#endif

#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "json_utils.h"

#ifdef __cpluscplus
}
#endif

using namespace std;
using namespace testing::ext;

namespace {
class BindSessionClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BindSessionClientTest::SetUpTestCase() {}

void BindSessionClientTest::TearDownTestCase() {}

void BindSessionClientTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void BindSessionClientTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(BindSessionClientTest, BindSessionClientTest0100, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *in = CreateJson();
    do {
        if (in == nullptr) {
            break;
        }
        (void)DoubleCheckChannelId(1, 2); // 1 2 is wrong number for unit test.

        (void)OnBindChannelOpened(nullptr, 0, 0); // 0 is channel id for unit test.

        (void)CreateClientBindSession(nullptr, nullptr);

        if (AddIntToJson(in, FIELD_OPERATION_CODE, 100) != HC_SUCCESS) {// 100 is wrong number for unit test.
            break;
        }
        (void)CreateClientBindSession(in, nullptr);
    } while (0);
    FreeJson(in);
    EXPECT_EQ(ret, HC_SUCCESS);
}
}