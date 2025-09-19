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

#include <gtest/gtest.h>
#include <unistd.h>
#include "base/security/device_auth/services/frameworks/src/account_subscriber/account_subscriber.cpp"

using namespace std;
using namespace testing::ext;

namespace {
class AccountSubscriberTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountSubscriberTest::SetUpTestCase() {}
void AccountSubscriberTest::TearDownTestCase() {}

void AccountSubscriberTest::SetUp() {}

void AccountSubscriberTest::TearDown() {}

HWTEST_F(AccountSubscriberTest, AddOsAccountIdInEventDataTest001, TestSize.Level0)
{
    OHOS::AAFwk::Want want;
    std::string action = "usual.event.USER_UNLOCKED";
    want.SetAction(action);
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    int32_t osAccountId = 100;
    eventData.SetCode(osAccountId);
    int32_t res = OHOS::DevAuth::AddOsAccountIdInEventData(eventData, nullptr);
    EXPECT_EQ(res, HC_ERR_JSON_ADD);
    CJson *out = CreateJson();
    res = OHOS::DevAuth::AddOsAccountIdInEventData(eventData, out);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(out);
}

HWTEST_F(AccountSubscriberTest, AddOsAccountIdInEventDataTest002, TestSize.Level0)
{
    OHOS::AAFwk::Want want;
    std::string action = "common.event.DISTRIBUTED_ACCOUNT_LOGIN";
    want.SetAction(action);
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    CJson *out = CreateJson();
    int32_t res = OHOS::DevAuth::AddOsAccountIdInEventData(eventData, out);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(out);
}

HWTEST_F(AccountSubscriberTest, AddOsAccountIdInEventDataTest003, TestSize.Level0)
{
    OHOS::AAFwk::Want want;
    std::string action = "common.event.DISTRIBUTED_ACCOUNT_LOGOUT";
    want.SetAction(action);
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    CJson *out = CreateJson();
    int32_t res = OHOS::DevAuth::AddOsAccountIdInEventData(eventData, out);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(out);
}

HWTEST_F(AccountSubscriberTest, AddOsAccountIdInEventDataTest004, TestSize.Level0)
{
    OHOS::AAFwk::Want want;
    std::string action = "common.event.USER_REMOVED";
    want.SetAction(action);
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    int32_t osAccountId = 100;
    eventData.SetCode(osAccountId);
    CJson *out = CreateJson();
    int32_t res = OHOS::DevAuth::AddOsAccountIdInEventData(eventData, out);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(out);
}

HWTEST_F(AccountSubscriberTest, AddOsAccountIdInEventDataTest005, TestSize.Level0)
{
    OHOS::AAFwk::Want want;
    std::string action = "usual.event.USER_SWITCHED";
    want.SetAction(action);
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    int32_t osAccountId = 100;
    eventData.SetCode(osAccountId);
    CJson *out = CreateJson();
    int32_t res = OHOS::DevAuth::AddOsAccountIdInEventData(eventData, out);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(out);
}

HWTEST_F(AccountSubscriberTest, AddOsAccountIdInEventDataTest006, TestSize.Level0)
{
    OHOS::AAFwk::Want want;
    std::string action = "usual.event.bluetooth.host.STATE_UPDATE";
    want.SetAction(action);
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    CJson *out = CreateJson();
    int32_t res = OHOS::DevAuth::AddOsAccountIdInEventData(eventData, out);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(out);
}
}