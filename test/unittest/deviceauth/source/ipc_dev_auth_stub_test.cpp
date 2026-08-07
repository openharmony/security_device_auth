/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "ipc_dev_auth_stub.h"
#include "ipc_callback_stub.h"
#include "ipc_adapt.h"
#include "ipc_sdk_defines.h"
#include "device_auth_defines.h"
#include "dev_auth_ipc_interface_code.h"
#include "hc_log.h"

using namespace testing::ext;
using namespace OHOS;

namespace {
static int32_t g_testServiceCallResult = HC_SUCCESS;
static int32_t g_testServiceCallCount = 0;

static int32_t TestServiceCall(const IpcDataInfo *params, int32_t paramNum, uintptr_t reply)
{
    (void)params;
    (void)paramNum;
    (void)reply;
    g_testServiceCallCount++;
    return g_testServiceCallResult;
}

static sptr<IRemoteObject> CreateTestRemoteObject()
{
    sptr<StubDevAuthCb> stubCb = new(std::nothrow) StubDevAuthCb();
    if (stubCb == nullptr) {
        return nullptr;
    }
    return stubCb->AsObject();
}
}

class IpcDevAuthStubTest : public testing::Test {
public:
    IpcDevAuthStubTest() = default;
    ~IpcDevAuthStubTest() override = default;
    void SetUp() override;
    void TearDown() override;
    static void SetUpTestCase();
    static void TearDownTestCase();
    static ServiceDevAuth *service_;
};

ServiceDevAuth *IpcDevAuthStubTest::service_ = nullptr;

void IpcDevAuthStubTest::SetUpTestCase()
{
    service_ = new(std::nothrow) ServiceDevAuth();
    ASSERT_NE(service_, nullptr);
}

void IpcDevAuthStubTest::TearDownTestCase()
{
    if (service_ != nullptr) {
        delete service_;
        service_ = nullptr;
    }
}

void IpcDevAuthStubTest::SetUp()
{
    g_testServiceCallResult = HC_SUCCESS;
    g_testServiceCallCount = 0;
}

void IpcDevAuthStubTest::TearDown() {}

HWTEST_F(IpcDevAuthStubTest, SetCallMap_Success, TestSize.Level0)
{
    int32_t ret = service_->SetCallMap(TestServiceCall, IPC_CALL_ID_REG_CB);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(IpcDevAuthStubTest, SetCallMap_MultipleCalls, TestSize.Level0)
{
    int32_t ret = service_->SetCallMap(TestServiceCall, IPC_CALL_ID_REG_CB);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = service_->SetCallMap(TestServiceCall, IPC_CALL_ID_UNREG_CB);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = service_->SetCallMap(TestServiceCall, IPC_CALL_ID_REG_LISTENER);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(IpcDevAuthStubTest, SetCallMap_NullMethod, TestSize.Level0)
{
    int32_t ret = service_->SetCallMap(nullptr, IPC_CALL_ID_DEL_GROUP);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(IpcDevAuthStubTest, SetCallMap_ExpandTable, TestSize.Level0)
{
    ServiceDevAuth tempService;
    for (int32_t i = 0; i < MAX_CALLMAP_SIZE + 1; i++) {
        int32_t ret = tempService.SetCallMap(TestServiceCall, i + 1);
        EXPECT_EQ(ret, HC_SUCCESS);
    }
}

HWTEST_F(IpcDevAuthStubTest, SetRemoteObject_ResetRemoteObject, TestSize.Level0)
{
    sptr<IRemoteObject> obj = CreateTestRemoteObject();
    if (obj == nullptr) {
        return;
    }
    int32_t idx = ServiceDevAuth::SetRemoteObject(obj);
    EXPECT_GE(idx, 0);
    ServiceDevAuth::ResetRemoteObject(idx);
}

HWTEST_F(IpcDevAuthStubTest, SetRemoteObject_MultipleObjects, TestSize.Level0)
{
    sptr<IRemoteObject> obj1 = CreateTestRemoteObject();
    sptr<IRemoteObject> obj2 = CreateTestRemoteObject();
    if (obj1 == nullptr || obj2 == nullptr) {
        return;
    }
    int32_t idx1 = ServiceDevAuth::SetRemoteObject(obj1);
    int32_t idx2 = ServiceDevAuth::SetRemoteObject(obj2);
    EXPECT_GE(idx1, 0);
    EXPECT_GE(idx2, 0);
    EXPECT_NE(idx1, idx2);
    ServiceDevAuth::ResetRemoteObject(idx1);
    ServiceDevAuth::ResetRemoteObject(idx2);
}

HWTEST_F(IpcDevAuthStubTest, ResetRemoteObject_InvalidIdx, TestSize.Level0)
{
    ServiceDevAuth::ResetRemoteObject(-1);
    ServiceDevAuth::ResetRemoteObject(MAX_CBSTUB_SIZE);
}

HWTEST_F(IpcDevAuthStubTest, ResetRemoteObject_ReuseSlot, TestSize.Level0)
{
    sptr<IRemoteObject> obj = CreateTestRemoteObject();
    if (obj == nullptr) {
        return;
    }
    int32_t idx1 = ServiceDevAuth::SetRemoteObject(obj);
    EXPECT_GE(idx1, 0);
    ServiceDevAuth::ResetRemoteObject(idx1);
    int32_t idx2 = ServiceDevAuth::SetRemoteObject(obj);
    EXPECT_GE(idx2, 0);
    EXPECT_EQ(idx1, idx2);
    ServiceDevAuth::ResetRemoteObject(idx2);
}

HWTEST_F(IpcDevAuthStubTest, AddCbDeathRecipient_InvalidIdx, TestSize.Level0)
{
    ServiceDevAuth::AddCbDeathRecipient(-1, 0);
    ServiceDevAuth::AddCbDeathRecipient(MAX_CBSTUB_SIZE, 0);
}

HWTEST_F(IpcDevAuthStubTest, AddCbDeathRecipient_NotInUse, TestSize.Level0)
{
    ServiceDevAuth::AddCbDeathRecipient(0, 0);
}

HWTEST_F(IpcDevAuthStubTest, AddCbDeathRecipient_WithValidObject, TestSize.Level0)
{
    sptr<IRemoteObject> obj = CreateTestRemoteObject();
    if (obj == nullptr) {
        return;
    }
    int32_t idx = ServiceDevAuth::SetRemoteObject(obj);
    EXPECT_GE(idx, 0);
    ServiceDevAuth::AddCbDeathRecipient(idx, 0);
    ServiceDevAuth::ResetRemoteObject(idx);
}

HWTEST_F(IpcDevAuthStubTest, ActCallback_InvalidIdx, TestSize.Level0)
{
    MessageParcel dataParcel;
    MessageParcel reply;
    ServiceDevAuth::ActCallback(-1, CB_ID_ON_TRANS, true, dataParcel, reply);
    ServiceDevAuth::ActCallback(MAX_CBSTUB_SIZE, CB_ID_ON_TRANS, true, dataParcel, reply);
}

HWTEST_F(IpcDevAuthStubTest, ActCallback_NotInUse, TestSize.Level0)
{
    MessageParcel dataParcel;
    MessageParcel reply;
    ServiceDevAuth::ActCallback(0, CB_ID_ON_TRANS, true, dataParcel, reply);
}

HWTEST_F(IpcDevAuthStubTest, Dump_EmptyArgs, TestSize.Level0)
{
    std::vector<std::u16string> args;
    int32_t ret = service_->Dump(0, args);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(IpcDevAuthStubTest, Dump_WithArgs, TestSize.Level0)
{
    std::vector<std::u16string> args;
    args.push_back(Str8ToStr16("performance"));
    args.push_back(Str8ToStr16("--enable"));
    int32_t ret = service_->Dump(0, args);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(IpcDevAuthStubTest, Dump_WithDisableArgs, TestSize.Level0)
{
    std::vector<std::u16string> args;
    args.push_back(Str8ToStr16("performance"));
    args.push_back(Str8ToStr16("--disable"));
    int32_t ret = service_->Dump(0, args);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(IpcDevAuthStubTest, DevAuthDeathRecipient_Constructor, TestSize.Level0)
{
    DevAuthDeathRecipient recipient(5);
}

HWTEST_F(IpcDevAuthStubTest, SetRemoteObject_FullTable, TestSize.Level0)
{
    std::vector<int32_t> indices;
    for (int32_t i = 0; i < MAX_CBSTUB_SIZE; i++) {
        sptr<IRemoteObject> obj = CreateTestRemoteObject();
        if (obj == nullptr) {
            break;
        }
        int32_t idx = ServiceDevAuth::SetRemoteObject(obj);
        if (idx >= 0) {
            indices.push_back(idx);
        }
    }
    sptr<IRemoteObject> extraObj = CreateTestRemoteObject();
    if (extraObj != nullptr) {
        int32_t extraIdx = ServiceDevAuth::SetRemoteObject(extraObj);
        EXPECT_EQ(extraIdx, -1);
    }
    for (int32_t idx : indices) {
        ServiceDevAuth::ResetRemoteObject(idx);
    }
}

HWTEST_F(IpcDevAuthStubTest, Destructor_NoCallMap, TestSize.Level0)
{
    ServiceDevAuth *tempService = new(std::nothrow) ServiceDevAuth();
    ASSERT_NE(tempService, nullptr);
    delete tempService;
    tempService = nullptr;
}

HWTEST_F(IpcDevAuthStubTest, OnRemoteRequest_InvalidToken, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"invalid.token");
    int32_t ret = service_->OnRemoteRequest(
        static_cast<uint32_t>(DevAuthInterfaceCode::DEV_AUTH_CALL_REQUEST), data, reply, option);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(IpcDevAuthStubTest, OnRemoteRequest_RestoreCall, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Updater.RestoreData");
    int32_t ret = service_->OnRemoteRequest(14701, data, reply, option);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(IpcDevAuthStubTest, HandleDeviceAuthCall_NoMethodIdData, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"deviceauth.IMethodsIpcCall");
    int32_t ret = service_->OnRemoteRequest(
        static_cast<uint32_t>(DevAuthInterfaceCode::DEV_AUTH_CALL_REQUEST), data, reply, option);
    EXPECT_NE(ret, 0);
}

HWTEST_F(IpcDevAuthStubTest, HandleDeviceAuthCall_CheckPermissionFail, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"deviceauth.IMethodsIpcCall");
    data.WriteInt32(IPC_CALL_ID_REG_CB);
    int32_t ret = service_->OnRemoteRequest(
        static_cast<uint32_t>(DevAuthInterfaceCode::DEV_AUTH_CALL_REQUEST), data, reply, option);
    EXPECT_NE(ret, 0);
}

HWTEST_F(IpcDevAuthStubTest, HandleDeviceAuthCall_DefaultCode, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"deviceauth.IMethodsIpcCall");
    int32_t ret = service_->OnRemoteRequest(99999, data, reply, option);
    EXPECT_NE(ret, 0);
}
