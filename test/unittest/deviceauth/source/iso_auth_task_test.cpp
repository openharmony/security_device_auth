/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "iso_auth_client_task.h"
#include "iso_auth_server_task.h"
#include "iso_auth_task_common.h"
#include "json_utils.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {
static const std::string TEST_USER_ID = "1234ABCD";
static const std::string TEST_AUTH_ID = "TestAuthId";
static const std::string TEST_DEV_ID_EXCEED =
    "37364761534f454d33567a73424e794f33573330507069434b31676f7254706069434b3";
static const std::string TEST_UDID = "TestUdid";
static const std::string TEST_SESSION_KEY = "2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335";
static const std::string TEST_SEED = "2f7562744654535564586e665467546b322b4b506b65626373466f48766a4335";
static const std::string TEST_SALT = "2f7562744654535564586e665467546b";
static const std::string TEST_AUTH_CODE = "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b";
static const std::string TEST_PAYLOAD = "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b";
static const std::string TEST_DEV_ID = "abcabcdefa";
static const std::string TEST_AUTH_RESULT_MAC = "37364761534f454d33567a73424e794f33573330507069434b31676f7254706b";

static const int SESSION_BYTES_LENGTH = 32;
static const int INVALID_TASK_STATUS = -1;
static const int TASK_STATUS_SERVER_BEGIN_TOKEN = 0;
static const int TASK_STATUS_SERVER_GEN_SESSION_KEY = 1;
static const int TASK_STATUS_SERVER_END = 2;
static const int TASK_STATUS_ISO_MAIN_STEP_ONE = 1;
static const int TASK_STATUS_ISO_MAIN_STEP_TWO = 2;
static const int TASK_STATUS_ISO_MAIN_END = 3;

class IsoAuthTaskTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IsoAuthTaskTest::SetUpTestCase() {}
void IsoAuthTaskTest::TearDownTestCase() {}

void IsoAuthTaskTest::SetUp() {}

void IsoAuthTaskTest::TearDown() {}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest001, TestSize.Level0)
{
    TaskBase *task = CreateIsoAuthTask(nullptr, nullptr, nullptr);
    EXPECT_EQ(task, nullptr);

    CJson *inJson = CreateJson();
    EXPECT_NE(inJson, nullptr);
    (void)AddIntToJson(inJson, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    CJson *outJson = CreateJson();
    EXPECT_NE(outJson, nullptr);
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};

    task = CreateIsoAuthClientTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    (void)AddIntToJson(inJson, FIELD_CREDENTIAL_TYPE, SYMMETRIC_CRED);

    task = CreateIsoAuthClientTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    (void)AddIntToJson(inJson, FIELD_LOCAL_DEVICE_TYPE, DEVICE_TYPE_CONTROLLER);

    task = CreateIsoAuthClientTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    (void)AddStringToJson(inJson, FIELD_SELF_USER_ID, TEST_USER_ID.c_str());

    task = CreateIsoAuthClientTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    (void)AddStringToJson(inJson, FIELD_SELF_DEV_ID, TEST_DEV_ID_EXCEED.c_str());

    task = CreateIsoAuthClientTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    (void)AddStringToJson(inJson, FIELD_SELF_DEV_ID, TEST_UDID.c_str());

    task = CreateIsoAuthClientTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    (void)AddIntToJson(inJson, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED);
    (void)AddIntToJson(inJson, FIELD_LOCAL_DEVICE_TYPE, DEVICE_TYPE_ACCESSORY);
    (void)AddStringToJson(inJson, FIELD_SELF_DEVICE_ID, TEST_AUTH_ID.c_str());

    task = CreateIsoAuthClientTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    FreeJson(inJson);
    FreeJson(outJson);
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest002, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    IsoAuthParams *params = static_cast<IsoAuthParams *>(HcMalloc(sizeof(IsoAuthParams), 0));
    EXPECT_NE(params, nullptr);
    params->localDevType = DEVICE_TYPE_CONTROLLER;
    ret = AccountAuthGeneratePsk(params);
    EXPECT_NE(ret, HC_SUCCESS);

    const char *userId = TEST_USER_ID.c_str();
    uint32_t userIdLen = HcStrlen(userId) + 1;
    params->userIdPeer = static_cast<char *>(HcMalloc(userIdLen, 0));
    EXPECT_NE(params->userIdPeer, nullptr);
    (void)memcpy_s(params->userIdPeer, userIdLen, userId, userIdLen);

    const char *udid = TEST_UDID.c_str();
    uint32_t udidLen = HcStrlen(udid) + 1;
    params->devIdPeer.val = static_cast<uint8_t *>(HcMalloc(udidLen, 0));
    EXPECT_NE(params->devIdPeer.val, nullptr);
    (void)memcpy_s(params->devIdPeer.val, udidLen, udid, udidLen);
    params->devIdPeer.length = udidLen;

    params->isoBaseParams.loader = GetLoaderInstance();

    ret = AccountAuthGeneratePsk(params);
    EXPECT_NE(ret, HC_SUCCESS);

    HcFree(params->devIdPeer.val);
    HcFree(params->userIdPeer);
    HcFree(params);
    DestroyDeviceAuthService();
}

static uint8_t *GetSessionKey()
{
    uint8_t *sessionBytes = static_cast<uint8_t *>(HcMalloc(SESSION_BYTES_LENGTH, 0));
    (void)HexStringToByte(TEST_SESSION_KEY.c_str(), sessionBytes, SESSION_BYTES_LENGTH);
    return sessionBytes;
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest003, TestSize.Level0)
{
    IsoAuthParams params;
    int32_t ret = AuthIsoSendFinalToOut(&params, nullptr);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    params.isoBaseParams.sessionKey.val = GetSessionKey();
    params.isoBaseParams.sessionKey.length = SESSION_BYTES_LENGTH;

    ret = AuthIsoSendFinalToOut(&params, nullptr);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    params.isoBaseParams.sessionKey.val = GetSessionKey();
    params.isoBaseParams.sessionKey.length = SESSION_BYTES_LENGTH;
    params.userIdPeer = const_cast<char *>(TEST_USER_ID.c_str());

    ret = AuthIsoSendFinalToOut(&params, nullptr);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    params.isoBaseParams.sessionKey.val = GetSessionKey();
    params.isoBaseParams.sessionKey.length = SESSION_BYTES_LENGTH;
    params.deviceIdPeer = const_cast<char *>(TEST_AUTH_ID.c_str());

    ret = AuthIsoSendFinalToOut(&params, nullptr);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    params.isoBaseParams.sessionKey.val = GetSessionKey();
    params.isoBaseParams.sessionKey.length = SESSION_BYTES_LENGTH;

    uint32_t udidLen = HcStrlen(TEST_UDID.c_str()) + 1;
    uint8_t *udidVal = static_cast<uint8_t *>(HcMalloc(udidLen, 0));
    EXPECT_NE(udidVal, nullptr);
    (void)memcpy_s(udidVal, udidLen, TEST_UDID.c_str(), udidLen);

    params.devIdPeer.val = udidVal;
    params.devIdPeer.length = udidLen;

    ret = AuthIsoSendFinalToOut(&params, nullptr);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    HcFree(udidVal);
}

static TaskBase *CreateServerTask(void)
{
    CJson *inJson = CreateJson();
    if (inJson == nullptr) {
        return nullptr;
    }
    CJson *outJson = CreateJson();
    if (outJson == nullptr) {
        FreeJson(inJson);
        return nullptr;
    }
    (void)AddIntToJson(inJson, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    (void)AddIntToJson(inJson, FIELD_CREDENTIAL_TYPE, SYMMETRIC_CRED);
    (void)AddIntToJson(inJson, FIELD_LOCAL_DEVICE_TYPE, DEVICE_TYPE_CONTROLLER);
    (void)AddStringToJson(inJson, FIELD_SELF_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(inJson, FIELD_SELF_DEV_ID, TEST_UDID.c_str());
    (void)AddStringToJson(inJson, FIELD_SELF_DEVICE_ID, TEST_AUTH_ID.c_str());
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    TaskBase *task = CreateIsoAuthServerTask(inJson, outJson, &info);
    FreeJson(inJson);
    FreeJson(outJson);
    return task;
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest004, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    CJson *outJson = CreateJson();
    EXPECT_NE(outJson, nullptr);
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    TaskBase *task = CreateIsoAuthServerTask(nullptr, outJson, &info);
    EXPECT_EQ(task, nullptr);

    CJson *inJson = CreateJson();
    EXPECT_NE(inJson, nullptr);
    task = CreateIsoAuthServerTask(inJson, nullptr, &info);
    EXPECT_EQ(task, nullptr);

    task = CreateIsoAuthServerTask(inJson, outJson, nullptr);
    EXPECT_EQ(task, nullptr);

    task = CreateIsoAuthServerTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    FreeJson(inJson);
    FreeJson(outJson);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest005, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    (void)task->getTaskType();

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest006, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    IsoAuthServerTask *innerTask = reinterpret_cast<IsoAuthServerTask *>(task);
    HcFree(innerTask->params.userIdPeer);
    innerTask->params.userIdPeer = nullptr;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_MEMORY_COPY);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest007, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest008, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SEED, TEST_SEED.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest009, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SEED, TEST_SEED.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest010, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    task->taskStatus = INVALID_TASK_STATUS;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_BAD_MESSAGE);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest011, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_GEN_SESSION_KEY;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_SUCCESS);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest012, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_TWO);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_BEGIN_TOKEN;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_BAD_MESSAGE);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest013, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_TWO);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_END;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_SUCCESS);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest014, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_TWO);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_GEN_SESSION_KEY;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest015, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_TWO);
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_GEN_SESSION_KEY;
    ret = task->process(task, in, out, &status);
    EXPECT_NE(ret, HC_SUCCESS);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest016, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateServerTask();
    EXPECT_NE(task, nullptr);

    int32_t status = 0;
    ret = task->process(task, nullptr, nullptr, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest017, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    CJson *outJson = CreateJson();
    ASSERT_NE(outJson, nullptr);
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    TaskBase *task = CreateIsoAuthClientTask(nullptr, outJson, &info);
    EXPECT_EQ(task, nullptr);

    CJson *inJson = CreateJson();
    ASSERT_NE(inJson, nullptr);
    task = CreateIsoAuthClientTask(inJson, nullptr, &info);
    EXPECT_EQ(task, nullptr);

    task = CreateIsoAuthClientTask(inJson, outJson, nullptr);
    EXPECT_EQ(task, nullptr);

    task = CreateIsoAuthClientTask(inJson, outJson, &info);
    EXPECT_EQ(task, nullptr);

    FreeJson(inJson);
    FreeJson(outJson);
    DestroyDeviceAuthService();
}

static TaskBase *CreateClientTask(void)
{
    CJson *inJson = CreateJson();
    if (inJson == nullptr) {
        return nullptr;
    }
    CJson *outJson = CreateJson();
    if (outJson == nullptr) {
        FreeJson(inJson);
        return nullptr;
    }
    (void)AddIntToJson(inJson, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    (void)AddIntToJson(inJson, FIELD_CREDENTIAL_TYPE, SYMMETRIC_CRED);
    (void)AddIntToJson(inJson, FIELD_LOCAL_DEVICE_TYPE, DEVICE_TYPE_CONTROLLER);
    (void)AddStringToJson(inJson, FIELD_SELF_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(inJson, FIELD_SELF_DEV_ID, TEST_UDID.c_str());
    (void)AddStringToJson(inJson, FIELD_SELF_DEVICE_ID, TEST_AUTH_ID.c_str());
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    TaskBase *task = CreateIsoAuthClientTask(inJson, outJson, &info);
    FreeJson(inJson);
    FreeJson(outJson);
    return task;
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest018, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    (void)task->getTaskType();

    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.isoBaseParams.authIdSelf.val);
    innerTask->params.isoBaseParams.authIdSelf.val = nullptr;
    ret = task->process(task, nullptr, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    task->destroyTask(task);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest019, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.userIdSelf);
    innerTask->params.userIdSelf = nullptr;
    ret = task->process(task, nullptr, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    task->destroyTask(task);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest020, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.devIdSelf.val);
    innerTask->params.devIdSelf.val = nullptr;
    ret = task->process(task, nullptr, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    task->destroyTask(task);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest021, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    int32_t status = 0;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.deviceIdSelf);
    innerTask->params.deviceIdSelf = nullptr;
    ret = task->process(task, nullptr, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    task->destroyTask(task);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest022, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    int32_t status = 0;
    ret = task->process(task, nullptr, nullptr, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_ADD);

    task->destroyTask(task);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest023, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest024, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.userIdPeer);
    innerTask->params.userIdPeer = nullptr;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_MEMORY_COPY);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest025, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest026, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest027, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, TEST_PAYLOAD.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest028, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, "");
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_ALLOC_MEMORY);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest029, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, TEST_PAYLOAD.c_str());
    // GetPayloadValue convert hex string to byte failed
    (void)AddStringToJson(in, FIELD_DEV_ID, TEST_UDID.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_CONVERT_FAILED);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest030, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, TEST_PAYLOAD.c_str());
    (void)AddStringToJson(in, FIELD_DEV_ID, TEST_DEV_ID.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest031, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, TEST_PAYLOAD.c_str());
    (void)AddStringToJson(in, FIELD_DEV_ID, TEST_DEV_ID.c_str());
    (void)AddStringToJson(in, FIELD_DEVICE_ID, TEST_AUTH_ID.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_MEMORY_COMPARE);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest032, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = INVALID_TASK_STATUS;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_BAD_MESSAGE);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest033, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_TWO;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_SUCCESS);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest034, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_TWO);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_BAD_MESSAGE);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest035, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_TWO);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_END;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_SUCCESS);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest036, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_TWO);
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_TWO;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest037, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    CJson *in = CreateJson();
    EXPECT_NE(in, nullptr);
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_TWO);
    (void)AddStringToJson(in, FIELD_AUTH_RESULT_MAC, TEST_AUTH_RESULT_MAC.c_str());
    CJson *out = CreateJson();
    EXPECT_NE(out, nullptr);
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_TWO;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    EXPECT_NE(ret, HC_SUCCESS);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

HWTEST_F(IsoAuthTaskTest, IsoAuthTaskTest038, TestSize.Level0)
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);

    TaskBase *task = CreateClientTask();
    EXPECT_NE(task, nullptr);

    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, nullptr, nullptr, &status);
    EXPECT_EQ(ret, HC_ERR_JSON_GET);

    task->destroyTask(task);
    DestroyDeviceAuthService();
}
}