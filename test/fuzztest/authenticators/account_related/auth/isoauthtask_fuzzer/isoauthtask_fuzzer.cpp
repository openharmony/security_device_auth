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

#include "isoauthtask_fuzzer.h"
#include "iso_auth_task_common.h"
#include "json_utils.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "iso_auth_client_task.h"
#include "iso_auth_server_task.h"
#include "securec.h"

namespace OHOS {
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
static const int DEFAULT_OS_ACCOUNT = 100;

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
    (void)AddIntToJson(inJson, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    TaskBase *task = CreateIsoAuthServerTask(inJson, outJson, &info);
    FreeJson(inJson);
    FreeJson(outJson);
    return task;
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
    (void)AddIntToJson(inJson, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    TaskBase *task = CreateIsoAuthClientTask(inJson, outJson, &info);
    FreeJson(inJson);
    FreeJson(outJson);
    return task;
}

static void IsoAuthTaskTest01(void)
{
    CJson *inJson = CreateJson();
    CJson *outJson = CreateJson();

    TaskBase *task = CreateIsoAuthTask(nullptr, nullptr, nullptr);

    (void)AddIntToJson(inJson, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    task = CreateIsoAuthClientTask(inJson, outJson, &info);

    (void)AddIntToJson(inJson, FIELD_CREDENTIAL_TYPE, SYMMETRIC_CRED);
    task = CreateIsoAuthClientTask(inJson, outJson, &info);

    (void)AddIntToJson(inJson, FIELD_LOCAL_DEVICE_TYPE, DEVICE_TYPE_CONTROLLER);
    task = CreateIsoAuthClientTask(inJson, outJson, &info);

    (void)AddStringToJson(inJson, FIELD_SELF_USER_ID, TEST_USER_ID.c_str());
    task = CreateIsoAuthClientTask(inJson, outJson, &info);

    (void)AddStringToJson(inJson, FIELD_SELF_DEV_ID, TEST_DEV_ID_EXCEED.c_str());
    task = CreateIsoAuthClientTask(inJson, outJson, &info);

    (void)AddStringToJson(inJson, FIELD_SELF_DEV_ID, TEST_UDID.c_str());
    task = CreateIsoAuthClientTask(inJson, outJson, &info);

    (void)AddIntToJson(inJson, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED);
    (void)AddIntToJson(inJson, FIELD_LOCAL_DEVICE_TYPE, DEVICE_TYPE_ACCESSORY);
    (void)AddStringToJson(inJson, FIELD_SELF_DEVICE_ID, TEST_AUTH_ID.c_str());
    task = CreateIsoAuthClientTask(inJson, outJson, &info);

    FreeJson(inJson);
    FreeJson(outJson);
}

static void IsoAuthTaskTest02(void)
{
    int32_t ret = InitDeviceAuthService();

    IsoAuthParams *params = static_cast<IsoAuthParams *>(HcMalloc(sizeof(IsoAuthParams), 0));
    params->localDevType = DEVICE_TYPE_CONTROLLER;
    ret = AccountAuthGeneratePsk(params);

    const char *userId = TEST_USER_ID.c_str();
    uint32_t userIdLen = HcStrlen(userId) + 1;
    params->userIdPeer = static_cast<char *>(HcMalloc(userIdLen, 0));

    (void)memcpy_s(params->userIdPeer, userIdLen, userId, userIdLen);

    const char *udid = TEST_UDID.c_str();
    uint32_t udidLen = HcStrlen(udid) + 1;
    params->devIdPeer.val = static_cast<uint8_t *>(HcMalloc(udidLen, 0));
    (void)memcpy_s(params->devIdPeer.val, udidLen, udid, udidLen);
    params->devIdPeer.length = udidLen;
    params->isoBaseParams.loader = GetLoaderInstance();
    ret = AccountAuthGeneratePsk(params);
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

static void IsoAuthTaskTest03(void)
{
    IsoAuthParams params;
    AuthIsoSendFinalToOut(&params, nullptr);
    params.isoBaseParams.sessionKey.val = GetSessionKey();
    params.isoBaseParams.sessionKey.length = SESSION_BYTES_LENGTH;
    AuthIsoSendFinalToOut(&params, nullptr);
    params.isoBaseParams.sessionKey.val = GetSessionKey();
    params.isoBaseParams.sessionKey.length = SESSION_BYTES_LENGTH;
    params.userIdPeer = const_cast<char *>(TEST_USER_ID.c_str());
    AuthIsoSendFinalToOut(&params, nullptr);
    params.isoBaseParams.sessionKey.val = GetSessionKey();
    params.isoBaseParams.sessionKey.length = SESSION_BYTES_LENGTH;
    params.deviceIdPeer = const_cast<char *>(TEST_AUTH_ID.c_str());
    AuthIsoSendFinalToOut(&params, nullptr);
    params.isoBaseParams.sessionKey.val = GetSessionKey();
    params.isoBaseParams.sessionKey.length = SESSION_BYTES_LENGTH;
    uint32_t udidLen = HcStrlen(TEST_UDID.c_str()) + 1;
    uint8_t *udidVal = static_cast<uint8_t *>(HcMalloc(udidLen, 0));
    (void)memcpy_s(udidVal, udidLen, TEST_UDID.c_str(), udidLen);
    params.devIdPeer.val = udidVal;
    params.devIdPeer.length = udidLen;
    AuthIsoSendFinalToOut(&params, nullptr);
    HcFree(udidVal);
}

static void IsoAuthTaskTest05(void)
{
    InitDeviceAuthService();
    CJson *outJson = CreateJson();
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    TaskBase *task = CreateIsoAuthServerTask(nullptr, outJson, &info);

    CJson *inJson = CreateJson();
    task = CreateIsoAuthServerTask(inJson, nullptr, &info);
    task = CreateIsoAuthServerTask(inJson, outJson, nullptr);
    task = CreateIsoAuthServerTask(inJson, outJson, &info);

    FreeJson(inJson);
    FreeJson(outJson);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest06(void)
{
    InitDeviceAuthService();
    TaskBase *task = CreateServerTask();
    (void)task->getTaskType();
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    CJson *out = CreateJson();
    int32_t status = 0;
    task->process(task, in, out, &status);
    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest07(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    CJson *out = CreateJson();
    int32_t status = 0;
    IsoAuthServerTask *innerTask = reinterpret_cast<IsoAuthServerTask *>(task);
    HcFree(innerTask->params.userIdPeer);
    innerTask->params.userIdPeer = nullptr;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest08(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();
    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    CJson *out = CreateJson();
    int32_t status = 0;
    ret = task->process(task, in, out, &status);
    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest09(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SEED, TEST_SEED.c_str());
    CJson *out = CreateJson();
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest10(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SEED, TEST_SEED.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    CJson *out = CreateJson();
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest11(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    CJson *out = CreateJson();
    int32_t status = 0;
    task->taskStatus = INVALID_TASK_STATUS;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest12(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_ONE);
    CJson *out = CreateJson();
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_GEN_SESSION_KEY;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest13(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_TWO);
    CJson *out = CreateJson();
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_BEGIN_TOKEN;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest14(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_TWO);
    CJson *out = CreateJson();
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_END;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest15(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_TWO);
    CJson *out = CreateJson();
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_GEN_SESSION_KEY;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest16(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, CMD_ISO_AUTH_MAIN_TWO);
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    CJson *out = CreateJson();
    int32_t status = 0;
    task->taskStatus = TASK_STATUS_SERVER_GEN_SESSION_KEY;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest17(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateServerTask();

    int32_t status = 0;
    ret = task->process(task, nullptr, nullptr, &status);

    task->destroyTask(task);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest18(void)
{
    InitDeviceAuthService();

    CJson *outJson = CreateJson();
    AccountVersionInfo info = { AUTH_PAKE_V2_EC_P256, PAKE_V2, PAKE_ALG_EC, CURVE_256, false, nullptr, nullptr};
    TaskBase *task = CreateIsoAuthClientTask(nullptr, outJson, &info);

    CJson *inJson = CreateJson();
    task = CreateIsoAuthClientTask(inJson, nullptr, &info);
    task = CreateIsoAuthClientTask(inJson, outJson, nullptr);
    task = CreateIsoAuthClientTask(inJson, outJson, &info);

    FreeJson(inJson);
    FreeJson(outJson);
    DestroyDeviceAuthService();
}


static void IsoAuthTaskTest19(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    (void)task->getTaskType();

    CJson *out = CreateJson();
    int32_t status = 0;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.isoBaseParams.authIdSelf.val);
    innerTask->params.isoBaseParams.authIdSelf.val = nullptr;
    ret = task->process(task, nullptr, out, &status);

    task->destroyTask(task);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest20(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *out = CreateJson();
    int32_t status = 0;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.userIdSelf);
    innerTask->params.userIdSelf = nullptr;
    ret = task->process(task, nullptr, out, &status);

    task->destroyTask(task);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest21(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *out = CreateJson();
    int32_t status = 0;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.devIdSelf.val);
    innerTask->params.devIdSelf.val = nullptr;
    ret = task->process(task, nullptr, out, &status);

    task->destroyTask(task);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest22(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *out = CreateJson();
    int32_t status = 0;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.deviceIdSelf);
    innerTask->params.deviceIdSelf = nullptr;
    ret = task->process(task, nullptr, out, &status);

    task->destroyTask(task);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest23(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    int32_t status = 0;
    ret = task->process(task, nullptr, nullptr, &status);

    task->destroyTask(task);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest24(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest25(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    IsoAuthClientTask *innerTask = reinterpret_cast<IsoAuthClientTask *>(task);
    HcFree(innerTask->params.userIdPeer);
    innerTask->params.userIdPeer = nullptr;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest26(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest04(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest27(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, TEST_PAYLOAD.c_str());
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest28(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, "");
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest29(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, TEST_PAYLOAD.c_str());
    // GetPayloadValue convert hex string to byte failed
    (void)AddStringToJson(in, FIELD_DEV_ID, TEST_UDID.c_str());
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest30(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, TEST_PAYLOAD.c_str());
    (void)AddStringToJson(in, FIELD_DEV_ID, TEST_DEV_ID.c_str());
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest31(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    (void)AddStringToJson(in, FIELD_USER_ID, TEST_USER_ID.c_str());
    (void)AddStringToJson(in, FIELD_SALT, TEST_SALT.c_str());
    (void)AddStringToJson(in, FIELD_TOKEN, TEST_AUTH_CODE.c_str());
    (void)AddStringToJson(in, FIELD_PAYLOAD, TEST_PAYLOAD.c_str());
    (void)AddStringToJson(in, FIELD_DEV_ID, TEST_DEV_ID.c_str());
    (void)AddStringToJson(in, FIELD_DEVICE_ID, TEST_AUTH_ID.c_str());
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest32(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    CJson *out = CreateJson();
    task->taskStatus = INVALID_TASK_STATUS;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest33(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_ONE);
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_TWO;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest34(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_TWO);
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest35(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_TWO);
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_END;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest36(void)
{
    int32_t ret = InitDeviceAuthService();

    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_TWO);
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_TWO;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest37(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    CJson *in = CreateJson();
    (void)AddIntToJson(in, FIELD_STEP, RET_ISO_AUTH_FOLLOWER_TWO);
    (void)AddStringToJson(in, FIELD_AUTH_RESULT_MAC, TEST_AUTH_RESULT_MAC.c_str());
    CJson *out = CreateJson();
    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_TWO;
    int32_t status = 0;
    ret = task->process(task, in, out, &status);

    task->destroyTask(task);
    FreeJson(in);
    FreeJson(out);
    DestroyDeviceAuthService();
}

static void IsoAuthTaskTest38(void)
{
    int32_t ret = InitDeviceAuthService();
    TaskBase *task = CreateClientTask();

    task->taskStatus = TASK_STATUS_ISO_MAIN_STEP_ONE;
    int32_t status = 0;
    ret = task->process(task, nullptr, nullptr, &status);

    task->destroyTask(task);
    DestroyDeviceAuthService();
}

bool FuzzDoRegCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)IsoAuthTaskTest01();
    (void)IsoAuthTaskTest02();
    (void)IsoAuthTaskTest03();
    (void)IsoAuthTaskTest04();
    (void)IsoAuthTaskTest05();
    (void)IsoAuthTaskTest06();
    (void)IsoAuthTaskTest07();
    (void)IsoAuthTaskTest08();
    (void)IsoAuthTaskTest09();
    (void)IsoAuthTaskTest10();
    (void)IsoAuthTaskTest11();
    (void)IsoAuthTaskTest12();
    (void)IsoAuthTaskTest13();
    (void)IsoAuthTaskTest14();
    (void)IsoAuthTaskTest15();
    (void)IsoAuthTaskTest16();
    (void)IsoAuthTaskTest17();
    (void)IsoAuthTaskTest18();
    (void)IsoAuthTaskTest19();
    (void)IsoAuthTaskTest20();
    (void)IsoAuthTaskTest21();
    (void)IsoAuthTaskTest22();
    (void)IsoAuthTaskTest23();
    (void)IsoAuthTaskTest24();
    (void)IsoAuthTaskTest25();
    (void)IsoAuthTaskTest26();
    (void)IsoAuthTaskTest27();
    (void)IsoAuthTaskTest28();
    (void)IsoAuthTaskTest29();
    (void)IsoAuthTaskTest30();
    (void)IsoAuthTaskTest31();
    (void)IsoAuthTaskTest32();
    (void)IsoAuthTaskTest33();
    (void)IsoAuthTaskTest34();
    (void)IsoAuthTaskTest35();
    (void)IsoAuthTaskTest36();
    (void)IsoAuthTaskTest37();
    (void)IsoAuthTaskTest38();
    return true;
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoRegCallback(data, size);
    return 0;
}

