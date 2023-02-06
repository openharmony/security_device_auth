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

#include "auth_session_dir_test.h"
#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>

using namespace std;
using namespace testing::ext;

namespace {
// Beginning for auth_session_client.c test.
class AuthSessionClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionClientTest::SetUpTestCase() {}

void AuthSessionClientTest::TearDownTestCase() {}

void AuthSessionClientTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void AuthSessionClientTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(AuthSessionClientTest, AuthSessionClientTest0100, TestSize.Level0)
{
    DeviceAuthCallback callback;
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    Session *session = CreateClientAuthSession(param, &callback);
    if (session == nullptr) {
        FreeJson(param);
        return;
    }

    EXPECT_EQ(session, nullptr);

    if (session != nullptr) {
        session->destroy(session);
    }
    FreeJson(param);
}

HWTEST_F(AuthSessionClientTest, AuthSessionClientTest0101, TestSize.Level0)
{
    DeviceAuthCallback callback;
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    Session *session = CreateClientAuthSession(param, &callback);
    if (session == nullptr) {
        FreeJson(param);
        return;
    }
    (void)AddIntToJson(param, FIELD_KEY_LENGTH, 10); // For test length.
    EXPECT_EQ(session, nullptr);
    if (session != nullptr) {
        session->destroy(session);
    }
    FreeJson(param);
}

HWTEST_F(AuthSessionClientTest, AuthSessionClientTest0102, TestSize.Level0)
{
    DeviceAuthCallback callback;
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    Session *session = CreateClientAuthSession(param, &callback);
    if (session == nullptr) {
        FreeJson(param);
        return;
    }

    (void)AddIntToJson(param, FIELD_KEY_LENGTH, 1025); // For test length.
    
    EXPECT_EQ(session, nullptr);
    if (session != nullptr) {
        session->destroy(session);
    }
    FreeJson(param);
}

HWTEST_F(AuthSessionClientTest, AuthSessionClientTest0103, TestSize.Level0)
{
    DeviceAuthCallback callback;
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    Session *session = CreateClientAuthSession(param, &callback);
    if (session == nullptr) {
        FreeJson(param);
        return;
    }

    (void)AddIntToJson(param, FIELD_KEY_LENGTH, 32); // For test length.
    (void)AddStringToJson(param, FIELD_SERVICE_PKG_NAME, "FIELD_SERVICE_PKG_NAME"); // For unit test.
    
    EXPECT_EQ(session, nullptr);
    if (session != nullptr) {
        session->destroy(session);
    }
    FreeJson(param);
}

HWTEST_F(AuthSessionClientTest, AuthSessionClientTest0104, TestSize.Level0)
{
    DeviceAuthCallback callback;
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    Session *session = CreateClientAuthSession(param, &callback);
    if (session == nullptr) {
        FreeJson(param);
        return;
    }

    (void)AddIntToJson(param, FIELD_KEY_LENGTH, 32); // 32 if for unit test.
    (void)AddStringToJson(param, FIELD_SERVICE_PKG_NAME, "FIELD_SERVICE_PKG_NAME"); // For unit test.
    (void)AddIntToJson(param, FIELD_OS_ACCOUNT_ID, 0); // 0 if for unit test.
    
    EXPECT_EQ(session, nullptr);
    if (session != nullptr) {
        session->destroy(session);
    }
    FreeJson(param);
}

HWTEST_F(AuthSessionClientTest, AuthSessionClientTest0105, TestSize.Level0)
{
    DeviceAuthCallback callback;
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    Session *session = CreateClientAuthSession(param, &callback);
    if (session == nullptr) {
        FreeJson(param);
        return;
    }

    (void)AddIntToJson(param, FIELD_KEY_LENGTH, 32); // 32 if for unit test.
    (void)AddStringToJson(param, FIELD_SERVICE_PKG_NAME, "FIELD_SERVICE_PKG_NAME"); // For unit test.
    (void)AddIntToJson(param, FIELD_OS_ACCOUNT_ID, 0); // 0 if for unit test.
    (void)AddStringToJson(param, FIELD_GROUP_ID, "FIELD_GROUP_ID");
    EXPECT_EQ(session, nullptr);
    if (session != nullptr) {
        session->destroy(session);
    }
    FreeJson(param);
}
// Ending for auth_session_client.c test.

// Beginning for auth_session_common.c test.
class AuthSessionCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionCommonTest::SetUpTestCase() {}

void AuthSessionCommonTest::TearDownTestCase() {}

void AuthSessionCommonTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void AuthSessionCommonTest::TearDown()
{
    DestroyDeviceAuthService();
}

static bool OnTransmitTrue(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return true;
}

static bool OnTransmitFalse(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return false;
}

static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
}

static void OnFinish(int64_t requestId, int operationCode, const char *returnData)
{
    (void)requestId;
    (void)operationCode;
    (void)returnData;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
}

static char *OnRequest(int64_t requestId, int operationCode, const char *reqParams)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParams;
    return nullptr;
}

static DeviceAuthCallback g_deviceAuthCallBack = {
    .onTransmit = OnTransmitTrue,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnRequest
};

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0100, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }

    DeviceAuthCallback callback;
    (void)InformLocalAuthError(authParam, &callback);
    EXPECT_EQ(ret, HC_SUCCESS);

    (void)AddStringToJson(authParam, FIELD_ALTERNATIVE, "FIELD_ALTERNATIVE"); // For unit test.
    (void)InformLocalAuthError(authParam, &callback);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(authParam);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0101, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    DeviceAuthCallback callback;
    (void)InformLocalAuthError(authParam, &callback);
    EXPECT_EQ(ret, HC_SUCCESS);

    (void)AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    (void)InformLocalAuthError(authParam, &callback);
    EXPECT_EQ(ret, HC_SUCCESS);

    (void)AddStringToJson(authParam, FIELD_ALTERNATIVE, "FIELD_ALTERNATIVE"); // For unit test.
    (void)InformLocalAuthError(authParam, &callback);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(authParam);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0102, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    int64_t requestIdTest = 123456;
    (void)AddByteToJson(authParam, FIELD_REQUEST_ID, reinterpret_cast<uint8_t *>(&requestIdTest), sizeof(int64_t));

    (void)InformLocalAuthError(authParam, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);

    (void)InformLocalAuthError(authParam, &g_deviceAuthCallBack);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(authParam);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0110, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    (void)InformPeerAuthError(authParam, &g_deviceAuthCallBack);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(authParam);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0111, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    int64_t requestIdTest = 123456;
    AddByteToJson(authParam, FIELD_REQUEST_ID, reinterpret_cast<uint8_t *>(&requestIdTest), sizeof(int64_t));

    InformPeerAuthError(authParam, nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(authParam);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0112, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    int64_t requestIdTest = 123456;
    (void)AddByteToJson(authParam, FIELD_REQUEST_ID, reinterpret_cast<uint8_t *>(&requestIdTest), sizeof(int64_t));

    DeviceAuthCallback callback = g_deviceAuthCallBack;
    callback.onTransmit = nullptr;

    InformPeerAuthError(authParam, &callback);
    EXPECT_EQ(ret, HC_SUCCESS);

    callback.onTransmit = OnTransmitFalse;
    InformPeerAuthError(authParam, &callback);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(authParam);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0120, TestSize.Level0)
{
    CJson *out = CreateJson();
    if (out == nullptr) {
        return;
    }
    CJson *paramInSession = CreateJson();
    if (paramInSession == nullptr) {
        FreeJson(out);
        return;
    }

    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    int32_t ret = InformAuthError(&session, out, 0); // For unit test
    EXPECT_NE(ret, HC_SUCCESS);
    
    (void)session.paramsList.pushBackT(&session.paramsList, paramInSession);
    session.currentIndex = 0; // For unit test
    ret = InformAuthError(&session, out, 0); // For unit test
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(out);
    FreeJson(paramInSession);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0121, TestSize.Level0)
{
    CJson *out = CreateJson();
    if (out == nullptr) {
        return;
    }
    CJson *paramInSession = CreateJson();
    if (paramInSession == nullptr) {
        FreeJson(out);
        return;
    }

    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    
    session.paramsList.pushBackT(&session.paramsList, paramInSession);
    session.currentIndex = 0; // For unit test.
    int32_t ret = InformAuthError(&session, out, 0); // For unit test.
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0122, TestSize.Level0)
{
    CJson *out = CreateJson();
    if (out == nullptr) {
        return;
    }
    CJson *paramInSession = CreateJson();
    if (paramInSession == nullptr) {
        FreeJson(out);
        return;
    }

    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);

    session.paramsList.pushBackT(&session.paramsList, paramInSession);
    session.currentIndex = 0; // For unit test.
    int32_t ret = InformAuthError(&session, out, 0); // For unit test.
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0123, TestSize.Level0)
{
    CJson *out = CreateJson();
    if (out == nullptr) {
        return;
    }
    CJson *paramInSession = CreateJson();
    if (paramInSession == nullptr) {
        FreeJson(out);
        return;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == nullptr) {
        FreeJson(out);
        FreeJson(paramInSession);
        return;
    }

    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    
    session.paramsList.pushBackT(&session.paramsList, paramInSession);
    session.currentIndex = 0; // For unit test.
    
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    int32_t ret = InformAuthError(&session, out, 0); // For unit test.
    EXPECT_NE(ret, HC_SUCCESS);

    int64_t requestIdTest = 123456;
    (void)AddByteToJson(sendToPeer, FIELD_REQUEST_ID,
        reinterpret_cast<uint8_t *>(&requestIdTest), sizeof(int64_t));    
    ret = InformAuthError(&session, out, 0); // For unit test.
    EXPECT_NE(ret, HC_SUCCESS);

    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(sendToPeer);
    FreeJson(out);
    FreeJson(paramInSession);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0124, TestSize.Level0)
{
    CJson *out = CreateJson();
    if (out == nullptr) {
        return;
    }
    CJson *paramInSession = CreateJson();
    if (paramInSession == nullptr) {
        FreeJson(out);
        return;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == nullptr) {
        FreeJson(out);
        FreeJson(paramInSession);
        return;
    }

    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    
    session.paramsList.pushBackT(&session.paramsList, paramInSession);
    session.currentIndex = 0;
    
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);

    int64_t requestIdTest = 123456;
    (void)AddByteToJson(sendToPeer, FIELD_REQUEST_ID,
        reinterpret_cast<uint8_t *>(&requestIdTest), sizeof(int64_t));    

    DeviceAuthCallback callback = g_deviceAuthCallBack;
    session.base.callback = &callback;
    callback.onTransmit = OnTransmitFalse;
    int32_t ret = InformAuthError(&session, out, 0);
    EXPECT_NE(ret, HC_SUCCESS);

    callback.onTransmit = OnTransmitTrue;
    ret = InformAuthError(&session, out, 0);
    EXPECT_NE(ret, HC_SUCCESS);

    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(paramInSession);
    FreeJson(sendToPeer);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0130, TestSize.Level0)
{
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    ParamsVec vec;
    CreateAuthParamsVec(&vec);

    int32_t ret = GetAuthParamsList(0, param, &vec);
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&vec);
    FreeJson(param);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0131, TestSize.Level0)
{
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    ParamsVec vec;
    CreateAuthParamsVec(&vec);
    (void)AddStringToJson(param, FIELD_GROUP_ID, "FIELD_GROUP_ID");
    int32_t ret = GetAuthParamsList(0, param, &vec);
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&vec);
    FreeJson(param);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0140, TestSize.Level0)
{
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(param);
        return;
    }
    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    
    int32_t ret = ProcessTaskStatusForAuth(&session, param, out, -1); // -1 for default branch
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(param);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0141, TestSize.Level0)
{
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(param);
        return;
    }
    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    
    int32_t ret = ProcessTaskStatusForAuth(&session, param, out, IGNORE_MSG);
    EXPECT_EQ(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(param);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0142, TestSize.Level0)
{
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(param);
        return;
    }
    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    
    int32_t ret = ProcessTaskStatusForAuth(&session, param, out, FINISH);
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(param);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0143, TestSize.Level0)
{
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(param);
        return;
    }

    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    
    int32_t ret = ProcessTaskStatusForAuth(&session, param, out, CONTINUE);
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(param);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0144, TestSize.Level0)
{
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(param);
        return;
    }
    CJson *sendToPeer = CreateJson();
    if (sendToPeer == nullptr) {
        FreeJson(param);
        FreeJson(out);
        return;
    }

    AuthSession session; // This can not be NULL in unit test.
    CreateAuthParamsVec(&session.paramsList);
    
    (void)AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    int32_t ret = ProcessTaskStatusForAuth(&session, param, out, CONTINUE);
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyAuthParamsVec(&session.paramsList);
    FreeJson(sendToPeer);
    FreeJson(param);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0150, TestSize.Level0)
{
    AuthSession session; // This can not be NULL in unit test.
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(param);
        return;
    }

    (void)AddIntToJson(param, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    int32_t ret = ProcessTaskStatusForAuth(&session, param, out, CONTINUE);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(param);
    FreeJson(out);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0160, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *paramInSession = CreateJson();
    if (paramInSession == nullptr) {
        return;
    }
    DestroyAuthSession(nullptr);
    EXPECT_EQ(ret, HC_SUCCESS);

    AuthSession *session = (AuthSession *)HcMalloc(sizeof(AuthSession), 0);
    session->base.appId = static_cast<char *>(malloc(1)); // For unit test.

    CreateAuthParamsVec(&session->paramsList);
    session->paramsList.pushBackT(&session->paramsList, paramInSession);
    session->currentIndex = 0;
    DestroyAuthSession(reinterpret_cast<Session *>(session));

    DestroyAuthParamsVec(&session->paramsList);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0161, TestSize.Level0)
{
    int32_t ret = HC_SUCCESS;
    CJson *paramInSession = CreateJson();
    if (paramInSession == nullptr) {
        return;
    }

    DeleteCachedData(paramInSession);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(paramInSession);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0162, TestSize.Level0)
{
    int32_t ret = GetGroupAuthType(AUTH_FORM_ACCOUNT_UNRELATED);
    EXPECT_EQ(ret, ACCOUNT_UNRELATED_GROUP_AUTH_TYPE);

    ret = GetGroupAuthType(AUTH_FORM_IDENTICAL_ACCOUNT);
    EXPECT_EQ(ret, ACCOUNT_RELATED_GROUP_AUTH_TYPE);

    ret = GetGroupAuthType(AUTH_FORM_ACROSS_ACCOUNT);
    EXPECT_EQ(ret, ACCOUNT_RELATED_GROUP_AUTH_TYPE);

    ret = GetGroupAuthType(888);
    EXPECT_EQ(ret, INVALID_GROUP_AUTH_TYPE);
}

HWTEST_F(AuthSessionCommonTest, AuthSessionCommonTest0170, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    if (authParam == nullptr) {
        return;
    }
    CJson *out = CreateJson();
    if (out == nullptr) {
        FreeJson(authParam);
        return;
    }
    DeviceAuthCallback callback = g_deviceAuthCallBack;

    int32_t ret = ReturnSessionKey(0, authParam, out, &callback);
    EXPECT_NE(ret, HC_SUCCESS);

    (void)AddIntToJson(authParam, FIELD_KEY_LENGTH, 2);
    ret = ReturnSessionKey(0, authParam, out, &callback);
    EXPECT_NE(ret, HC_SUCCESS);

    uint8_t sessionKey[2] = { 0x31, 0x32 };
    (void)AddByteToJson(authParam, FIELD_SESSION_KEY, sessionKey, sizeof(sessionKey));
    ret = ReturnSessionKey(0, authParam, out, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);

    callback.onSessionKeyReturned = nullptr;
    ret = ReturnSessionKey(0, authParam, out, &callback);
    EXPECT_NE(ret, HC_SUCCESS);

    callback.onSessionKeyReturned = OnSessionKeyReturned;
    ret = ReturnSessionKey(0, authParam, out, &callback);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(authParam);
    FreeJson(out);
}
// Ending for auth_session_common.c test.

// Beginning for auth_session_server.c test.
class AuthSessionServerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionServerTest::SetUpTestCase() {}

void AuthSessionServerTest::TearDownTestCase() {}

void AuthSessionServerTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void AuthSessionServerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(AuthSessionServerTest, AuthSessionServerTest0100, TestSize.Level0)
{
    CJson *param = CreateJson();
    if (param == nullptr) {
        return;
    }

    DeviceAuthCallback callback = g_deviceAuthCallBack;
    Session *session = CreateServerAuthSession(param, &callback);
    EXPECT_EQ(session, nullptr);
    FreeJson(param);
}
// Ending for auth_session_server.c test.

// Beginning for auth_session_util.c test.
class AuthSessionUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionUtilTest::SetUpTestCase() {}

void AuthSessionUtilTest::TearDownTestCase() {}

void AuthSessionUtilTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void AuthSessionUtilTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(AuthSessionUtilTest, AuthSessionUtilTest0100, TestSize.Level0)
{
    BaseGroupAuth *base = GetGroupAuth(ACCOUNT_UNRELATED_GROUP_AUTH_TYPE);
    EXPECT_NE(base, nullptr);

    base = GetGroupAuth(ACCOUNT_RELATED_GROUP_AUTH_TYPE);
    EXPECT_NE(base, nullptr);

    base = GetGroupAuth(INVALID_GROUP_AUTH_TYPE);
    EXPECT_EQ(base, nullptr);
}

HWTEST_F(AuthSessionUtilTest, AuthSessionUtilTest0200, TestSize.Level0)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }

    int32_t ret = GetAuthModuleType(in);
    EXPECT_NE(ret, HC_SUCCESS);

    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    ret = GetAuthModuleType(in);
    EXPECT_EQ(ret, DAS_MODULE);

    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    ret = GetAuthModuleType(in);
    EXPECT_EQ(ret, ACCOUNT_MODULE);

    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_ACROSS_ACCOUNT);
    ret = GetAuthModuleType(in);
    EXPECT_EQ(ret, ACCOUNT_MODULE);

    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_INVALID_TYPE);
    ret = GetAuthModuleType(in);
    EXPECT_EQ(ret, INVALID_MODULE_TYPE);
}

HWTEST_F(AuthSessionUtilTest, AuthSessionUtilTest0300, TestSize.Level0)
{
    uint8_t info[] = "TEST"; // For unit test.

    uint32_t strHashLen = SHA256_LEN;
    char *strHash = static_cast<char *>(malloc(strHashLen));
    ASSERT_NE(strHash, nullptr);

    int32_t ret = GetInfoHash(info, sizeof(info), strHash, strHashLen);
    free(strHash);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(AuthSessionUtilTest, AuthSessionUtilTest0301, TestSize.Level0)
{
    uint8_t info[] = "TEST"; // For unit test.

    uint32_t strHashLen = SHA256_LEN * 2 + 1;
    char *strHash = static_cast<char *>(malloc(strHashLen));
    ASSERT_NE(strHash, nullptr);

    int32_t ret = GetInfoHash(info, sizeof(info), strHash, strHashLen);
    free(strHash);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(AuthSessionUtilTest, AuthSessionUtilTest0400, TestSize.Level0)
{
    int32_t ret = GroupTypeToAuthForm(PEER_TO_PEER_GROUP);
    EXPECT_EQ(ret, AUTH_FORM_ACCOUNT_UNRELATED);

    ret = GroupTypeToAuthForm(COMPATIBLE_GROUP);
    EXPECT_EQ(ret, AUTH_FORM_ACCOUNT_UNRELATED);

    ret = GroupTypeToAuthForm(IDENTICAL_ACCOUNT_GROUP);
    EXPECT_EQ(ret, AUTH_FORM_IDENTICAL_ACCOUNT);

    ret = GroupTypeToAuthForm(ACROSS_ACCOUNT_AUTHORIZE_GROUP);
    EXPECT_EQ(ret, AUTH_FORM_ACROSS_ACCOUNT);

    ret = GroupTypeToAuthForm(GROUP_TYPE_INVALID);
    EXPECT_EQ(ret, AUTH_FORM_INVALID_TYPE);
}

HWTEST_F(AuthSessionUtilTest, AuthSessionUtilTest0500, TestSize.Level0)
{
    int32_t ret = AuthFormToGroupType(AUTH_FORM_ACCOUNT_UNRELATED);
    EXPECT_EQ(ret, PEER_TO_PEER_GROUP);

    ret = AuthFormToGroupType(AUTH_FORM_IDENTICAL_ACCOUNT);
    EXPECT_EQ(ret, IDENTICAL_ACCOUNT_GROUP);

    ret = AuthFormToGroupType(AUTH_FORM_ACROSS_ACCOUNT);
    EXPECT_EQ(ret, ACROSS_ACCOUNT_AUTHORIZE_GROUP);

    ret = AuthFormToGroupType(AUTH_FORM_INVALID_TYPE);
    EXPECT_EQ(ret, GROUP_TYPE_INVALID);
}
// Ending for auth_session_util.c test.
}