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


#include <cinttypes>
#include <cstring>
#include <unistd.h>
#include <gtest/gtest.h>
#include "device_auth.h"
#include "device_auth_defines.h"
#include "json_utils.h"
#include "securec.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "hc_dev_info.h"
#include "hc_types.h"
#include "base/security/device_auth/services/device_auth.c"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_REQ_ID 123
#define TEST_REQ_ID_0 0
#define TEST_REQ_ID1 124
#define TEST_REQ_ID2 125
#define TEST_OS_ACCOUNT_ID 100
#define TEST_OS_ACCOUNT_ID_0 0
#define TEST_APP_ID "TestAppId"
#define TEST_USER_ID "testUserId"
#define TEST_RANDOM_LEN 16
#define TEST_RANDOM_VAL "17A9B0AC2C578A138C77B76B11CC0FBB"
#define TEST_FIELD_RANDOM_VAL "randomVal"
#define TEST_FIELD_LIGHTMSG "lightAccountMsg"

static const char *TEST_LIGHT_MSG =
"{\"randomVal\": \"17A9B0AC2C578A138C77B76B11CC0FBB\","
"\"version\": \"19\","
"\"userId\": \"12345678901234567\","
"\"deviceId\": \"17A9B0AC2C578A138C77\","
"\"devicePk\": \"17A9B0AC2C578A138C7717A9B0AC2C578A138C7717A9B0A"
"C2C578A138C7717A9B0AC2C578A138C7717A9B0AC2C578A138C7717A9B0AC2C578A138C7711CC0FBB\","
"\"pkInfoSignature\": \"17A9B0AC2C578A138C7717A9B0AC2C578A138C771"
"7A9B0AC2C578A138C7717A9B0AC2C578A138C7717A9B0AC2C5"
"78A138C7717A9B0AC2C578A138C7711CC0FBB\"}";

static const char *OUT_DATA =
"{\"sharedKeyVal\": \"17A9B0AC2C578A138C77B76B11CC0FBB17A9B0AC"
"2C578A138C77B76B11CC0FBB\",\"sharedKeyLen\": \"32\","
"\"randomVal\": \"17A9B0AC2C578A138C77B76B11CC0FBB\","
"\"randomLen\": \"16\","
"\"peerRandomVal\": \"17A9B0AC2C578A138C77B76B11CC0FBB\","
"\"peerRandomLen\": \"16\","
"\"peerUserId\": \"12345678901234567\"}";

static const char *SERVICE_ID = "testServiceID";

static bool OnLightTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return true;
}

static char *OnLightAuthRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddStringToJson(json, FIELD_APP_ID, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static void OnLightSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
}

static void OnLightFinish(int64_t requestId, int operationCode, const char *authReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)authReturn;
}

static void OnLightError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
}

class LaInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LaInterfaceTest::SetUpTestCase() {}
void LaInterfaceTest::TearDownTestCase() {}

void LaInterfaceTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void LaInterfaceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(LaInterfaceTest, LaInterfaceTest001, TestSize.Level0)
{
    (void)InitDeviceAuthService();
    const LightAccountVerifier *lightVerifier = GetLightAccountVerifierInstance();
    ASSERT_NE(lightVerifier, nullptr);

    DeviceAuthCallback laCallback = { NULL };
    int32_t testMsgLen = HcStrlen(TEST_LIGHT_MSG) + 1;
    DataBuff testInMsg = {(uint8_t *)TEST_LIGHT_MSG, testMsgLen};

    int32_t res = lightVerifier->startLightAccountAuth(TEST_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, &laCallback);
    ASSERT_NE(res, HC_SUCCESS);

    res = lightVerifier->processLightAccountAuth(TEST_OS_ACCOUNT_ID, TEST_REQ_ID, &testInMsg, &laCallback);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(LaInterfaceTest, LaInterfaceTest002, TestSize.Level0)
{
    CJson *json = CreateJson();
    int32_t ret = AddStringToJson(json, TEST_FIELD_RANDOM_VAL, TEST_RANDOM_VAL);
    EXPECT_EQ(ret, HC_SUCCESS);
    CJson *out = CreateJsonFromString(OUT_DATA);
    EXPECT_NE(out, nullptr);
    CJson *msg = CreateJsonFromString(TEST_LIGHT_MSG);
    EXPECT_NE(msg, nullptr);
    ret = AddObjToJson(out, TEST_FIELD_LIGHTMSG, msg);
    EXPECT_EQ(ret, HC_SUCCESS);

    DataBuff returnRandom = {0};
    ret = GetRandomValFromOutJson(out, &returnRandom);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = GetRandomValFromOutJson(nullptr, &returnRandom);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetPeerRandomValFromOutJson(out, &returnRandom);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = GetPeerRandomValFromOutJson(nullptr, &returnRandom);
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyDataBuff(&returnRandom);

    ret = LightAuthVerifySign(TEST_OS_ACCOUNT_ID, json, json);
    EXPECT_NE(ret, HC_SUCCESS);

    DeviceAuthCallback laCallback = { NULL };
    laCallback.onTransmit = OnLightTransmit;
    laCallback.onError = OnLightError;
    laCallback.onSessionKeyReturned = OnLightSessionKeyReturned;
    laCallback.onFinish = OnLightFinish;
    laCallback.onRequest = OnLightAuthRequest;

    ret = StartLightAccountAuthInner(TEST_OS_ACCOUNT_ID, TEST_REQ_ID,
        TEST_APP_ID, &laCallback, json);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(json);
    FreeJson(msg);
    FreeJson(out);

    ret = StartLightAccountAuth(TEST_OS_ACCOUNT_ID, TEST_REQ_ID,
        TEST_APP_ID, &laCallback);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(LaInterfaceTest, LaInterfaceTest003, TestSize.Level0)
{
    CJson *out = CreateJsonFromString(OUT_DATA);
    EXPECT_NE(out, nullptr);
    CJson *msg = CreateJsonFromString(TEST_LIGHT_MSG);
    EXPECT_NE(msg, nullptr);
    int32_t ret = AddObjToJson(out, TEST_FIELD_LIGHTMSG, msg);
    EXPECT_EQ(ret, HC_SUCCESS);

    DataBuff returnRandom = { 0 };
    ret = GetRandomValFromOutJson(out, &returnRandom);
    EXPECT_EQ(ret, HC_SUCCESS);

    uint32_t hkdfSaltLen = TEST_RANDOM_LEN + TEST_RANDOM_LEN;
    uint8_t *hkdfSalt = (uint8_t *)HcMalloc(hkdfSaltLen, 0);
    ret = ConstructSaltInner(returnRandom, returnRandom, hkdfSalt, hkdfSaltLen);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(hkdfSalt);

    ret = GetRandomVal(out, returnRandom.data, true, &returnRandom);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = GetRandomVal(nullptr, returnRandom.data, true, &returnRandom);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = GetRandomVal(out, returnRandom.data, false, &returnRandom);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = GetRandomVal(nullptr, returnRandom.data, false, &returnRandom);
    EXPECT_NE(ret, HC_SUCCESS);

    Uint8Buff hkdfSaltBuff = { 0 };
    ret = ConstructSalt(out, returnRandom.data, &hkdfSaltBuff, true);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ConstructSalt(out, returnRandom.data, &hkdfSaltBuff, false);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ConstructSalt(nullptr, returnRandom.data, &hkdfSaltBuff, true);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ConstructSalt(nullptr, returnRandom.data, &hkdfSaltBuff, false);
    EXPECT_NE(ret, HC_SUCCESS);
    HcFree(hkdfSaltBuff.val);
    DestroyDataBuff(&returnRandom);
    FreeJson(out);
    FreeJson(msg);

    Uint8Buff keyInfoBuff = { 0 };
    ret = ConstructKeyInfo(out, SERVICE_ID, &keyInfoBuff, true);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ConstructKeyInfo(out, SERVICE_ID, &keyInfoBuff, false);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(keyInfoBuff.val);
}

HWTEST_F(LaInterfaceTest, LaInterfaceTest004, TestSize.Level0)
{
    CJson *out = CreateJsonFromString(OUT_DATA);
    EXPECT_NE(out, nullptr);
    CJson *msg = CreateJsonFromString(TEST_LIGHT_MSG);
    EXPECT_NE(msg, nullptr);
    int32_t ret = AddObjToJson(out, TEST_FIELD_LIGHTMSG, msg);
    EXPECT_EQ(ret, HC_SUCCESS);

    DataBuff returnRandom = { 0 };
    ret = GetRandomValFromOutJson(out, &returnRandom);
    EXPECT_EQ(ret, HC_SUCCESS);

    DeviceAuthCallback laCallback = { NULL };
    laCallback.onTransmit = OnLightTransmit;
    laCallback.onError = OnLightError;
    laCallback.onSessionKeyReturned = OnLightSessionKeyReturned;
    laCallback.onFinish = OnLightFinish;
    laCallback.onRequest = OnLightAuthRequest;

    Uint8Buff returnKeyBuff = { 0 };
    ret = ComputeHkdfKeyClient(TEST_OS_ACCOUNT_ID, out, returnRandom.data,
        SERVICE_ID, &returnKeyBuff);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ComputeHkdfKeyServer(TEST_OS_ACCOUNT_ID, out, returnRandom.data,
        SERVICE_ID, &returnKeyBuff);
    EXPECT_EQ(ret, HC_SUCCESS);
    HcFree(returnKeyBuff.val);
    DestroyDataBuff(&returnRandom);

    ret = LightAuthOnFinish(TEST_REQ_ID, out, &laCallback);
    EXPECT_EQ(ret, HC_SUCCESS);

    ret = LightAuthOnTransmit(TEST_REQ_ID, out, &laCallback);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(out);
    FreeJson(msg);

    int32_t testMsgLen = HcStrlen(TEST_LIGHT_MSG) + 1;
    DataBuff testInMsg = {(uint8_t *)TEST_LIGHT_MSG, testMsgLen};
    ret = ProcessLightAccountAuth(TEST_OS_ACCOUNT_ID, TEST_REQ_ID, &testInMsg, &laCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ProcessLightAccountAuth(TEST_OS_ACCOUNT_ID, TEST_REQ_ID_0, &testInMsg, &laCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    DestroyDataBuff(&testInMsg);
}

}