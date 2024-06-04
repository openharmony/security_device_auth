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

#include <gtest/gtest.h>
#include <unistd.h>
#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "json_utils.h"
#include "nativetoken_kit.h"
#include "os_account_adapter.h"
#include "pseudonym_manager.h"
#include "string_util.h"
#include "token_setproc.h"
#include "want.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_APP_ID "TestAppId"
#define TEST_PDID "TestPdid"
#define TEST_AUTH_ID "TestAuthId"
#define TEST_USER_ID "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4"
#define TEST_GROUP_DATA_PATH "/data/service/el1/public/deviceauthMock"
#define TEST_HKS_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
#define TEST_REQ_ID 123
#define TEST_OS_ACCOUNT_ID 100
#define TEST_OS_ACCOUNT_ID2 105
#define TEST_DEV_AUTH_SLEEP_TIME 100000

enum AsyncStatus {
    ASYNC_STATUS_WAITING = 0,
    ASYNC_STATUS_TRANSMIT = 1,
    ASYNC_STATUS_FINISH = 2,
    ASYNC_STATUS_ERROR = 3
};

static AsyncStatus volatile g_asyncStatus;

static const char *CREATE_PARAMS = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,"
    "\"groupVisibility\":-1,\"userType\":0,\"expireTime\":-1}";
static const char *REGISTER_PARAMS =
    "{\"version\":\"1.0.0\",\"deviceId\":\"TestAuthId\",\"userId\":"
    "\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\"}";
static const char *ADD_MULTI_PARAMS =
    "{\"groupType\":1,\"groupId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\",\"deviceList\":"
    "[{\"deviceId\":\"TestAuthId2\",\"udid\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\",\"credential\":{\"credentialType"
    "\":1,\"authCode\":\"10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92\"}}]}";

static const uint32_t TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN = 32;
static const uint32_t TEST_DEV_AUTH_BUFFER_SIZE = 128;

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return true;
}

static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
    return;
}

static void OnFinish(int64_t requestId, int operationCode, const char *authReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)authReturn;
    g_asyncStatus = ASYNC_STATUS_FINISH;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
    g_asyncStatus = ASYNC_STATUS_ERROR;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char* reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    return nullptr;
}

static DeviceAuthCallback g_gmCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest
};

static void CreateDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId, const char *createParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    EXPECT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static bool GenerateTempKeyPair(Uint8Buff *keyAlias)
{
    int res = GetLoaderInstance()->checkKeyExist(keyAlias);
    if (res == HC_SUCCESS) {
        printf("Server key pair already exists\n");
        return true;
    }
    printf("Key pair not exist, start to generate\n");
    int32_t authId = 0;
    Uint8Buff authIdBuff = { reinterpret_cast<uint8_t *>(&authId), sizeof(int32_t) };
    ExtraInfo extInfo = { authIdBuff, -1, -1 };
    res = GetLoaderInstance()->generateKeyPairWithStorage(keyAlias, TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN, P256,
        KEY_PURPOSE_SIGN_VERIFY, &extInfo);
    if (res != HC_SUCCESS) {
        printf("Generate key pair failed\n");
        return false;
    }
    printf("Generate key pair for server success\n");
    return true;
}

static CJson *GetAsyCredentialJson(string registerInfo)
{
    uint8_t keyAliasValue[] = "TestServerKeyPair";
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = sizeof(keyAliasValue)
    };
    if (!GenerateTempKeyPair(&keyAlias)) {
        return nullptr;
    }
    uint8_t *serverPkVal = reinterpret_cast<uint8_t *>(HcMalloc(SERVER_PK_SIZE, 0));
    Uint8Buff serverPk = {
        .val = serverPkVal,
        .length = SERVER_PK_SIZE
    };

    int32_t ret = GetLoaderInstance()->exportPublicKey(&keyAlias, &serverPk);
    if (ret != HC_SUCCESS) {
        printf("export PublicKey failed\n");
        HcFree(serverPkVal);
        return nullptr;
    }

    Uint8Buff messageBuff = {
        .val = reinterpret_cast<uint8_t *>(const_cast<char *>(registerInfo.c_str())),
        .length = registerInfo.length() + 1
    };
    uint8_t *signatureValue = reinterpret_cast<uint8_t *>(HcMalloc(SIGNATURE_SIZE, 0));
    Uint8Buff signature = {
        .val = signatureValue,
        .length = SIGNATURE_SIZE
    };
    ret = GetLoaderInstance()->sign(&keyAlias, &messageBuff, P256, &signature, true);
    if (ret != HC_SUCCESS) {
        printf("Sign pkInfo failed.\n");
        HcFree(serverPkVal);
        HcFree(signatureValue);
        return nullptr;
    }

    CJson *pkInfoJson = CreateJsonFromString(registerInfo.c_str());
    CJson *credentialJson = CreateJson();
    (void)AddIntToJson(credentialJson, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED);
    (void)AddByteToJson(credentialJson, FIELD_SERVER_PK, serverPkVal, serverPk.length);
    (void)AddByteToJson(credentialJson, FIELD_PK_INFO_SIGNATURE, signatureValue, signature.length);
    (void)AddObjToJson(credentialJson, FIELD_PK_INFO, pkInfoJson);
    FreeJson(pkInfoJson);
    return credentialJson;
}

static void CreateDemoIdenticalAccountGroup(int32_t osAccountId, const char *userId,
    const char *registerInfoParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(registerInfoParams, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    string registerInfo(returnData);

    CJson *credJson = GetAsyCredentialJson(registerInfo);
    ASSERT_NE(credJson, nullptr);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, userId);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    gm->destroyInfo(&returnData);
    ASSERT_NE(jsonStr, nullptr);
    ret = gm->createGroup(osAccountId, TEST_REQ_ID, TEST_APP_ID, jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void NativeTokenSet(void)
{
    const char *acls[] = {
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.MANAGE_LOCAL_ACCOUNTS"
    };
    const char *perms[] = {
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.MANAGE_LOCAL_ACCOUNTS"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 2,
        .dcaps = NULL,
        .perms = perms,
        .acls = acls,
        .processName = "deviceauth_service",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}

static void RemoveDir(const char *path)
{
    char strBuf[TEST_DEV_AUTH_BUFFER_SIZE] = { 0 };
    if (path == nullptr) {
        return;
    }
    if (sprintf_s(strBuf, sizeof(strBuf) - 1, "rm -rf %s", path) < 0) {
        return;
    }
    system(strBuf);
}

static void DeleteDatabase(void)
{
    RemoveDir(TEST_GROUP_DATA_PATH);
    RemoveDir(TEST_HKS_DATA_PATH);
}

static void OnOsAccountUnlocked(int32_t osAccountId)
{
    (void)osAccountId;
}

static void OnOsAccountRemoved(int32_t osAccountId)
{
    (void)osAccountId;
}

static void PublicCommonEvent(bool isUserUnlockEvent, int32_t osAccountId)
{
    OHOS::AAFwk::Want want;
    if (isUserUnlockEvent) {
        want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    } else {
        want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    }
    OHOS::EventFwk::CommonEventData commonData {want};
    commonData.SetCode(osAccountId);
    OHOS::EventFwk::CommonEventManager::PublishCommonEvent(commonData);
}

class OsAccountAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void OsAccountAdapterTest::SetUpTestCase() {}
void OsAccountAdapterTest::TearDownTestCase() {}

void OsAccountAdapterTest::SetUp() {}

void OsAccountAdapterTest::TearDown() {}

HWTEST_F(OsAccountAdapterTest, OsAccountAdapterTest001, TestSize.Level0)
{
    AddOsAccountEventCallback(GROUP_DATA_CALLBACK, nullptr, nullptr);
    RemoveOsAccountEventCallback(GROUP_DATA_CALLBACK);
    InitOsAccountAdapter();
    InitOsAccountAdapter();
    AddOsAccountEventCallback(GROUP_DATA_CALLBACK, nullptr, nullptr);
    AddOsAccountEventCallback(GROUP_DATA_CALLBACK, OnOsAccountUnlocked, nullptr);
    AddOsAccountEventCallback(GROUP_DATA_CALLBACK, OnOsAccountUnlocked, OnOsAccountRemoved);
    AddOsAccountEventCallback(GROUP_DATA_CALLBACK, OnOsAccountUnlocked, OnOsAccountRemoved);
    RemoveOsAccountEventCallback(ASY_TOKEN_DATA_CALLBACK);
    RemoveOsAccountEventCallback(GROUP_DATA_CALLBACK);
    DestroyOsAccountAdapter();
    DestroyOsAccountAdapter();
    int32_t osAccountId = DevAuthGetRealOsAccountLocalId(ANY_OS_ACCOUNT);
    EXPECT_NE(osAccountId, INVALID_OS_ACCOUNT);
    osAccountId = DevAuthGetRealOsAccountLocalId(DEFAULT_OS_ACCOUNT);
    EXPECT_EQ(osAccountId, DEFAULT_OS_ACCOUNT);
    osAccountId = DevAuthGetRealOsAccountLocalId(INVALID_OS_ACCOUNT);
    EXPECT_EQ(osAccountId, INVALID_OS_ACCOUNT);
    int32_t res = GetAllOsAccountIds(nullptr, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    int32_t *osAccountIds = nullptr;
    res = GetAllOsAccountIds(&osAccountIds, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    uint32_t size = 0;
    NativeTokenSet();
    bool status = IsOsAccountUnlocked(DEFAULT_OS_ACCOUNT);
    EXPECT_EQ(status, false);
    status = IsOsAccountUnlocked(TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(status, true);
    res = GetAllOsAccountIds(&osAccountIds, &size);
    EXPECT_EQ(res, HC_SUCCESS);
    HcFree(osAccountIds);
}

HWTEST_F(OsAccountAdapterTest, OsAccountAdapterTest002, TestSize.Level0)
{
    NativeTokenSet();
    DeleteDatabase();
    int32_t res = InitDeviceAuthService();
    EXPECT_EQ(res, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    res = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    EXPECT_EQ(res, HC_SUCCESS);
    int32_t osAccountId = DevAuthGetRealOsAccountLocalId(ANY_OS_ACCOUNT);
    EXPECT_NE(osAccountId, INVALID_OS_ACCOUNT);
    CreateDemoGroup(osAccountId, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    CreateDemoIdenticalAccountGroup(osAccountId, TEST_USER_ID, REGISTER_PARAMS);
    res = gm->addMultiMembersToGroup(osAccountId, TEST_APP_ID, ADD_MULTI_PARAMS);
    EXPECT_EQ(res, HC_SUCCESS);
    res = GetPseudonymInstance()->savePseudonymId(osAccountId, TEST_PDID, TEST_USER_ID, TEST_AUTH_ID, TEST_USER_ID);
    EXPECT_EQ(res, HC_SUCCESS);
    bool status = IsOsAccountUnlocked(osAccountId);
    EXPECT_EQ(status, true);
    PublicCommonEvent(true, osAccountId);
    PublicCommonEvent(false, osAccountId);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    DestroyDeviceAuthService();
}
}