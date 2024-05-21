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
#include <ctime>
#include <unistd.h>
#include <gtest/gtest.h>
#include "account_module_defines.h"
#include "alg_loader.h"
#include "asy_token_manager.h"
#include "common_defs.h"
#include "creds_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info_mock.h"
#include "hc_log.h"
#include "json_utils.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {
static const std::string TEST_PIN_CODE = "123456";
static const std::string TEST_APP_ID = "TestAppId";
static const std::string TEST_APP_ID2 = "TestAppId2";
static const std::string TEST_AUTH_ID = "TestAuthId";
static const std::string TEST_AUTH_ID2 = "TestAuthId2";
static const std::string TEST_UDID_CLIENT = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static const std::string TEST_UDID_SERVER = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";
static const std::string TEST_CREATE_PARAMS = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"group"
    "Type\":256,\"groupVisibility\":-1,\"userType\":0,\"expireTime\":-1}";
static const std::string TEST_CREATE_PARAMS2 = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"group"
    "Type\":256,\"groupVisibility\":0,\"userType\":0,\"expireTime\":-1}";
static const std::string TEST_ADD_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\","
    "\"groupType\":256,\"pinCode\":\"123456\"}";
static const std::string TEST_GROUP_ID = "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21";
static const std::string TEST_USER_ID = "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4";
static const std::string TEST_REGISTER_INFO_PARAM =
    "{\"version\":\"1.0.0\",\"deviceId\":\"TestAuthId\",\"userId\":"
    "\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\"}";
static const std::string TEST_REGISTER_INFO_PARAM2 =
    "{\"version\":\"1.0.0\",\"deviceId\":\"TestAuthId2\",\"userId\":"
    "\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\"}";
static const std::string TEST_ADD_MULTI_PARAM =
    "{\"groupType\":1,\"groupId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\",\"deviceList\":"
    "[{\"deviceId\":\"TestAuthId2\",\"udid\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C\","
    "\"userId\":\"4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4\",\"credential\":{\"credentialType"
    "\":1,\"authCode\":\"10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92\"}}]}";
static const std::string TEST_AUTH_PARAMS = "{\"peerConnDeviceId\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\",\"servicePkgName\":\"TestAppId\",\"isClient\":true}";
static const std::string TEST_AUTH_CODE = "1234123412341234123412341234123412341234123412341234123412341234";
static const std::string TEST_GROUP_DATA_PATH = "/data/service/el1/public/deviceauthMock";
static const std::string TEST_HKS_DATA_PATH = "/data/service/el1/public/huks_service/tmp/+0+0+0+0";

static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;
static const int32_t TEST_AUTH_OS_ACCOUNT_ID = 100;
static const int64_t TEST_REQ_ID = 123;
static const int64_t TEST_REQ_ID2 = 321;
static const uint32_t TEST_DEV_AUTH_SLEEP_TIME = 50000;
static const uint32_t TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN = 32;

enum AsyncStatus {
    ASYNC_STATUS_WAITING = 0,
    ASYNC_STATUS_TRANSMIT = 1,
    ASYNC_STATUS_FINISH = 2,
    ASYNC_STATUS_ERROR = 3
};

static AsyncStatus volatile g_asyncStatus;
static uint8_t g_transmitData[2048] = { 0 };
static uint32_t g_transmitDataLen = 0;

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    if (memcpy_s(g_transmitData, sizeof(g_transmitData), data, dataLen) != EOK) {
        return false;
    }
    g_transmitDataLen = dataLen;
    g_asyncStatus = ASYNC_STATUS_TRANSMIT;
    return true;
}

static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
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
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2.c_str());
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnAuthRequest(int64_t requestId, int operationCode, const char* reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT.c_str());
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static DeviceAuthCallback g_gmCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest
};

static DeviceAuthCallback g_gaCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequest
};

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

static void DeleteDatabase()
{
    RemoveDir(TEST_GROUP_DATA_PATH.c_str());
    RemoveDir(TEST_HKS_DATA_PATH.c_str());
}

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
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void AddDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_ADD_PARAMS.c_str());
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        if (isClient) {
            ret = gm->processData(TEST_REQ_ID, g_transmitData, g_transmitDataLen);
        } else {
            ret = gm->processData(TEST_REQ_ID2, g_transmitData, g_transmitDataLen);
        }
        (void)memset_s(g_transmitData, sizeof(g_transmitData), 0, sizeof(g_transmitData));
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    SetDeviceStatus(true);
}

static void AuthDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    int32_t ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_AUTH_PARAMS.c_str(), &g_gaCallback);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        if (isClient) {
            ret = ga->processData(TEST_REQ_ID, g_transmitData, g_transmitDataLen, &g_gaCallback);
        } else {
            ret = ga->processData(TEST_REQ_ID2, g_transmitData, g_transmitDataLen, &g_gaCallback);
        }
        (void)memset_s(g_transmitData, sizeof(g_transmitData), 0, sizeof(g_transmitData));
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    SetDeviceStatus(true);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
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
    ret = gm->createGroup(osAccountId, TEST_REQ_ID, TEST_APP_ID.c_str(), jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void CreateClientSymIdenticalAccountGroup(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);

    CJson *credJson = CreateJson();
    ASSERT_NE(credJson, nullptr);
    (void)AddIntToJson(credJson, FIELD_CREDENTIAL_TYPE, SYMMETRIC_CRED);
    (void)AddStringToJson(credJson, FIELD_AUTH_CODE, TEST_AUTH_CODE.c_str());
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID.c_str());
    AddStringToJson(json, FIELD_USER_ID, TEST_USER_ID.c_str());
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    ASSERT_NE(jsonStr, nullptr);
    int32_t res = gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(res, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void CreateServerSymIdenticalAccountGroup(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);

    CJson *credJson = CreateJson();
    ASSERT_NE(credJson, nullptr);
    (void)AddIntToJson(credJson, FIELD_CREDENTIAL_TYPE, SYMMETRIC_CRED);
    (void)AddStringToJson(credJson, FIELD_AUTH_CODE, TEST_AUTH_CODE.c_str());
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2.c_str());
    AddStringToJson(json, FIELD_USER_ID, TEST_USER_ID.c_str());
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    ASSERT_NE(jsonStr, nullptr);
    int32_t res = gm->createGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID.c_str(), jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(res, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static CJson *GetAddMultiParams(int32_t osAccountId, const char *udid, const char *deviceId, const char *userId,
    const char *registerInfoParams)
{
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm == nullptr) {
        return nullptr;
    }
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(registerInfoParams, &returnData);
    if (ret != HC_SUCCESS) {
        return nullptr;
    }
    string registerInfo(returnData);
    CJson *credJson = GetAsyCredentialJson(registerInfo);
    gm->destroyInfo(&returnData);
    if (credJson == nullptr) {
        return nullptr;
    }

    CJson *credInfo = CreateJson();
    AddStringToJson(credInfo, FIELD_UDID, udid);
    AddStringToJson(credInfo, FIELD_DEVICE_ID, deviceId);
    AddStringToJson(credInfo, FIELD_USER_ID, userId);
    AddObjToJson(credInfo, FIELD_CREDENTIAL, credJson);

    CJson *deviceList = CreateJsonArray();
    AddObjToArray(deviceList, credInfo);
    CJson *addMultiParam = CreateJson();
    AddObjToJson(addMultiParam, FIELD_DEVICE_LIST, deviceList);
    AddStringToJson(addMultiParam, FIELD_UDID, udid);

    FreeJson(credJson);
    FreeJson(deviceList);
    return addMultiParam;
}

static int32_t GenerateSeed(Uint8Buff *seed)
{
    uint8_t *random = (uint8_t *)HcMalloc(SEED_LEN, 0);
    if (random == nullptr) {
        LOGE("malloc random failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff randomBuf = { random, SEED_LEN };
    int ret = GetLoaderInstance()->generateRandom(&randomBuf);
    if (ret != 0) {
        LOGE("generate random failed, ret:%d", ret);
        HcFree(random);
        return ret;
    }
    clock_t times = 0;
    uint8_t *input = (uint8_t *)HcMalloc(SEED_LEN + sizeof(clock_t), 0);
    if (input == nullptr) {
        LOGE("malloc failed");
        HcFree(random);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(input, SEED_LEN + sizeof(clock_t), random, SEED_LEN) != EOK) {
        LOGE("memcpy seed failed.");
        HcFree(random);
        HcFree(input);
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(input + SEED_LEN, sizeof(clock_t), &times, sizeof(clock_t)) != EOK) {
        LOGE("memcpy times failed.");
        HcFree(random);
        HcFree(input);
        return HC_ERR_MEMORY_COPY;
    }
    Uint8Buff inputBuf = { input, SEED_LEN + sizeof(clock_t) };
    ret = GetLoaderInstance()->sha256(&inputBuf, seed);
    if (ret != HC_SUCCESS) {
        LOGE("sha256 failed.");
    }
    HcFree(random);
    HcFree(input);
    return ret;
}

static int32_t GetSeedValue(Uint8Buff *seedBuff)
{
    seedBuff->val = (uint8_t *)HcMalloc(SEED_LEN, 0);
    if (seedBuff->val == NULL) {
        LOGE("Failed to alloc seed memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    seedBuff->length = SEED_LEN;
    int32_t ret = GenerateSeed(seedBuff);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate seed!");
        FreeUint8Buff(seedBuff);
    }
    return ret;
}

static int32_t GetNonceValue(Uint8Buff *nonceBuff)
{
    nonceBuff->val = (uint8_t *)HcMalloc(PAKE_NONCE_LEN, 0);
    if (nonceBuff->val == NULL) {
        LOGE("Failed to malloc nonce value!");
        return HC_ERR_ALLOC_MEMORY;
    }
    nonceBuff->length = PAKE_NONCE_LEN;
    int32_t ret = GetLoaderInstance()->generateRandom(nonceBuff);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to generate random!");
        FreeUint8Buff(nonceBuff);
    }
    return ret;
}

static void GetCertInfo(int32_t osAccountId, const char *userId, const char *deviceId, CertInfo *certInfo)
{
    AccountToken *token = CreateAccountToken();
    ASSERT_NE(token, nullptr);
    int32_t res = GetAccountAuthTokenManager()->getToken(osAccountId, token, userId, deviceId);
    ASSERT_EQ(res, HC_SUCCESS);
    certInfo->pkInfoStr.val = (uint8_t *)HcMalloc(token->pkInfoStr.length, 0);
    ASSERT_NE(certInfo->pkInfoStr.val, nullptr);
    certInfo->pkInfoStr.length = token->pkInfoStr.length;
    (void)memcpy_s(certInfo->pkInfoStr.val, certInfo->pkInfoStr.length, token->pkInfoStr.val, token->pkInfoStr.length);
    certInfo->pkInfoSignature.val = (uint8_t *)HcMalloc(token->pkInfoSignature.length, 0);
    ASSERT_NE(certInfo->pkInfoSignature.val, nullptr);
    certInfo->pkInfoSignature.length = token->pkInfoSignature.length;
    (void)memcpy_s(certInfo->pkInfoSignature.val, certInfo->pkInfoSignature.length, token->pkInfoSignature.val,
        token->pkInfoSignature.length);
    certInfo->signAlg = P256;
    DestroyAccountToken(token);
}

class CredsManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CredsManagerTest::SetUpTestCase() {}
void CredsManagerTest::TearDownTestCase() {}

void CredsManagerTest::SetUp()
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    ret = gm->regCallback(TEST_APP_ID.c_str(), &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
}

void CredsManagerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(CredsManagerTest, CredsManagerTest001, TestSize.Level0)
{
    int32_t res = GetCredInfosByPeerIdentity(nullptr, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    CJson *json = CreateJson();
    res = GetCredInfosByPeerIdentity(json, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest002, TestSize.Level0)
{
    CJson *json = CreateJson();
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest003, TestSize.Level0)
{
    CJson *json = CreateJson();
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest004, TestSize.Level0)
{
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_ERR_NO_CANDIDATE_GROUP);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest005, TestSize.Level0)
{
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_TYPE, TEST_GROUP_ID.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_ERR_NO_CANDIDATE_GROUP);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest006, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());

    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest007, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest008, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_UDID, TEST_UDID_SERVER.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest009, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest010, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS2.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID2.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest011, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest012, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());

    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest013, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    (void)AddBoolToJson(json, FIELD_IS_DEVICE_LEVEL, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest014, TestSize.Level0)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t res = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID.c_str(), TEST_ADD_MULTI_PARAM.c_str());
    ASSERT_EQ(res, HC_SUCCESS);
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    (void)AddBoolToJson(json, FIELD_IS_DEVICE_LEVEL, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest015, TestSize.Level0)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    CJson *addMultiParam = GetAddMultiParams(DEFAULT_OS_ACCOUNT, TEST_UDID_SERVER.c_str(), TEST_AUTH_ID2.c_str(),
        TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM2.c_str());
    AddStringToJson(addMultiParam, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    AddIntToJson(addMultiParam, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    char *addMultiParamStr = PackJsonToString(addMultiParam);
    FreeJson(addMultiParam);
    ASSERT_NE(addMultiParamStr, nullptr);
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t res = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID.c_str(), addMultiParamStr);
    FreeJsonString(addMultiParamStr);
    ASSERT_EQ(res, HC_SUCCESS);

    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    (void)AddBoolToJson(json, FIELD_IS_DEVICE_LEVEL, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest016, TestSize.Level0)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    SetDeviceStatus(false);
    CreateDemoIdenticalAccountGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM2.c_str());
    SetDeviceStatus(true);
    AuthDemoMember();
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    (void)AddBoolToJson(json, FIELD_IS_DEVICE_LEVEL, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest017, TestSize.Level0)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    (void)AddBoolToJson(json, FIELD_IS_DEVICE_LEVEL, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    int32_t res = GetCredInfosByPeerIdentity(json, &vec);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(CredsManagerTest, CredsManagerTest018, TestSize.Level0)
{
    int32_t res = GetCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);

    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    res = GetCredInfoByPeerUrl(json, nullptr, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);

    Uint8Buff presharedUrl = { nullptr, 0 };
    res = GetCredInfoByPeerUrl(json, &presharedUrl, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);

    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest019, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff presharedUrl = { nullptr, 0 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_JSON_CREATE);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest020, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest021, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_KEY_TYPE, KEY_TYPE_SYM);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_CREDENTIAL_TYPE, PRE_SHARED);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_SUCCESS);
    DestroyIdentityInfo(info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest022, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest023, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest024, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_GROUP_NOT_EXIST);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest025, TestSize.Level0)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_SUCCESS);
    DestroyIdentityInfo(info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest026, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, -1);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest027, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest028, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest029, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_GROUP_NOT_EXIST);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest030, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest031, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_UDID, TEST_UDID_SERVER.c_str());
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_DEVICE_NOT_EXIST);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest032, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_DEVICE_NOT_EXIST);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest033, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest034, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    AddIntToJson(presharedUrlJson, PRESHARED_URL_KEY_TYPE, KEY_TYPE_ASYM);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    Uint8Buff presharedUrl = { (uint8_t *)presharedUrlStr, strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    EXPECT_EQ(res, HC_SUCCESS);
    DestroyIdentityInfo(info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest035, TestSize.Level0)
{
    int32_t res = GetCredInfoByPeerCert(nullptr, nullptr, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    res = GetCredInfoByPeerCert(json, nullptr, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    res = GetCredInfoByPeerCert(json, &certInfo, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    IdentityInfo *info = nullptr;
    res = GetCredInfoByPeerCert(json, &certInfo, &info);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    res = GetCredInfoByPeerCert(json, &certInfo, &info);
    EXPECT_EQ(res, HC_ERR_GROUP_NOT_EXIST);
    CJson *pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    ASSERT_NE(pkInfoStr, nullptr);
    certInfo.pkInfoStr.val = (uint8_t *)pkInfoStr;
    certInfo.pkInfoStr.length = strlen(pkInfoStr) + 1;
    res = GetCredInfoByPeerCert(json, &certInfo, &info);
    EXPECT_EQ(res, HC_ERR_GROUP_NOT_EXIST);
    FreeJsonString(pkInfoStr);
    pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_USER_ID.c_str());
    pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    ASSERT_NE(pkInfoStr, nullptr);
    certInfo.pkInfoStr.val = (uint8_t *)pkInfoStr;
    certInfo.pkInfoStr.length = strlen(pkInfoStr) + 1;
    res = GetCredInfoByPeerCert(json, &certInfo, &info);
    EXPECT_EQ(res, HC_ERR_GROUP_NOT_EXIST);
    FreeJsonString(pkInfoStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest036, TestSize.Level0)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    CJson *pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_USER_ID.c_str());
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    ASSERT_NE(pkInfoStr, nullptr);
    certInfo.pkInfoStr.val = (uint8_t *)pkInfoStr;
    certInfo.pkInfoStr.length = strlen(pkInfoStr) + 1;
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerCert(json, &certInfo, &info);
    EXPECT_EQ(res, HC_ERROR);
    FreeJsonString(pkInfoStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest037, TestSize.Level0)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    CJson *pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_USER_ID.c_str());
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    ASSERT_NE(pkInfoStr, nullptr);
    certInfo.pkInfoStr.val = (uint8_t *)pkInfoStr;
    certInfo.pkInfoStr.length = strlen(pkInfoStr) + 1;
    IdentityInfo *info = nullptr;
    int32_t res = GetCredInfoByPeerCert(json, &certInfo, &info);
    EXPECT_EQ(res, HC_SUCCESS);
    DestroyIdentityInfo(info);
    FreeJsonString(pkInfoStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest038, TestSize.Level0)
{
    int32_t res = GetSharedSecretByUrl(nullptr, nullptr, ALG_ISO, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    res = GetSharedSecretByUrl(json, nullptr, ALG_ISO, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    Uint8Buff presharedUrl = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    EXPECT_EQ(res, HC_ERR_JSON_CREATE);
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_KEY_TYPE, KEY_TYPE_SYM);
    presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest039, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest040, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    EXPECT_EQ(res, HC_SUCCESS);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_SUCCESS);
    HcFree(sharedSecret.val);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest041, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_KEY_TYPE, KEY_TYPE_SYM);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest042, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_SUCCESS);
    HcFree(sharedSecret.val);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest043, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, -1);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest044, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest045, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest046, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest047, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_DEVICE_NOT_EXIST);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest048, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_DEVICE_NOT_EXIST);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest049, TestSize.Level0)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest050, TestSize.Level0)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    EXPECT_EQ(res, HC_SUCCESS);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_SUCCESS);
    HcFree(sharedSecret.val);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest051, TestSize.Level0)
{
    CreateClientSymIdenticalAccountGroup();
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t res = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID.c_str(), TEST_ADD_MULTI_PARAM.c_str());
    ASSERT_EQ(res, HC_SUCCESS);
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    res = GetSeedValue(&seedBuff);
    EXPECT_EQ(res, HC_SUCCESS);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_SUCCESS);
    HcFree(sharedSecret.val);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest052, TestSize.Level0)
{
    CreateClientSymIdenticalAccountGroup();
    SetDeviceStatus(false);
    CreateServerSymIdenticalAccountGroup();
    SetDeviceStatus(true);
    AuthDemoMember();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    EXPECT_EQ(res, HC_SUCCESS);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_SUCCESS);
    HcFree(sharedSecret.val);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest053, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest054, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest055, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    EXPECT_EQ(res, HC_SUCCESS);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest056, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    EXPECT_EQ(res, HC_SUCCESS);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_DEVICE_NOT_EXIST);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest057, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    EXPECT_EQ(res, HC_SUCCESS);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    HcFree(sharedSecret.val);
    EXPECT_NE(res, HC_SUCCESS);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest058, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest059, TestSize.Level0)
{
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_DEVICE_NOT_EXIST);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest060, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest061, TestSize.Level0)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff nonceBuff = { nullptr, 0 };
    int32_t res = GetNonceValue(&nonceBuff);
    EXPECT_EQ(res, HC_SUCCESS);
    AddByteToJson(json, FIELD_NONCE, nonceBuff.val, nonceBuff.length);
    HcFree(nonceBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    ASSERT_NE(presharedUrlJson, nullptr);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    ASSERT_NE(presharedUrlStr, nullptr);
    presharedUrl.val = (uint8_t *)presharedUrlStr;
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    EXPECT_EQ(res, HC_SUCCESS);
    HcFree(sharedSecret.val);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest062, TestSize.Level0)
{
    int32_t res = GetSharedSecretByPeerCert(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    res = GetSharedSecretByPeerCert(json, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    res = GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByPeerCert(json, &certInfo, ALG_ISO, &sharedSecret);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    res = GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_EQ(res, HC_ERR_JSON_GET);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    res = GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_EQ(res, HC_ERR_GROUP_NOT_EXIST);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest063, TestSize.Level0)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    CJson *pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_USER_ID.c_str());
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    ASSERT_NE(pkInfoStr, nullptr);
    certInfo.pkInfoStr.val = (uint8_t *)pkInfoStr;
    certInfo.pkInfoStr.length = strlen(pkInfoStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_EQ(res, HC_ERR_VERIFY_FAILED);
    FreeJsonString(pkInfoStr);
    FreeJson(json);
}

HWTEST_F(CredsManagerTest, CredsManagerTest064, TestSize.Level0)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    SetDeviceStatus(false);
    CreateDemoIdenticalAccountGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM2.c_str());
    SetDeviceStatus(true);
    CJson *json = CreateJson();
    ASSERT_NE(json, nullptr);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    GetCertInfo(TEST_AUTH_OS_ACCOUNT_ID, TEST_USER_ID.c_str(), TEST_AUTH_ID2.c_str(), &certInfo);
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t res = GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_EQ(res, HC_SUCCESS);
    HcFree(certInfo.pkInfoStr.val);
    HcFree(certInfo.pkInfoSignature.val);
    HcFree(sharedSecret.val);
    FreeJson(json);
}
}