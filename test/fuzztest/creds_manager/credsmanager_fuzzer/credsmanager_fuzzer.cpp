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

#include "credsmanager_fuzzer.h"

#include <ctime>
#include <unistd.h>
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

namespace OHOS {
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
static const std::string TEST_HKS_MAIN_DATA_PATH = "/data/service/el1/public/huks_service/tmp/+0+0+0+0";

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
    RemoveDir(TEST_HKS_MAIN_DATA_PATH.c_str());
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
            if (ret != HC_SUCCESS) {
                return;
            }
        } else {
            ret = gm->processData(TEST_REQ_ID2, g_transmitData, g_transmitDataLen);
            if (ret != HC_SUCCESS) {
                return;
            }
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
}

static bool GenerateTempKeyPair(Uint8Buff *keyAlias)
{
    int res = GetLoaderInstance()->checkKeyExist(keyAlias, false, DEFAULT_OS_ACCOUNT);
    if (res == HC_SUCCESS) {
        printf("Server key pair already exists\n");
        return true;
    }
    printf("Key pair not exist, start to generate\n");
    int32_t authId = 0;
    Uint8Buff authIdBuff = { reinterpret_cast<uint8_t *>(&authId), sizeof(int32_t) };
    ExtraInfo extInfo = { authIdBuff, -1, -1 };
    KeyParams keyParams = { { keyAlias->val, keyAlias->length, true }, false, DEFAULT_OS_ACCOUNT };
    res = GetLoaderInstance()->generateKeyPairWithStorage(&keyParams, TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN, P256,
        KEY_PURPOSE_SIGN_VERIFY, &extInfo);
    if (res != HC_SUCCESS) {
        printf("Generate key pair failed\n");
        return false;
    }
    printf("Generate key pair for server success\n");
    return true;
}

static CJson *GetAsyCredentialJson(const std::string registerInfo)
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

    KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, false, DEFAULT_OS_ACCOUNT };
    int32_t ret = GetLoaderInstance()->exportPublicKey(&keyAliasParams, &serverPk);
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
    ret = GetLoaderInstance()->sign(&keyAliasParams, &messageBuff, P256, &signature);
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
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(registerInfoParams, &returnData);
    if (ret != HC_SUCCESS) {
        return;
    }
    std::string registerInfo(returnData);

    CJson *credJson = GetAsyCredentialJson(registerInfo);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, userId);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    gm->destroyInfo(&returnData);
    ret = gm->createGroup(osAccountId, TEST_REQ_ID, TEST_APP_ID.c_str(), jsonStr);
    FreeJsonString(jsonStr);
    if (ret != HC_SUCCESS) {
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
}

static void CreateClientSymIdenticalAccountGroup(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();

    CJson *credJson = CreateJson();
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
    (void)gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), jsonStr);
    FreeJsonString(jsonStr);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
}

static void CreateServerSymIdenticalAccountGroup(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();

    CJson *credJson = CreateJson();
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
    (void)gm->createGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID.c_str(), jsonStr);
    FreeJsonString(jsonStr);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
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
    std::string registerInfo(returnData);
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
    uint8_t *random = reinterpret_cast<uint8_t *>(HcMalloc(SEED_LEN, 0));
    if (random == nullptr) {
        LOGE("malloc random failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    Uint8Buff randomBuf = { random, SEED_LEN };
    int ret = GetLoaderInstance()->generateRandom(&randomBuf);
    if (ret != 0) {
        LOGE("generate random failed, ret:%" LOG_PUB "d", ret);
        HcFree(random);
        return ret;
    }
    clock_t times = 0;
    uint8_t *input = reinterpret_cast<uint8_t *>(HcMalloc(SEED_LEN + sizeof(clock_t), 0));
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
    seedBuff->val = reinterpret_cast<uint8_t *>(HcMalloc(SEED_LEN, 0));
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
    nonceBuff->val = reinterpret_cast<uint8_t *>(HcMalloc(PAKE_NONCE_LEN, 0));
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
    (void)GetAccountAuthTokenManager()->getToken(osAccountId, token, userId, deviceId);
    certInfo->pkInfoStr.val = reinterpret_cast<uint8_t *>(HcMalloc(token->pkInfoStr.length, 0));
    certInfo->pkInfoStr.length = token->pkInfoStr.length;
    (void)memcpy_s(certInfo->pkInfoStr.val, certInfo->pkInfoStr.length, token->pkInfoStr.val, token->pkInfoStr.length);
    certInfo->pkInfoSignature.val = reinterpret_cast<uint8_t *>(HcMalloc(token->pkInfoSignature.length, 0));
    certInfo->pkInfoSignature.length = token->pkInfoSignature.length;
    (void)memcpy_s(certInfo->pkInfoSignature.val, certInfo->pkInfoSignature.length, token->pkInfoSignature.val,
        token->pkInfoSignature.length);
    certInfo->signAlg = P256;
    DestroyAccountToken(token);
}

static void CredsManagerTest01(void)
{
    int32_t res = GetCredInfosByPeerIdentity(nullptr, nullptr);
    if (res != HC_SUCCESS) {
        return;
    }
    CJson *json = CreateJson();
    res = GetCredInfosByPeerIdentity(json, nullptr);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest02(void)
{
    CJson *json = CreateJson();
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest03(void)
{
    CJson *json = CreateJson();
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest04(void)
{
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest05(void)
{
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_TYPE, TEST_GROUP_ID.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest06(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());

    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest07(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest08(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_UDID, TEST_UDID_SERVER.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest09(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest10(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS2.c_str());
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID2.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest11(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest12(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());

    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest13(void)
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
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest14(void)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t res = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID.c_str(), TEST_ADD_MULTI_PARAM.c_str());
    if (res != HC_SUCCESS) {
        return;
    }
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    (void)AddBoolToJson(json, FIELD_IS_DEVICE_LEVEL, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    res = GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest15(void)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    CJson *addMultiParam = GetAddMultiParams(DEFAULT_OS_ACCOUNT, TEST_UDID_SERVER.c_str(), TEST_AUTH_ID2.c_str(),
        TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM2.c_str());
    AddStringToJson(addMultiParam, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    AddIntToJson(addMultiParam, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    char *addMultiParamStr = PackJsonToString(addMultiParam);
    FreeJson(addMultiParam);
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t res = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID.c_str(), addMultiParamStr);
    FreeJsonString(addMultiParamStr);
    if (res != HC_SUCCESS) {
        return;
    }
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    (void)AddBoolToJson(json, FIELD_IS_DEVICE_LEVEL, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    res = GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest16(void)
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
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest17(void)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    (void)AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    (void)AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID.c_str());
    (void)AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    (void)AddBoolToJson(json, FIELD_IS_DEVICE_LEVEL, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(json, &vec);
    FreeJson(json);
    ClearIdentityInfoVec(&vec);
}

static void CredsManagerTest18(void)
{
    int32_t res = GetCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    if (res != HC_SUCCESS) {
        return;
    }
    CJson *json = CreateJson();
    res = GetCredInfoByPeerUrl(json, nullptr, nullptr);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    res = GetCredInfoByPeerUrl(json, &presharedUrl, nullptr);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest19(void)
{
    CJson *json = CreateJson();
    Uint8Buff presharedUrl = { nullptr, 0 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJson(json);
}

static void CredsManagerTest20(void)
{
    CJson *json = CreateJson();
    CJson *presharedUrlJson = CreateJson();
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest21(void)
{
    CJson *json = CreateJson();
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_KEY_TYPE, KEY_TYPE_SYM);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_CREDENTIAL_TYPE, PRE_SHARED);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    DestroyIdentityInfo(info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest22(void)
{
    CJson *json = CreateJson();
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest23(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest24(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest25(void)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    DestroyIdentityInfo(info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest26(void)
{
    CJson *json = CreateJson();
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, -1);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest27(void)
{
    CJson *json = CreateJson();
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest28(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest29(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest30(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest31(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_UDID, TEST_UDID_SERVER.c_str());
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest32(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest33(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest34(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    AddIntToJson(presharedUrlJson, PRESHARED_URL_KEY_TYPE, KEY_TYPE_ASYM);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(json, &presharedUrl, &info);
    DestroyIdentityInfo(info);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTestInner(CertInfo *certInfo, CJson *json, IdentityInfo *info)
{
    CJson *pkInfoJson = CreateJson();
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    certInfo->pkInfoStr.val = reinterpret_cast<uint8_t *>(pkInfoStr);
    certInfo->pkInfoStr.length = strlen(pkInfoStr) + 1;
    int32_t res = GetCredInfoByPeerCert(json, certInfo, &info);
    FreeJsonString(pkInfoStr);
    if (res != HC_SUCCESS) {
        return;
    }
    pkInfoJson = CreateJson();
    AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_USER_ID.c_str());
    pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    certInfo->pkInfoStr.val = reinterpret_cast<uint8_t *>(pkInfoStr);
    certInfo->pkInfoStr.length = strlen(pkInfoStr) + 1;
    (void)GetCredInfoByPeerCert(json, certInfo, &info);
    FreeJsonString(pkInfoStr);
}

static void CredsManagerTest35(void)
{
    int32_t res = GetCredInfoByPeerCert(nullptr, nullptr, nullptr);
    if (res != HC_SUCCESS) {
        return;
    }
    CJson *json = CreateJson();
    res = GetCredInfoByPeerCert(json, nullptr, nullptr);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    res = GetCredInfoByPeerCert(json, &certInfo, nullptr);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    IdentityInfo *info = nullptr;
    res = GetCredInfoByPeerCert(json, &certInfo, &info);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    res = GetCredInfoByPeerCert(json, &certInfo, &info);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    CredsManagerTestInner(&certInfo, json, info);
    FreeJson(json);
}

static void CredsManagerTest36(void)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    CJson *pkInfoJson = CreateJson();
    AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_USER_ID.c_str());
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    certInfo.pkInfoStr.val = reinterpret_cast<uint8_t *>(pkInfoStr);
    certInfo.pkInfoStr.length = strlen(pkInfoStr) + 1;
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerCert(json, &certInfo, &info);
    FreeJsonString(pkInfoStr);
    FreeJson(json);
}

static void CredsManagerTest37(void)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    CJson *pkInfoJson = CreateJson();
    AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_USER_ID.c_str());
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    certInfo.pkInfoStr.val = reinterpret_cast<uint8_t *>(pkInfoStr);
    certInfo.pkInfoStr.length = strlen(pkInfoStr) + 1;
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerCert(json, &certInfo, &info);
    DestroyIdentityInfo(info);
    FreeJsonString(pkInfoStr);
    FreeJson(json);
}

static void CredsManagerTest38(void)
{
    int32_t res = GetSharedSecretByUrl(nullptr, nullptr, ALG_ISO, nullptr);
    if (res != HC_SUCCESS) {
        return;
    }
    CJson *json = CreateJson();
    res = GetSharedSecretByUrl(json, nullptr, ALG_ISO, nullptr);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, nullptr);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    CJson *presharedUrlJson = CreateJson();
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_KEY_TYPE, KEY_TYPE_SYM);
    presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest39(void)
{
    CJson *json = CreateJson();
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest40(void)
{
    CJson *json = CreateJson();
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    HcFree(sharedSecret.val);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest41(void)
{
    CJson *json = CreateJson();
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    AddIntToJson(presharedUrlJson, PRESHARED_URL_KEY_TYPE, KEY_TYPE_SYM);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest42(void)
{
    CJson *json = CreateJson();
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_PIN);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    HcFree(sharedSecret.val);
    FreeJson(json);
}

static void CredsManagerTest43(void)
{
    CJson *json = CreateJson();
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, -1);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest44(void)
{
    CJson *json = CreateJson();
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest45(void)
{
    CJson *json = CreateJson();
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest46(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest47(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest48(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest49(void)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest50(void)
{
    CreateClientSymIdenticalAccountGroup();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    HcFree(sharedSecret.val);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest51(void)
{
    CreateClientSymIdenticalAccountGroup();
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t res = gm->addMultiMembersToGroup(DEFAULT_OS_ACCOUNT, TEST_APP_ID.c_str(), TEST_ADD_MULTI_PARAM.c_str());
    if (res != HC_SUCCESS) {
        return;
    }
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    res = GetSeedValue(&seedBuff);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    HcFree(sharedSecret.val);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest52(void)
{
    CreateClientSymIdenticalAccountGroup();
    SetDeviceStatus(false);
    CreateServerSymIdenticalAccountGroup();
    SetDeviceStatus(true);
    AuthDemoMember();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_USER_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    HcFree(sharedSecret.val);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest53(void)
{
    CJson *json = CreateJson();
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest54(void)
{
    CJson *json = CreateJson();
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest55(void)
{
    CJson *json = CreateJson();
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest56(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest57(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff seedBuff = { nullptr, 0 };
    int32_t res = GetSeedValue(&seedBuff);
    AddByteToJson(json, FIELD_SEED, seedBuff.val, seedBuff.length);
    HcFree(seedBuff.val);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    HcFree(sharedSecret.val);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest58(void)
{
    CJson *json = CreateJson();
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest59(void)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest60(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(json);
}

static void CredsManagerTest61(void)
{
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID.c_str(), TEST_CREATE_PARAMS.c_str());
    AddDemoMember();
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2.c_str());
    Uint8Buff nonceBuff = { nullptr, 0 };
    int32_t res = GetNonceValue(&nonceBuff);
    AddByteToJson(json, FIELD_NONCE, nonceBuff.val, nonceBuff.length);
    HcFree(nonceBuff.val);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_P2P);
    AddStringToJson(presharedUrlJson, FIELD_GROUP_ID, TEST_GROUP_ID.c_str());
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByUrl(json, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    HcFree(sharedSecret.val);
    FreeJson(json);
    if (res != HC_SUCCESS) {
        return;
    }
}

static void CredsManagerTest62(void)
{
    int32_t res = GetSharedSecretByPeerCert(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    if (res != HC_SUCCESS) {
        return;
    }
    CJson *json = CreateJson();
    res = GetSharedSecretByPeerCert(json, nullptr, ALG_EC_SPEKE, nullptr);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    res = GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, nullptr);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    Uint8Buff sharedSecret = { nullptr, 0 };
    res = GetSharedSecretByPeerCert(json, &certInfo, ALG_ISO, &sharedSecret);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    res = GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    res = GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    if (res != HC_SUCCESS) {
        FreeJson(json);
        return;
    }
    FreeJson(json);
}

static void CredsManagerTest63(void)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    CJson *pkInfoJson = CreateJson();
    AddStringToJson(pkInfoJson, FIELD_USER_ID, TEST_USER_ID.c_str());
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    certInfo.pkInfoStr.val = reinterpret_cast<uint8_t *>(pkInfoStr);
    certInfo.pkInfoStr.length = strlen(pkInfoStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    FreeJsonString(pkInfoStr);
    FreeJson(json);
}

static void CredsManagerTest64(void)
{
    CreateDemoIdenticalAccountGroup(DEFAULT_OS_ACCOUNT, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM.c_str());
    SetDeviceStatus(false);
    CreateDemoIdenticalAccountGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_USER_ID.c_str(), TEST_REGISTER_INFO_PARAM2.c_str());
    SetDeviceStatus(true);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    GetCertInfo(TEST_AUTH_OS_ACCOUNT_ID, TEST_USER_ID.c_str(), TEST_AUTH_ID2.c_str(), &certInfo);
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByPeerCert(json, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    HcFree(certInfo.pkInfoStr.val);
    HcFree(certInfo.pkInfoSignature.val);
    HcFree(sharedSecret.val);
    FreeJson(json);
}

static void FuzzInnerPart1(void)
{
    (void)CredsManagerTest01();
    (void)CredsManagerTest02();
    (void)CredsManagerTest03();
    (void)CredsManagerTest04();
    (void)CredsManagerTest05();
    (void)CredsManagerTest06();
    (void)CredsManagerTest07();
    (void)CredsManagerTest08();
    (void)CredsManagerTest09();
    (void)CredsManagerTest10();
    (void)CredsManagerTest11();
    (void)CredsManagerTest12();
    (void)CredsManagerTest13();
    (void)CredsManagerTest14();
    (void)CredsManagerTest15();
    (void)CredsManagerTest16();
    (void)CredsManagerTest17();
    (void)CredsManagerTest18();
    (void)CredsManagerTest19();
    (void)CredsManagerTest20();
    (void)CredsManagerTest21();
    (void)CredsManagerTest22();
    (void)CredsManagerTest23();
    (void)CredsManagerTest24();
    (void)CredsManagerTest25();
    (void)CredsManagerTest26();
    (void)CredsManagerTest27();
    (void)CredsManagerTest28();
    (void)CredsManagerTest29();
    (void)CredsManagerTest30();
    (void)CredsManagerTest31();
}

static void FuzzInnerPart2(void)
{
    (void)CredsManagerTest32();
    (void)CredsManagerTest33();
    (void)CredsManagerTest34();
    (void)CredsManagerTest35();
    (void)CredsManagerTest36();
    (void)CredsManagerTest37();
    (void)CredsManagerTest38();
    (void)CredsManagerTest39();
    (void)CredsManagerTest40();
    (void)CredsManagerTest41();
    (void)CredsManagerTest42();
    (void)CredsManagerTest43();
    (void)CredsManagerTest44();
    (void)CredsManagerTest45();
    (void)CredsManagerTest46();
    (void)CredsManagerTest47();
    (void)CredsManagerTest48();
    (void)CredsManagerTest49();
    (void)CredsManagerTest50();
    (void)CredsManagerTest51();
    (void)CredsManagerTest52();
    (void)CredsManagerTest53();
    (void)CredsManagerTest54();
    (void)CredsManagerTest55();
    (void)CredsManagerTest56();
    (void)CredsManagerTest57();
    (void)CredsManagerTest58();
    (void)CredsManagerTest59();
    (void)CredsManagerTest60();
    (void)CredsManagerTest61();
    (void)CredsManagerTest62();
    (void)CredsManagerTest63();
    (void)CredsManagerTest64();
}

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    DeleteDatabase();
    InitDeviceAuthService();
    const DeviceGroupManager *gm = GetGmInstance();
    gm->regCallback(TEST_APP_ID.c_str(), &g_gmCallback);
    (void)data;
    (void)size;
    (void)FuzzInnerPart1();
    (void)FuzzInnerPart2();
    DestroyDeviceAuthService();
    return true;
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoCallback(data, size);
    return 0;
}

