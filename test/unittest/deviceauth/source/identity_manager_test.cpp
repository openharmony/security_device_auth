/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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
#include "device_auth_defines.h"
#include "device_auth.h"
#include "string_util.h"
#include "cert_operation.h"
#include "identity_manager.h"
#include "identity_common.h"
#include "base/security/device_auth/services/legacy/identity_manager/src/identity_cred.c"

using namespace std;
using namespace testing::ext;

namespace {
static const int TEST_SIGNATURE_LEN = 32;
static const int TEST_OS_ACCOUNT_ID = 100;

#define TEST_GROUP_ID "TestGroupId"
#define TEST_DEVICE_ID "TestDeviceId"
#define TEST_USER_ID "TestUsertId"
#define TEST_REQUEST_JSON_STR "TestRequestJsonStr"
#define TEST_PIN_CODE "11111"

#define UNSUPPORTED_TYPE 0
#define UNSUPPORTED_PROOF_TYPE (-1)
#define TEST_BYTE "TestBytes"
#define TEST_CRED_ID "TestCredId"

extern "C" int32_t GenerateCertInfo(const Uint8Buff *pkInfoStr, const Uint8Buff *pkInfoSignature, CertInfo *certInfo);

class IdentityManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IdentityManagerTest::SetUpTestCase() {}
void IdentityManagerTest::TearDownTestCase() {}

void IdentityManagerTest::SetUp()
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void IdentityManagerTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest001, TestSize.Level0)
{
    int32_t ret = AddCertInfoToJson(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo info = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = AddCertInfoToJson(&info, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    ASSERT_NE(pkInfoStr, nullptr);
    info.pkInfoStr.val = (uint8_t *)pkInfoStr;
    info.pkInfoStr.length = strlen(pkInfoStr) + 1;
    info.signAlg = P256;
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    ret = AddCertInfoToJson(&info, out);
    EXPECT_NE(ret, HC_SUCCESS);
    uint8_t testSignature[TEST_SIGNATURE_LEN] = { 0 };
    info.pkInfoSignature.val = testSignature;
    info.pkInfoSignature.length = TEST_SIGNATURE_LEN;
    ret = AddCertInfoToJson(&info, out);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJsonString(pkInfoStr);
    FreeJson(out);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest002, TestSize.Level0)
{
    Uint8Buff pkInfoBuf = { nullptr, 0 };
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    int32_t ret = GenerateCertInfo(&pkInfoBuf, nullptr, &certInfo);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *pkInfoJson = CreateJson();
    ASSERT_NE(pkInfoJson, nullptr);
    char *pkInfoStr = PackJsonToString(pkInfoJson);
    FreeJson(pkInfoJson);
    pkInfoBuf.val = (uint8_t *)pkInfoStr;
    pkInfoBuf.length = HcStrlen(pkInfoStr) + 1;
    Uint8Buff pkInfoSigBuf = { nullptr, 0 };
    ret = GenerateCertInfo(&pkInfoBuf, &pkInfoSigBuf, &certInfo);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(pkInfoStr);
    HcFree(certInfo.pkInfoStr.val);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest003, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    ASSERT_NE(info, nullptr);
    int32_t ret = GetAccountRelatedCredInfo(TEST_OS_ACCOUNT_ID, TEST_GROUP_ID,
        TEST_DEVICE_ID, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountRelatedCredInfo(TEST_OS_ACCOUNT_ID, nullptr, TEST_DEVICE_ID, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountRelatedCredInfo(TEST_OS_ACCOUNT_ID, TEST_GROUP_ID, nullptr, true, info);
    DestroyIdentityInfo(info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountRelatedCredInfo(TEST_OS_ACCOUNT_ID, TEST_GROUP_ID, TEST_DEVICE_ID, true, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountAsymSharedSecret(TEST_OS_ACCOUNT_ID, nullptr, FIELD_PEER_USER_ID, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo peerCertInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = GetAccountAsymSharedSecret(TEST_OS_ACCOUNT_ID, nullptr, FIELD_PEER_USER_ID, &peerCertInfo, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountSymSharedSecret(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = GetAccountSymSharedSecret(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *urlJson = CreateJson();
    ASSERT_NE(urlJson, nullptr);
    ret = GetAccountSymSharedSecret(in, urlJson, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
    FreeJson(urlJson);
    ret = GetAccountAsymCredInfo(TEST_OS_ACCOUNT_ID, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = GetAccountAsymCredInfo(TEST_OS_ACCOUNT_ID, &certInfo, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetAccountSymCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = GetAccountSymCredInfoByPeerUrl(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    urlJson = CreateJson();
    ASSERT_NE(urlJson, nullptr);
    ret = GetAccountSymCredInfoByPeerUrl(in, urlJson, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
    FreeJson(urlJson);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest004, TestSize.Level0)
{
    const CredentialOperator *credOperator = GetCredentialOperator();
    EXPECT_NE(credOperator, nullptr);
    int32_t ret = credOperator->queryCredential(TEST_REQUEST_JSON_STR, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest005, TestSize.Level0)
{
    Uint8Buff srcPsk = { nullptr, 0 };
    Uint8Buff sharedSecret = { nullptr, 0 };
    int32_t ret = ConvertPsk(&srcPsk, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest006, TestSize.Level0)
{
    const AuthIdentity *identity = GetGroupAuthIdentity();
    EXPECT_NE(identity, nullptr);
    int32_t ret = identity->getCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = identity->getCredInfoByPeerUrl(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    Uint8Buff presharedUrl = { nullptr, 0 };
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getCredInfoByPeerCert(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getCredInfoByPeerCert(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = identity->getCredInfoByPeerCert(in, &certInfo, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByPeerCert(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByPeerCert(in, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo peerCertInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    ret = identity->getSharedSecretByPeerCert(in, &peerCertInfo, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest007, TestSize.Level0)
{
    const AuthIdentity *identity = GetP2pAuthIdentity();
    EXPECT_NE(identity, nullptr);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    int32_t ret = identity->getCredInfosByPeerIdentity(in, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    (void)AddStringToJson(in, FIELD_PEER_CONN_DEVICE_ID, TEST_DEVICE_ID);
    ret = identity->getCredInfosByPeerIdentity(in, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_ACQURIED_TYPE, ACQUIRE_TYPE_INVALID);
    ret = identity->getCredInfosByPeerIdentity(in, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
    ret = identity->getCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = identity->getCredInfoByPeerUrl(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    Uint8Buff presharedUrl = { nullptr, 0 };
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    IdentityInfo *info = nullptr;
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    Uint8Buff sharedSecret = { nullptr, 0 };
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
}

HWTEST_F(IdentityManagerTest, IdentityManagerTest008, TestSize.Level0)
{
    const AuthIdentity *identity = GetPinAuthIdentity();
    EXPECT_NE(identity, nullptr);
    int32_t ret = identity->getCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    ret = identity->getCredInfoByPeerUrl(in, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    Uint8Buff presharedUrl = { nullptr, 0 };
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    IdentityInfo *info = nullptr;
    CJson *urlJson = CreateJson();
    ASSERT_NE(urlJson, nullptr);
    char *urlStr = PackJsonToString(urlJson);
    FreeJson(urlJson);
    ASSERT_NE(urlStr, nullptr);
    presharedUrl.val = (uint8_t *)urlStr;
    presharedUrl.length = HcStrlen(urlStr) + 1;
    ret = identity->getCredInfoByPeerUrl(in, &presharedUrl, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(nullptr, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, nullptr, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(in, FIELD_PIN_CODE, TEST_PIN_CODE);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_ISO, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = identity->getSharedSecretByUrl(in, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(in);
    FreeJsonString(urlStr);
}

class IdentityCredTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
};

void IdentityCredTest::SetUpTestCase() {}
void IdentityCredTest::TearDownTestCase() {}

void IdentityCredTest::SetUp()
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void IdentityCredTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(IdentityCredTest, IdentityCredTest001, TestSize.Level0)
{
    char* urlStr = nullptr;
    int32_t ret = CreateUrlStr(ACCOUNT_UNRELATED, KEY_TYPE_SYM, &urlStr);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJsonString(urlStr);
    ret = CreateUrlStr(ACCOUNT_RELATED, KEY_TYPE_SYM, &urlStr);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJsonString(urlStr);
}

HWTEST_F(IdentityCredTest, IdentityCredTest002, TestSize.Level0)
{
    IdentityProofType tmpType;
    int32_t ret = ConvertISProofTypeToCertType(PROOF_TYPE_PSK, &tmpType);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ConvertISProofTypeToCertType(PROOF_TYPE_PKI, &tmpType);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ConvertISProofTypeToCertType(UNSUPPORTED_TYPE, &tmpType);
    EXPECT_EQ(ret, HC_ERR_NOT_SUPPORT);
}

HWTEST_F(IdentityCredTest, IdentityCredTest003, TestSize.Level0)
{
    Algorithm algType;
    int32_t ret = ConvertISAlgToCertAlg(ALGO_TYPE_P256, &algType);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ConvertISAlgToCertAlg(UNSUPPORTED_TYPE, &algType);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityCredTest, IdentityCredTest004, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    int32_t ret = ISSetISOEntity(info);
    EXPECT_EQ(ret, HC_SUCCESS);
    DestroyIdentityInfo(info);
}

HWTEST_F(IdentityCredTest, IdentityCredTest005, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    int32_t ret = ISSetEcSpekeEntity(info, false);
    EXPECT_EQ(ret, HC_SUCCESS);
    DestroyIdentityInfo(info);

    info = CreateIdentityInfo();
    ret = ISSetEcSpekeEntity(info, true);
    EXPECT_EQ(ret, HC_SUCCESS);
    DestroyIdentityInfo(info);
}

HWTEST_F(IdentityCredTest, IdentityCredTest006, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    CJson *credAuthInfo = CreateJson();
    CJson *context = CreateJson();
    int32_t ret = ISSetCertInfoAndEntity(TEST_OS_ACCOUNT_ID, context, credAuthInfo, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(credAuthInfo, FIELD_DEVICE_ID, TEST_DEVICE_ID);
    ret = ISSetCertInfoAndEntity(TEST_OS_ACCOUNT_ID, context, credAuthInfo, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(credAuthInfo, FIELD_USER_ID, TEST_USER_ID);
    ret = ISSetCertInfoAndEntity(TEST_OS_ACCOUNT_ID, context, credAuthInfo, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
    FreeJson(credAuthInfo);
    DestroyIdentityInfo(info);
}

HWTEST_F(IdentityCredTest, IdentityCredTest007, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    CJson *credAuthInfo = CreateJson();
    int32_t ret = ISSetPreShareUrlAndEntity(credAuthInfo, info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_CRED_TYPE, ACCOUNT_UNRELATED);
    ret = ISSetPreShareUrlAndEntity(credAuthInfo, info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_KEY_FORMAT, SYMMETRIC_KEY);
    ret = ISSetPreShareUrlAndEntity(credAuthInfo, info);
    EXPECT_EQ(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_KEY_FORMAT, ASYMMETRIC_KEY);
    ret = ISSetPreShareUrlAndEntity(credAuthInfo, info);
    EXPECT_EQ(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_KEY_FORMAT, ASYMMETRIC_PUB_KEY);
    ret = ISSetPreShareUrlAndEntity(credAuthInfo, info);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(credAuthInfo);
    DestroyIdentityInfo(info);
}

HWTEST_F(IdentityCredTest, IdentityCredTest008, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    CJson *credAuthInfo = CreateJson();
    CJson *context = CreateJson();
    info->proofType = (IdentityProofType)UNSUPPORTED_PROOF_TYPE;
    int32_t ret = ISSetCertProofAndEntity(context, credAuthInfo, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    info->proofType = PRE_SHARED;
    ret = ISSetCertProofAndEntity(context, credAuthInfo, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    info->proofType = CERTIFICATED;
    ret = ISSetCertProofAndEntity(context, credAuthInfo, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(context, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    ret = ISSetCertProofAndEntity(context, credAuthInfo, true, info);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
    FreeJson(credAuthInfo);
    DestroyIdentityInfo(info);
}

HWTEST_F(IdentityCredTest, IdentityCredTest009, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    CJson *credAuthInfo = CreateJson();
    CJson *context = CreateJson();
    int32_t ret = ISGetIdentityInfo(context, true, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddObjToJson(context, FIELD_CREDENTIAL_OBJ, credAuthInfo);
    ret = ISGetIdentityInfo(context, true, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_PROOF_TYPE, PROOF_TYPE_PSK);
    (void)AddObjToJson(context, FIELD_CREDENTIAL_OBJ, credAuthInfo);
    ret = ISGetIdentityInfo(context, true, &info);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ISGetIdentityInfo(context, false, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_PROOF_TYPE, PROOF_TYPE_PKI);
    (void)AddObjToJson(context, FIELD_CREDENTIAL_OBJ, credAuthInfo);
    ret = ISGetIdentityInfo(context, false, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
    FreeJson(credAuthInfo);
    DestroyIdentityInfo(info);
}

HWTEST_F(IdentityCredTest, IdentityCredTest010, TestSize.Level0)
{
    IdentityInfoVec vec = CreateIdentityInfoVec();
    CJson *context = CreateJson();
    CJson *credAuthInfo = CreateJson();
    int32_t ret = AddIdentityInfoToVec(context, false, &vec);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_PROOF_TYPE, PROOF_TYPE_PSK);
    (void)AddObjToJson(context, FIELD_CREDENTIAL_OBJ, credAuthInfo);
    ret = AddIdentityInfoToVec(context, true, &vec);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(credAuthInfo);
    FreeJson(context);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(IdentityCredTest, IdentityCredTest011, TestSize.Level0)
{
    IdentityInfoVec vec = CreateIdentityInfoVec();
    CJson *context = CreateJson();
    CJson *credAuthInfo = CreateJson();
    int32_t ret = GetCredInfosByPeerIdentity(nullptr, &vec);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetCredInfosByPeerIdentity(context, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetCredInfosByPeerIdentity(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetCredInfosByPeerIdentity(context, &vec);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(credAuthInfo);
    FreeJson(context);
    ClearIdentityInfoVec(&vec);
}

HWTEST_F(IdentityCredTest, IdentityCredTest012, TestSize.Level0)
{
    IdentityInfo *info = CreateIdentityInfo();
    CJson *context = CreateJson();
    Uint8Buff presharedUrl = {nullptr, 0};
    int32_t ret = GetCredInfoByPeerUrl(nullptr, &presharedUrl, &info);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = GetCredInfoByPeerUrl(context, nullptr, &info);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = GetCredInfoByPeerUrl(context, &presharedUrl, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    ret = GetCredInfoByPeerUrl(context, &presharedUrl, &info);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetCredInfoByPeerUrl(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
    DestroyIdentityInfo(info);
}

HWTEST_F(IdentityCredTest, IdentityCredTest013, TestSize.Level0)
{
    CJson *context = CreateJson();
    Uint8Buff credIdByte = {nullptr, 0};
    Uint8Buff sharedSecret = {nullptr, 0};
    int32_t ret = ComputeHkdfKeyAlias(context, TEST_OS_ACCOUNT_ID, &credIdByte, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    AddByteToJson(context, FIELD_NONCE, reinterpret_cast<const uint8_t *>(TEST_BYTE), HcStrlen(TEST_BYTE));
    ret = ComputeHkdfKeyAlias(context, TEST_OS_ACCOUNT_ID, &credIdByte, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest014, TestSize.Level0)
{
    CJson *context = CreateJson();
    Uint8Buff keyAlias = {nullptr, 0};
    Uint8Buff authToken = {nullptr, 0};
    int32_t ret = ComputeAuthToken(TEST_OS_ACCOUNT_ID, TEST_USER_ID, keyAlias, &authToken);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest015, TestSize.Level0)
{
    CJson *context = CreateJson();
    Uint8Buff authToken = {nullptr, 0};
    int32_t ret = GenerateAuthTokenForAccessory(TEST_OS_ACCOUNT_ID, TEST_CRED_ID, context, &authToken);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(context, FIELD_USER_ID, TEST_USER_ID);
    ret = GenerateAuthTokenForAccessory(TEST_OS_ACCOUNT_ID, TEST_CRED_ID, context, &authToken);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest016, TestSize.Level0)
{
    Uint8Buff authToken = {nullptr, 0};
    int32_t ret = GenerateTokenAliasForController(TEST_OS_ACCOUNT_ID, TEST_CRED_ID, &authToken);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityCredTest, IdentityCredTest017, TestSize.Level0)
{
    CJson *context = CreateJson();
    CJson *credAuthInfo = CreateJson();
    Uint8Buff authToken = {nullptr, 0};
    bool isTokenStored = true;
    int32_t ret = GenerateAuthTokenByDevType(TEST_OS_ACCOUNT_ID, context, &authToken, &isTokenStored);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(context, FIELD_CRED_ID, TEST_CRED_ID);
    ret = GenerateAuthTokenByDevType(TEST_OS_ACCOUNT_ID, context, &authToken, &isTokenStored);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddObjToJson(context, FIELD_CREDENTIAL_OBJ, credAuthInfo);
    ret = GenerateAuthTokenByDevType(TEST_OS_ACCOUNT_ID, context, &authToken, &isTokenStored);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_SUBJECT, SUBJECT_ACCESSORY_DEVICE);
    (void)AddObjToJson(context, FIELD_CREDENTIAL_OBJ, credAuthInfo);
    ret = GenerateAuthTokenByDevType(TEST_OS_ACCOUNT_ID, context, &authToken, &isTokenStored);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(credAuthInfo, FIELD_SUBJECT, SUBJECT_MASTER_CONTROLLER);
    (void)AddObjToJson(context, FIELD_CREDENTIAL_OBJ, credAuthInfo);
    ret = GenerateAuthTokenByDevType(TEST_OS_ACCOUNT_ID, context, &authToken, &isTokenStored);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(credAuthInfo);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest018, TestSize.Level0)
{
    CJson *context = CreateJson();
    int32_t ret = ISGetAccountSymSharedSecret(context, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ISGetAccountSymSharedSecret(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    Uint8Buff sharedSecret = {nullptr, 0};
    ret = ISGetAccountSymSharedSecret(context, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(context, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    ret = ISGetAccountSymSharedSecret(context, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest019, TestSize.Level0)
{
    CJson *context = CreateJson();
    int32_t ret = AuthGeneratePsk(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(context, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    ret = AuthGeneratePsk(context, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(context, FIELD_CRED_ID, TEST_CRED_ID);
    ret = AuthGeneratePsk(context, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest020, TestSize.Level0)
{
    int32_t ret = GetSharedSecretForP2pInIso(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityCredTest, IdentityCredTest021, TestSize.Level0)
{
    int32_t ret = GetSharedSecretForP2pInPake(nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *context = CreateJson();
    (void)AddStringToJson(context, FIELD_CRED_ID, TEST_CRED_ID);
    ret = GetSharedSecretForP2pInPake(context, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(context, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    ret = GetSharedSecretForP2pInPake(context, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest022, TestSize.Level0)
{
    Uint8Buff sharedSecret = {nullptr, 0};
    int32_t ret = GetSharedSecretForP2p(nullptr, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretForP2p(nullptr, ALG_ISO, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityCredTest, IdentityCredTest023, TestSize.Level0)
{
    Uint8Buff sharedSecret = {nullptr, 0};
    int32_t ret = GetSharedSecretForUid(nullptr, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretForUid(nullptr, ALG_ISO, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(IdentityCredTest, IdentityCredTest024, TestSize.Level0)
{
    CJson *context = CreateJson();
    Uint8Buff sharedSecret = {nullptr, 0};
    Uint8Buff presharedUrl = {nullptr, 0};
    int32_t ret = GetSharedSecretByUrl(nullptr, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretByUrl(context, nullptr, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretByUrl(context, &presharedUrl, ALG_EC_SPEKE, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretByUrl(context, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    char *urlStr = nullptr;
    (void)CreateUrlStr(ACCOUNT_RELATED, KEY_TYPE_SYM, &urlStr);
    SetPreSharedUrlForProof(urlStr, &presharedUrl);
    ret = GetSharedSecretByUrl(context, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(urlStr);
    urlStr = nullptr;
    (void)CreateUrlStr(ACCOUNT_UNRELATED, KEY_TYPE_SYM, &urlStr);
    SetPreSharedUrlForProof(urlStr, &presharedUrl);
    ret = GetSharedSecretByUrl(context, &presharedUrl, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(urlStr);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest025, TestSize.Level0)
{
    CJson *context = CreateJson();
    int32_t ret = GetCredInfoByPeerCert(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetCredInfoByPeerCert(context, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    CertInfo certInfo = {{nullptr, 0}, {nullptr, 0}, P256, false};
    ret = GetCredInfoByPeerCert(context, &certInfo, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
}

HWTEST_F(IdentityCredTest, IdentityCredTest026, TestSize.Level0)
{
    CertInfo certInfo = {{nullptr, 0}, {nullptr, 0}, P256, false};
    Uint8Buff sharedSecret = {nullptr, 0};
    CJson *context = CreateJson();
    int32_t ret = GetSharedSecretByPeerCert(nullptr, &certInfo, ALG_ISO, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretByPeerCert(context, nullptr, ALG_ISO, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretByPeerCert(context, &certInfo, ALG_ISO, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretByPeerCert(context, &certInfo, ALG_ISO, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = GetSharedSecretByPeerCert(context, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddIntToJson(context, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    ret = GetSharedSecretByPeerCert(context, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    (void)AddStringToJson(context, FIELD_ACROSS_ACCOUNT_CRED_ID, TEST_CRED_ID);
    ret = GetSharedSecretByPeerCert(context, &certInfo, ALG_EC_SPEKE, &sharedSecret);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(context);
}
}