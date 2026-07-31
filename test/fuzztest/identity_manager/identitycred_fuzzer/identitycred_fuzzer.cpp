/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "identitycred_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "asy_token_manager.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "identity_manager.h"
#include "json_utils.h"
#include "securec.h"
#include "base/security/device_auth/services/legacy/identity_manager/src/identity_cred.c"

namespace OHOS {
static const std::string TEST_AUTH_ID = "TestAuthId";
static const std::string TEST_USER_ID = "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4";
static const std::string TEST_DEVICE_ID = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";

static void IdentityCredTest01(void)
{
    OpenAccountToken *token = CreateOpenAccountToken();
    if (token == nullptr) {
        return;
    }
    DestroyOpenAccountToken(token);
}

static void IdentityCredTest02(void)
{
    OpenAccountToken *token = CreateOpenAccountToken();
    if (token == nullptr) {
        return;
    }
    OpenAccountToken *token2 = CreateOpenAccountToken();
    if (token2 == nullptr) {
        DestroyOpenAccountToken(token);
        return;
    }
    (void)GetAccountAuthTokenManager()->getOpenToken(DEFAULT_OS_ACCOUNT, token2, TEST_DEVICE_ID.c_str());
    DestroyOpenAccountToken(token);
    DestroyOpenAccountToken(token2);
}

static void IdentityCredTest03(void)
{
    (void)GetAccountAuthTokenManager()->getOpenToken(DEFAULT_OS_ACCOUNT, nullptr, TEST_DEVICE_ID.c_str());
}

static void IdentityCredTest04(void)
{
    OpenAccountToken *token = CreateOpenAccountToken();
    if (token == nullptr) {
        return;
    }
    (void)GetAccountAuthTokenManager()->getOpenToken(DEFAULT_OS_ACCOUNT, token, nullptr);
    DestroyOpenAccountToken(token);
}

static void IdentityCredTest05(void)
{
    OpenAccountToken *token = CreateOpenAccountToken();
    if (token == nullptr) {
        return;
    }
    (void)GetAccountAuthTokenManager()->getOpenToken(DEFAULT_OS_ACCOUNT, token, "");
    DestroyOpenAccountToken(token);
}

static void IdentityCredTest06(void)
{
    IdentityInfo *info = CreateIdentityInfo();
    if (info == nullptr) {
        return;
    }
    (void)ISSetISOEntity(info, ACCOUNT_UNRELATED);
    (void)ISSetISOEntity(info, ACCOUNT_RELATED);
    DestroyIdentityInfo(info);
}

static void IdentityCredTest07(void)
{
    IdentityInfo *info = CreateIdentityInfo();
    if (info == nullptr) {
        return;
    }
    (void)ISSetEcSpekeEntityForAccountUnrelated(info);
    DestroyIdentityInfo(info);
}

static void IdentityCredTest08(void)
{
    IdentityInfo *info = CreateIdentityInfo();
    if (info == nullptr) {
        return;
    }
    (void)ISSetEcSpekeEntityForAccountRelated(info, true);
    (void)ISSetEcSpekeEntityForAccountRelated(info, false);
    DestroyIdentityInfo(info);
}

static void IdentityCredTest09(void)
{
    IdentityProofType returnType = PRE_SHARED;
    (void)ConvertProofType(PROOF_TYPE_PSK, &returnType);
    (void)ConvertProofType(PROOF_TYPE_PKI, &returnType);
    (void)ConvertProofType(0xFF, &returnType);
}

static void IdentityCredTest10(void)
{
    CJson *context = CreateJson();
    if (context == nullptr) {
        return;
    }
    CJson *credAuthInfo = CreateJson();
    if (credAuthInfo == nullptr) {
        FreeJson(context);
        return;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == nullptr) {
        FreeJson(context);
        FreeJson(credAuthInfo);
        return;
    }
    (void)ISSetCertInfoAndEntity(context, credAuthInfo, info);
    DestroyIdentityInfo(info);
    FreeJson(context);
    FreeJson(credAuthInfo);
}

static void IdentityCredTest11(void)
{
    CJson *context = CreateJson();
    if (context == nullptr) {
        return;
    }
    AddIntToJson(context, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(context, FIELD_DEVICE_ID, TEST_DEVICE_ID.c_str());
    AddStringToJson(context, FIELD_USER_ID, TEST_USER_ID.c_str());
    AddBoolToJson(context, FIELD_IS_OPEN_CRED_AUTH, true);
    CJson *credAuthInfo = CreateJson();
    if (credAuthInfo == nullptr) {
        FreeJson(context);
        return;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == nullptr) {
        FreeJson(context);
        FreeJson(credAuthInfo);
        return;
    }
    (void)ISSetCertInfoAndEntity(context, credAuthInfo, info);
    DestroyIdentityInfo(info);
    FreeJson(context);
    FreeJson(credAuthInfo);
}

static void IdentityCredTest12(void)
{
    CJson *context = CreateJson();
    if (context == nullptr) {
        return;
    }
    AddBoolToJson(context, FIELD_IS_OPEN_CRED_AUTH, true);
    CJson *credAuthInfo = CreateJson();
    if (credAuthInfo == nullptr) {
        FreeJson(context);
        return;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == nullptr) {
        FreeJson(context);
        FreeJson(credAuthInfo);
        return;
    }
    (void)ISSetCertInfoAndEntity(context, credAuthInfo, info);
    DestroyIdentityInfo(info);
    FreeJson(context);
    FreeJson(credAuthInfo);
}

static void IdentityCredTest13(void)
{
    CJson *context = CreateJson();
    if (context == nullptr) {
        return;
    }
    IdentityInfo *info = CreateIdentityInfo();
    if (info == nullptr) {
        FreeJson(context);
        return;
    }
    info->proofType = PRE_SHARED;
    (void)ISSetProofAndEntity(context, info);
    info->proofType = CERTIFICATED;
    (void)ISSetProofAndEntity(context, info);
    info->proofType = (IdentityProofType)0xFF;
    (void)ISSetProofAndEntity(context, info);
    DestroyIdentityInfo(info);
    FreeJson(context);
}

static void IdentityCredTest14(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(nullptr, nullptr);
    (void)GetCredInfosByPeerIdentity(in, nullptr);
    (void)GetCredInfosByPeerIdentity(nullptr, &vec);
    (void)GetCredInfosByPeerIdentity(in, &vec);
    ClearIdentityInfoVec(&vec);
    FreeJson(in);
}

static void IdentityCredTest15(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    AddBoolToJson(in, FIELD_IS_OPEN_CRED_AUTH, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(in, &vec);
    ClearIdentityInfoVec(&vec);
    FreeJson(in);
}

static void IdentityCredTest16(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    AddBoolToJson(in, FIELD_IS_OPEN_CRED_AUTH, false);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(in, &vec);
    ClearIdentityInfoVec(&vec);
    FreeJson(in);
}

static void IdentityCredTest17(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CJson *credObj = CreateJson();
    if (credObj == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(credObj, FIELD_PROOF_TYPE, PROOF_TYPE_PSK);
    AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credObj);
    FreeJson(credObj);
    AddBoolToJson(in, FIELD_IS_OPEN_CRED_AUTH, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(in, &vec);
    ClearIdentityInfoVec(&vec);
    FreeJson(in);
}

static void IdentityCredTest18(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CJson *credObj = CreateJson();
    if (credObj == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(credObj, FIELD_PROOF_TYPE, PROOF_TYPE_PKI);
    AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credObj);
    FreeJson(credObj);
    AddBoolToJson(in, FIELD_IS_OPEN_CRED_AUTH, true);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(in, &vec);
    ClearIdentityInfoVec(&vec);
    FreeJson(in);
}

static void IdentityCredTest19(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CJson *credObj = CreateJson();
    if (credObj == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(credObj, FIELD_PROOF_TYPE, 0xFF);
    AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credObj);
    FreeJson(credObj);
    IdentityInfoVec vec = CreateIdentityInfoVec();
    (void)GetCredInfosByPeerIdentity(in, &vec);
    ClearIdentityInfoVec(&vec);
    FreeJson(in);
}

static void IdentityCredTest20(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    Uint8Buff presharedUrl = { nullptr, 0 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(in, &presharedUrl, &info);
    FreeJson(in);
}

static void IdentityCredTest21(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CJson *presharedUrlJson = CreateJson();
    if (presharedUrlJson == nullptr) {
        FreeJson(in);
        return;
    }
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    if (presharedUrlStr == nullptr) {
        FreeJson(in);
        return;
    }
    Uint8Buff presharedUrl = { reinterpret_cast<uint8_t *>(presharedUrlStr), strlen(presharedUrlStr) + 1 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerUrl(in, &presharedUrl, &info);
    FreeJsonString(presharedUrlStr);
    FreeJson(in);
}

static void IdentityCredTest22(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerCert(in, &certInfo, &info);
    FreeJson(in);
}

static void IdentityCredTest23(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CJson *credObj = CreateJson();
    if (credObj == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(credObj, FIELD_PROOF_TYPE, PROOF_TYPE_PKI);
    AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credObj);
    FreeJson(credObj);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerCert(in, &certInfo, &info);
    DestroyIdentityInfo(info);
    FreeJson(in);
}

static void IdentityCredTest24(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CJson *credObj = CreateJson();
    if (credObj == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(credObj, FIELD_PROOF_TYPE, PROOF_TYPE_PSK);
    AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credObj);
    FreeJson(credObj);
    CertInfo certInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    IdentityInfo *info = nullptr;
    (void)GetCredInfoByPeerCert(in, &certInfo, &info);
    FreeJson(in);
}

static void IdentityCredTest25(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CertInfo peerCertInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByPeerCert(in, &peerCertInfo, ALG_EC_SPEKE, &sharedSecret);
    FreeJson(in);
}

static void IdentityCredTest26(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CertInfo peerCertInfo = { { nullptr, 0 }, { nullptr, 0 }, P256 };
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByPeerCert(in, &peerCertInfo, ALG_ISO, &sharedSecret);
    FreeJson(in);
}

static void IdentityCredTest27(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    AddIntToJson(in, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    Uint8Buff presharedUrl = { nullptr, 0 };
    CJson *presharedUrlJson = CreateJson();
    if (presharedUrlJson == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(presharedUrlJson, PRESHARED_URL_TRUST_TYPE, TRUST_TYPE_UID);
    char *presharedUrlStr = PackJsonToString(presharedUrlJson);
    FreeJson(presharedUrlJson);
    if (presharedUrlStr == nullptr) {
        FreeJson(in);
        return;
    }
    presharedUrl.val = reinterpret_cast<uint8_t *>(presharedUrlStr);
    presharedUrl.length = strlen(presharedUrlStr) + 1;
    Uint8Buff sharedSecret = { nullptr, 0 };
    (void)GetSharedSecretByUrl(in, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJsonString(presharedUrlStr);
    FreeJson(in);
}

static void IdentityCredTest28(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    AddIntToJson(in, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    CJson *credObj = CreateJson();
    if (credObj == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(credObj, FIELD_PROOF_TYPE, PROOF_TYPE_PSK);
    AddIntToJson(credObj, FIELD_CRED_TYPE, ACCOUNT_UNRELATED);
    AddIntToJson(credObj, FIELD_KEY_FORMAT, SYMMETRIC_KEY);
    AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credObj);
    FreeJson(credObj);
    IdentityInfo *info = nullptr;
    (void)ISGetIdentityInfo(in, &info);
    DestroyIdentityInfo(info);
    FreeJson(in);
}

static void IdentityCredTest29(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CJson *credObj = CreateJson();
    if (credObj == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(credObj, FIELD_PROOF_TYPE, PROOF_TYPE_PKI);
    AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credObj);
    FreeJson(credObj);
    AddBoolToJson(in, FIELD_IS_OPEN_CRED_AUTH, true);
    IdentityInfo *info = nullptr;
    (void)ISGetIdentityInfo(in, &info);
    DestroyIdentityInfo(info);
    FreeJson(in);
}

static void IdentityCredTest30(void)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    CJson *credObj = CreateJson();
    if (credObj == nullptr) {
        FreeJson(in);
        return;
    }
    AddIntToJson(credObj, FIELD_PROOF_TYPE, PROOF_TYPE_PSK);
    AddIntToJson(credObj, FIELD_CRED_TYPE, ACCOUNT_UNRELATED);
    AddIntToJson(credObj, FIELD_KEY_FORMAT, ASYMMETRIC_KEY);
    AddObjToJson(in, FIELD_CREDENTIAL_OBJ, credObj);
    FreeJson(credObj);
    IdentityInfo *info = nullptr;
    (void)ISGetIdentityInfo(in, &info);
    DestroyIdentityInfo(info);
    FreeJson(in);
}

using TestFunc = void (*)(void);
static TestFunc g_testFuncs[] = {
    IdentityCredTest01,  IdentityCredTest02,  IdentityCredTest03,
    IdentityCredTest04,  IdentityCredTest05,  IdentityCredTest06,
    IdentityCredTest07,  IdentityCredTest08,  IdentityCredTest09,
    IdentityCredTest10,  IdentityCredTest11,  IdentityCredTest12,
    IdentityCredTest13,  IdentityCredTest14,  IdentityCredTest15,
    IdentityCredTest16,  IdentityCredTest17,  IdentityCredTest18,
    IdentityCredTest19,  IdentityCredTest20,  IdentityCredTest21,
    IdentityCredTest22,  IdentityCredTest23,  IdentityCredTest24,
    IdentityCredTest25,  IdentityCredTest26,  IdentityCredTest27,
    IdentityCredTest28,  IdentityCredTest29,  IdentityCredTest30,
};
constexpr size_t TEST_FUNC_COUNT = sizeof(g_testFuncs) / sizeof(g_testFuncs[0]);

bool FuzzDoCallback(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t testId = fdp.ConsumeIntegral<uint32_t>();

    g_testFuncs[testId % TEST_FUNC_COUNT]();

    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    InitDeviceAuthService();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::FuzzDoCallback(data, size);
    return 0;
}
