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

#include "pakeauthtask_fuzzer.h"

#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info_mock.h"
#include "json_utils.h"
#include "protocol_task_main_mock.h"
#include "securec.h"
#include "json_utils.h"
#include "string_util.h"
#include "account_task_main.h"
#include "pake_v2_auth_client_task.h"
#include "pake_v2_auth_server_task.h"
#include "pake_v2_auth_task_common.h"
#include "account_version_util.h"
#include "asy_token_manager.h"
#include "pake_defs.h"

namespace OHOS {
static void PakeV2AuthClientTaskTest001(void)
{
    CJson *in = nullptr;
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    (void)CreatePakeV2AuthClientTask(in, out, verInfo);
}

static void PakeV2AuthClientTaskTest002(void)
{
    CJson *in = CreateJson();
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    (void)CreatePakeV2AuthClientTask(in, out, verInfo);
    FreeJson(in);
}

static void PakeV2AuthClientTaskTest003(void)
{
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    AccountVersionInfo *verInfo = nullptr;
    (void)CreatePakeV2AuthClientTask(in, out, verInfo);
    FreeJson(in);
    FreeJson(out);
}

static void PakeV2AuthClientTaskTest004(void)
{
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    AccountVersionInfo verInfo;
    (void)CreatePakeV2AuthClientTask(in, out, &verInfo);
    FreeJson(in);
    FreeJson(out);
}

static void PakeV2AuthServerTaskTest001(void)
{
    CJson *in = nullptr;
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    (void)CreatePakeV2AuthServerTask(in, out, verInfo);
}

static void PakeV2AuthServerTaskTest002(void)
{
    CJson *in = CreateJson();
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    (void)CreatePakeV2AuthServerTask(in, out, verInfo);
    FreeJson(in);
}

static void PakeV2AuthServerTaskTest003(void)
{
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    AccountVersionInfo *verInfo = nullptr;
    (void)CreatePakeV2AuthServerTask(in, out, verInfo);
    FreeJson(in);
    FreeJson(out);
}

static void PakeV2AuthServerTaskTest004(void)
{
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    AccountVersionInfo verInfo;
    (void)CreatePakeV2AuthServerTask(in, out, &verInfo);
    FreeJson(in);
    FreeJson(out);
}

static void PakeV2AuthTaskCommonTest001(void)
{
    CJson *in = nullptr;
    PakeAuthParams *params = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    (void)InitPakeAuthParams(in, params, verInfo);
}

static void PakeV2AuthTaskCommonTest002(void)
{
    CJson *in = CreateJson();
    PakeAuthParams *params = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    (void)InitPakeAuthParams(in, params, verInfo);
    FreeJson(in);
}

static void PakeV2AuthTaskCommonTest003(void)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo *verInfo = nullptr;
    (void)InitPakeAuthParams(in, &params, verInfo);
    FreeJson(in);
}

static void PakeV2AuthTaskCommonTest004(void)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    (void)InitPakeAuthParams(in, &params, &verInfo);
    FreeJson(in);
}

static void PakeV2AuthTaskCommonTest005(void)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    (void)AddStringToJson(in, FIELD_SELF_DEVICE_ID, "device_id_unit_test");
    (void)InitPakeAuthParams(in, &params, &verInfo);
    FreeJson(in);
}

static void PakeV2AuthTaskCommonTest006(void)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    (void)AddStringToJson(in, FIELD_SELF_DEVICE_ID, "device_id_unit_test");
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, 0);
    (void)InitPakeAuthParams(in, &params, &verInfo);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
}

static void PakeV2AuthTaskCommonTest007(void)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    (void)AddStringToJson(in, FIELD_SELF_DEVICE_ID, "device_id_unit_test");
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, 0);
    (void)AddStringToJson(in, FIELD_SELF_USER_ID, "self_user_id_unit_test");
    (void)InitPakeAuthParams(in, &params, &verInfo);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
}

static void PakeV2AuthTaskCommonTest008(void)
{
    CJson *in = CreateJson();
    PakeAuthParams params;
    AccountVersionInfo verInfo;
    (void)AddStringToJson(in, FIELD_SELF_DEVICE_ID, "device_id_unit_test");
    (void)AddIntToJson(in, FIELD_OS_ACCOUNT_ID, 0);
    (void)AddStringToJson(in, FIELD_SELF_USER_ID, "self_user_id_unit_test");
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
    (void)InitPakeAuthParams(in, &params, &verInfo);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
}

static void PakeV2AuthTaskCommonTest009(void)
{
    (void)IsPakeV2AuthTaskSupported();
    CJson *in = nullptr;
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    (void)CreatePakeV2AuthTask(in, out, verInfo);
}

static void PakeV2AuthTaskCommonTest010(void)
{
    CJson *in = CreateJson();
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
    CJson *out = nullptr;
    AccountVersionInfo *verInfo = nullptr;
    (void)CreatePakeV2AuthTask(in, out, verInfo);
    FreeJson(in);
}

static void PakeV2AuthTaskCommonTest011(void)
{
    PakeAuthParams params;
    InitTokenManager();
    (void)VerifyPkSignPeer(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest012(void)
{
    PakeAuthParams params;
    InitTokenManager();
    (void)GenerateEcdhSharedKey(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest013(void)
{
    PakeAuthParams *params = nullptr;
    CJson *in = nullptr;
    InitTokenManager();
    (void)GetPkInfoPeer(params, in);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest014(void)
{
    PakeAuthParams params;
    CJson *in = nullptr;
    InitTokenManager();
    (void)GetPkInfoPeer(&params, in);
    in = CreateJson();
    (void)GetPkInfoPeer(&params, in);
    (void)AddStringToJson(in, FIELD_AUTH_PK_INFO, "auth_pk_info");
    (void)GetPkInfoPeer(&params, in);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest015(void)
{
    PakeAuthParams *params = nullptr;
    InitTokenManager();
    CJson *in = CreateJson();
    (void)AddStringToJson(in, FIELD_AUTH_PK_INFO, "auth_pk_info");
    DestroyPakeAuthParams(params);
    DestroyTokenManager();
    FreeJson(in);
}

static void PakeV2AuthTaskCommonTest016(void)
{
    PakeAuthParams *params = nullptr;
    CJson *in = nullptr;
    InitTokenManager();
    (void)ExtractPakePeerId(params, in);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest017(void)
{
    PakeAuthParams params;
    CJson *in = nullptr;
    InitTokenManager();
    (void)ExtractPakePeerId(&params, in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest018(void)
{
    PakeAuthParams params;
    CJson *in = CreateJson();
    InitTokenManager();
    (void)ExtractPakePeerId(&params, in);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest019(void)
{
    PakeAuthParams *params = nullptr;
    InitTokenManager();
    (void)ExtractPakeSelfId(params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest020(void)
{
    PakeAuthParams params;
    InitTokenManager();
    (void)ExtractPakeSelfId(&params);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest021(void)
{
    PakeAuthParams *params = nullptr;
    CJson *in = nullptr;
    InitTokenManager();
    (void)ExtractPeerDeviceId(params, in);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest022(void)
{
    PakeAuthParams params;
    CJson *in = nullptr;
    InitTokenManager();
    (void)ExtractPeerDeviceId(&params, in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest023(void)
{
    PakeAuthParams params;
    CJson *in = CreateJson();
    InitTokenManager();
    (void)ExtractPeerDeviceId(&params, in);
    (void)AddStringToJson(in, FIELD_DEVICE_ID, "device_id_unit_test");
    (void)ExtractPeerDeviceId(&params, in);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest024(void)
{
    PakeAuthParams *params = nullptr;
    CJson *in = nullptr;
    InitTokenManager();
    (void)ExtractPeerDevId(params, in);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest025(void)
{
    PakeAuthParams params;
    CJson *in = nullptr;
    InitTokenManager();
    (void)ExtractPeerDevId(&params, in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

static void PakeV2AuthTaskCommonTest026(void)
{
    PakeAuthParams params;
    CJson *in = CreateJson();
    InitTokenManager();
    (void)ExtractPeerDevId(&params, in);
    (void)AddStringToJson(in, FIELD_DEV_ID, "dev_id_unit_test");
    (void)ExtractPeerDevId(&params, in);
    FreeJson(in);
    DestroyPakeAuthParams(&params);
    DestroyTokenManager();
}

bool FuzzDoRegCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)PakeV2AuthClientTaskTest001();
    (void)PakeV2AuthClientTaskTest002();
    (void)PakeV2AuthClientTaskTest003();
    (void)PakeV2AuthClientTaskTest004();
    (void)PakeV2AuthServerTaskTest001();
    (void)PakeV2AuthServerTaskTest002();
    (void)PakeV2AuthServerTaskTest003();
    (void)PakeV2AuthServerTaskTest004();
    (void)PakeV2AuthTaskCommonTest001();
    (void)PakeV2AuthTaskCommonTest002();
    (void)PakeV2AuthTaskCommonTest003();
    (void)PakeV2AuthTaskCommonTest004();
    (void)PakeV2AuthTaskCommonTest005();
    (void)PakeV2AuthTaskCommonTest006();
    (void)PakeV2AuthTaskCommonTest007();
    (void)PakeV2AuthTaskCommonTest008();
    (void)PakeV2AuthTaskCommonTest009();
    (void)PakeV2AuthTaskCommonTest010();
    (void)PakeV2AuthTaskCommonTest011();
    (void)PakeV2AuthTaskCommonTest012();
    (void)PakeV2AuthTaskCommonTest013();
    (void)PakeV2AuthTaskCommonTest014();
    (void)PakeV2AuthTaskCommonTest015();
    (void)PakeV2AuthTaskCommonTest016();
    (void)PakeV2AuthTaskCommonTest017();
    (void)PakeV2AuthTaskCommonTest018();
    (void)PakeV2AuthTaskCommonTest019();
    (void)PakeV2AuthTaskCommonTest020();
    (void)PakeV2AuthTaskCommonTest021();
    (void)PakeV2AuthTaskCommonTest022();
    (void)PakeV2AuthTaskCommonTest023();
    (void)PakeV2AuthTaskCommonTest024();
    (void)PakeV2AuthTaskCommonTest025();
    (void)PakeV2AuthTaskCommonTest026();
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

