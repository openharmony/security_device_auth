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

#include "dev_session_v2.h"

#include <inttypes.h>
#include <time.h>
#include "alg_loader.h"
#include "callback_manager.h"
#include "channel_manager.h"
#include "common_defs.h"
#include "creds_manager.h"
#include "data_manager.h"
#include "dev_session_util.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_types.h"
#include "performance_dumper.h"

#include "auth_sub_session.h"
#include "iso_protocol.h"
#include "dl_speke_protocol.h"
#include "ec_speke_protocol.h"

#include "expand_sub_session.h"
#include "auth_code_import.h"
#include "mk_agree.h"
#include "pseudonym_manager.h"
#include "pub_key_exchange.h"
#include "save_trusted_info.h"

#define FIELD_DATA "data"
#define FIELD_VR "vr"
#define FIELD_INDEX "index"
#define FIELD_TOTAL "total"
#define FIELD_CRED_URL "credUrl"
#define FIELD_PROTOCOL "protocol"
#define FIELD_CMDS "cmds"
#define FIELD_AUTH_MSG "authMsg"
#define FIELD_AUTH_DATA "authData"
#define FIELD_ABILITY "ability"
#define FIELD_TYPE "type"

#define FIELD_HAND_SHAKE "handshake"
#define FIELD_AUTH_EVENT "authEvent"
#define FIELD_ID "id"
#define FIELD_TD_CMDS "tdCmds"
#define FIELD_SP_CMDS "spCmds"
#define FIELD_CMD_EVENT "cmdEvent"
#define FIELD_SESSION_FAIL_EVENT "failEvent"

#define DEV_SESSION_SALT_LEN 32
#define VERSION_2_0_0 "2.0.0"

IMPLEMENT_HC_VECTOR(EventList, SessionEvent, 3)
IMPLEMENT_HC_VECTOR(AuthSubSessionList, AuthSubSession *, 1)

typedef struct {
    int32_t curState;
    int32_t eventType;
    int32_t (*processFunc)(SessionImpl *self, SessionEvent *inputEvent, CJson *sessionMsg, JumpPolicy *policy);
    int32_t nextState;
} SessionStateNode;

typedef struct {
    int32_t id;
    int32_t strategy;
    int32_t (*cmdGenerator)(SessionImpl *impl);
} CmdProcessor;

typedef bool (*CmdInterceptor)(SessionImpl *impl, CmdProcessor processor);

static int32_t CmdExchangePkGenerator(SessionImpl *impl)
{
    int32_t userType;
    if (GetIntFromJson(impl->context, FIELD_USER_TYPE, &userType) != HC_SUCCESS) {
        LOGE("get userType from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(impl->context, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("get groupId from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *authId = GetStringFromJson(impl->context, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGE("get authId from context fail.");
        return HC_ERR_JSON_GET;
    }
    Uint8Buff authIdBuf = { (uint8_t *)authId, HcStrlen(authId) };
    PubKeyExchangeParams params = { userType, GROUP_MANAGER_PACKAGE_NAME, groupId, authIdBuf };
    return impl->expandSubSession->addCmd(impl->expandSubSession, PUB_KEY_EXCHANGE_CMD_TYPE, (void *)&params,
        (!impl->isClient), ABORT_IF_ERROR);
}

static int32_t CmdImportAuthCodeGenerator(SessionImpl *impl)
{
    int32_t userType;
    if (GetIntFromJson(impl->context, FIELD_USER_TYPE, &userType) != HC_SUCCESS) {
        LOGE("get userType from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(impl->context, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("get groupId from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *authId = GetStringFromJson(impl->context, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGE("get authId from context fail.");
        return HC_ERR_JSON_GET;
    }
    Uint8Buff authIdBuf = { (uint8_t *)authId, HcStrlen(authId) };
    AuthCodeImportParams params = { userType, GROUP_MANAGER_PACKAGE_NAME, groupId, authIdBuf };
    return impl->expandSubSession->addCmd(impl->expandSubSession, AUTH_CODE_IMPORT_CMD_TYPE, (void *)&params,
        (!impl->isClient), ABORT_IF_ERROR);
}

static int32_t CmdSaveTrustedInfoGenerator(SessionImpl *impl)
{
    int32_t osAccountId;
    if (GetIntFromJson(impl->context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("get osAccountId from context fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t credType = (impl->protocolEntity.protocolType == ALG_EC_SPEKE ? ASYMMETRIC_CRED : SYMMETRIC_CRED);
    int32_t visibility = GROUP_VISIBILITY_PUBLIC;
    (void)GetIntFromJson(impl->context, FIELD_GROUP_VISIBILITY, &visibility);
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(impl->context, FIELD_USER_TYPE, &userType);
    const char *appId = GetStringFromJson(impl->context, FIELD_APP_ID);
    if (appId == NULL) {
        LOGE("get appId from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(impl->context, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("get groupId from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *authId = GetStringFromJson(impl->context, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGE("get authId from context fail.");
        return HC_ERR_JSON_GET;
    }
    SaveTrustedInfoParams params = { osAccountId, credType, userType, visibility, appId, groupId, authId };
    return impl->expandSubSession->addCmd(impl->expandSubSession, SAVE_TRUSTED_INFO_CMD_TYPE, (void *)&params,
        (!impl->isClient), ABORT_IF_ERROR);
}

static int32_t CmdMkAgreeGenerator(SessionImpl *impl)
{
    int32_t osAccountId;
    if (GetIntFromJson(impl->context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    const char *peerInfo = GetStringFromJson(impl->context, FIELD_REAL_INFO);
    if (peerInfo == NULL) {
        LOGE("Failed to get peerInfo!");
        return HC_ERR_JSON_GET;
    }
    const char *pdidIndex = GetStringFromJson(impl->context, FIELD_INDEX_KEY);
    if (pdidIndex == NULL) {
        LOGE("Failed to get pdidIndex!");
        return HC_ERR_JSON_GET;
    }
    MkAgreeParams params = { osAccountId, peerInfo, pdidIndex };
    return impl->expandSubSession->addCmd(impl->expandSubSession, MK_AGREE_CMD_TYPE, (void *)&params,
        (!impl->isClient), CONTINUE_IF_ERROR);
}

static const CmdProcessor CMDS_LIB[] = {
    { CMD_EXCHANGE_PK, ABORT_IF_ERROR, CmdExchangePkGenerator },
    { CMD_IMPORT_AUTH_CODE, ABORT_IF_ERROR, CmdImportAuthCodeGenerator },
    { CMD_ADD_TRUST_DEVICE, ABORT_IF_ERROR, CmdSaveTrustedInfoGenerator },
    { CMD_MK_AGREE, CONTINUE_IF_ERROR, CmdMkAgreeGenerator }
};

static bool InterceptNotSupportCmd(SessionImpl *impl, CmdProcessor processor)
{
    (void)impl;
    return !IsCmdSupport(processor.id);
}

static const CmdInterceptor CMDS_INTERCEPTOR_LIB[] = {
    InterceptNotSupportCmd,
};

static inline bool HasNextCredInfo(SessionImpl *impl)
{
    return impl->credCurIndex < impl->credTotalNum;
}

static void ResetAuthSubSessionList(AuthSubSessionList *authSubSessionList)
{
    uint32_t index;
    AuthSubSession **ptr;
    FOR_EACH_HC_VECTOR(*authSubSessionList, index, ptr) {
        AuthSubSession *authSubSesion = *ptr;
        authSubSesion->destroy(authSubSesion);
    }
    authSubSessionList->clear(authSubSessionList);
}

static void ResetSessionState(SessionImpl *impl)
{
    ClearFreeUint8Buff(&impl->sessionKey);
    if (HC_VECTOR_SIZE(&impl->credList) > 0) {
        IdentityInfo *curCredInfo;
        HC_VECTOR_POPELEMENT(&impl->credList, &curCredInfo, 0);
        DestroyIdentityInfo(curCredInfo);
    }
    ResetAuthSubSessionList(&impl->authSubSessionList);
    if (impl->expandSubSession != NULL) {
        impl->expandSubSession->destroy(impl->expandSubSession);
        impl->expandSubSession = NULL;
    }
}

static int32_t RestartSession(SessionImpl *impl, JumpPolicy *policy)
{
    if (!HasNextCredInfo(impl)) {
        LOGE("session has no next available credential, session failed.");
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    RESET_PERFORM_DATA(impl->base.id);
    ResetSessionState(impl);
    if (impl->isClient) {
        SessionEvent event = { START_EVENT, NULL };
        HC_VECTOR_PUSHBACK(&impl->eventList, &event);
        LOGI("push startEvent success.");
    }
    *policy = RESTART_STATE;
    LOGI("restart session success.");
    return HC_SUCCESS;
}

static int32_t AddMsgToSessionMsg(int32_t eventType, const CJson *msg, CJson *sessionMsg)
{
    CJson *event = CreateJson();
    if (event == NULL) {
        LOGE("allocate event memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddIntToJson(event, FIELD_TYPE, eventType) != HC_SUCCESS) {
        LOGE("add eventType to event fail.");
        FreeJson(event);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToJson(event, FIELD_DATA, msg) != HC_SUCCESS) {
        LOGE("add msg to event fail.");
        FreeJson(event);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToArray(sessionMsg, event) != HC_SUCCESS) {
        LOGE("add event to sessionMsg fail.");
        FreeJson(event);
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static void ErrorInformPeer(int32_t errorCode, CJson *sessionMsg)
{
    CJson *errMsg = CreateJson();
    if (errMsg == NULL) {
        LOGW("allocate errMsg memory fail.");
        return;
    }
    if (AddIntToJson(errMsg, FIELD_ERROR_CODE, errorCode) != HC_SUCCESS) {
        LOGW("add errorCode to errMsg fail.");
        FreeJson(errMsg);
        return;
    }
    (void)AddMsgToSessionMsg(SESSION_FAIL_EVENT, errMsg, sessionMsg);
    FreeJson(errMsg);
}

static void RemoveUnsupportedProtocols(IdentityInfo *cred)
{
    uint32_t index = 0;
    while (index < HC_VECTOR_SIZE(&cred->protocolVec)) {
        ProtocolEntity *entity = cred->protocolVec.get(&cred->protocolVec, index);
        if (IsProtocolSupport(entity->protocolType)) {
            index++;
            continue;
        }
        LOGI("remove unsupported protocol from credential information. [ProtocolType]: %d", entity->protocolType);
        ProtocolEntity *popEntity = NULL;
        HC_VECTOR_POPELEMENT(&cred->protocolVec, &popEntity, index);
        HcFree(popEntity);
    }
}

static void CheckAllCredsValidity(SessionImpl *impl)
{
    uint32_t index = 0;
    while (index < HC_VECTOR_SIZE(&impl->credList)) {
        IdentityInfo *cred = impl->credList.get(&impl->credList, index);
        RemoveUnsupportedProtocols(cred);
        uint32_t protocolNum = HC_VECTOR_SIZE(&cred->protocolVec);
        if (protocolNum > 0) {
            index++;
            continue;
        }
        LOGW("remove credential without available protocol.");
        IdentityInfo *popCred = NULL;
        HC_VECTOR_POPELEMENT(&impl->credList, &popCred, index);
        DestroyIdentityInfo(cred);
    }
}

static int32_t GetAllCredsWithPeer(SessionImpl *impl)
{
    int32_t res = GetCredInfosByPeerIdentity(impl->context, &impl->credList);
    if (res != HC_SUCCESS) {
        LOGE("failed to get creds with peer. [Res]: %d", res);
        return res;
    }
    CheckAllCredsValidity(impl);
    uint32_t credNum = HC_VECTOR_SIZE(&impl->credList);
    if (credNum == 0) {
        LOGE("No valid credentials with peer.");
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    impl->credCurIndex = 0;
    impl->credTotalNum = credNum;
    LOGI("Get creds with peer success. [CredNum]: %u", credNum);
    return HC_SUCCESS;
}

static int32_t AddCmdInfoToJsonArray(const CmdProcessor *cmdInfo, CJson *array, bool isTodoCmd)
{
    CJson *cmd = CreateJson();
    if (cmd == NULL) {
        LOGE("allocate cmd memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddIntToJson(cmd, FIELD_ID, cmdInfo->id) != HC_SUCCESS) {
        LOGE("add cmdId to json fail.");
        FreeJson(cmd);
        return HC_ERR_JSON_ADD;
    }
    if (isTodoCmd && AddIntToJson(cmd, FIELD_TYPE, cmdInfo->strategy) != HC_SUCCESS) {
        LOGE("add strategy to json fail.");
        FreeJson(cmd);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToArray(array, cmd) != HC_SUCCESS) {
        LOGE("add cmd to array fail.");
        FreeJson(cmd);
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static bool IsCmdIntercepted(SessionImpl *impl, CmdProcessor processor)
{
    for (uint32_t i = 0; i < sizeof(CMDS_INTERCEPTOR_LIB) / sizeof(CMDS_INTERCEPTOR_LIB[0]); i++) {
        if (CMDS_INTERCEPTOR_LIB[i](impl, processor)) {
            LOGI("Command intercepted. [Interceptor]: %u", i);
            return true;
        }
    }
    return false;
}

static int32_t AddTodoCmdsToAbility(SessionImpl *impl, ProtocolEntity *entity, CJson *ability)
{
    CJson *todoCmds = CreateJsonArray();
    if (todoCmds == NULL) {
        LOGE("allocate todoCmds memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    for (uint32_t i = 0; i < sizeof(CMDS_LIB) / sizeof(CMDS_LIB[0]); i++) {
        if (((entity->expandProcessCmds & CMDS_LIB[i].id) == 0) || (IsCmdIntercepted(impl, CMDS_LIB[i]))) {
            continue;
        }
        int32_t res = AddCmdInfoToJsonArray(&CMDS_LIB[i], todoCmds, true);
        if (res != HC_SUCCESS) {
            FreeJson(todoCmds);
            return res;
        }
    }
    if (AddObjToJson(ability, FIELD_TD_CMDS, todoCmds) != HC_SUCCESS) {
        LOGE("add todoCmds to ability fail.");
        FreeJson(todoCmds);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(todoCmds);
    return HC_SUCCESS;
}

static int32_t AddCredAbilityToArray(SessionImpl *impl, ProtocolEntity *entity, CJson *abilityArray)
{
    CJson *ability = CreateJson();
    if (ability == NULL) {
        LOGE("allocate abilityArray memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddIntToJson(ability, FIELD_PROTOCOL, entity->protocolType) != HC_SUCCESS) {
        LOGE("add protocol to ability fail.");
        FreeJson(ability);
        return HC_ERR_JSON_ADD;
    }
    int32_t res = AddTodoCmdsToAbility(impl, entity, ability);
    if (res != HC_SUCCESS) {
        FreeJson(ability);
        return res;
    }
    if (AddObjToArray(abilityArray, ability) != HC_SUCCESS) {
        LOGE("add ability to abilityArray fail.");
        FreeJson(ability);
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddAllCredAbilityToCredInfo(SessionImpl *impl, IdentityInfo *cred, CJson *credInfo)
{
    CJson *abilityArray = CreateJsonArray();
    if (abilityArray == NULL) {
        LOGE("allocate abilityArray memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    uint32_t index;
    ProtocolEntity **ptr;
    FOR_EACH_HC_VECTOR(cred->protocolVec, index, ptr) {
        ProtocolEntity *entity = *ptr;
        int32_t res = AddCredAbilityToArray(impl, entity, abilityArray);
        if (res != HC_SUCCESS) {
            FreeJson(abilityArray);
            return res;
        }
    }
    if (AddObjToJson(credInfo, FIELD_ABILITY, abilityArray) != HC_SUCCESS) {
        LOGE("add ability to abilityArray fail.");
        FreeJson(abilityArray);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(abilityArray);
    return HC_SUCCESS;
}

static int32_t AddPreSharedCredInfo(SessionImpl *impl, IdentityInfo *cred, CJson *credInfo)
{
    if (AddStringToJson(credInfo, FIELD_CRED_URL, (const char *)cred->proof.preSharedUrl.val) != HC_SUCCESS) {
        LOGE("add preSharedUrl to json fail.");
        return HC_ERR_JSON_ADD;
    }
    return AddAllCredAbilityToCredInfo(impl, cred, credInfo);
}

static int32_t AddCertCredInfo(SessionImpl *impl, IdentityInfo *cred, CJson *credInfo)
{
    if (AddIntToJson(credInfo, FIELD_SIGN_ALG, cred->proof.certInfo.signAlg) != HC_SUCCESS) {
        LOGE("add signAlg to json fail.");
        return HC_ERR_JSON_ADD;
    }
    int32_t res = HC_ERROR;
    if (cred->proof.certInfo.isPseudonym) {
        res = AddPkInfoWithPdid(impl->context, credInfo, (const char *)cred->proof.certInfo.pkInfoStr.val);
    }
    if (res != HC_SUCCESS && AddStringToJson(credInfo, FIELD_PK_INFO,
        (const char *)cred->proof.certInfo.pkInfoStr.val) != HC_SUCCESS) {
        LOGE("add pkInfoStr to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(credInfo, FIELD_PK_INFO_SIGNATURE, cred->proof.certInfo.pkInfoSignature.val,
        cred->proof.certInfo.pkInfoSignature.length) != HC_SUCCESS) {
        LOGE("add pkInfoSignature to json fail.");
        return HC_ERR_JSON_ADD;
    }
    return AddAllCredAbilityToCredInfo(impl, cred, credInfo);
}

static int32_t AddCredInfoToEventData(SessionImpl *impl, IdentityInfo *cred, CJson *eventData)
{
    if (AddIntToJson(eventData, FIELD_TYPE, cred->proofType) != HC_SUCCESS) {
        LOGE("add credType to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (cred->proofType == PRE_SHARED) {
        return AddPreSharedCredInfo(impl, cred, eventData);
    } else {
        return AddCertCredInfo(impl, cred, eventData);
    }
}

static int32_t GetPreSharedCredInfo(SessionImpl *impl, const CJson *credInfo, IdentityInfo **selfCred)
{
    const char *preSharedUrl = GetStringFromJson(credInfo, FIELD_CRED_URL);
    if (preSharedUrl == NULL) {
        LOGE("get preSharedUrl from json fail.");
        return HC_ERR_JSON_GET;
    }
    CJson *urlJson = CreateJsonFromString(preSharedUrl);
    if (urlJson == NULL) {
        LOGE("Failed to create url json!");
        return HC_ERR_JSON_FAIL;
    }
    bool isDirectAuth = false;
    (void)GetBoolFromJson(urlJson, FIELD_IS_DIRECT_AUTH, &isDirectAuth);
    if (AddBoolToJson(impl->context, FIELD_IS_DIRECT_AUTH, isDirectAuth) != HC_SUCCESS) {
        LOGE("Faild to add isDirectAuth to context");
        FreeJson(urlJson);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(urlJson);
    Uint8Buff peerSharedUrl = { (uint8_t *)preSharedUrl, HcStrlen(preSharedUrl) + 1 };
    IdentityInfo *info;
    int32_t res = GetCredInfoByPeerUrl(impl->context, &peerSharedUrl, &info);
    if (res != HC_SUCCESS) {
        LOGE("get cred info by peer url fail.");
        return res;
    }
    *selfCred = info;
    return HC_SUCCESS;
}

static int32_t BuildPeerCertInfo(const char *pkInfoStr, const char *pkInfoSignHexStr, int32_t signAlg,
    CertInfo *peerCert)
{
    Uint8Buff pkInfoStrBuff = { (uint8_t *)pkInfoStr, HcStrlen(pkInfoStr) + 1 };
    uint32_t pkInfoSignatureLen = HcStrlen(pkInfoSignHexStr) / BYTE_TO_HEX_OPER_LENGTH;
    if (DeepCopyUint8Buff(&pkInfoStrBuff, &peerCert->pkInfoStr) != HC_SUCCESS) {
        LOGE("copy pkInfoStr fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (InitUint8Buff(&peerCert->pkInfoSignature, pkInfoSignatureLen) != HC_SUCCESS) {
        LOGE("allocate pkInfoSignature memory fail.");
        ClearFreeUint8Buff(&peerCert->pkInfoStr);
        return HC_ERR_ALLOC_MEMORY;
    }
    if (HexStringToByte(pkInfoSignHexStr, peerCert->pkInfoSignature.val,
        peerCert->pkInfoSignature.length) != HC_SUCCESS) {
        LOGE("get pkInfoSignature from json fail.");
        ClearFreeUint8Buff(&peerCert->pkInfoStr);
        ClearFreeUint8Buff(&peerCert->pkInfoSignature);
        return HC_ERR_JSON_ADD;
    }
    peerCert->signAlg = signAlg;
    return HC_SUCCESS;
}

static void DestroyCertInfo(CertInfo *certInfo)
{
    ClearFreeUint8Buff(&certInfo->pkInfoSignature);
    ClearFreeUint8Buff(&certInfo->pkInfoStr);
}

static int32_t GetPeerCertInfo(CJson *context, const CJson *credInfo, CertInfo *peerCert)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return HC_ERR_JSON_GET;
    }
    int32_t signAlg;
    if (GetIntFromJson(credInfo, FIELD_SIGN_ALG, &signAlg) != HC_SUCCESS) {
        LOGE("get signAlg from json fail.");
        return HC_ERR_JSON_ADD;
    }
    char *pkInfoStr = NULL;
    int32_t res = GetRealPkInfoStr(osAccountId, credInfo, &pkInfoStr, &peerCert->isPseudonym);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get real pkInfo string!");
        return res;
    }
    const char *pkInfoSignHexStr = GetStringFromJson(credInfo, FIELD_PK_INFO_SIGNATURE);
    if (pkInfoSignHexStr == NULL) {
        LOGE("get pkInfoSignature from json fail.");
        HcFree(pkInfoStr);
        return HC_ERR_JSON_GET;
    }
    res = BuildPeerCertInfo(pkInfoStr, pkInfoSignHexStr, signAlg, peerCert);
    HcFree(pkInfoStr);
    return res;
}

static int32_t GetCertCredInfo(SessionImpl *impl, const CJson *credInfo, IdentityInfo **selfCred)
{
    int32_t res = CheckPeerPkInfoForPdid(impl->context, credInfo);
    if (res != HC_SUCCESS) {
        LOGE("Failed to check peer pkInfo!");
        return res;
    }
    CertInfo cert;
    res = GetPeerCertInfo(impl->context, credInfo, &cert);
    if (res != HC_SUCCESS) {
        LOGE("get peer cert fail.");
        return res;
    }
    IdentityInfo *info;
    res = GetCredInfoByPeerCert(impl->context, &cert, &info);
    DestroyCertInfo(&cert);
    if (res != HC_SUCCESS) {
        LOGE("get cred info by peer url fail.");
        return res;
    }
    *selfCred = info;
    return HC_SUCCESS;
}

static int32_t GetSelfCredByInput(SessionImpl *impl, const CJson *inputData)
{
    int32_t credType;
    if (GetIntFromJson(inputData, FIELD_TYPE, &credType) != HC_SUCCESS) {
        LOGE("get cred type from json fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t res;
    IdentityInfo *info = NULL;
    if (credType == PRE_SHARED) {
        res = GetPreSharedCredInfo(impl, inputData, &info);
    } else {
        res = GetCertCredInfo(impl, inputData, &info);
    }
    if (res != HC_SUCCESS) {
        return res;
    }
    if (impl->credList.pushBackT(&impl->credList, info) == NULL) {
        LOGE("push cred to list fail.");
        DestroyIdentityInfo(info);
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t GetSaltMsg(Uint8Buff *saltMsg)
{
    uint8_t randomVal[DEV_SESSION_SALT_LEN] = { 0 };
    Uint8Buff random = { randomVal, DEV_SESSION_SALT_LEN };
    int32_t res = GetLoaderInstance()->generateRandom(&random);
    if (res != HC_SUCCESS) {
        LOGE("generate random failed, res: %d", res);
        return res;
    }
    clock_t times = 0;
    if (memcpy_s(saltMsg->val, saltMsg->length, random.val, random.length) != EOK) {
        LOGE("memcpy random failed.");
        return HC_ERR_MEMORY_COPY;
    }
    if (memcpy_s(saltMsg->val + random.length, saltMsg->length - random.length, &times, sizeof(clock_t)) != EOK) {
        LOGE("memcpy times failed.");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t CalSalt(Uint8Buff *salt)
{
    uint32_t saltMsgLen = DEV_SESSION_SALT_LEN + sizeof(clock_t);
    Uint8Buff saltMsg = { NULL, 0 };
    if (InitUint8Buff(&saltMsg, saltMsgLen) != HC_SUCCESS) {
        LOGE("allocate saltMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GetSaltMsg(&saltMsg);
    if (res != HC_SUCCESS) {
        FreeUint8Buff(&saltMsg);
        return res;
    }
    res = GetLoaderInstance()->sha256(&saltMsg, salt);
    FreeUint8Buff(&saltMsg);
    if (res != HC_SUCCESS) {
        LOGE("sha256 for session salt failed.");
        return res;
    }
    return HC_SUCCESS;
}

static int32_t GenerateDevSessionSalt(SessionImpl *impl)
{
    if (InitUint8Buff(&impl->salt, DEV_SESSION_SALT_LEN) != HC_SUCCESS) {
        LOGE("Failed to alloc salt memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = CalSalt(&impl->salt);
    if (res != HC_SUCCESS) {
        LOGE("Failed to generate salt!");
        return res;
    }
    if (AddByteToJson(impl->context, FIELD_NONCE, impl->salt.val, impl->salt.length) != HC_SUCCESS) {
        LOGE("add nonce to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(impl->context, FIELD_SEED, impl->salt.val, impl->salt.length) != HC_SUCCESS) {
        LOGE("add seed to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t AddSessionInfoToEventData(SessionImpl *impl, CJson *eventData)
{
    if (AddStringToJson(eventData, FIELD_VR, VERSION_2_0_0) != HC_SUCCESS) {
        LOGE("add version to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(eventData, FIELD_SALT, impl->salt.val, impl->salt.length) != HC_SUCCESS) {
        LOGE("add session salt to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(eventData, FIELD_INDEX, impl->credCurIndex) != HC_SUCCESS) {
        LOGE("add cred index to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(eventData, FIELD_TOTAL, impl->credTotalNum) != HC_SUCCESS) {
        LOGE("add cred num to json fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

/**
 * @brief auth with credentials directly no need for abilities negotiation of two devices,
 * so we set support commands empty here.
 *
 * @param eventData
 * @return int32_t
 */
static int32_t AddSupportCmdsForDirectAuth(CJson *eventData)
{
    // added empty spCmds array to eventData
    CJson *supportCmds = CreateJsonArray();
    if (supportCmds == NULL) {
        LOGE("allocate supportCmds memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddObjToJson(eventData, FIELD_SP_CMDS, supportCmds) != HC_SUCCESS) {
        LOGE("add supportCmds to json fail.");
        FreeJson(supportCmds);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(supportCmds);
    return HC_SUCCESS;
}

static int32_t AddSupportCmdsToEventData(CJson *eventData)
{
    CJson *supportCmds = CreateJsonArray();
    if (supportCmds == NULL) {
        LOGE("allocate supportCmds memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    for (uint32_t i = 0; i < sizeof(CMDS_LIB) / sizeof(CMDS_LIB[0]); i++) {
        if (!IsCmdSupport(CMDS_LIB[i].id)) {
            continue;
        }
        int32_t res = AddCmdInfoToJsonArray(&CMDS_LIB[i], supportCmds, false);
        if (res != HC_SUCCESS) {
            FreeJson(supportCmds);
            return res;
        }
    }
    if (AddObjToJson(eventData, FIELD_SP_CMDS, supportCmds) != HC_SUCCESS) {
        LOGE("add supportCmds to json fail.");
        FreeJson(supportCmds);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(supportCmds);
    return HC_SUCCESS;
}

static int32_t GenerateHandshakeEventData(SessionImpl *impl, IdentityInfo *cred, CJson *eventData)
{
    int32_t res = AddSessionInfoToEventData(impl, eventData);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddCredInfoToEventData(impl, cred, eventData);
    if (res != HC_SUCCESS) {
        return res;
    }
    bool isDirectAuth = false;
    (void)GetBoolFromJson(impl->context, FIELD_IS_DIRECT_AUTH, &isDirectAuth);
    if (isDirectAuth) {
        return AddSupportCmdsForDirectAuth(eventData);
    } else {
        return AddSupportCmdsToEventData(eventData);
    }
    return HC_SUCCESS;
}

static int32_t SetAuthProtectedMsg(SessionImpl *impl, const CJson *msgJson, bool isSelf)
{
    char *msgStr = PackJsonToString(msgJson);
    if (msgStr == NULL) {
        LOGE("convert msgJson to msgStr fail.");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    Uint8Buff msg = { (uint8_t *)msgStr, HcStrlen(msgStr) + 1 };
    int32_t res;
    uint32_t index;
    AuthSubSession **ptr;
    FOR_EACH_HC_VECTOR(impl->authSubSessionList, index, ptr) {
        AuthSubSession *authSubSession = *ptr;
        if (isSelf) {
            res = authSubSession->setSelfProtectedMsg(authSubSession, &msg);
        } else {
            res = authSubSession->setPeerProtectedMsg(authSubSession, &msg);
        }
        if (res != HC_SUCCESS) {
            break;
        }
    }
    FreeJsonString(msgStr);
    return res;
}

static int32_t AddStartHandshakeMsg(SessionImpl *impl, IdentityInfo *cred, CJson *sessionMsg)
{
    LOGI("Start handshake with peer. [CredIndex]: %u, [CredTotalNum]: %u", impl->credCurIndex, impl->credTotalNum);
    CJson *eventData = CreateJson();
    if (eventData == NULL) {
        LOGE("allocate eventData memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateHandshakeEventData(impl, cred, eventData);
    if (res != HC_SUCCESS) {
        FreeJson(eventData);
        return res;
    }
    res = SetAuthProtectedMsg(impl, eventData, true);
    if (res != HC_SUCCESS) {
        FreeJson(eventData);
        return res;
    }
    res = AddMsgToSessionMsg(HAND_SHAKE_EVENT, eventData, sessionMsg);
    FreeJson(eventData);
    return res;
}

static int32_t AddAuthMsgToSessionMsg(AuthSubSession *authSubSession, CJson *authData, CJson *sessionMsg)
{
    CJson *eventData = CreateJson();
    if (eventData == NULL) {
        LOGE("allocate eventData memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddIntToJson(eventData, FIELD_PROTOCOL, authSubSession->protocolType) != HC_SUCCESS) {
        LOGE("add protocol to json fail.");
        FreeJson(eventData);
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToJson(eventData, FIELD_AUTH_DATA, authData) != HC_SUCCESS) {
        LOGE("add auth data to json fail.");
        FreeJson(eventData);
        return HC_ERR_JSON_ADD;
    }
    int32_t res = AddMsgToSessionMsg(AUTH_EVENT, eventData, sessionMsg);
    FreeJson(eventData);
    return res;
}

static int32_t AddAuthFirstMsg(AuthSubSession *authSubSession, CJson *sessionMsg, bool shouldReplace)
{
    CJson *authData = NULL;
    int32_t res = authSubSession->start(authSubSession, &authData);
    if (res != HC_SUCCESS) {
        LOGE("process auth sub session fail. [Res]: %d", res);
        return res;
    }
    if (shouldReplace) {
        res = ReplaceAuthIdWithRandom(authData);
        if (res != HC_SUCCESS) {
            FreeJson(authData);
            return res;
        }
    }
    res = AddAuthMsgToSessionMsg(authSubSession, authData, sessionMsg);
    FreeJson(authData);
    return res;
}

static int32_t AddAllAuthFirstMsg(SessionImpl *impl, CJson *sessionMsg, bool shouldReplace)
{
    uint32_t index;
    AuthSubSession **ptr;
    FOR_EACH_HC_VECTOR(impl->authSubSessionList, index, ptr) {
        AuthSubSession *authSubSesion = *ptr;
        int32_t res = AddAuthFirstMsg(authSubSesion, sessionMsg, shouldReplace);
        if (res != HC_SUCCESS) {
            return res;
        }
    }
    return HC_SUCCESS;
}

static int32_t CreateIsoSubSession(SessionImpl *impl, const IdentityInfo *cred, AuthSubSession **returnSubSession)
{
    if (cred->proofType == CERTIFICATED) {
        LOGE("cert credential not support.");
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    const char *authId = GetStringFromJson(impl->context, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGE("get self authId fail.");
        return HC_ERR_JSON_GET;
    }
    Uint8Buff authIdBuff = { (uint8_t *)authId, HcStrlen(authId) + 1 };
    IsoInitParams params = { authIdBuff };
    AuthSubSession *authSubSession;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_ISO, &params, impl->isClient, &authSubSession);
    if (res != HC_SUCCESS) {
        LOGE("create iso auth sub session fail. [Res]: %d", res);
        return res;
    }
    *returnSubSession = authSubSession;
    LOGI("create ISO authSubSession success.");
    return HC_SUCCESS;
}

static int32_t CreateDlSpekeSubSession(SessionImpl *impl, const IdentityInfo *cred, AuthSubSession **returnSubSession)
{
    if (cred->proofType == CERTIFICATED) {
        LOGE("Cert credential not support.");
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    CJson *urlJson = CreateJsonFromString((const char *)cred->proof.preSharedUrl.val);
    if (urlJson == NULL) {
        LOGE("Failed to create preshared url json!");
        return HC_ERR_JSON_CREATE;
    }
    int32_t trustType;
    if (GetIntFromJson(urlJson, PRESHARED_URL_TRUST_TYPE, &trustType) != HC_SUCCESS) {
        LOGE("Failed to get trust type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_GET;
    }
    FreeJson(urlJson);
    if (trustType != TRUST_TYPE_PIN) {
        LOGE("Invalid trust type!");
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    const char *authId = GetStringFromJson(impl->context, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGE("Failed to get self authId!");
        return HC_ERR_JSON_GET;
    }
    DlSpekePrimeMod primeMod = DL_SPEKE_PRIME_MOD_NONE;
#ifdef P2P_PAKE_DL_PRIME_LEN_384
    primeMod = (uint32_t)primeMod | DL_SPEKE_PRIME_MOD_384;
#endif
#ifdef P2P_PAKE_DL_PRIME_LEN_256
    primeMod = (uint32_t)primeMod | DL_SPEKE_PRIME_MOD_256;
#endif
    Uint8Buff authIdBuff = { (uint8_t *)authId, HcStrlen(authId) + 1 };
    DlSpekeInitParams params = { primeMod, authIdBuff };
    AuthSubSession *authSubSession;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_DL_SPEKE, &params, impl->isClient, &authSubSession);
    if (res != HC_SUCCESS) {
        LOGE("create dl speke auth sub session fail. [Res]: %d", res);
        return res;
    }
    *returnSubSession = authSubSession;
    LOGI("create dl speke auth sub session success.");
    return HC_SUCCESS;
}

static int32_t CreateEcSpekeSubSession(SessionImpl *impl, const IdentityInfo *cred, AuthSubSession **returnSubSession)
{
    EcSpekeCurveType curveType = (cred->proofType == CERTIFICATED) ? CURVE_TYPE_256 : CURVE_TYPE_25519;
    const char *authId = GetStringFromJson(impl->context, FIELD_AUTH_ID);
    if (authId == NULL) {
        LOGE("get self authId fail.");
        return HC_ERR_JSON_GET;
    }
    Uint8Buff authIdBuff = { (uint8_t *)authId, HcStrlen(authId) + 1 };
    EcSpekeInitParams params = { curveType, authIdBuff };
    AuthSubSession *authSubSession;
    int32_t res = CreateAuthSubSession(PROTOCOL_TYPE_EC_SPEKE, &params, impl->isClient, &authSubSession);
    if (res != HC_SUCCESS) {
        LOGE("create ecspeke auth sub session fail. [Res]: %d", res);
        return res;
    }
    *returnSubSession = authSubSession;
    LOGI("create EC_SPEKE authSubSession success.");
    return HC_SUCCESS;
}

static TrustedGroupEntry *GetGroupEntryById(int32_t osAccountId, const char *groupId)
{
    if (groupId == NULL) {
        LOGE("The input groupId is NULL!");
        return NULL;
    }
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    QueryGroupParams params = InitQueryGroupParams();
    params.groupId = groupId;
    if (QueryGroups(osAccountId, &params, &groupEntryVec) != HC_SUCCESS) {
        LOGE("Failed to query groups!");
        ClearGroupEntryVec(&groupEntryVec);
        return NULL;
    }
    FOR_EACH_HC_VECTOR(groupEntryVec, index, entry) {
        TrustedGroupEntry *returnEntry = DeepCopyGroupEntry(*entry);
        ClearGroupEntryVec(&groupEntryVec);
        return returnEntry;
    }
    ClearGroupEntryVec(&groupEntryVec);
    return NULL;
}

static int32_t AddP2PGroupInfoToContext(SessionImpl *impl, const TrustedGroupEntry *entry)
{
    if (AddStringToJson(impl->context, FIELD_GROUP_ID, StringGet(&entry->id)) != HC_SUCCESS) {
        LOGE("add groupId to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(impl->context, FIELD_OPERATION_CODE, AUTH_FORM_ACCOUNT_UNRELATED) != HC_SUCCESS) {
        LOGE("add operationCode to json fail.");
        return HC_ERR_JSON_ADD;
    }
    impl->base.opCode = AUTH_FORM_ACCOUNT_UNRELATED;
    return HC_SUCCESS;
}

static int32_t AddIdenticalAccountGroupInfoToContext(SessionImpl *impl, const TrustedGroupEntry *entry)
{
    if (AddStringToJson(impl->context, FIELD_GROUP_ID, StringGet(&entry->id)) != HC_SUCCESS) {
        LOGE("add groupId to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(impl->context, FIELD_OPERATION_CODE, AUTH_FORM_IDENTICAL_ACCOUNT) != HC_SUCCESS) {
        LOGE("add operationCode to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(impl->context, FIELD_USER_ID, StringGet(&entry->userId)) != HC_SUCCESS) {
        LOGE("add userId to json fail.");
        return HC_ERR_JSON_ADD;
    }
    impl->base.opCode = AUTH_FORM_IDENTICAL_ACCOUNT;
    return HC_SUCCESS;
}

static int32_t AddAcrossAccountGroupInfoToContext(SessionImpl *impl, const TrustedGroupEntry *entry)
{
    if (AddStringToJson(impl->context, FIELD_GROUP_ID, StringGet(&entry->id)) != HC_SUCCESS) {
        LOGE("add groupId to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(impl->context, FIELD_OPERATION_CODE, AUTH_FORM_ACROSS_ACCOUNT) != HC_SUCCESS) {
        LOGE("add operationCode to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(impl->context, FIELD_USER_ID, StringGet(&entry->userId)) != HC_SUCCESS) {
        LOGE("add userId to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(impl->context, FIELD_SHARED_USER_ID, StringGet(&entry->sharedUserId)) != HC_SUCCESS) {
        LOGE("add sharedUserId to json fail.");
        return HC_ERR_JSON_ADD;
    }
    impl->base.opCode = AUTH_FORM_ACROSS_ACCOUNT;
    return HC_SUCCESS;
}

static int32_t AddGroupInfoToContext(SessionImpl *impl, int32_t osAccountId, const char *groupId)
{
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        LOGE("The group cannot be found!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    int32_t res;
    if (entry->type == IDENTICAL_ACCOUNT_GROUP) {
        res = AddIdenticalAccountGroupInfoToContext(impl, entry);
    } else if (entry->type == PEER_TO_PEER_GROUP) {
        res = AddP2PGroupInfoToContext(impl, entry);
    } else {
        res = AddAcrossAccountGroupInfoToContext(impl, entry);
    }
    DestroyGroupEntry(entry);
    return res;
}

static int32_t AddDevInfoToContext(SessionImpl *impl, int32_t osAccountId, const char *groupId, const char *selfUdid)
{
    TrustedDeviceEntry *deviceEntry = GetDeviceEntryById(osAccountId, selfUdid, true, groupId);
    if (deviceEntry == NULL) {
        LOGE("The trusted device is not found!");
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    if (AddStringToJson(impl->context, FIELD_AUTH_ID, StringGet(&deviceEntry->authId)) != HC_SUCCESS) {
        LOGE("add selfAuthId to context fail.");
        DestroyDeviceEntry(deviceEntry);
        return HC_ERR_ALLOC_MEMORY;
    }
    DestroyDeviceEntry(deviceEntry);
    return HC_SUCCESS;
}

static int32_t AddAuthInfoToContextByDb(SessionImpl *impl, const char *selfUdid, CJson *urlJson)
{
    int32_t osAccountId;
    if (GetIntFromJson(impl->context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("get osAccountId from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(urlJson, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get group id!");
        return HC_ERR_JSON_GET;
    }
    int32_t res = AddGroupInfoToContext(impl, osAccountId, groupId);
    if (res != HC_SUCCESS) {
        return res;
    }
    return AddDevInfoToContext(impl, osAccountId, groupId, selfUdid);
}

static bool IsPeerSameUserId(int32_t osAccountId, const char *peerUserId)
{
    GroupEntryVec groupVec = CreateGroupEntryVec();
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupType = IDENTICAL_ACCOUNT_GROUP;
    if (QueryGroups(osAccountId, &queryParams, &groupVec) != HC_SUCCESS || groupVec.size(&groupVec) <= 0) {
        LOGE("get identical account group from db fail.");
        ClearGroupEntryVec(&groupVec);
        return false;
    }
    TrustedGroupEntry *groupEntry = groupVec.get(&groupVec, 0);
    bool isSame = (strcmp(StringGet(&(groupEntry->userId)), peerUserId) == 0);
    ClearGroupEntryVec(&groupVec);
    return isSame;
}

static int32_t AddAcrossAccountAuthInfoToContext(SessionImpl *impl, int32_t osAccountId, const char *peerUserId)
{
    GroupEntryVec groupVec = CreateGroupEntryVec();
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupType = ACROSS_ACCOUNT_AUTHORIZE_GROUP;
    queryParams.sharedUserId = peerUserId;
    if (QueryGroups(osAccountId, &queryParams, &groupVec) != HC_SUCCESS || groupVec.size(&groupVec) <= 0) {
        LOGE("get across account group from db by peerUserId fail.");
        ClearGroupEntryVec(&groupVec);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    TrustedGroupEntry *groupEntry = groupVec.get(&groupVec, 0);
    if (AddStringToJson(impl->context, FIELD_GROUP_ID, StringGet(&groupEntry->id)) != HC_SUCCESS) {
        LOGE("add groupId to context fail.");
        ClearGroupEntryVec(&groupVec);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(impl->context, FIELD_OPERATION_CODE, AUTH_FORM_IDENTICAL_ACCOUNT) != HC_SUCCESS) {
        LOGE("add operationCode to context fail.");
        ClearGroupEntryVec(&groupVec);
        return HC_ERR_JSON_ADD;
    }
    impl->base.opCode = AUTH_FORM_IDENTICAL_ACCOUNT;
    ClearGroupEntryVec(&groupVec);
    return HC_SUCCESS;
}

static int32_t AddIdenticalAccountAuthInfoToContext(SessionImpl *impl, int32_t osAccountId, const char *peerUserId)
{
    GroupEntryVec groupVec = CreateGroupEntryVec();
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupType = IDENTICAL_ACCOUNT_GROUP;
    queryParams.userId = peerUserId;
    if (QueryGroups(osAccountId, &queryParams, &groupVec) != HC_SUCCESS || groupVec.size(&groupVec) <= 0) {
        LOGE("get identical account group from db by peerUserId fail.");
        ClearGroupEntryVec(&groupVec);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    TrustedGroupEntry *groupEntry = groupVec.get(&groupVec, 0);
    if (AddStringToJson(impl->context, FIELD_GROUP_ID, StringGet(&groupEntry->id)) != HC_SUCCESS) {
        LOGE("add groupId to context fail.");
        ClearGroupEntryVec(&groupVec);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(impl->context, FIELD_OPERATION_CODE, AUTH_FORM_ACROSS_ACCOUNT) != HC_SUCCESS) {
        LOGE("add operationCode to context fail.");
        ClearGroupEntryVec(&groupVec);
        return HC_ERR_JSON_ADD;
    }
    impl->base.opCode = AUTH_FORM_ACROSS_ACCOUNT;
    ClearGroupEntryVec(&groupVec);
    return HC_SUCCESS;
}

static int32_t AddAuthInfoToContextByCert(SessionImpl *impl)
{
    int32_t osAccountId;
    if (GetIntFromJson(impl->context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("get osAccountId from context fail.");
        return HC_ERR_JSON_GET;
    }
    const char *peerUserId = GetStringFromJson(impl->context, FIELD_USER_ID);
    if (peerUserId != NULL && !IsPeerSameUserId(osAccountId, peerUserId)) {
        return AddAcrossAccountAuthInfoToContext(impl, osAccountId, peerUserId);
    } else {
        return AddIdenticalAccountAuthInfoToContext(impl, osAccountId, peerUserId);
    }
}

static int32_t AddAuthInfoToContextByCred(SessionImpl *impl, IdentityInfo *cred)
{
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid!");
        return res;
    }
    PRINT_SENSITIVE_DATA("SelfUdid", selfUdid);
    bool isDirectAuth = false;
    (void)GetBoolFromJson(impl->context, FIELD_IS_DIRECT_AUTH, &isDirectAuth);
    if (cred->proofType == CERTIFICATED) {
        if (AddStringToJson(impl->context, FIELD_AUTH_ID, selfUdid) != HC_SUCCESS) {
            LOGE("add selfAuthId to json fail.");
            return HC_ERR_ALLOC_MEMORY;
        }
        return AddAuthInfoToContextByCert(impl);
    } else if (isDirectAuth) {  // auth with credentials directly
        if (AddStringToJson(impl->context, FIELD_AUTH_ID, selfUdid) != HC_SUCCESS) {
            LOGE("add selfAuthId to json fail.");
            return HC_ERR_ALLOC_MEMORY;
        }
        return HC_SUCCESS;
    }
    CJson *urlJson = CreateJsonFromString((const char *)cred->proof.preSharedUrl.val);
    if (urlJson == NULL) {
        LOGE("create urlJson from string fail.");
        return HC_ERR_JSON_CREATE;
    }
    int32_t trustType;
    if (GetIntFromJson(urlJson, PRESHARED_URL_TRUST_TYPE, &trustType) != HC_SUCCESS) {
        LOGE("Failed to get trust type!");
        FreeJson(urlJson);
        return HC_ERR_JSON_GET;
    }
    if (trustType == TRUST_TYPE_PIN) {
        FreeJson(urlJson);
        return HC_SUCCESS;
    }
    res = AddAuthInfoToContextByDb(impl, selfUdid, urlJson);
    FreeJson(urlJson);
    return res;
}

static int32_t AddAuthSubSessionToVec(SessionImpl *impl, IdentityInfo *cred, ProtocolEntity *entity)
{
    int32_t res;
    AuthSubSession *authSubSession = NULL;
    if (entity->protocolType == ALG_EC_SPEKE) {
        res = CreateEcSpekeSubSession(impl, cred, &authSubSession);
    } else if (entity->protocolType == ALG_DL_SPEKE) {
        res = CreateDlSpekeSubSession(impl, cred, &authSubSession);
    } else {
        res = CreateIsoSubSession(impl, cred, &authSubSession);
    }
    if (res != HC_SUCCESS) {
        return res;
    }
    if (impl->authSubSessionList.pushBackT(&impl->authSubSessionList, authSubSession) == NULL) {
        LOGE("push authSubSession to authSubSessionList fail.");
        authSubSession->destroy(authSubSession);
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t ClientCreateAuthSubSessionByCred(SessionImpl *impl, IdentityInfo *cred)
{
    uint32_t protocolNum = cred->protocolVec.size(&cred->protocolVec);
    if (protocolNum == 0) {
        LOGE("The credential does not have a valid protocol.");
        return HC_ERR_UNSUPPORTED_VERSION;
    }
    int32_t res = AddAuthInfoToContextByCred(impl, cred);
    if (res != HC_SUCCESS) {
        return res;
    }
    uint32_t index;
    ProtocolEntity **ptr;
    FOR_EACH_HC_VECTOR(cred->protocolVec, index, ptr) {
        res = AddAuthSubSessionToVec(impl, cred, *ptr);
        if (res != HC_SUCCESS) {
            return res;
        }
    }
    return HC_SUCCESS;
}

static int32_t ProcStartEventInner(SessionImpl *impl, CJson *sessionMsg)
{
    int32_t res;
    if (impl->credTotalNum == 0) {
        res = GetAllCredsWithPeer(impl);
        if (res != HC_SUCCESS) {
            LOGE("get all credentials with peer device fail.");
            return res;
        }
        res = GenerateDevSessionSalt(impl);
        if (res != HC_SUCCESS) {
            return res;
        }
    }
    impl->credCurIndex += 1;
    IdentityInfo *curCred = HC_VECTOR_GET(&impl->credList, 0);
    bool isDirectAuth = curCred->IdInfoType == P2P_DIRECT_AUTH ? true : false;
    if (AddBoolToJson(impl->context, FIELD_IS_DIRECT_AUTH, isDirectAuth) != HC_SUCCESS) {
        LOGE("Failed to add isDirectAuth to context!");
        return HC_ERR_JSON_ADD;
    }
    res = ClientCreateAuthSubSessionByCred(impl, curCred);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddStartHandshakeMsg(impl, curCred, sessionMsg);
    if (res != HC_SUCCESS) {
        return res;
    }
    /* auth with credentail directly no need replace auth id with random number */
    return AddAllAuthFirstMsg(impl, sessionMsg, (IsP2pAuth(curCred) && !isDirectAuth));
}

static int32_t GetSessionSaltFromInput(SessionImpl *impl, const CJson *inputData)
{
    if (InitUint8Buff(&impl->salt, DEV_SESSION_SALT_LEN) != HC_SUCCESS) {
        LOGE("allocate salt memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(inputData, FIELD_SALT, impl->salt.val, impl->salt.length) != HC_SUCCESS) {
        LOGE("get session salt from json fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddByteToJson(impl->context, FIELD_NONCE, impl->salt.val, impl->salt.length) != HC_SUCCESS) {
        LOGE("add nonce to context fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(impl->context, FIELD_SEED, impl->salt.val, impl->salt.length) != HC_SUCCESS) {
        LOGE("add seed to context fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t GetSharedSecret(SessionImpl *impl, const CJson *inputData, IdentityInfo *selfCred, Uint8Buff *psk)
{
    if (selfCred->proofType == PRE_SHARED) {
        return GetSharedSecretByUrl(impl->context, &selfCred->proof.preSharedUrl,
            impl->protocolEntity.protocolType, psk);
    }
    int32_t res = SetPeerInfoToContext(impl->context, inputData);
    if (res != HC_SUCCESS) {
        return res;
    }
    CertInfo peerCert;
    res = GetPeerCertInfo(impl->context, inputData, &peerCert);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = GetSharedSecretByPeerCert(impl->context, &peerCert, impl->protocolEntity.protocolType, psk);
    DestroyCertInfo(&peerCert);
    return res;
}

static int32_t SetPeerUserIdToContext(CJson *context, const CJson *inputData, const IdentityInfo *cred)
{
    if (cred->proofType != CERTIFICATED) {
        LOGI("credential type is not certificate, no need to set peer userId!");
        return HC_SUCCESS;
    }
    CertInfo peerCert;
    int32_t res = GetPeerCertInfo(context, inputData, &peerCert);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get peer cert!");
        return res;
    }
    CJson *pkInfoJson = CreateJsonFromString((const char *)peerCert.pkInfoStr.val);
    DestroyCertInfo(&peerCert);
    if (pkInfoJson == NULL) {
        LOGE("Failed to create pkInfo json!");
        return HC_ERR_JSON_CREATE;
    }
    const char *userId = GetStringFromJson(pkInfoJson, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId!");
        FreeJson(pkInfoJson);
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_USER_ID, userId) != HC_SUCCESS) {
        LOGE("Failed to add userId!");
        FreeJson(pkInfoJson);
        return HC_ERR_JSON_ADD;
    }
    FreeJson(pkInfoJson);
    return HC_SUCCESS;
}

static int32_t ServerCreateAuthSubSessionByCred(SessionImpl *impl, const CJson *inputData, IdentityInfo *cred)
{
    int32_t res = SetPeerUserIdToContext(impl->context, inputData, cred);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddAuthInfoToContextByCred(impl, cred);
    if (res != HC_SUCCESS) {
        return res;
    }
    return AddAuthSubSessionToVec(impl, cred, &impl->protocolEntity);
}

static int32_t SyncCredState(SessionImpl *impl, const CJson *inputData)
{
    int32_t credIndex;
    if (GetIntFromJson(inputData, FIELD_INDEX, &credIndex) != HC_SUCCESS) {
        LOGE("get credIndex from inputData fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t credNum;
    if (GetIntFromJson(inputData, FIELD_TOTAL, &credNum) != HC_SUCCESS) {
        LOGE("get credNum from inputData fail.");
        return HC_ERR_JSON_GET;
    }
    impl->credCurIndex = credIndex;
    impl->credTotalNum = credNum;
    return HC_SUCCESS;
}

static int32_t GenerateHandshakeRspEventData(SessionImpl *impl, IdentityInfo *selfCred, CJson *eventData)
{
    if (AddStringToJson(eventData, FIELD_VR, VERSION_2_0_0) != HC_SUCCESS) {
        LOGE("add version to json fail.");
        return HC_ERR_JSON_ADD;
    }
    int32_t res = AddCredInfoToEventData(impl, selfCred, eventData);
    if (res != HC_SUCCESS) {
        return res;
    }
    bool isDirectAuth = false;
    (void)GetBoolFromJson(impl->context, FIELD_IS_DIRECT_AUTH, &isDirectAuth);
    if (isDirectAuth) {
        return AddSupportCmdsForDirectAuth(eventData);
    } else {
        return AddSupportCmdsToEventData(eventData);
    }
}

static int32_t AddHandshakeRspMsg(SessionImpl *impl, IdentityInfo *selfCred, CJson *sessionMsg)
{
    CJson *eventData = CreateJson();
    if (eventData == NULL) {
        LOGE("allocate eventData memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateHandshakeRspEventData(impl, selfCred, eventData);
    if (res != HC_SUCCESS) {
        FreeJson(eventData);
        return res;
    }
    res = SetAuthProtectedMsg(impl, eventData, true);
    if (res != HC_SUCCESS) {
        FreeJson(eventData);
        return res;
    }
    res = AddMsgToSessionMsg(HAND_SHAKE_RSP_EVENT, eventData, sessionMsg);
    FreeJson(eventData);
    return res;
}

static bool IsPeerSupportCmd(int32_t cmdId, const CJson *supportCmds)
{
    uint32_t supportCmdsNum = GetItemNum(supportCmds);
    for (uint32_t i = 0; i < supportCmdsNum; i++) {
        CJson *cmd = GetItemFromArray(supportCmds, i);
        if (cmd == NULL) {
            LOGE("get cmd from supportCmds fail.");
            return false;
        }
        int32_t id;
        if (GetIntFromJson(cmd, FIELD_ID, &id) != HC_SUCCESS) {
            LOGE("get cmd id from json fail.");
            return false;
        }
        if (id == cmdId) {
            return true;
        }
    }
    return false;
}

static int32_t SelfCmdsNegotiate(SessionImpl *impl, const CJson *supportCmds, const ProtocolEntity *selfProtocolEntity)
{
    uint32_t selfCmds = 0;
    for (uint32_t i = 0; i < sizeof(CMDS_LIB) / sizeof(CMDS_LIB[0]); i++) {
        if (!IsCmdSupport(CMDS_LIB[i].id) || ((selfProtocolEntity->expandProcessCmds & CMDS_LIB[i].id) == 0)) {
            continue;
        }
        if (IsPeerSupportCmd(CMDS_LIB[i].id, supportCmds)) {
            selfCmds |= CMDS_LIB[i].id;
            continue;
        }
        if (CMDS_LIB[i].strategy == ABORT_IF_ERROR) {
            LOGW("The peer device does not support this cmd and it is not optional. [Cmd]: %d", CMDS_LIB[i].id);
            return HC_ERR_NOT_SUPPORT;
        }
    }
    impl->protocolEntity.expandProcessCmds |= selfCmds;
    LOGI("self todo cmds: %u", selfCmds);
    return HC_SUCCESS;
}

static int32_t PeerCmdsNegotiate(SessionImpl *impl, const CJson *credAbility)
{
    CJson *todoCmds = GetObjFromJson(credAbility, FIELD_TD_CMDS);
    if (todoCmds == NULL) {
        LOGE("get todoCmds from ability fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t peerCmds = 0;
    uint32_t todoCmdsNum = GetItemNum(todoCmds);
    for (uint32_t i = 0; i < todoCmdsNum; i++) {
        CJson *cmd = GetItemFromArray(todoCmds, i);
        if (cmd == NULL) {
            LOGE("get cmd from todoCmds fail.");
            return HC_ERR_JSON_GET;
        }
        int32_t id;
        if (GetIntFromJson(cmd, FIELD_ID, &id) != HC_SUCCESS) {
            LOGE("get cmd id from json fail.");
            return HC_ERR_JSON_GET;
        }
        if (IsCmdSupport(id)) {
            peerCmds |= (uint32_t)id;
            continue;
        }
        int32_t strategy;
        if (GetIntFromJson(cmd, FIELD_TYPE, &strategy) != HC_SUCCESS) {
            LOGE("get strategy from json fail.");
            return HC_ERR_JSON_GET;
        }
        if (strategy == ABORT_IF_ERROR) {
            LOGW("The local device does not support this cmd and it is not optional. [Cmd]: %d", id);
            return HC_ERR_NOT_SUPPORT;
        }
    }
    impl->protocolEntity.expandProcessCmds |= peerCmds;
    LOGI("peer todo cmds: %u", peerCmds);
    return HC_SUCCESS;
}

static int32_t ProtocolEntityNegotiate(SessionImpl *impl, const CJson *abilityArray, const CJson *supportCmds,
    ProtocolEntity *selfProtocolEntity)
{
    uint32_t abilityNum = GetItemNum(abilityArray);
    for (uint32_t i = 0; i < abilityNum; i++) {
        CJson *credAbility = GetItemFromArray(abilityArray, i);
        if (credAbility == NULL) {
            LOGE("get cred ability from abilityArray fail.");
            return HC_ERR_JSON_GET;
        }
        int32_t protocol;
        if (GetIntFromJson(credAbility, FIELD_PROTOCOL, &protocol) != HC_SUCCESS) {
            LOGE("get protocol from ability fail.");
            return HC_ERR_JSON_GET;
        }
        if (protocol != (int32_t)selfProtocolEntity->protocolType) {
            continue;
        }
        int32_t res = PeerCmdsNegotiate(impl, credAbility);
        if (res != HC_SUCCESS) {
            return res;
        }
        res = SelfCmdsNegotiate(impl, supportCmds, selfProtocolEntity);
        if (res != HC_SUCCESS) {
            return res;
        }
        impl->protocolEntity.protocolType = protocol;
        LOGI("negotiate result: protocol: %d, cmds: %u", impl->protocolEntity.protocolType,
            impl->protocolEntity.expandProcessCmds);
        return HC_SUCCESS;
    }
    return HC_ERR_UNSUPPORTED_VERSION;
}

static int32_t CredNegotiate(SessionImpl *impl, const CJson *inputData, IdentityInfo *selfCred)
{
    CJson *abilityArray = GetObjFromJson(inputData, FIELD_ABILITY);
    if (abilityArray == NULL) {
        LOGE("get ability array from json fail.");
        return HC_ERR_JSON_GET;
    }
    CJson *supportCmds = GetObjFromJson(inputData, FIELD_SP_CMDS);
    if (supportCmds == NULL) {
        LOGE("get supportCmds from json fail.");
        return HC_ERR_JSON_GET;
    }
    uint32_t index;
    ProtocolEntity **ptr;
    FOR_EACH_HC_VECTOR(selfCred->protocolVec, index, ptr) {
        ProtocolEntity *entity = *ptr;
        if (ProtocolEntityNegotiate(impl, abilityArray, supportCmds, entity) == HC_SUCCESS) {
            return HC_SUCCESS;
        }
    }
    LOGE("Credential negotiation failed.");
    return HC_ERR_UNSUPPORTED_VERSION;
}

static int32_t SetAuthPsk(SessionImpl *impl, const CJson *inputData, IdentityInfo *cred)
{
    AuthSubSession *curAuthSubSession = impl->authSubSessionList.get(&impl->authSubSessionList, 0);
    Uint8Buff psk;
    int32_t res = GetSharedSecret(impl, inputData, cred, &psk);
    if (res != HC_SUCCESS) {
        LOGE("get psk fail. [Res]: %d", res);
        return res;
    }
    res = curAuthSubSession->setPsk(curAuthSubSession, &psk);
    ClearFreeUint8Buff(&psk);
    if (res != HC_SUCCESS) {
        LOGE("set psk fail.");
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ProcHandshakeReqEventInner(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg)
{
    int32_t res = SyncCredState(impl, inputEvent->data);
    if (res != HC_SUCCESS) {
        return res;
    }
    LOGI("Recevice handshake with peer. [CredIndex]: %u, [CredTotalNum]: %u", impl->credCurIndex, impl->credTotalNum);
    res = GetSessionSaltFromInput(impl, inputEvent->data);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = GetSelfCredByInput(impl, inputEvent->data);
    if (res != HC_SUCCESS) {
        LOGE("get cred by input fail.");
        return res;
    }
    CheckAllCredsValidity(impl);
    IdentityInfo *selfCred = HC_VECTOR_GET(&impl->credList, 0);
    bool isDirectAuth = selfCred->IdInfoType == P2P_DIRECT_AUTH ? true : false;
    if (AddBoolToJson(impl->context, FIELD_IS_DIRECT_AUTH, isDirectAuth) != HC_SUCCESS) {
        LOGE("Failed to add isDirectAuth to context!");
        return HC_ERR_JSON_ADD;
    }
    res = SetPeerAuthIdToContextIfNeeded(impl->context, selfCred);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = CredNegotiate(impl, inputEvent->data, selfCred);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = ServerCreateAuthSubSessionByCred(impl, inputEvent->data, selfCred);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = SetAuthPsk(impl, inputEvent->data, selfCred);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = SetAuthProtectedMsg(impl, inputEvent->data, false);
    if (res != HC_SUCCESS) {
        return res;
    }
    return AddHandshakeRspMsg(impl, selfCred, sessionMsg);
}

static ProtocolAlgType GetAlgTypeByProtocolType(int32_t protocolType)
{
    if (protocolType == PROTOCOL_TYPE_EC_SPEKE) {
        return ALG_EC_SPEKE;
    } else if (protocolType == PROTOCOL_TYPE_DL_SPEKE) {
        return ALG_DL_SPEKE;
    } else {
        return ALG_ISO;
    }
}

static int32_t RemoveInvalidAuthSubSession(SessionImpl *impl)
{
    uint32_t index = 0;
    while (index < HC_VECTOR_SIZE(&impl->authSubSessionList)) {
        AuthSubSession *authSubSesion = impl->authSubSessionList.get(&impl->authSubSessionList, index);
        ProtocolAlgType curProtocolType = GetAlgTypeByProtocolType(authSubSesion->protocolType);
        if (curProtocolType == impl->protocolEntity.protocolType) {
            index++;
            continue;
        }
        LOGI("remove invalid authSubSession. [ProtocolType]: %d", curProtocolType);
        AuthSubSession *popAuthSubSession;
        HC_VECTOR_POPELEMENT(&impl->authSubSessionList, &popAuthSubSession, index);
        popAuthSubSession->destroy(popAuthSubSession);
    }
    return HC_SUCCESS;
}

static int32_t ProcHandshakeRspEventInner(SessionImpl *impl, SessionEvent *inputEvent)
{
    IdentityInfo *selfCred = impl->credList.get(&impl->credList, 0);
    bool isDirectAuth = selfCred->IdInfoType == P2P_DIRECT_AUTH ? true : false;
    if (AddBoolToJson(impl->context, FIELD_IS_DIRECT_AUTH, isDirectAuth) != HC_SUCCESS) {
        LOGE("Failed to add isDirectAuth to context!");
        return HC_ERR_JSON_ADD;
    }
    int32_t res = SetPeerAuthIdToContextIfNeeded(impl->context, selfCred);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = CredNegotiate(impl, inputEvent->data, selfCred);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = RemoveInvalidAuthSubSession(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = SetAuthPsk(impl, inputEvent->data, selfCred);
    if (res != HC_SUCCESS) {
        return res;
    }
    return SetAuthProtectedMsg(impl, inputEvent->data, false);
}

static int32_t AddAllCmds(SessionImpl *impl)
{
    uint32_t cmds = impl->protocolEntity.expandProcessCmds;
    for (uint32_t i = 0; i < sizeof(CMDS_LIB) / sizeof(CMDS_LIB[0]); i++) {
        if ((CMDS_LIB[i].id & cmds) != 0) {
            int32_t res = CMDS_LIB[i].cmdGenerator(impl);
            if (res != HC_SUCCESS) {
                LOGE("add cmd fail. [CmdId]: %u", CMDS_LIB[i].id);
                return res;
            }
            LOGI("add cmd success. [CmdId]: %u", CMDS_LIB[i].id);
        }
    }
    return HC_SUCCESS;
}

static int32_t CreateExpandSubSessionByCred(SessionImpl *impl)
{
    int32_t res = CreateExpandSubSession(&impl->salt, &impl->sessionKey, &impl->expandSubSession);
    if (res != HC_SUCCESS) {
        LOGE("create expand sub session fail.");
        return res;
    }
    return AddAllCmds(impl);
}

static int32_t StartExpandSubSession(ExpandSubSession *expandSubSession, CJson *sessionMsg)
{
    CJson *eventData = NULL;
    int32_t res = expandSubSession->start(expandSubSession, &eventData);
    if (res != HC_SUCCESS) {
        LOGE("create expand sub session fail.");
        return res;
    }
    res = AddMsgToSessionMsg(EXPAND_EVENT, eventData, sessionMsg);
    FreeJson(eventData);
    return res;
}

static int32_t ProcAuthSubSessionMsg(AuthSubSession *authSubSession, const CJson *receviedMsg, CJson *sessionMsg,
    bool shouldReplace)
{
    CJson *authData = NULL;
    int32_t res = authSubSession->process(authSubSession, receviedMsg, &authData);
    if (res != HC_SUCCESS) {
        LOGE("process auth sub session fail. [Res]: %d", res);
        if (authData != NULL) {
            (void)AddAuthMsgToSessionMsg(authSubSession, authData, sessionMsg);
            FreeJson(authData);
        }
        return res;
    }
    if (authData == NULL) {
        return HC_SUCCESS;
    }
    if (shouldReplace) {
        res = ReplaceAuthIdWithRandom(authData);
        if (res != HC_SUCCESS) {
            FreeJson(authData);
            return res;
        }
    }
    res = AddAuthMsgToSessionMsg(authSubSession, authData, sessionMsg);
    FreeJson(authData);
    return res;
}

static int32_t OnAuthSubSessionFinish(SessionImpl *impl, AuthSubSession *authSubSession, CJson *sessionMsg)
{
    int32_t res = authSubSession->getSessionKey(authSubSession, &impl->sessionKey);
    if (res != HC_SUCCESS) {
        LOGE("get session key fail.");
        return res;
    }
    LOGI("auth sub session finish.");
    if (impl->protocolEntity.expandProcessCmds == 0) {
        return HC_SUCCESS;
    }
    res = CreateExpandSubSessionByCred(impl);
    if (res != HC_SUCCESS) {
        return res;
    }
    if (!impl->isClient) {
        res = StartExpandSubSession(impl->expandSubSession, sessionMsg);
        if (res != HC_SUCCESS) {
            return res;
        }
    }
    return HC_SUCCESS;
}

static int32_t ProcAuthEventInner(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg, bool *isAuthFinish,
    bool isServerProcess)
{
    int32_t protocolType;
    if (GetIntFromJson(inputEvent->data, FIELD_PROTOCOL, &protocolType) != HC_SUCCESS) {
        LOGE("get protocol from json fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t res = FillPeerAuthIdIfNeeded(impl->isClient, impl->context, (CJson *)inputEvent->data);
    if (res != HC_SUCCESS) {
        return res;
    }
    AuthSubSession *curAuthSubSession = impl->authSubSessionList.get(&impl->authSubSessionList, 0);
    if (protocolType != curAuthSubSession->protocolType) {
        LOGI("Protocol type mismatch. Ignore it. [ProtocolType]: %d", protocolType);
        return HC_SUCCESS;
    }
    IdentityInfo *selfCred = HC_VECTOR_GET(&impl->credList, 0);
    bool isDirectAuth = selfCred->IdInfoType == P2P_DIRECT_AUTH ? true : false;
    if (AddBoolToJson(impl->context, FIELD_IS_DIRECT_AUTH, isDirectAuth) != HC_SUCCESS) {
        LOGE("Failed to add isDirectAuth to context!");
        return HC_ERR_JSON_ADD;
    }
    bool isP2pAuth = IsP2pAuth(selfCred);
    /* auth with credentail directly no need replace auth id with random number*/
    if (isServerProcess && isP2pAuth && !isDirectAuth) {
        res = ProcAuthSubSessionMsg(curAuthSubSession, inputEvent->data, sessionMsg, true);
    } else {
        res = ProcAuthSubSessionMsg(curAuthSubSession, inputEvent->data, sessionMsg, false);
    }
    if (res != HC_SUCCESS) {
        return res;
    }
    if (curAuthSubSession->state == AUTH_STATE_RUNNING) {
        *isAuthFinish = false;
        return HC_SUCCESS;
    }
    *isAuthFinish = true;
    return OnAuthSubSessionFinish(impl, curAuthSubSession, sessionMsg);
}

static int32_t ProcExpandEventInner(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg,
    bool *isExpandFinish)
{
    CJson *expandData = NULL;
    int32_t res = impl->expandSubSession->process(impl->expandSubSession, inputEvent->data, &expandData);
    if (res != HC_SUCCESS) {
        LOGE("process expand sub session fail. [Res]: %d", res);
        if (expandData != NULL) {
            (void)AddMsgToSessionMsg(EXPAND_EVENT, expandData, sessionMsg);
            FreeJson(expandData);
        }
        return res;
    }
    if (expandData != NULL) {
        res = AddMsgToSessionMsg(EXPAND_EVENT, expandData, sessionMsg);
        FreeJson(expandData);
        if (res != HC_SUCCESS) {
            return res;
        }
    }
    *isExpandFinish = impl->expandSubSession->state == EXPAND_STATE_FINISH;
    return HC_SUCCESS;
}

static int32_t ProcFailEvent(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg, JumpPolicy *policy)
{
    (void)sessionMsg;
    int32_t peerErrorCode = HC_ERR_PEER_ERROR;
    (void)GetIntFromJson(inputEvent->data, FIELD_ERROR_CODE, &peerErrorCode);
    LOGE("An exception occurred in the peer session. [Code]: %d", peerErrorCode);
    return RestartSession(impl, policy) == HC_SUCCESS ? HC_SUCCESS : peerErrorCode;
}

static int32_t ProcStartEvent(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg, JumpPolicy *policy)
{
    (void)inputEvent;
    int32_t res = ProcStartEventInner(impl, sessionMsg);
    if (res != HC_SUCCESS) {
        return RestartSession(impl, policy) == HC_SUCCESS ? HC_SUCCESS : res;
    }
    LOGI("process start event success.");
    *policy = JUMP_TO_NEXT_STATE;
    return HC_SUCCESS;
}

static int32_t ProcHandshakeReqEvent(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg, JumpPolicy *policy)
{
    int32_t res = ProcHandshakeReqEventInner(impl, inputEvent, sessionMsg);
    if (res != HC_SUCCESS) {
        ErrorInformPeer(res, sessionMsg);
        return RestartSession(impl, policy) == HC_SUCCESS ? HC_SUCCESS : res;
    }
    LOGI("process handshake request event success.");
    *policy = JUMP_TO_NEXT_STATE;
    return HC_SUCCESS;
}

static int32_t ProcHandshakeRspEvent(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg, JumpPolicy *policy)
{
    int32_t res = ProcHandshakeRspEventInner(impl, inputEvent);
    if (res != HC_SUCCESS) {
        ErrorInformPeer(res, sessionMsg);
        return RestartSession(impl, policy) == HC_SUCCESS ? HC_SUCCESS : res;
    }
    LOGI("process handshake response event success.");
    *policy = JUMP_TO_NEXT_STATE;
    return HC_SUCCESS;
}

static int32_t ProcFirstAuthEvent(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg, JumpPolicy *policy)
{
    bool isAuthFinish = false;
    int32_t res = ProcAuthEventInner(impl, inputEvent, sessionMsg, &isAuthFinish, true);
    if (res != HC_SUCCESS) {
        ErrorInformPeer(res, sessionMsg);
        return RestartSession(impl, policy) == HC_SUCCESS ? HC_SUCCESS : res;
    }
    LOGI("process first auth event success.");
    *policy = JUMP_TO_NEXT_STATE;
    return HC_SUCCESS;
}

static int32_t ProcAuthEvent(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg, JumpPolicy *policy)
{
    bool isAuthFinish = false;
    int32_t res = ProcAuthEventInner(impl, inputEvent, sessionMsg, &isAuthFinish, false);
    if (res != HC_SUCCESS) {
        ErrorInformPeer(res, sessionMsg);
        return RestartSession(impl, policy) == HC_SUCCESS ? HC_SUCCESS : res;
    }
    LOGI("process auth event success.");
    if (!isAuthFinish) {
        *policy = STAY_STATE;
    } else if (impl->protocolEntity.expandProcessCmds == 0) {
        *policy = JUMP_TO_FINISH_STATE;
    } else {
        *policy = JUMP_TO_NEXT_STATE;
    }
    return HC_SUCCESS;
}

static int32_t ProcExpandEvent(SessionImpl *impl, SessionEvent *inputEvent, CJson *sessionMsg, JumpPolicy *policy)
{
    bool isExpandFinsh = false;
    int32_t res = ProcExpandEventInner(impl, inputEvent, sessionMsg, &isExpandFinsh);
    if (res != HC_SUCCESS) {
        return RestartSession(impl, policy) == HC_SUCCESS ? HC_SUCCESS : res;
    }
    LOGI("process expand event success.");
    *policy = isExpandFinsh ? JUMP_TO_NEXT_STATE : STAY_STATE;
    return HC_SUCCESS;
}

static const SessionStateNode STATE_MACHINE[] = {
    { INIT_CLIENT_STATE, START_EVENT, ProcStartEvent, HAND_SHAKE_REQ_STATE },
    { INIT_SERVER_STATE, HAND_SHAKE_EVENT, ProcHandshakeReqEvent, HAND_SHAKE_RSP_STATE },
    { HAND_SHAKE_REQ_STATE, HAND_SHAKE_RSP_EVENT, ProcHandshakeRspEvent, AUTH_STATE },
    { HAND_SHAKE_RSP_STATE, AUTH_EVENT, ProcFirstAuthEvent, AUTH_STATE },
    { HAND_SHAKE_REQ_STATE, SESSION_FAIL_EVENT, ProcFailEvent, SESSION_FAIL_STATE },
    { HAND_SHAKE_RSP_STATE, SESSION_FAIL_EVENT, ProcFailEvent, SESSION_FAIL_STATE },
    { AUTH_STATE, AUTH_EVENT, ProcAuthEvent, EXPAND_STATE },
    { AUTH_STATE, SESSION_FAIL_EVENT, ProcFailEvent, SESSION_FAIL_STATE },
    { EXPAND_STATE, EXPAND_EVENT, ProcExpandEvent, SESSION_FINISH_STATE },
    { EXPAND_STATE, SESSION_FAIL_EVENT, ProcFailEvent, SESSION_FAIL_STATE },
};

int32_t SessionSwitchState(SessionImpl *impl, SessionEvent *event, CJson *sessionMsg)
{
    if (impl == NULL || event == NULL || sessionMsg == NULL) {
        LOGE("invalid params.");
        return HC_ERR_NULL_PTR;
    }
    for (uint32_t i = 0; i < sizeof(STATE_MACHINE) / sizeof(STATE_MACHINE[0]); i++) {
        if ((STATE_MACHINE[i].curState == impl->curState) && (STATE_MACHINE[i].eventType == event->type)) {
            JumpPolicy policy;
            int32_t preState = impl->curState;
            int32_t res = STATE_MACHINE[i].processFunc(impl, event, sessionMsg, &policy);
            if (res != HC_SUCCESS) {
                LOGE("An error occurred. [Res]: %d", res);
                impl->curState = SESSION_FAIL_STATE;
                return res;
            }
            if (policy == JUMP_TO_NEXT_STATE) {
                impl->curState = STATE_MACHINE[i].nextState;
            } else if (policy == RESTART_STATE) {
                impl->curState = impl->restartState;
            } else if (policy == JUMP_TO_FINISH_STATE) {
                impl->curState = SESSION_FINISH_STATE;
            }
            LOGI("[Event]: %d, [CurState]: %d, [nextState]: %d", event->type, preState, impl->curState);
            return HC_SUCCESS;
        }
    }
    LOGI("Unsupported event type. Ignore process. [Event]: %d, [CurState]: %d", event->type, impl->curState);
    return HC_SUCCESS;
}

#ifndef  DEV_AUTH_FUNC_TEST
bool IsSupportSessionV2(void)
{
    return true;
}
#endif
