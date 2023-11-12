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

#include "save_trusted_info.h"

#include "common_defs.h"
#include "data_manager.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_types.h"

#define PEER_TO_PEER_GROUP 256
#define DEFAULT_EXPIRE_TIME 90
#define SELF_CREATED 0

#define START_CMD_EVENT_NAME "StartCmd"
#define FAIL_EVENT_NAME "CmdFail"

#define FIELD_GROUP_NAME "groupName"
#define FIELD_USER_TYPE_CLIENT "userTypeC"
#define FIELD_USER_TYPE_SERVER "userTypeS"
#define FIELD_AUTH_ID_CLIENT "authIdC"
#define FIELD_AUTH_ID_SERVER "authIdS"
#define FIELD_UDID_CLIENT "udidC"
#define FIELD_UDID_SERVER "udidS"
#define FIELD_USER_ID_CLIENT "userIdC"
#define FIELD_USER_ID_SERVER "userIdS"

#define FIELD_EVENT "event"
#define FIELD_ERR_CODE "errCode"
#define FIELD_ERR_MSG "errMsg"

typedef struct {
    bool isGroupExistSelf;
    bool isGroupExistPeer;
    int32_t osAccountId;
    int32_t credType;
    int32_t userTypeSelf;
    int32_t userTypePeer;
    int32_t visibility;
    char *groupId;
    char *groupName;
    char *appId;
    char *authIdSelf;
    char *authIdPeer;
    char *udidSelf;
    char *udidPeer;
    char *userIdSelf;
    char *userIdPeer;
} CmdParams;

typedef struct {
    BaseCmd base;
    CmdParams params;
} SaveTrustedInfoCmd;

typedef enum {
    START_EVENT = 0,
    CLIENT_SEND_INFO_EVENT,
    SERVER_SEND_INFO_EVENT,
    FAIL_EVENT,
    UNKNOWN_EVENT,
} EventEnum;

typedef enum {
    CREATE_AS_CLIENT_STATE = 0,
    CREATE_AS_SERVER_STATE,
    CLIENT_START_REQ_STATE,
    /* FINISH STATE */
    CLIENT_FINISH_STATE,
    SERVER_FINISH_STATE,
    /* FAIL STATE */
    FAIL_STATE
} StateEnum;

typedef struct {
    int32_t curState;
    int32_t eventType;
    int32_t (*stateProcessFunc)(BaseCmd *self, const CJson *inputEvent, CJson **outputEvent);
    void (*exceptionHandleFunc)(int32_t errorCode, CJson **outputEvent);
    int32_t nextState;
} CmdStateNode;

static TrustedGroupEntry *GetGroupEntryById(int32_t osAccountId, const char *groupId)
{
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    QueryGroupParams params = InitQueryGroupParams();
    params.groupId = groupId;
    if (QueryGroups(osAccountId, &params, &groupEntryVec) != HC_SUCCESS) {
        LOGE("Failed to query groups!");
        ClearGroupEntryVec(&groupEntryVec);
        return NULL;
    }
    uint32_t index;
    TrustedGroupEntry **entry;
    FOR_EACH_HC_VECTOR(groupEntryVec, index, entry) {
        TrustedGroupEntry *returnEntry = DeepCopyGroupEntry(*entry);
        ClearGroupEntryVec(&groupEntryVec);
        return returnEntry;
    }
    ClearGroupEntryVec(&groupEntryVec);
    return NULL;
}

static int32_t ClientSendTrustedInfoProcEvent(CmdParams *params)
{
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return res;
    }
    if (DeepCopyString(udid, &params->udidSelf) != HC_SUCCESS) {
        LOGE("copy udid fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(params->osAccountId, params->groupId);
    if (entry == NULL) {
        params->isGroupExistSelf = false;
        return HC_SUCCESS;
    }
    params->isGroupExistSelf = true;
    if (DeepCopyString(StringGet(&entry->name), &params->groupName) != HC_SUCCESS) {
        LOGE("copy groupName fail.");
        DestroyGroupEntry(entry);
        return HC_ERR_ALLOC_MEMORY;
    }
    if ((entry->type != PEER_TO_PEER_GROUP) &&
        (DeepCopyString(StringGet(&entry->userId), &params->userIdSelf) != HC_SUCCESS)) {
        LOGE("copy userIdSelf fail.");
        DestroyGroupEntry(entry);
        return HC_ERR_ALLOC_MEMORY;
    }
    DestroyGroupEntry(entry);
    return HC_SUCCESS;
}

static int32_t ClientSendTrustedInfoBuildEvent(const CmdParams *params, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(json, FIELD_EVENT, CLIENT_SEND_INFO_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(json, FIELD_AUTH_ID_CLIENT, params->authIdSelf) != HC_SUCCESS) {
        LOGE("add authIdC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(json, FIELD_UDID_CLIENT, params->udidSelf) != HC_SUCCESS) {
        LOGE("add udidC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(json, FIELD_USER_TYPE_CLIENT, params->userTypeSelf) != HC_SUCCESS) {
        LOGE("add userTypeC to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (params->isGroupExistSelf) {
        if (AddStringToJson(json, FIELD_GROUP_NAME, params->groupName) != HC_SUCCESS) {
            LOGE("add groupName to json fail.");
            FreeJson(json);
            return HC_ERR_JSON_ADD;
        }
    }
    if (params->userIdSelf != NULL) {
        if (AddStringToJson(json, FIELD_USER_ID_CLIENT, params->userIdSelf) != HC_SUCCESS) {
            LOGE("add userIdC to json fail.");
            FreeJson(json);
            return HC_ERR_JSON_ADD;
        }
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t ServerSendTrustedInfoParseEvent(const CJson *inputEvent, CmdParams *params)
{
    const char *authId = GetStringFromJson(inputEvent, FIELD_AUTH_ID_CLIENT);
    if (authId == NULL) {
        LOGE("get authIdC from json fail.");
        return HC_ERR_JSON_GET;
    }
    const char *udid = GetStringFromJson(inputEvent, FIELD_UDID_CLIENT);
    if (udid == NULL) {
        LOGE("get udidC from json fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t userTypeC;
    if (GetIntFromJson(inputEvent, FIELD_USER_TYPE_CLIENT, &userTypeC) != HC_SUCCESS) {
        LOGE("get userTypeC from json fail.");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyString(authId, &(params->authIdPeer)) != HC_SUCCESS) {
        LOGE("copy groupId fail.");
        return HC_ERR_MEMORY_COPY;
    }
    if (DeepCopyString(udid, &(params->udidPeer)) != HC_SUCCESS) {
        LOGE("copy groupId fail.");
        return HC_ERR_MEMORY_COPY;
    }
    const char *groupName = GetStringFromJson(inputEvent, FIELD_GROUP_NAME);
    if (groupName != NULL) {
        if (DeepCopyString(groupName, &(params->groupName)) != HC_SUCCESS) {
            LOGE("copy groupName fail.");
            return HC_ERR_MEMORY_COPY;
        }
        params->isGroupExistPeer = true;
    } else {
        params->isGroupExistPeer = false;
    }
    const char *userId = GetStringFromJson(inputEvent, FIELD_USER_ID_CLIENT);
    if (userId != NULL) {
        if (DeepCopyString(userId, &(params->userIdPeer)) != HC_SUCCESS) {
            LOGE("copy userId fail.");
            return HC_ERR_MEMORY_COPY;
        }
    }
    params->userTypePeer = userTypeC;
    return HC_SUCCESS;
}

static int32_t GenerateGroupParams(const CmdParams *params, TrustedGroupEntry *groupParams)
{
    if (!StringSetPointer(&groupParams->name, params->groupName)) {
        LOGE("Failed to copy groupName!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&groupParams->id, params->groupId)) {
        LOGE("Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    HcString ownerName = CreateString();
    if (!StringSetPointer(&ownerName, params->appId)) {
        LOGE("Failed to copy groupOwner!");
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    if (groupParams->managers.pushBackT(&groupParams->managers, ownerName) == NULL) {
        LOGE("Failed to push owner to vec!");
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    groupParams->visibility = params->visibility;
    groupParams->type = PEER_TO_PEER_GROUP;
    groupParams->expireTime = DEFAULT_EXPIRE_TIME;
    return HC_SUCCESS;
}

static int32_t GeneratePeerDevParams(const CmdParams *params, TrustedDeviceEntry *devParams)
{
    if (!StringSetPointer(&devParams->groupId, params->groupId)) {
        LOGE("Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->udid, params->udidPeer)) {
        LOGE("Failed to copy udid!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->authId, params->authIdPeer)) {
        LOGE("Failed to copy authId!");
        return HC_ERR_MEMORY_COPY;
    }
    if (params->userIdPeer != NULL && !StringSetPointer(&devParams->userId, params->userIdPeer)) {
        LOGE("Failed to copy serviceType!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->serviceType, params->groupId)) {
        LOGE("Failed to copy serviceType!");
        return HC_ERR_MEMORY_COPY;
    }
    devParams->credential = params->credType;
    devParams->devType = params->userTypePeer;
    devParams->source = SELF_CREATED;
    return HC_SUCCESS;
}

static int32_t GenerateSelfDevParams(const CmdParams *params, TrustedDeviceEntry *devParams)
{
    if (!StringSetPointer(&devParams->udid, params->udidSelf)) {
        LOGE("Failed to copy udid!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->authId, params->authIdSelf)) {
        LOGE("Failed to copy authId!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->groupId, params->groupId)) {
        LOGE("Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    if (!StringSetPointer(&devParams->serviceType, params->groupId)) {
        LOGE("Failed to copy serviceType!");
        return HC_ERR_MEMORY_COPY;
    }
    devParams->devType = params->userTypeSelf;
    devParams->source = SELF_CREATED;
    devParams->credential = params->credType;
    return HC_SUCCESS;
}

static int32_t AddTrustedGroup(const CmdParams *params)
{
    TrustedGroupEntry *groupParams = CreateGroupEntry();
    if (groupParams == NULL) {
        LOGE("Failed to allocate groupParams memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateGroupParams(params, groupParams);
    if (res != HC_SUCCESS) {
        DestroyGroupEntry(groupParams);
        return res;
    }
    res = AddGroup(params->osAccountId, groupParams);
    DestroyGroupEntry(groupParams);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add the group to the database!");
    }
    return res;
}

static int32_t AddPeerTrustedDevice(const CmdParams *params)
{
    TrustedDeviceEntry *devParams = CreateDeviceEntry();
    if (devParams == NULL) {
        LOGE("Failed to allocate devParams memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GeneratePeerDevParams(params, devParams);
    if (res != HC_SUCCESS) {
        DestroyDeviceEntry(devParams);
        return res;
    }
    res = AddTrustedDevice(params->osAccountId, devParams);
    DestroyDeviceEntry(devParams);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add the peer trust device to the database!");
    } else {
        LOGI("add trusted device success.");
        PRINT_SENSITIVE_DATA("GroupId", params->groupId);
        PRINT_SENSITIVE_DATA("PeerAuthId", params->authIdPeer);
        PRINT_SENSITIVE_DATA("PeerUdid", params->udidPeer);
    }
    return res;
}

static int32_t AddSelfTrustedDevice(const CmdParams *params)
{
    TrustedDeviceEntry *devParams = CreateDeviceEntry();
    if (devParams == NULL) {
        LOGE("Failed to allocate devParams memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = GenerateSelfDevParams(params, devParams);
    if (res != HC_SUCCESS) {
        DestroyDeviceEntry(devParams);
        return res;
    }
    res = AddTrustedDevice(params->osAccountId, devParams);
    DestroyDeviceEntry(devParams);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add the self trust device to the database!");
    }
    return res;
}

static int32_t CreatePeerToPeerGroup(const CmdParams *params)
{
    int32_t res = AddTrustedGroup(params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return AddSelfTrustedDevice(params);
}

static TrustedDeviceEntry *GetTrustedDeviceEntryById(int32_t osAccountId, const char *udid, const char *groupId)
{
    DeviceEntryVec deviceEntryVec = CreateDeviceEntryVec();
    QueryDeviceParams params = InitQueryDeviceParams();
    params.groupId = groupId;
    params.udid = udid;
    if (QueryDevices(osAccountId, &params, &deviceEntryVec) != HC_SUCCESS) {
        LOGE("Failed to query trusted devices!");
        ClearDeviceEntryVec(&deviceEntryVec);
        return NULL;
    }
    uint32_t index;
    TrustedDeviceEntry **deviceEntry;
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, deviceEntry) {
        TrustedDeviceEntry *returnEntry = DeepCopyDeviceEntry(*deviceEntry);
        ClearDeviceEntryVec(&deviceEntryVec);
        return returnEntry;
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return NULL;
}

static bool IsDeviceImportedByCloud(const CmdParams *params)
{
    TrustedDeviceEntry *peerDeviceEntry = GetTrustedDeviceEntryById(params->osAccountId, params->udidPeer,
        params->groupId);
    if (peerDeviceEntry == NULL) {
        return false;
    }
    uint8_t source = peerDeviceEntry->source;
    DestroyDeviceEntry(peerDeviceEntry);
    return source == IMPORTED_FROM_CLOUD;
}

static int32_t ServerSendTrustedInfoProcEvent(CmdParams *params)
{
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %d", res);
        return res;
    }
    if (DeepCopyString(udid, &params->udidSelf) != HC_SUCCESS) {
        LOGE("copy udid fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(params->osAccountId, params->groupId);
    if (entry == NULL) {
        params->isGroupExistSelf = false;
        res = CreatePeerToPeerGroup(params);
        if (res != HC_SUCCESS) {
            LOGE("Failed to add the group to the database!");
            return res;
        }
    } else {
        params->isGroupExistSelf = true;
        if ((params->groupName == NULL) &&
            (DeepCopyString(StringGet(&entry->name), &params->groupName) != HC_SUCCESS)) {
            LOGE("copy groupName fail.");
            DestroyGroupEntry(entry);
            return HC_ERR_ALLOC_MEMORY;
        }
        if ((entry->type != PEER_TO_PEER_GROUP) &&
            (DeepCopyString(StringGet(&entry->userId), &params->userIdSelf) != HC_SUCCESS)) {
            LOGE("copy userIdSelf fail.");
            DestroyGroupEntry(entry);
            return HC_ERR_ALLOC_MEMORY;
        }
        DestroyGroupEntry(entry);
    }
    if (!IsDeviceImportedByCloud(params)) {
        res = AddPeerTrustedDevice(params);
        if (res != HC_SUCCESS) {
            return res;
        }
    } else {
        LOGI("Peer trusted device is imported from cloud, so there is no need to add it again.");
    }
    return SaveOsAccountDb(params->osAccountId);
}

static int32_t ServerSendTrustedInfoBuildEvent(const CmdParams *params, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddIntToJson(json, FIELD_EVENT, SERVER_SEND_INFO_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(json, FIELD_AUTH_ID_SERVER, params->authIdSelf) != HC_SUCCESS) {
        LOGE("add authIdS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(json, FIELD_UDID_SERVER, params->udidSelf) != HC_SUCCESS) {
        LOGE("add udidS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(json, FIELD_USER_TYPE_SERVER, params->userTypeSelf) != HC_SUCCESS) {
        LOGE("add userTypeS to json fail.");
        FreeJson(json);
        return HC_ERR_JSON_ADD;
    }
    if (!params->isGroupExistPeer) {
        if (AddStringToJson(json, FIELD_GROUP_NAME, params->groupName) != HC_SUCCESS) {
            LOGE("add groupName to json fail.");
            FreeJson(json);
            return HC_ERR_JSON_ADD;
        }
    }
    if (params->userIdSelf != NULL) {
        if (AddStringToJson(json, FIELD_USER_ID_SERVER, params->userIdSelf) != HC_SUCCESS) {
            LOGE("add userIdS to json fail.");
            FreeJson(json);
            return HC_ERR_JSON_ADD;
        }
    }
    *outputEvent = json;
    return HC_SUCCESS;
}

static int32_t ClientFinishProcParseEvent(const CJson *inputEvent, CmdParams *params)
{
    if (!params->isGroupExistSelf) {
        const char *groupName = GetStringFromJson(inputEvent, FIELD_GROUP_NAME);
        if (groupName == NULL) {
            LOGE("get groupName from json fail.");
            return HC_ERR_JSON_GET;
        }
        if (DeepCopyString(groupName, &(params->groupName)) != HC_SUCCESS) {
            LOGE("copy groupName fail.");
            return HC_ERR_MEMORY_COPY;
        }
    }
    const char *authId = GetStringFromJson(inputEvent, FIELD_AUTH_ID_SERVER);
    if (authId == NULL) {
        LOGE("get authIdS from json fail.");
        return HC_ERR_JSON_GET;
    }
    const char *udid = GetStringFromJson(inputEvent, FIELD_UDID_SERVER);
    if (udid == NULL) {
        LOGE("get udidS from json fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t userTypeS;
    if (GetIntFromJson(inputEvent, FIELD_USER_TYPE_SERVER, &userTypeS) != HC_SUCCESS) {
        LOGE("get userTypeS from json fail.");
        return HC_ERR_JSON_GET;
    }
    if (DeepCopyString(authId, &(params->authIdPeer)) != HC_SUCCESS) {
        LOGE("copy groupId fail.");
        return HC_ERR_MEMORY_COPY;
    }
    if (DeepCopyString(udid, &(params->udidPeer)) != HC_SUCCESS) {
        LOGE("copy groupId fail.");
        return HC_ERR_MEMORY_COPY;
    }
    const char *userId = GetStringFromJson(inputEvent, FIELD_USER_ID_SERVER);
    if (userId != NULL) {
        if (DeepCopyString(userId, &(params->userIdPeer)) != HC_SUCCESS) {
            LOGE("copy userId fail.");
            return HC_ERR_MEMORY_COPY;
        }
    }
    params->userTypePeer = userTypeS;
    return HC_SUCCESS;
}

static int32_t ClientFinishProcProcEvent(const CmdParams *params)
{
    int32_t res;
    if (!params->isGroupExistSelf) {
        res = CreatePeerToPeerGroup(params);
        if (res != HC_SUCCESS) {
            LOGE("Failed to add the group to the database!");
            return res;
        }
    }
    if (!IsDeviceImportedByCloud(params)) {
        res = AddPeerTrustedDevice(params);
        if (res != HC_SUCCESS) {
            return res;
        }
    }
    return SaveOsAccountDb(params->osAccountId);
}

static void ReturnError(int32_t errorCode, CJson **outputEvent)
{
    (void)errorCode;
    (void)outputEvent;
    return;
}

static void NotifyPeerError(int32_t errorCode, CJson **outputEvent)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("create json failed.");
        return;
    }
    if (AddIntToJson(json, FIELD_EVENT, FAIL_EVENT) != HC_SUCCESS) {
        LOGE("add eventName to json fail.");
        FreeJson(json);
        return;
    }
    if (AddIntToJson(json, FIELD_ERR_CODE, errorCode) != HC_SUCCESS) {
        LOGE("add errorCode to json fail.");
        FreeJson(json);
        return;
    }
    *outputEvent = json;
    return;
}

static int32_t ThrowException(BaseCmd *self, const CJson *baseEvent, CJson **outputEvent)
{
    (void)self;
    (void)outputEvent;
    int32_t peerErrorCode = HC_ERR_PEER_ERROR;
    (void)GetIntFromJson(baseEvent, FIELD_ERR_CODE, &peerErrorCode);
    LOGE("An exception occurred in the peer cmd. [Code]: %d", peerErrorCode);
    return peerErrorCode;
}

static int32_t ClientSendTrustedInfo(BaseCmd *self, const CJson *inputEvent, CJson **outputEvent)
{
    (void)inputEvent;
    SaveTrustedInfoCmd *impl = (SaveTrustedInfoCmd *)self;
    int32_t res = ClientSendTrustedInfoProcEvent(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ClientSendTrustedInfoBuildEvent(&impl->params, outputEvent);
}

static int32_t ServerSendTrustedInfo(BaseCmd *self, const CJson *inputEvent, CJson **outputEvent)
{
    SaveTrustedInfoCmd *impl = (SaveTrustedInfoCmd *)self;
    int32_t res = ServerSendTrustedInfoParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = ServerSendTrustedInfoProcEvent(&impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ServerSendTrustedInfoBuildEvent(&impl->params, outputEvent);
}

static int32_t ClientFinishProc(BaseCmd *self, const CJson *inputEvent, CJson **outputEvent)
{
    (void)outputEvent;
    SaveTrustedInfoCmd *impl = (SaveTrustedInfoCmd *)self;
    int32_t res = ClientFinishProcParseEvent(inputEvent, &impl->params);
    if (res != HC_SUCCESS) {
        return res;
    }
    return ClientFinishProcProcEvent(&impl->params);
}

static const CmdStateNode STATE_MACHINE[] = {
    { CREATE_AS_CLIENT_STATE, START_EVENT, ClientSendTrustedInfo, NotifyPeerError, CLIENT_START_REQ_STATE },
    { CREATE_AS_SERVER_STATE, CLIENT_SEND_INFO_EVENT, ServerSendTrustedInfo, NotifyPeerError, SERVER_FINISH_STATE },
    { CREATE_AS_SERVER_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
    { CLIENT_START_REQ_STATE, SERVER_SEND_INFO_EVENT, ClientFinishProc, ReturnError, CLIENT_FINISH_STATE },
    { CLIENT_START_REQ_STATE, FAIL_EVENT, ThrowException, ReturnError, FAIL_STATE },
};

static int32_t DecodeEvent(const CJson *receviedMsg)
{
    if (receviedMsg == NULL) {
        return START_EVENT;
    }
    int32_t event;
    if (GetIntFromJson(receviedMsg, FIELD_EVENT, &event) != HC_SUCCESS) {
        LOGE("get event from receviedMsg fail.");
        return UNKNOWN_EVENT;
    }
    if (START_EVENT <= event && event <= UNKNOWN_EVENT) {
        return event;
    }
    LOGE("unknown event.");
    return UNKNOWN_EVENT;
}

static int32_t SwitchState(BaseCmd *self, const CJson *receviedMsg, CJson **returnSendMsg, CmdState *returnState)
{
    int32_t eventType = DecodeEvent(receviedMsg);
    for (uint32_t i = 0; i < sizeof(STATE_MACHINE) / sizeof(STATE_MACHINE[0]); i++) {
        if ((STATE_MACHINE[i].curState == self->curState) && (STATE_MACHINE[i].eventType == eventType)) {
            int32_t res = STATE_MACHINE[i].stateProcessFunc(self, receviedMsg, returnSendMsg);
            if (res != HC_SUCCESS) {
                STATE_MACHINE[i].exceptionHandleFunc(res, returnSendMsg);
                self->curState = self->failState;
                return res;
            }
            LOGI("event: %d, curState: %d, nextState: %d", eventType, self->curState, STATE_MACHINE[i].nextState);
            self->curState = STATE_MACHINE[i].nextState;
            *returnState = (self->curState == self->finishState) ? CMD_STATE_FINISH : CMD_STATE_CONTINUE;
            return HC_SUCCESS;
        }
    }
    LOGI("Unsupported event type. Ignore process. [Event]: %d, [CurState]: %d", eventType, self->curState);
    return HC_SUCCESS;
}

static int32_t StartSaveTrustedInfoCmd(BaseCmd *self, CJson **returnSendMsg)
{
    if ((self == NULL) || (returnSendMsg == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if (self->curState != self->beginState) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    CmdState state;
    return SwitchState(self, NULL, returnSendMsg, &state);
}

static int32_t ProcessSaveTrustedInfoCmd(BaseCmd *self, const CJson *receviedMsg,
    CJson **returnSendMsg, CmdState *returnState)
{
    if ((self == NULL) || (receviedMsg == NULL) || (returnSendMsg == NULL) || (returnState == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    if ((self->curState == self->finishState) || (self->curState == self->failState)) {
        LOGE("The protocol has ended, and the state switch cannot continue!");
        return HC_ERR_UNSUPPORTED_OPCODE;
    }
    return SwitchState(self, receviedMsg, returnSendMsg, returnState);
}

static void DestroySaveTrustedInfoCmd(BaseCmd *self)
{
    if (self == NULL) {
        LOGD("self is null.");
        return;
    }
    SaveTrustedInfoCmd *impl = (SaveTrustedInfoCmd *)self;
    HcFree(impl->params.groupId);
    impl->params.groupId = NULL;
    HcFree(impl->params.groupName);
    impl->params.groupName = NULL;
    HcFree(impl->params.appId);
    impl->params.appId = NULL;
    HcFree(impl->params.authIdSelf);
    impl->params.authIdSelf = NULL;
    HcFree(impl->params.authIdPeer);
    impl->params.authIdPeer = NULL;
    HcFree(impl->params.udidSelf);
    impl->params.udidSelf = NULL;
    HcFree(impl->params.udidPeer);
    impl->params.udidPeer = NULL;
    HcFree(impl->params.userIdSelf);
    impl->params.userIdSelf = NULL;
    HcFree(impl->params.userIdPeer);
    impl->params.userIdPeer = NULL;
    HcFree(impl);
}

static inline bool IsSaveTrustedInfoParamsValid(const SaveTrustedInfoParams *params)
{
    return ((params != NULL) && (params->appId != NULL) && (params->authId != NULL) && (params->groupId != NULL));
}

static int32_t InitSaveTrustedInfoCmd(SaveTrustedInfoCmd *instance, const SaveTrustedInfoParams *params,
    bool isCaller, int32_t strategy)
{
    if (DeepCopyString(params->appId, &(instance->params.appId)) != HC_SUCCESS) {
        LOGE("copy appId fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyString(params->authId, &(instance->params.authIdSelf)) != HC_SUCCESS) {
        LOGE("copy authId fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (DeepCopyString(params->groupId, &(instance->params.groupId)) != HC_SUCCESS) {
        LOGE("copy groupId fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    instance->params.isGroupExistSelf = false;
    instance->params.isGroupExistPeer = false;
    instance->params.osAccountId = params->osAccountId;
    instance->params.credType = params->credType;
    instance->params.userTypeSelf = params->userType;
    instance->params.visibility = params->visibility;
    instance->base.type = SAVE_TRUSTED_INFO_CMD_TYPE;
    instance->base.strategy = strategy;
    instance->base.isCaller = isCaller;
    instance->base.beginState = isCaller ? CREATE_AS_CLIENT_STATE : CREATE_AS_SERVER_STATE;
    instance->base.finishState = isCaller ? CLIENT_FINISH_STATE : SERVER_FINISH_STATE;
    instance->base.failState = FAIL_STATE;
    instance->base.curState = instance->base.beginState;
    instance->base.start = StartSaveTrustedInfoCmd;
    instance->base.process = ProcessSaveTrustedInfoCmd;
    instance->base.destroy = DestroySaveTrustedInfoCmd;
    return HC_SUCCESS;
}

BaseCmd *CreateSaveTrustedInfoCmd(const void *baseParams, bool isCaller, int32_t strategy)
{
    const SaveTrustedInfoParams *params = (const SaveTrustedInfoParams *)baseParams;
    if (!IsSaveTrustedInfoParamsValid(params)) {
        LOGE("invalid params.");
        return NULL;
    }
    SaveTrustedInfoCmd *instance = (SaveTrustedInfoCmd *)HcMalloc(sizeof(SaveTrustedInfoCmd), 0);
    if (instance == NULL) {
        LOGE("allocate instance memory fail.");
        return NULL;
    }
    int32_t res = InitSaveTrustedInfoCmd(instance, params, isCaller, strategy);
    if (res != HC_SUCCESS) {
        DestroySaveTrustedInfoCmd((BaseCmd *)instance);
        return NULL;
    }
    return (BaseCmd *)instance;
}
