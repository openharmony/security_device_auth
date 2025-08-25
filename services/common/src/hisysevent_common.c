/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hisysevent_common.h"
#include "common_defs.h"
#include "hc_log.h"
#include "hc_dev_info.h"
#include "string_util.h"

#ifdef DEV_AUTH_HIVIEW_ENABLE

static int32_t WHITE_LIST[] = {
    PEER_OCCUR_ERROR,
    ACCOUNT_NOT_LOGIN,
    ACCOUNT_LOGINED_NOT_SAME_AS_PEER
};

const char *GetAddMemberCallEventFuncName(const char *addParams)
{
    if (addParams == NULL) {
        LOGE("add params is null!");
        return ADD_MEMBER_EVENT;
    }
    CJson *in = CreateJsonFromString(addParams);
    if (in == NULL) {
        LOGE("Failed to create json param!");
        return ADD_MEMBER_EVENT;
    }
    int32_t protocolExpandVal = INVALID_PROTOCOL_EXPAND_VALUE;
    (void)GetIntFromJson(in, FIELD_PROTOCOL_EXPAND, &protocolExpandVal);
    FreeJson(in);
    if (protocolExpandVal == LITE_PROTOCOL_STANDARD_MODE) {
        return ADD_MEMBER_WITH_LITE_STANDARD;
    } else if (protocolExpandVal == LITE_PROTOCOL_COMPATIBILITY_MODE) {
        return ADD_MEMBER_WITH_LITE_COMPATIBILITY;
    } else {
        return ADD_MEMBER_EVENT;
    }
}

DevAuthBizScene GetBizScene(bool isBind, bool isClient)
{
    if (isBind) {
        if (isClient) {
            return BIZ_SCENE_ADD_MEMBER_CLIENT;
        } else {
            return BIZ_SCENE_ADD_MEMBER_SERVER;
        }
    } else {
        if (isClient) {
            return BIZ_SCENE_AUTH_DEVICE_CLIENT;
        } else {
            return BIZ_SCENE_AUTH_DEVICE_SERVER;
        }
    }
}
void BuildStageRes(DevAuthBehaviorEvent *eventData, int32_t errorCode)
{
    for (uint32_t i = 0; i < sizeof(WHITE_LIST) / sizeof(WHITE_LIST[0]); i++) {
        if (WHITE_LIST[i] == errorCode) {
            eventData->stageRes = STAGE_RES_IGNORE;
            return;
        }
    }
    eventData->stageRes = STAGE_RES_FAILED;
}

#endif

void ReportBehaviorBeginEvent(bool isBind, bool isClient, int64_t reqId)
{
#ifdef DEV_AUTH_HIVIEW_ENABLE
    char *funcName = isBind ? ADD_MEMBER_EVENT : AUTH_DEV_EVENT;
    DevAuthBizScene scene = GetBizScene(isBind, isClient);
    DevAuthBehaviorEvent eventData = { 0 };
    BuildBehaviorEventData(&eventData, funcName, scene, BIZ_STATE_BEGIN, BIZ_STAGE_BEGIN);
    char anonymousLocalUdid[ANONYMOUS_UDID_LEN + 1] = { 0 };
    if (isBind) {
        eventData.hostPkg = ADD_MEMBER_HOST_PKG_NAME;
        eventData.toCallPkg = ADD_MEMBER_TO_CALL_PKG_NAME;
    } else {
        eventData.hostPkg = AUTH_DEVICE_HOST_PKG_NAME;
        char selfUdid[INPUT_UDID_LEN] = { 0 };
        (void)HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
        if (GetAnonymousString(selfUdid, anonymousLocalUdid, ANONYMOUS_UDID_LEN) == HC_SUCCESS) {
            eventData.localUdid = anonymousLocalUdid;
        }
    }
    char concurrentId[MAX_REQUEST_ID_LEN] = { 0 };
    (void)sprintf_s(concurrentId, sizeof(concurrentId), "%" PRId64, reqId);
    eventData.concurrentId = concurrentId;
    DevAuthReportBehaviorEvent(&eventData);
#else
    (void)isBind;
    (void)isClient;
    (void)reqId;
#endif
}

void ReportBehaviorBeginResultEvent(bool isBind, bool isClient, int64_t reqId, const char *peerUdid, int32_t res)
{
#ifdef DEV_AUTH_HIVIEW_ENABLE
    char *funcName = isBind ? ADD_MEMBER_EVENT : AUTH_DEV_EVENT;
    DevAuthBizScene scene = GetBizScene(isBind, isClient);
    DevAuthBehaviorEvent eventData = { 0 };
    BuildBehaviorEventData(&eventData, funcName, scene, BIZ_STATE_PROCESS, BIZ_STAGE_BEGIN);
    char anonymousLocalUdid[ANONYMOUS_UDID_LEN + 1] = { 0 };
    char anonymousPeerUdid[ANONYMOUS_UDID_LEN + 1] = { 0 };
    if (isBind) {
        eventData.hostPkg = ADD_MEMBER_HOST_PKG_NAME;
        eventData.toCallPkg = ADD_MEMBER_TO_CALL_PKG_NAME;
    } else {
        eventData.hostPkg = AUTH_DEVICE_HOST_PKG_NAME;
        char selfUdid[INPUT_UDID_LEN] = { 0 };
        (void)HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
        if (GetAnonymousString(selfUdid, anonymousLocalUdid, ANONYMOUS_UDID_LEN) == HC_SUCCESS) {
            eventData.localUdid = anonymousLocalUdid;
        }
        if (GetAnonymousString(peerUdid, anonymousPeerUdid, ANONYMOUS_UDID_LEN) == HC_SUCCESS) {
            eventData.peerUdid = anonymousPeerUdid;
        }
    }
    char concurrentId[MAX_REQUEST_ID_LEN] = { 0 };
    (void)sprintf_s(concurrentId, sizeof(concurrentId), "%" PRId64, reqId);
    eventData.concurrentId = concurrentId;
    if (res == HC_SUCCESS) {
        eventData.stageRes = STAGE_RES_SUCCESS;
    } else {
        BuildStageRes(&eventData, res);
        eventData.errorCode = res;
    }
    DevAuthReportBehaviorEvent(&eventData);
#else
    (void)isBind;
    (void)isClient;
    (void)reqId;
    (void)peerUdid;
    (void)res;
#endif
}