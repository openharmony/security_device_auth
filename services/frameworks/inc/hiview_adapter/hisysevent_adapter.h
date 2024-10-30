/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef HISYSEVENT_ADAPTER_H
#define HISYSEVENT_ADAPTER_H

#include <stddef.h>

#define CREATE_GROUP_EVENT "CreateGroup"
#define DELETE_GROUP_EVENT "DeleteGroup"
#define ADD_MEMBER_EVENT "AddMember"
#define DEL_MEMBER_EVENT "DelMember"
#define ADD_MULTI_MEMBER_EVENT "AddMultiMember"
#define DEL_MULTI_MEMBER_EVENT "DelMultiMember"
#define AUTH_DEV_EVENT "AuthDevice"

#define CANCEL_REQUEST_EVENT "CancelRequest"
#define GET_REGISTER_INFO_EVENT "GetRegisterInfo"
#define GET_PK_INFO_LIST_EVENT "GetPkInfoList"

#define ADD_MEMBER_WITH_LITE_COMPATIBILITY "AddMemberWithLiteCompatibility"
#define ADD_MEMBER_WITH_LITE_STANDARD "AddMemberWithLiteStandard"
#define UPGRADE_DATA_EVENT "UpgradeData"
#define BIND_CONSUME_EVENT "BindConsume"
#define AUTH_CONSUME_EVENT "AuthConsume"

#define DEFAULT_GROUP_TYPE 0
#define DEFAULT_MULTI_MEMBER_GROUP_TYPE 1
#define DEFAULT_CRED_TYPE 0
#define DEFAULT_CALL_RESULT 0
#define DEFAULT_APPID NULL

#define DEFAULT_EXECUTION_TIME 0
#define DEFAULT_REQ_ID 0
#define DEFAULT_FAULT_INFO NULL
#define DEFAULT_EXT_INFO NULL

#include <stdint.h>

enum DevAuthReportProcessCode {
    PROCESS_BIND_V1 = 0x001000,
    PROCESS_AUTH_V1,
    PROCESS_BIND_V2,
    PROCESS_AUTH_V2,
    PROCESS_CREATE_GROUP,
    PROCESS_DELETE_GROUP,
    PROCESS_DELETE_MEMBER_FROM_GROUP,
    PROCESS_ADD_MULTI_MEMBERS_TO_GROUP,
    PROCESS_DEL_MULTI_MEMBERS_FROM_GROUP,
    PROCESS_UPDATE
};

#define DEFAULT_PNAMEID "device_auth"
#define DEFAULT_PVERSIONID "1.0"

#ifndef DEV_AUTH_HIVIEW_ENABLE

#define DEV_AUTH_REPORT_CALL_EVENT(eventData)
#define DEV_AUTH_REPORT_FAULT_EVENT(eventdata)
#define DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(funcName, processCode, errorCode)
#define DEV_AUTH_REPORT_UE_CALL_EVENT(osAccountId, groupType, appId, funcName)
#define DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, inParams, appId, funcName)
#else

#define DEV_AUTH_REPORT_CALL_EVENT(eventData) \
    DevAuthReportCallEvent(eventData)
#define DEV_AUTH_REPORT_FAULT_EVENT(eventdata) \
    DevAuthReportFaultEvent(eventdata)
#define DEV_AUTH_REPORT_FAULT_EVENT_WITH_ERR_CODE(funcName, processCode, errorCode) \
    DevAuthReportFaultEventWithErrCode(funcName, processCode, errorCode)
#define DEV_AUTH_REPORT_UE_CALL_EVENT(osAccountId, groupType, appId, funcName) \
    DevAuthReportUeCallEvent(osAccountId, groupType, appId, funcName)
#define DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, inParams, appId, funcName) \
    DevAuthReportUeCallEventByParams(osAccountId, inParams, appId, funcName)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *funcName;
    const char *appId;
    int32_t osAccountId;
    int32_t callResult;
    int32_t processCode;
    uint8_t credType;
    int32_t groupType;
    int64_t executionTime;
    const char *extInfo;
} DevAuthCallEvent;

typedef struct {
    const char *appId;
    int32_t processCode;
    const char *funcName;
    int64_t reqId;
    int32_t errorCode;
    const char *faultInfo;
} DevAuthFaultEvent;

void DevAuthReportCallEvent(const DevAuthCallEvent eventData);
void DevAuthReportFaultEvent(const DevAuthFaultEvent eventdata);
void DevAuthReportFaultEventWithErrCode(const char *funcName, const int32_t processCode, const int32_t errorCode);
void DevAuthReportUeCallEvent(int32_t osAccountId, int32_t groupType, const char *appId,
    const char *funcName);
void DevAuthReportUeCallEventByParams(int32_t osAccountId, const char *inParams, const char *appId,
    const char *funcName);

#ifdef __cplusplus
}
#endif

#endif

#endif
