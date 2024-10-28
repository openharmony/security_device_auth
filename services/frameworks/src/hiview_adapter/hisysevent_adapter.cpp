/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hisysevent_adapter.h"
#include "common_defs.h"

#include "hisysevent.h"

#define STR_CALL_EVENT "CALL_EVENT"
#define STR_FAULT_EVENT "FAULT_EVENT"
#define STR_STATISTIC_EVENT "STATISTIC_EVENT"
#define STR_OS_ACCOUNT_ID "OS_ACCOUNT_ID"
#define STR_FUNC_NAME "FUNC_NAME"
#define STR_FAULT_REASON "FAULT_REASON"
#define STR_CRED_TYPE "CRED_TYPE"
#define STR_GROUP_TYPE "GROUP_TYPE"
#define STR_COST_TIME "COST_TIME"
#define STR_PROTOCOL_TYPE "PROTOCOL_TYPE"
#define STR_APP_ID "APP_ID"
#define STR_REQ_ID "REQ_ID"
#define STR_CALL_RESULT "CALL_RESULT"
#define STR_UNKNOWN "unknown"
#define STR_PROCESS_CODE "PROCESS_CODE"
#define STR_EXECUTION_TIME "EXECUTION_TIME"
#define STR_EXT_INFO "EXT_INFO"
#define STR_FAULT_INFO "FAULT_INFO"
#define STR_ERROR_CODE "ERROR_CODE"
#define STR_PNAME_ID "PNAMEID"
#define STR_PVERSION_ID "PVERSIONID"

void DevAuthReportCallEvent(const DevAuthCallEvent eventData)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_AUTH,
        STR_CALL_EVENT, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        STR_FUNC_NAME, ((eventData.funcName != NULL) ? eventData.funcName : STR_UNKNOWN),
        STR_APP_ID, ((eventData.appId != NULL) ? eventData.appId : STR_UNKNOWN),
        STR_OS_ACCOUNT_ID, eventData.osAccountId,
        STR_CALL_RESULT, eventData.callResult,
        STR_PROCESS_CODE, eventData.processCode,
        STR_CRED_TYPE, eventData.credType,
        STR_GROUP_TYPE, eventData.groupType,
        STR_EXECUTION_TIME, eventData.executionTime,
        STR_EXT_INFO, ((eventData.extInfo != NULL) ? eventData.extInfo : STR_UNKNOWN));
}

void DevAuthReportFaultEvent(DevAuthFaultEvent eventData)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_AUTH,
        STR_FAULT_EVENT, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        STR_APP_ID, ((eventData.appId != NULL) ? eventData.appId : STR_UNKNOWN),
        STR_PROCESS_CODE, eventData.processCode,
        STR_FUNC_NAME, ((eventData.funcName != NULL) ? eventData.funcName : STR_UNKNOWN),
        STR_REQ_ID, eventData.reqId,
        STR_ERROR_CODE, eventData.errorCode,
        STR_FAULT_INFO, ((eventData.faultInfo != NULL) ? eventData.faultInfo : STR_UNKNOWN));
}

void DevAuthReportCallEventWithResult(const char *appId, const char *funcName, const int32_t osAccountId,
    const int32_t callResult, const int32_t processCode)
{
    DevAuthCallEvent eventData;
    eventData.appId = appId;
    eventData.funcName = funcName;
    eventData.osAccountId = osAccountId;
    eventData.callResult = callResult;
    eventData.processCode = processCode;
    eventData.credType = DEFAULT_CRED_TYPE;
    eventData.groupType = DEFAULT_GROUP_TYPE;
    eventData.executionTime = DEFAULT_EXECUTION_TIME;
    eventData.extInfo = DEFAULT_EXT_INFO;
    DevAuthReportCallEvent(eventData);
}

void DevAuthReportFaultEventWithErrCode(const char *funcName, const int32_t processCode, const int32_t errorCode)
{
    DevAuthFaultEvent eventData;
    eventData.appId = DEFAULT_APPID;
    eventData.processCode = processCode;
    eventData.funcName = funcName;
    eventData.reqId = DEFAULT_REQ_ID;
    eventData.errorCode = errorCode;
    eventData.faultInfo = DEFAULT_FAULT_INFO;
    DevAuthReportFaultEvent(eventData);
}

void DevAuthReportUeCallEvent(int32_t osAccountId, int32_t groupType, const char *appId, const char *funcName)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_AUTH_UE,
        STR_CALL_EVENT, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        STR_APP_ID, ((appId != NULL) ? appId : STR_UNKNOWN),
        STR_FUNC_NAME, ((funcName != NULL) ? funcName : STR_UNKNOWN),
        STR_OS_ACCOUNT_ID, osAccountId,
        STR_GROUP_TYPE, groupType,
        STR_PNAME_ID, DEFAULT_PNAMEID,
        STR_PVERSION_ID, DEFAULT_PVERSIONID);
}

void DevAuthReportUeCallEventByParams(int32_t osAccountId, const char *inParams, const char *appId,
    const char *funcName)
{
    int32_t groupType = GROUP_TYPE_INVALID;
    CJson *params = CreateJsonFromString(inParams);
    if (params != NULL) {
        (void)GetIntFromJson(params, FIELD_GROUP_TYPE, &groupType);
        FreeJson(params);
    }
    DEV_AUTH_REPORT_UE_CALL_EVENT(osAccountId, groupType, appId, funcName);
}