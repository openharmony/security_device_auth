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

#include "hisysevent.h"

#define STR_CALL_EVENT "CALL_EVENT"
#define STR_FAULT_EVENT "FAULT_EVENT"
#define STR_STATISTIC_EVENT "STATISTIC_EVENT"
#define STR_OS_ACCOUNT_ID "OS_ACCOUNT_ID"
#define STR_FUNC_NAME "FUNC_NAME"
#define STR_FUNCTION_NAME "FUNCTION_NAME"
#define STR_FAULT_REASON "FAULT_REASON"
#define STR_CRED_TYPE "CRED_TYPE"
#define STR_GROUP_TYPE "GROUP_TYPE"
#define STR_COST_TIME "COST_TIME"
#define STR_PROTOCOL_TYPE "PROTOCOL_TYPE"
#define STR_APP_ID "APP_ID"
#define STR_REQ_ID "REQ_ID"
#define STR_CALL_RESULT "CALL_RESULT"
#define STR_UNKNOWN "unknown"

void DevAuthReportCallEvent(int64_t reqId, const char *funcName, const char *appId, int32_t osAccountId,
    int32_t callResult)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_AUTH,
        STR_CALL_EVENT, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        STR_REQ_ID, reqId,
        STR_FUNC_NAME, ((funcName != NULL) ? funcName : STR_UNKNOWN),
        STR_APP_ID, ((appId != NULL) ? appId : STR_UNKNOWN),
        STR_OS_ACCOUNT_ID, osAccountId,
        STR_CALL_RESULT, callResult);
}

void DevAuthReportFaultEvent(const char *funcName, int32_t faultReason, uint8_t credType, int32_t groupType,
    const char *appId)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_AUTH,
        STR_CALL_EVENT, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        STR_FUNCTION_NAME, ((funcName != NULL) ? funcName : STR_UNKNOWN),
        STR_FAULT_REASON, faultReason,
        STR_CRED_TYPE, credType,
        STR_GROUP_TYPE, groupType,
        STR_APP_ID, ((appId != NULL) ? appId : STR_UNKNOWN));
}

void DevAuthReportStatisticEvent(const char *appId, int32_t callResult, const char *funcName, uint8_t credType,
    int32_t protocolType)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_AUTH,
        STR_CALL_EVENT, OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        STR_APP_ID, ((appId != NULL) ? appId : STR_UNKNOWN),
        STR_CALL_RESULT, callResult,
        STR_FUNCTION_NAME, ((funcName != NULL) ? funcName : STR_UNKNOWN),
        STR_CRED_TYPE, credType,
        STR_PROTOCOL_TYPE, protocolType);
}