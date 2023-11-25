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

#define CREATE_GROUP_EVENT "CreateGroup"
#define DELETE_GROUP_EVENT "DeleteGroup"
#define ADD_MEMBER_EVENT "AddMember"
#define DEL_MEMBER_EVENT "DelMember"
#define ADD_MULTI_MEMBER_EVENT "AddMultiMember"
#define DEL_MULTI_MEMBER_EVENT "DelMultiMember"
#define AUTH_DEV_EVENT "AuthDevice"
#define ADD_MEMBER_WITH_LITE_COMPATIBILITY "AddMemberWithLiteCompatibility"
#define ADD_MEMBER_WITH_LITE_STANDARD "AddMemberWithLiteStandard"

#ifndef DEV_AUTH_HIVIEW_ENABLE

#define DEV_AUTH_REPORT_CALL_EVENT(reqId, funcName, appId, osAccountId, callResult)
#define DEV_AUTH_REPORT_FAULT_EVENT(funcName, faultReason, credType, groupType, appId)
#define DEV_AUTH_REPORT_STATISTIC_EVENT(appId, callResult, funcName, credType, protocolType)

#else

#include <stdint.h>

#define DEV_AUTH_REPORT_CALL_EVENT(reqId, funcName, appId, osAccountId, callResult) \
    DevAuthReportCallEvent(reqId, funcName, appId, osAccountId, callResult)
#define DEV_AUTH_REPORT_FAULT_EVENT(funcName, faultReason, credType, groupType, appId) \
    DevAuthReportFaultEvent(funcName, faultReason, credType, groupType, appId)
#define DEV_AUTH_REPORT_STATISTIC_EVENT(appId, callResult, funcName, credType, protocolType) \
    DevAuthReportStatisticEvent(appId, callResult, funcName, credType, protocolType)

#ifdef __cplusplus
extern "C" {
#endif

void DevAuthReportCallEvent(int64_t reqId, const char *funcName, const char *appId, int32_t osAccountId,
    int32_t callResult);
void DevAuthReportFaultEvent(const char *funcName, int32_t faultReason, uint8_t credType, int32_t groupType,
    const char *appId);
void DevAuthReportStatisticEvent(const char *appId, int32_t callResult, const char *funcName, uint8_t credType,
    int32_t protocolType);

#ifdef __cplusplus
}
#endif

#endif

#endif
