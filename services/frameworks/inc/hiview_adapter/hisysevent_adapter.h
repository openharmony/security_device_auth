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
#define DESTROY_DEVICE_AUTH_SERVICE_EVENT "DestroyDeviceAuthService"
#define INIT_DEVICE_AUTH_SERVICE_EVENT "InitDeviceAuthService"

#define CANCEL_REQUEST_EVENT "CancelRequest"
#define GET_REAL_INFO_EVENT "GetRealInfo"
#define GET_PSEUDONYM_ID_EVENT "GetPseudonymId"
#define REG_CALLBACK_EVENT "RegCallback"
#define UN_REG_GROUP_MANAGER_CALLBACK_EVENT "UnRegGroupManagerCallback"
#define REG_LISTENER_EVENT "RegListener"
#define UN_REG_LISTENER_EVENT "UnRegListener"
#define GET_REGISTER_INFO_EVENT "GetRegisterInfo"
#define CHECK_ACCESS_TO_GROUP_EVENT "CheckAccessToGroup"
#define GET_ACCESSIBLE_GROUP_INFO_BY_ID_EVENT "GetAccessibleGroupInfoById"
#define GET_ACCESSIBLE_GROUP_INFO_EVENT "GetAccessibleGroupInfo"
#define GET_ACCESSIBLE_JOINED_GROUPS_EVENT "GetAccessibleJoinedGroups"
#define GET_ACCESSIBLE_RELATED_GROUPS_EVENT "GetAccessibleRelatedGroups"
#define GET_ACCESSIBLE_DEVICE_INFO_BY_ID_EVENT "GetAccessibleDeviceInfoById"
#define GET_ACCESSIBLE_TRUSTED_DEVICES_EVENT "GetAccessibleTrustedDevices"
#define IS_DEVICE_IN_ACCESSIBLE_GROUP_EVENT "IsDeviceInAccessibleGroup"
#define GET_PK_INFO_LIST_EVENT "GetPkInfoList"
#define DESTROY_INFO_EVENT "DestroyInfo"

#define ADD_MEMBER_WITH_LITE_COMPATIBILITY "AddMemberWithLiteCompatibility"
#define ADD_MEMBER_WITH_LITE_STANDARD "AddMemberWithLiteStandard"
#define UPGRADE_DATA_EVENT "UpgradeData"
#define BIND_CONSUME_EVENT "BindConsume"
#define AUTH_CONSUME_EVENT "AuthConsume"

#define DEFAULT_GROUP_TYPE 256
#define DEFAULT_CRED_TYPE 0
#define DEFAULT_APPID NULL
#define DEFAULT_PNAMEID "device_auth"
#define DEFAULT_PVERSIONID "1.0"

#ifndef DEV_AUTH_HIVIEW_ENABLE

#define DEV_AUTH_REPORT_CALL_EVENT(reqId, funcName, appId, osAccountId, callResult)
#define DEV_AUTH_REPORT_FAULT_EVENT(funcName, faultReason, credType, groupType, appId)
#define DEV_AUTH_REPORT_UE_CALL_EVENT(osAccountId, groupType, appId, funcName)
#define DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, inParams, appId, funcName)
#else

#include <stdint.h>

#define DEV_AUTH_REPORT_CALL_EVENT(reqId, funcName, appId, osAccountId, callResult) \
    DevAuthReportCallEvent(reqId, funcName, appId, osAccountId, callResult)
#define DEV_AUTH_REPORT_FAULT_EVENT(funcName, faultReason, credType, groupType, appId) \
    DevAuthReportFaultEvent(funcName, faultReason, credType, groupType, appId)
#define DEV_AUTH_REPORT_UE_CALL_EVENT(osAccountId, groupType, appId, funcName) \
    DevAuthReportUeCallEvent(osAccountId, groupType, appId, funcName)
#define DEV_AUTH_REPORT_UE_CALL_EVENT_BY_PARAMS(osAccountId, inParams, appId, funcName) \
    DevAuthReportUeCallEventByParams(osAccountId, inParams, appId, funcName)

#ifdef __cplusplus
extern "C" {
#endif

void DevAuthReportCallEvent(int64_t reqId, const char *funcName, const char *appId, int32_t osAccountId,
    int32_t callResult);
void DevAuthReportFaultEvent(const char *funcName, int32_t faultReason, uint8_t credType, int32_t groupType,
    const char *appId);
void DevAuthReportUeCallEvent(int32_t osAccountId, int32_t groupType, const char *appId,
    const char *funcName);
void DevAuthReportUeCallEventByParams(int32_t osAccountId, const char *inParams, const char *appId,
    const char *funcName);

#ifdef __cplusplus
}
#endif

#endif

#endif
