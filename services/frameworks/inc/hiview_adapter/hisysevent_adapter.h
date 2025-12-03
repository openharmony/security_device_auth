/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#define ADD_CREDENTIAL_EVENT "AddCredential"
#define EXPORT_CREDENTIAL_EVENT "ExportCredential"
#define QUERY_CREDENTIAL_BY_PARAMS_EVENT "QueryCredentialByParams"
#define QUERY_CRED_INFO_BY_CRED_ID_EVENT "QueryCredInfoByCredId"
#define DELETE_CREDENTIAL_EVENT "DeleteCredential"
#define DELETE_CREDENTIAL_BY_PARAMS_EVENT "DeleteCredByParams"
#define UPDATE_CREDENTIAL_INFO_EVENT "UpdateCredInfo"
#define BATCH_UPDATE_CREDENTIALS_EVENT "BatchUpdateCredentials"
#define AGREE_CREDENTIAL_EVENT "AgreeCredential"
#define AUTH_IDENTITY_SERVICE_EVENT "AuthIdentityService"

#define ADD_MEMBER_WITH_LITE_COMPATIBILITY "AddMemberWithLiteCompatibility"
#define ADD_MEMBER_WITH_LITE_STANDARD "AddMemberWithLiteStandard"
#define UPGRADE_DATA_EVENT "UpgradeData"
#define BIND_CONSUME_EVENT "BindConsume"
#define AUTH_CONSUME_EVENT "AuthConsume"
#define ADD_MEMBER_TO_CALL_PKG_NAME "dsoftbus"
#define ADD_MEMBER_HOST_PKG_NAME "deviceManager"
#define AUTH_DEVICE_HOST_PKG_NAME "dsoftbus"

#define ANONYMOUS_UDID_LEN 12

#define DEFAULT_GROUP_TYPE 0
#define DEFAULT_MULTI_MEMBER_GROUP_TYPE 1
#define DEFAULT_CRED_TYPE 0
#define DEFAULT_CALL_RESULT 0
#define DEFAULT_APPID "unknown appId"

#define DEFAULT_EXECUTION_TIME 0
#define DEFAULT_REQ_ID 0
#define DEFAULT_FAULT_INFO NULL
#define DEFAULT_EXT_INFO NULL

#include <stdint.h>

enum DevAuthReportProcessCode {
    PROCESS_BIND_V1 = 0x001000,                 //4096
    PROCESS_AUTH_V1,                            //4097
    PROCESS_BIND_V2,                            //4098
    PROCESS_AUTH_V2,                            //4099
    PROCESS_CREATE_GROUP,                       //4100
    PROCESS_DELETE_GROUP,                       //4101
    PROCESS_DELETE_MEMBER_FROM_GROUP,           //4102
    PROCESS_ADD_MULTI_MEMBERS_TO_GROUP,         //4103
    PROCESS_DEL_MULTI_MEMBERS_FROM_GROUP,       //4104
    PROCESS_UPDATE,                             //4105
    PROCESS_ADD_CREDENTIAL,                     //4106
    PROCESS_EXPORT_CREDENTIAL,                  //4107
    PROCESS_QUERY_CREDENTIAL_BY_PARAMS,         //4108
    PROCESS_QUERY_CRED_INFO_BY_CRED_ID,         //4109
    PROCESS_DELETE_CREDENTIAL,                  //4110
    PROCESS_DELETE_CREDENTIAL_BY_PARAMS,        //4111
    PROCESS_UPDATE_CREDENTIAL_INFO,             //4112
    PROCESS_BATCH_UPDATE_CREDENTIALS,           //4113
    PROCESS_AGREE_CREDENTIAL,                   //4114
    PROCESS_AUTH_IDENTITY_SERVICE,              //4115
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
    const char *orgPkg;
    const char *funcName;
    int32_t bizScene;
    int32_t bizState;
    int32_t bizStage;
    int32_t stageRes;
    int32_t errorCode;
    const char *toCallPkg;
    const char *hostPkg;
    const char *localUdid;
    const char *peerUdid;
    const char *concurrentId;
} DevAuthBehaviorEvent;

typedef struct {
    const char *appId;
    int32_t processCode;
    const char *funcName;
    int64_t reqId;
    int32_t errorCode;
    const char *faultInfo;
} DevAuthFaultEvent;

typedef enum {
    BIZ_SCENE_ADD_MEMBER_CLIENT = 1,
    BIZ_SCENE_ADD_MEMBER_SERVER,
    BIZ_SCENE_AUTH_DEVICE_CLIENT,
    BIZ_SCENE_AUTH_DEVICE_SERVER
} DevAuthBizScene;

typedef enum {
    BIZ_STATE_PROCESS = 0,
    BIZ_STATE_BEGIN,
    BIZ_STATE_END
} DevAuthBizState;

typedef enum {
    BIZ_STAGE_BEGIN = 1,
    BIZ_STAGE_PROCESS
} DevAuthBizStage;

typedef enum {
    STAGE_RES_IDLE = 0,
    STAGE_RES_SUCCESS,
    STAGE_RES_FAILED,
    STAGE_RES_CANCEL,
    STAGE_RES_IGNORE
} DevAuthStageRes;

void DevAuthReportCallEvent(const DevAuthCallEvent eventData);
void DevAuthReportBehaviorEvent(const DevAuthBehaviorEvent *eventData);
void BuildBehaviorEventData(DevAuthBehaviorEvent *eventData, const char *funcName, int32_t bizScene, int32_t bizState,
    int32_t bizStage);
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
