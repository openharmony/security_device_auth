/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef IPC_SDK_H
#define IPC_SDK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPC_CALL_BACK_STUB_AUTH_ID 0
#define IPC_CALL_BACK_STUB_BIND_ID 1
#define IPC_CALL_BACK_STUB_DIRECT_AUTH_ID 2

#define IPC_CALL_CONTEXT_INIT 0x0

/* params type for ipc call */
#define PARAM_TYPE_APPID 1
#define PARAM_TYPE_DEV_AUTH_CB 2
#define PARAM_TYPE_LISTERNER 3
#define PARAM_TYPE_REQID 4
#define PARAM_TYPE_CREATE_PARAMS 5
#define PARAM_TYPE_GROUPID 6
#define PARAM_TYPE_UDID 7
#define PARAM_TYPE_ADD_PARAMS 8
#define PARAM_TYPE_DEL_PARAMS 9
#define PARAM_TYPE_COMM_DATA 10
#define PARAM_TYPE_GROUP_TYPE 14
#define PARAM_TYPE_QUERY_PARAMS 18
#define PARAM_TYPE_REG_INFO 19
#define PARAM_TYPE_DATA_NUM 20
#define PARAM_TYPE_SESS_KEY 21
#define PARAM_TYPE_OPCODE 22
#define PARAM_TYPE_IPC_RESULT 23
#define PARAM_TYPE_IPC_RESULT_NUM 24
#define PARAM_TYPE_ERRCODE 25
#define PARAM_TYPE_ERR_INFO 26
#define PARAM_TYPE_REQ_INFO 27
#define PARAM_TYPE_GROUP_INFO 28
#define PARAM_TYPE_DEVICE_INFO 29
#define PARAM_TYPE_AUTH_PARAMS 30
#define PARAM_TYPE_CB_OBJECT 31
#define PARAM_TYPE_OS_ACCOUNT_ID 32
#define PARAM_TYPE_RETURN_DATA 33
#define PARAM_TYPE_REQ_JSON 34
#define PARAM_TYPE_PSEUDONYM_ID 35
#define PARAM_TYPE_INDEX_KEY 36
#define PARAM_TYPE_CRED_ID 37
#define PARAM_TYPE_CRED_INFO 38
#define PARAM_TYPE_CRED_INFO_LIST 39
#define PARAM_TYPE_REQUEST_PARAMS 40
#define PARAM_TYPE_CRED_VAL 41

enum {
    IPC_CALL_ID_REG_CB = 1,
    IPC_CALL_ID_UNREG_CB,
    IPC_CALL_ID_REG_LISTENER,
    IPC_CALL_ID_UNREG_LISTENER,
    IPC_CALL_ID_CREATE_GROUP,
    IPC_CALL_ID_DEL_GROUP,
    IPC_CALL_ID_ADD_GROUP_MEMBER,
    IPC_CALL_ID_DEL_GROUP_MEMBER,
    IPC_CALL_ID_GM_PROC_DATA,
    IPC_CALL_ID_APPLY_REG_INFO,
    IPC_CALL_ID_CHECK_ACCESS_TO_GROUP,
    IPC_CALL_ID_GET_PK_INFO_LIST,
    IPC_CALL_ID_GET_GROUP_INFO,
    IPC_CALL_ID_SEARCH_GROUPS,
    IPC_CALL_ID_GET_JOINED_GROUPS,
    IPC_CALL_ID_GET_RELATED_GROUPS,
    IPC_CALL_ID_GET_DEV_INFO_BY_ID,
    IPC_CALL_ID_GET_TRUST_DEVICES,
    IPC_CALL_ID_IS_DEV_IN_GROUP,
    IPC_CALL_ID_DESTROY_INFO,
    IPC_CALL_ID_GA_PROC_DATA,
    IPC_CALL_ID_AUTH_DEVICE,
    IPC_CALL_ID_ADD_MULTI_GROUP_MEMBERS,
    IPC_CALL_ID_DEL_MULTI_GROUP_MEMBERS,
    IPC_CALL_GM_CANCEL_REQUEST,
    IPC_CALL_GA_CANCEL_REQUEST,
    IPC_CALL_ID_GET_REAL_INFO,
    IPC_CALL_ID_GET_PSEUDONYM_ID,
    IPC_CALL_ID_PROCESS_CREDENTIAL,
    IPC_CALL_ID_DA_PROC_DATA,
    IPC_CALL_ID_DA_AUTH_DEVICE,
    IPC_CALL_ID_DA_CANCEL_REQUEST,
    IPC_CALL_ID_CM_ADD_CREDENTIAL,
    IPC_CALL_ID_CM_REG_LISTENER,
    IPC_CALL_ID_CM_UNREG_LISTENER,
    IPC_CALL_ID_CM_EXPORT_CREDENTIAL,
    IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_PARAMS,
    IPC_CALL_ID_CM_QUERY_CREDENTIAL_BY_CRED_ID,
    IPC_CALL_ID_CM_DEL_CREDENTIAL,
    IPC_CALL_ID_CM_UPDATE_CRED_INFO,
    IPC_CALL_ID_CA_AUTH_DEVICE,
    IPC_CALL_ID_CA_PROCESS_CRED_DATA,
};

#ifdef __cplusplus
}
#endif
#endif
