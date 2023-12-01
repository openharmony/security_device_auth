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

#ifndef DEVICE_AUTH_H
#define DEVICE_AUTH_H

#include <stdint.h>
#include <stdbool.h>

#if defined(__LINUX__) || defined(_UNIX)
#define DEVICE_AUTH_API_PUBLIC __attribute__ ((visibility("default")))
#else
#define DEVICE_AUTH_API_PUBLIC
#endif

#define FIELD_GROUP_ID "groupId"
#define FIELD_GROUP_TYPE "groupType"
#define FIELD_GROUP_NAME "groupName"
#define FIELD_PEER_DEVICE_ID "peerDeviceId"
#define FIELD_IS_ADMIN "isAdmin"
#define FIELD_CREDENTIAL_TYPE "credentialType"
#define FIELD_IS_FORCE_DELETE "isForceDelete"
#define FIELD_IS_IGNORE_CHANNEL "isIgnoreChannel"
#define FIELD_CONNECT_PARAMS "connectParams"
#define FIELD_ADD_ID "addId"
#define FIELD_DELETE_ID "deleteId"
#define FIELD_APP_ID "appId"
#define FIELD_SERVICE_TYPE "serviceType"
#define FIELD_IS_DEVICE_LEVEL "isDeviceLevel"
#define FIELD_ALTERNATIVE "alternative"
#define FIELD_PEER_UDID "peerUdid"
#define FIELD_PEER_CONN_DEVICE_ID "peerConnDeviceId"
#define FIELD_KEY_LENGTH "keyLength"
#define FIELD_IS_CLIENT "isClient"
#define FIELD_SESSION_KEY "sessionKey"
#define FIELD_AUTH_FORM "authForm"
#define FIELD_CONFIRMATION "confirmation"
#define FIELD_GROUP_OWNER "groupOwner"
#define FIELD_PEER_AUTH_ID "peerAuthId"
#define FIELD_PEER_USER_TYPE "peerUserType"
#define FIELD_PEER_USER_ID "peerUserId"
#define FIELD_SERVICE_PKG_NAME "servicePkgName"
#define FIELD_USER_TYPE "userType"
#define FIELD_USER_ID "userId"
#define FIELD_SHARED_USER_ID "sharedUserId"
#define FIELD_OWNER_USER_ID "ownerUserId"
#define FIELD_DEVICE_ID "deviceId"
#define FIELD_PIN_CODE "pinCode"
#define FIELD_AUTH_ID "authId"
#define FIELD_UDID "udid"
#define FIELD_IS_SELF_PK "isSelfPk"
#define FIELD_GROUP_VISIBILITY "groupVisibility"
#define FIELD_EXPIRE_TIME "expireTime"
#define FIELD_IS_DELETE_ALL "isDeleteAll"
#define FIELD_OS_ACCOUNT_ID "osAccountId"
#define FIELD_ACQURIED_TYPE "acquireType"
#define FIELD_CRED_OP_FLAG "flag"
#define FIELD_CRED_OP_RESULT "result"
#define FIELD_AUTH_CODE "authCode"
#define FIELD_DEVICE_LIST "deviceList"
#define FIELD_IS_UDID_HASH "isUdidHash"
#define FIELD_PROTOCOL_EXPAND "protocolExpand"

/**
 * @brief protocol expand value for bind
 */
typedef enum {
    /** use this flag to support bind base on symmetric credential when interact with lite device */
    LITE_PROTOCOL_STANDARD_MODE = 1,
    /** use this flag when interact with lite device which used iso with short pin */
    LITE_PROTOCOL_COMPATIBILITY_MODE = 2,
} ProtocolExpandValue;

/**
 * @brief type of local system account
 */
typedef enum {
    /** default local system account */
    DEFAULT_OS_ACCOUNT = 0,
    /** the local system account of foreground user */
    ANY_OS_ACCOUNT = -2,
} OsAccountEnum;

/**
 * @brief describes all group types
 */
typedef enum {
    /** refers to all group types and is used to query group information */
    ALL_GROUP = 0,
    /** group type of the same clound account */
    IDENTICAL_ACCOUNT_GROUP = 1,
    /** group type of the p2p binding */
    PEER_TO_PEER_GROUP = 256,
    /** group type shared to other cloud accounts */
    ACROSS_ACCOUNT_AUTHORIZE_GROUP = 1282
} GroupType;

/**
 * @brief describes all group visibility types
 */
typedef enum {
    /** visibility type of private group */
    GROUP_VISIBILITY_PRIVATE = 0,
    /** visibility type of public group */
    GROUP_VISIBILITY_PUBLIC = -1
} GroupVisibility;

/**
 * @brief describes all group operation codes
 */
typedef enum {
    /** opeation code for group creation */
    GROUP_CREATE = 0,
    /** opeation code for group destruction */
    GROUP_DISBAND = 1,
    /** opeation code for inviting the peer device to join the local trusted group */
    MEMBER_INVITE = 2,
    /** opeation code for joining the peer trusted group */
    MEMBER_JOIN = 3,
    /** opeation code for unbinding with peer device */
    MEMBER_DELETE = 4,
} GroupOperationCode;

/**
 * @brief describes all group authentication types
 */
typedef enum {
    /** invalid group authentication type */
    AUTH_FORM_INVALID_TYPE = -1,
    /** p2p group authentication type */
    AUTH_FORM_ACCOUNT_UNRELATED = 0,
    /** group authentication type of the same cloud account */
    AUTH_FORM_IDENTICAL_ACCOUNT = 1,
    /** group authentication type shared to other cloud accounts */
    AUTH_FORM_ACROSS_ACCOUNT = 2,
} GroupAuthForm;

/**
 * @brief describes all credential types
 */
typedef enum {
    /** symmetrical credential type */
    SYMMETRIC_CRED = 1,
    /** asymmetric credential type */
    ASYMMETRIC_CRED = 2,
} CredType;

/**
 * @brief describes all device types
 */
typedef enum {
    /** device type is accessory */
    DEVICE_TYPE_ACCESSORY = 0,
    /** device type is controller */
    DEVICE_TYPE_CONTROLLER = 1,
    /** device type is proxy */
    DEVICE_TYPE_PROXY = 2
} UserType;

/**
 * @brief describes request response results
 */
typedef enum {
    /** reject the request from the peer device */
    REQUEST_REJECTED = 0x80000005,
    /** accept the request from the peer device */
    REQUEST_ACCEPTED = 0x80000006,
} RequestResponse;

/**
 * @brief This structure provides the ability to monitor changes in trusted groups and devices.
 */
typedef struct {
    /** Call it when a new group is created. */
    void (*onGroupCreated)(const char *groupInfo);
    /** Call it when a group is destroyed. */
    void (*onGroupDeleted)(const char *groupInfo);
    /** Call it when a group adds a trusted device. */
    void (*onDeviceBound)(const char *peerUdid, const char *groupInfo);
    /** Call it when a group deletes a trusted device. */
    void (*onDeviceUnBound)(const char *peerUdid, const char *groupInfo);
    /** Call it when a device has no trust relationship in all groups. */
    void (*onDeviceNotTrusted)(const char *peerUdid);
    /** Call it when a device has no trust relationship in all groups of a certain type. */
    void (*onLastGroupDeleted)(const char *peerUdid, int groupType);
    void (*onTrustedDeviceNumChanged)(int curTrustedDeviceNum);
} DataChangeListener;

/**
 * @brief This structure describes the callbacks that need to be provided by the business.
 */
typedef struct {
    /** Call it when there is data to be sent. */
    bool (*onTransmit)(int64_t requestId, const uint8_t *data, uint32_t dataLen);
    /** Call it when the session key is returned. */
    void (*onSessionKeyReturned)(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen);
    /** Call it when the asynchronous operation is successful. */
    void (*onFinish)(int64_t requestId, int operationCode, const char *returnData);
    /** Call it when the asynchronous operation fails. */
    void (*onError)(int64_t requestId, int operationCode, int errorCode, const char *errorReturn);
    /** Call it when receiving requests from other devices. */
    char *(*onRequest)(int64_t requestId, int operationCode, const char *reqParams);
} DeviceAuthCallback;

/**
 * @brief This structure provides all the capabilities of group authentication.
 */
typedef struct {
    /** This interface is used to process authentication data. */
    int32_t (*processData)(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
        const DeviceAuthCallback *gaCallback);
    /** This interface is used to initiate authentication between devices. */
    int32_t (*authDevice)(int32_t osAccountId, int64_t authReqId, const char *authParams,
        const DeviceAuthCallback *gaCallback);
    /** This interface is used to cancel an authentication process. */
    void (*cancelRequest)(int64_t requestId, const char *appId);
    /** This interface is used to get real info by pseudonym id. */
    int32_t (*getRealInfo)(int32_t osAccountId, const char *pseudonymId, char **realInfo);
    /** This interface is used to get pseudonym id by an index. */
    int32_t (*getPseudonymId)(int32_t osAccountId, const char *indexKey, char **pseudonymId);
} GroupAuthManager;

typedef struct {
    /** This interface is used to register business callbacks. */
    int32_t (*regCallback)(const char *appId, const DeviceAuthCallback *callback);
    /** This interface is used to unregister business callbacks. */
    int32_t (*unRegCallback)(const char *appId);
    /** This interface is used to register callback for data change monitoring. */
    int32_t (*regDataChangeListener)(const char *appId, const DataChangeListener *listener);
    /** This interface is used to unregister callback for data change monitoring. */
    int32_t (*unRegDataChangeListener)(const char *appId);
    /** This interface is used to create a trusted group. */
    int32_t (*createGroup)(int32_t osAccountId, int64_t requestId, const char *appId, const char *createParams);
    /** This interface is used to delete a trusted group. */
    int32_t (*deleteGroup)(int32_t osAccountId, int64_t requestId, const char *appId, const char *disbandParams);
    /** This interface is used to add a trusted device to a trusted group. */
    int32_t (*addMemberToGroup)(int32_t osAccountId, int64_t requestId, const char *appId, const char *addParams);
    /** This interface is used to delete a trusted device from a trusted group. */
    int32_t (*deleteMemberFromGroup)(int32_t osAccountId, int64_t requestId, const char *appId,
        const char *deleteParams);
    /** This interface is used to process data of binding or unbinding devices. */
    int32_t (*processData)(int64_t requestId, const uint8_t *data, uint32_t dataLen);
    /** This interface is used to batch add trusted devices with account relationships. */
    int32_t (*addMultiMembersToGroup)(int32_t osAccountId, const char *appId, const char *addParams);
    /** This interface is used to batch delete trusted devices with account relationships. */
    int32_t (*delMultiMembersFromGroup)(int32_t osAccountId, const char *appId, const char *deleteParams);
    /** This interface is used to obtain the registration information of the local device. */
    int32_t (*getRegisterInfo)(const char *reqJsonStr, char **returnRegisterInfo);
    /** This interface is used to check whether the specified application has access rights to the group. */
    int32_t (*checkAccessToGroup)(int32_t osAccountId, const char *appId, const char *groupId);
    /** This interface is used to obtain all public key information related to a device. */
    int32_t (*getPkInfoList)(int32_t osAccountId, const char *appId, const char *queryParams, char **returnInfoList,
        uint32_t *returnInfoNum);
    /** This interface is used to obtain group information of a group. */
    int32_t (*getGroupInfoById)(int32_t osAccountId, const char *appId, const char *groupId, char **returnGroupInfo);
    /** This interface is used to obtain the group information of groups that meet the query parameters. */
    int32_t (*getGroupInfo)(int32_t osAccountId, const char *appId, const char *queryParams,
        char **returnGroupVec, uint32_t *groupNum);
    /** This interface is used to obtain all group information of a specific group type. */
    int32_t (*getJoinedGroups)(int32_t osAccountId, const char *appId, int groupType,
        char **returnGroupVec, uint32_t *groupNum);
    /** This interface is used to obtain all group information related to a certain device. */
    int32_t (*getRelatedGroups)(int32_t osAccountId, const char *appId, const char *peerDeviceId,
        char **returnGroupVec, uint32_t *groupNum);
    /** This interface is used to obtain the information of a trusted device. */
    int32_t (*getDeviceInfoById)(int32_t osAccountId, const char *appId, const char *deviceId, const char *groupId,
        char **returnDeviceInfo);
    /** This interface is used to obtain all trusted device information in a group. */
    int32_t (*getTrustedDevices)(int32_t osAccountId, const char *appId, const char *groupId,
        char **returnDevInfoVec, uint32_t *deviceNum);
    /** This interface is used to query whether a specified device exists in the group. */
    bool (*isDeviceInGroup)(int32_t osAccountId, const char *appId, const char *groupId, const char *deviceId);
    /** This interface is used to cancel a binding or unbinding process. */
    void (*cancelRequest)(int64_t requestId, const char *appId);
    /** This interface is used to destroy the information returned by the internal allocated memory. */
    void (*destroyInfo)(char **returnInfo);
} DeviceGroupManager;

/**
 * @brief This enum provides all the operationCode of interface ProcessCredential.
 */
enum {
    /** invalid operationCode for initialize */
    CRED_OP_INVALID = -1,
    /** operationCode for ProcessCredential to query credential */
    CRED_OP_QUERY,
    /** operationCode for ProcessCredential to create credential */
    CRED_OP_CREATE,
    /** operationCode for ProcessCredential to import credential */
    CRED_OP_IMPORT,
    /** operationCode for ProcessCredential to delete credential */
    CRED_OP_DELETE,
};

/**
 * @brief This enum provides all the flag of reqJsion for interface ProcessCredential.
 */
enum {
    /** invalid flag for initialize */
    RETURN_FLAG_INVALID = -1,
    /** flag for only return result */
    RETURN_FLAG_DEFAULT,
    /** flag for return result and publicKey */
    RETURN_FLAG_PUBLIC_KEY,
};

/**
 * @brief This enum provides all the acquireType of interface StartAuthDevice & ProcessAuthDevice.
 */
typedef enum {
    /** invalid acquireType for initialize */
    ACQUIRE_TYPE_INVALID = -1,
    /** acquireType for p2p bind */
    P2P_BIND,
} AcquireType;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Process Credential data.
 *
 * This API is used to process Credential data.
 *
 * @param operationCode: use one of CRED_OP_QUERY|CRED_OP_CREATE|CRED_OP_IMPORT|CRED_OP_DELETE
 * @param requestParams: json string contains group of osAccountId|deviceId|serviceType|acquireType|flag
 * @param returnData: json string contains group of result|publicKey
 *
 * @return When the ipc call is successful, it returns HC_SUCCESS.
 * Otherwise, it returns other values.
 */
DEVICE_AUTH_API_PUBLIC int32_t ProcessCredential(
    int32_t operationCode, const char *requestParams, char **returnData);

/**
 * @brief Start to auth device.
 *
 * This API is used to start to auth device.
 *
 * @param requestId: id of a request
 * @param authParams: json string contains group of osAccountId|deviceId|serviceType|acquireType|pinCode
 * @param callbak: callback object
 *
 * @return When the ipc call is successful, it returns HC_SUCCESS.
 * Otherwise, it returns other values.
 */
DEVICE_AUTH_API_PUBLIC int32_t StartAuthDevice(
    int64_t requestId, const char *authParams, const DeviceAuthCallback *callbak);

/**
 * @brief Process auth device data.
 *
 * This API is used to process auth device data.
 *
 * @param requestId: id of a request
 * @param authParams: json string contains group of osAccountId|data
 * @param callbak: callback object
 *
 * @return When the ipc call is successful, it returns HC_SUCCESS.
 * Otherwise, it returns other values.
 */
DEVICE_AUTH_API_PUBLIC int32_t ProcessAuthDevice(
    int64_t requestId, const char *authParams, const DeviceAuthCallback *callbak);

/**
 * @brief Cancle auth device request.
 *
 * This API is used to cancle auth device request.
 *
 * @param requestId: id of a request
 * @param authParams: json string contains osAccountId or NULL
 *
 * @return When the ipc call is successful, it returns HC_SUCCESS.
 * Otherwise, it returns other values.
 */
DEVICE_AUTH_API_PUBLIC int32_t CancelAuthRequest(int64_t requestId, const char *authParams);

/**
 * @brief Initialize device auth service.
 *
 * This API is used to initialize device auth service.
 *
 * @return When the service initialization is successful, it returns HC_SUCCESS.
 * Otherwise, it returns other values.
 * @see DestroyDeviceAuthService
 */
DEVICE_AUTH_API_PUBLIC int InitDeviceAuthService(void);

/**
 * @brief Destroy device auth service.
 *
 * This API is used to destroy device auth service.
 *
 * @see InitDeviceAuthService
 */
DEVICE_AUTH_API_PUBLIC void DestroyDeviceAuthService(void);

/**
 * @brief Get group authentication instance.
 *
 * This API is used to get group authentication instance.
 * The InitDeviceAuthService function must be called before using this method.
 *
 * @return When the method call result is successful, it returns GroupAuthManager instance.
 * Otherwise, it returns NULL.
 */
DEVICE_AUTH_API_PUBLIC const GroupAuthManager *GetGaInstance(void);

/**
 * @brief Get group management instance.
 *
 * This API is used to get group management instance.
 * The InitDeviceAuthService function must be called before using this method.
 *
 * @return When the method call result is successful, it returns DeviceGroupManager instance.
 * Otherwise, it returns NULL.
 */
DEVICE_AUTH_API_PUBLIC const DeviceGroupManager *GetGmInstance(void);

#ifdef __cplusplus
}
#endif
#endif
