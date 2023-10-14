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

#ifndef DEVICE_AUTH_EXT
#define DEVICE_AUTH_EXT

#include "device_auth.h"
#include "cJSON.h"

/** The Type of account auth plugin. */
#define EXT_PLUGIN_ACCT_AUTH 1000
/** The Type of account lifecycle plugin. */
#define EXT_PLUGIN_ACCT_LIFECYCLE 1001

/**
 * @brief This structure describes the ext plugin context.
 */
typedef struct ExtPluginCtx {
    /** The context of ext, the user can inject the method into the plugin. */
    void *instance;
} ExtPluginCtx;

/**
 * @brief This structure describes the base ext plugin.
 */
typedef struct ExtPlugin {
    /** The tyep of plugin, the caller can convert the plugin to object based on the type. */
    int32_t pluginType;
    /** The init function. */
    int32_t (*init)(struct ExtPlugin *extPlugin, const cJSON *params, const struct ExtPluginCtx *context);
    /** The destroy function. */
    void (*destroy)(struct ExtPlugin *extPlugin);
} ExtPlugin;

/**
 * @brief This structure describes the ext list.
 */
typedef struct ExtPluginNode {
    /** The element of list, denote the plugin. */
    ExtPlugin *plugin;
    /** The next node of list. */
    struct ExtPluginNode *next;
} ExtPluginNode, *ExtPluginList;

/**
 * @brief This structure describes the ext plugin.
 */
typedef struct ExtPart {
    /** The instance of plugin. */
    void *instance;
} ExtPart;

/**
 * @brief This structure describes task function.
 */
typedef struct ExtWorkerTask {
    /** The function of task, this can execute time-consuming function. */
    void (*execute)(struct ExtWorkerTask *task);

    /** The deinit of task, this can destroy the task. */
    void (*destroy)(struct ExtWorkerTask *task);
} ExtWorkerTask;

/**
 * @brief This structure describes account auth plugin.
 */
typedef struct {
    /** The base object contains init func and destroy func. */
    ExtPlugin base;
    /** Call it when account cred needs to update, query, delete or add. */
    int32_t (*excuteCredMgrCmd)(int32_t osAccount, int32_t cmdId, const cJSON *in, cJSON *out);
    /** This function is used to initiate authentication between devices.. */
    int32_t (*createSession)(int32_t *sessionId, const cJSON *in, cJSON *out);
    /** This function is used to process authentication dat. */
    int32_t (*processSession)(int32_t *sessionId, const cJSON *in, cJSON *out, int32_t *status);
    /** This function is used to destroy authentication dat. */
    int32_t (*destroySession)(int32_t sessionId);
} AccountAuthExtPlug;

/**
 * @brief This structure describes the account auth plugin context.
 */
typedef struct {
    /** The base context. */
    ExtPluginCtx base;
    /** The function will return storage path. */
    const char *(*getStoragePath)(void);
} AccountAuthExtPlugCtx;

/**
 * @brief This structure describes the account lifecycle plugin.
 */
typedef struct {
    /** The base account lifecycle plugin. */
    ExtPlugin base;
} AccountLifecyleExtPlug;

/**
 * @brief This structure describes the account lifecycle plugin context.
 */
typedef struct {
    /** The base account lifecycle context. */
    ExtPluginCtx base;
    /** This interface is used to create a trusted group. */
    int32_t (*createGroup)(int32_t osAccountId, int64_t requestId, const char *appId, const char *createParams);
    /** This interface is used to delete a trusted group. */
    int32_t (*deleteGroup)(int32_t osAccountId, int64_t requestId, const char *appId, const char *disbandParams);
    /** This interface is used to obtain the group information of groups that meet the query parameters. */
    int32_t (*getGroupInfo)(int32_t osAccountId, const char *appId, const char *queryParams,
        char **returnGroupVec, uint32_t *groupNum);
    /** This interface is used to obtain the registration information of the local device. */
    int32_t (*getRegisterInfo)(const char *reqJsonStr, char **returnRegisterInfo);
    /** This interface is used to register business callbacks. */
    int32_t (*regCallback)(const char *appId, const DeviceAuthCallback *callback);
    /** This interface is used to unregister business callbacks. */
    int32_t (*unRegCallback)(const char *appId);
    /** This interface is used to execute business function. */
    int32_t (*executeWorkerTask)(struct ExtWorkerTask *task);
} AccountLifecyleExtPlugCtx;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize ext part.
 *
 * This API is used to initialize ext part.
 *
 * @param params The plugin needs params.
 * @param extPart The interface of ext part.
 * @return When the service initialization is successful, it returns HC_SUCCESS.
 * Otherwise, it returns other values.
 */
int32_t InitExtPart(const cJSON *params, ExtPart *extPart);

/**
 * @brief Get plugin list.
 *
 * This API is used to get all plugins.
 *
 * @param extPart The interface of ext part.
 * @return The list of plugin.
 */
ExtPluginList GetExtPlugins(ExtPart *extPart);

/**
 * @brief Destroy ext part.
 *
 * This API is used to destroy ext part.
 *
 * @param extPart The interface of ext part.
 */
void DestroyExtPart(ExtPart *extPart);

#ifdef __cplusplus
}
#endif

#endif
