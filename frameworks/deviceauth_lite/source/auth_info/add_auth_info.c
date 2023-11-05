/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
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

#include "add_auth_info.h"
#include <string.h>
#include "securec.h"
#include "log.h"
#include "base.h"
#include "mem_stat.h"
#include "parsedata.h"
#include "commonutil.h"
#include "huks_adapter.h"

#if !(defined(_CUT_STS_) || defined(_CUT_STS_SERVER_) || defined(_CUT_ADD_) || defined(_CUT_ADD_SERVER_))
#define HC_ADDAUTH_CIPHER_LEN 32
#define HICHAIN_ADD_INFO_RESPONSE "hichain_add_info_response"
#define HICHAIN_ADD_INFO_REQUEST  "hichain_add_info_request"
#define AUTH_INFO_LENGTH 1000

#if (defined(_SUPPORT_SEC_CLONE_) || defined(_SUPPORT_SEC_CLONE_SERVER_))
static const uint8_t g_import_aad[] = "com.huawei.deviceauth";
#endif
static int32_t parse_add_request_data(const struct hichain *hichain, add_request_data *receive,
    struct auth_info_cache *cache);
static int32_t build_add_response_data(const struct hichain *hichain, add_response_data *send);
int32_t send_add_response(const struct hichain *hichain, struct message *receive, struct message *send)
{
    add_response_data *send_data = malloc_auth_info_msg(HC_ADDAUTH_CIPHER_LEN);
    if (send_data == NULL) {
        LOGE("Malloc struct add_response_data failed");
        send->msg_code = INFORM_MESSAGE;
        return HC_MALLOC_FAILED;
    }
    struct auth_info_cache cache;
    int32_t ret = parse_add_request_data(hichain, (add_request_data *)receive->payload, &cache);
    if (ret != HC_OK) {
        LOGE("Parse add request failed, error code is %d", ret);
        goto error;
    }
    ret = build_add_response_data(hichain, send_data);
    if (ret != HC_OK) {
        LOGE("Build add response failed, error code is %d", ret);
        goto error;
    }
    ret = save_auth_info(hichain, HC_PAIR_TYPE_AUTH, &cache);
    if (ret != HC_OK) {
        LOGE("Save ltpk failed, error code is %d", ret);
        goto error;
    }

    DBG_OUT("Send add response success");
    send->payload = send_data;
    send->msg_code = ADD_AUTHINFO_RESPONSE;
    return HC_OK;

error:
    free_auth_info_msg(send_data);
    send->msg_code = INFORM_MESSAGE;
    return ret;
}

static int32_t get_field_from_request_payload(struct uint8_buff *payload, int32_t *user_type,
    struct hc_auth_id *auth_id, struct ltpk *ltpk);
static int32_t parse_add_request_data(const struct hichain *hichain, add_request_data *receive,
    struct auth_info_cache *cache)
{
    const struct sts_session_key *session_key = get_sts_session_key(hichain);
    if (session_key == NULL) {
        LOGE("Get sts session key failed");
        return HC_STS_OBJECT_ERROR;
    }
    struct uint8_buff plain = { NULL, 0, 0 };
    int32_t ret = decrypt_payload((const struct var_buffer *)session_key, &receive->cipher,
        HICHAIN_ADD_INFO_REQUEST, &plain);
    if (ret != HC_OK) {
        LOGE("Decrypt add request payload failed");
        return ret;
    }
    ret = get_field_from_request_payload(&plain, &cache->user_type, &cache->auth_id, &cache->ltpk);
    FREE(plain.val);
    plain.val = NULL;
    if (ret != HC_OK) {
        LOGE("Get field from add request message failed, error code is %d", ret);
        return ret;
    }
    return HC_OK;
}

static int32_t build_add_response_data(const struct hichain *hichain, add_response_data *send)
{
    uint8_t array[sizeof(int32_t)] = {0};
    struct uint8_buff plain = {
        .val = array,
        .size = sizeof(array),
        .length = sizeof(array)
    };

    const struct sts_session_key *key = get_sts_session_key(hichain);
    int32_t ret = encrypt_payload((const struct var_buffer *)key, &plain, HICHAIN_ADD_INFO_RESPONSE, &send->cipher);
    if (ret != HC_OK) {
        LOGE("Encrypt add response failed, error code is %d", ret);
        return HC_ENCRYPT_FAILED;
    }
    return HC_OK;
}

static int32_t get_field_from_request_payload(struct uint8_buff *payload, int32_t *user_type,
    struct hc_auth_id *auth_id, struct ltpk *ltpk)
{
    struct add_auth_data *add_auth_data = parse_add_auth_info_data((char *)payload->val, JSON_STRING_DATA);
    if (add_auth_data == NULL) {
        LOGE("Parse add auth info data failed");
        return HC_DECRYPT_FAILED;
    }
    *user_type = add_auth_data->user_type;
    *auth_id = add_auth_data->auth_id;
    *ltpk = add_auth_data->ltpk;
    free_add_auth_info_data(add_auth_data);
    return HC_OK;
}

#endif /* _CUT_XXX_ */