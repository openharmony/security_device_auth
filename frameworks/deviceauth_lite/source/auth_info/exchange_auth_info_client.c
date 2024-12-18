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

#if !(defined(_CUT_PAKE_) || defined(_CUT_PAKE_CLIENT_) || defined(_CUT_EXCHANGE_) || defined(_CUT_EXCHANGE_CLIENT_))
#include "exchange_auth_info_client.h"
#include "securec.h"
#include "log.h"
#include "base.h"
#include "mem_stat.h"
#include "parsedata.h"
#include "commonutil.h"
#include "huks_adapter.h"

#ifdef DESC
#undef DESC
#endif
#define DESC(...) 1

#define HC_EXCHANGE_REQUEST_LEN 1024

#define HICHAIN_EXCHANGE_REQUEST  "hichain_exchange_request"
#define HICHAIN_EXCHANGE_RESPONSE "hichain_exchange_response"

static int32_t build_exchange_request(const struct hichain *hichain, exchange_request_data *send);
static int32_t get_field_from_request_payload(struct uint8_buff *payload, struct signature *sign_result,
    struct hc_auth_id *auth_id, struct ltpk *ltpk);
static int32_t verify_peer_public_key(const struct hichain *hichain, struct uint8_buff *auth_info,
    struct signature *sign_result, struct ltpk *ltpk);
static int32_t parse_exchange_response_data(const struct hichain *hichain, const exchange_request_data *receive,
    struct auth_info_cache *cache);
#if DESC("interface")
int32_t send_exchange_request(const struct hichain *hichain, struct message *send)
{
    exchange_request_data *send_data = malloc_auth_info_msg(HC_EXCHANGE_REQUEST_LEN);
    if (send_data == NULL) {
        LOGE("Malloc exchange request data failed");
        send->msg_code = INFORM_MESSAGE;
        return HC_MALLOC_FAILED;
    }

    int32_t ret = build_exchange_request(hichain, send_data);
    if (ret != HC_OK) {
        LOGE("Build exchange request failed, error code is %d", ret);
        free_auth_info_msg(send_data);
        send_data = NULL;
        send->msg_code = INFORM_MESSAGE;
        return ret;
    }

    DBG_OUT("Send exchange request success");
    send->payload = send_data;
    send->msg_code = EXCHANGE_REQUEST;
    return HC_OK;
}

int32_t receive_exchange_response(const struct hichain *hichain, const struct message *receive)
{
    struct auth_info_cache cache = { HC_USER_TYPE_ACCESSORY, {0, {0}}, {0, {0}}};

    int32_t ret = parse_exchange_response_data(hichain, (exchange_request_data *)receive->payload, &cache);
    if (ret != HC_OK) {
        LOGE("Parse exchange response data failed, error code is %d", ret);
        return ret;
    }

    ret = save_auth_info(hichain, HC_PAIR_TYPE_BIND, &cache);
    if (ret != HC_OK) {
        LOGE("Save ltpk failed, error code is %d", ret);
        return ret;
    }
    return HC_OK;
}
#endif /* DESC */

static int32_t parse_exchange_response_data(const struct hichain *hichain,
    const exchange_request_data *receive, struct auth_info_cache *cache)
{
    if (hichain->pake_client == NULL) {
        LOGE("Pake client is null");
        return HC_PAKE_OBJECT_ERROR;
    }
    const struct pake_session_key *key = &hichain->pake_client->session_key;
    if (key->length < PAKE_SESSION_KEY_LENGTH) {
        LOGE("Get pake session key failed");
        return HC_PAKE_SESSION_KEY_ERROR;
    }
    struct uint8_buff plain = { 0, 0, 0 };
    int32_t ret = decrypt_payload((struct var_buffer *)key, &receive->cipher, HICHAIN_EXCHANGE_RESPONSE, &plain);
    if (ret != HC_OK) {
        LOGE("Decrypt exchange request payload failed");
        return ret;
    }

    struct signature sign_result;
    ret = get_field_from_request_payload(&plain, &sign_result, &cache->auth_id, &cache->ltpk);
    if (ret != HC_OK) {
        LOGE("Get field from exchange response message failed, error code is %d", ret);
        (void)memset_s(plain.val, plain.size, 0, plain.size);
        FREE(plain.val);
        return ret;
    }
    struct uint8_buff *auth_info = &plain;
    ret = verify_peer_public_key(hichain, auth_info, &sign_result, &cache->ltpk);
    (void)memset_s(plain.val, plain.size, 0, plain.size);
    FREE(plain.val);
    if (ret != HC_OK) {
        LOGE("Verify exchange request message failed, error code is %d", ret);
        return ret;
    }

    return HC_OK;
}

static int32_t build_auth_info(struct uint8_buff *auth_info, const struct hc_auth_id *auth_id, struct ltpk *ltpk);
static int32_t sign_self_public_key(const struct hichain *hichain, struct uint8_buff *auth_info,
    const struct hc_auth_id *auth_id, struct signature *sign_result);
static int32_t get_self_key_id(const struct hichain *hichain, const struct hc_auth_id *auth_id, struct ltpk *ltpk);
static int32_t build_exchange_request(const struct hichain *hichain, exchange_request_data *send)
{
    const struct hc_auth_id *auth_id = &hichain->pake_client->self_id;
    struct ltpk ltpk;
    int32_t ret = get_self_key_id(hichain, auth_id, &ltpk);
    if (ret != HC_OK) {
        LOGE("Get ltpk failed, error code is %d", ret);
        return ret;
    }

    struct uint8_buff auth_info = { NULL, 0, 0 };
    ret = build_auth_info(&auth_info, auth_id, &ltpk);
    if (ret != HC_OK) {
        return HC_BUILD_OBJECT_FAILED;
    }
    struct signature sign_result = { 0, {0} };
    ret = sign_self_public_key(hichain, &auth_info, auth_id, &sign_result);
    if (ret != HC_OK) {
        FREE(auth_info.val);
        LOGE("Sign self public key failed, error code is %d", ret);
        return ret;
    }

    struct uint8_buff plain;
    plain.size = auth_info.length + sign_result.length;
    plain.val = (uint8_t *)MALLOC(plain.size);
    if (plain.val == NULL) {
        FREE(auth_info.val);
        return HC_MALLOC_FAILED;
    }
    (void)memset_s(plain.val, plain.size, 0, plain.size);
    if (memcpy_s(plain.val, plain.size, auth_info.val, auth_info.length) != EOK) {
        FREE(auth_info.val);
        FREE(plain.val);
        return memory_copy_error(__func__, __LINE__);
    }
    plain.length = auth_info.length;
    FREE(auth_info.val);
    if (memcpy_s(plain.val + plain.length, plain.size - plain.length, sign_result.signature, sign_result.length)
        != EOK) {
        FREE(plain.val);
        return memory_copy_error(__func__, __LINE__);
    }
    plain.length += sign_result.length;

    const struct pake_session_key *key = &hichain->pake_client->session_key;
    ret = encrypt_payload((struct var_buffer *)key, &plain, HICHAIN_EXCHANGE_REQUEST, &send->cipher);
    FREE(plain.val);
    if (ret != HC_OK) {
        LOGE("Encrypt payload failed, error code is %d", ret);
        return HC_ENCRYPT_FAILED;
    }

    return HC_OK;
}

static int32_t get_self_key_id(const struct hichain *hichain, const struct hc_auth_id *auth_id, struct ltpk *ltpk)
{
    struct service_id service_id = generate_service_id(&hichain->identity);
    if (service_id.length == 0) {
        LOGE("Generate service id failed");
        return HC_GEN_SERVICE_ID_FAILED;
    }
#if (defined(_SUPPORT_SEC_CLONE_) || defined(_SUPPORT_SEC_CLONE_SERVER_))
    struct hc_key_alias alias = generate_key_alias(&service_id, auth_id, KEY_ALIAS_LT_KEY_PAIR);
#else
    struct hc_key_alias alias = generate_key_alias(&service_id, auth_id, KEY_ALIAS_ACCESSOR_PK);
#endif
    if (alias.length == 0) {
        LOGE("Generate key alias failed");
        return HC_GEN_ALIAS_FAILED;
    }
    int32_t ret = check_lt_public_key_exist(&alias);
    if (ret != HC_OK) {
        ret = generate_lt_key_pair(&alias, auth_id);
        if (ret != HC_OK) {
            LOGE("Generate self ltpk return value is %d", ret);
            return HC_GET_LTPK_FAILED;
        }
    }

    ret = export_lt_public_key(&alias, ltpk);
    if (ret != HC_OK) {
        LOGE("Get self ltpk failed, error code is %d", ret);
        return HC_GET_LTPK_FAILED;
    }
    DBG_OUT("Get ltpk success");
    return HC_OK;
}

static int32_t parse_auth_info(const struct uint8_buff *auth_info, struct hc_auth_id *auth_id, struct ltpk *ltpk);
static int32_t get_field_from_request_payload(struct uint8_buff *payload, struct signature *sign_result,
    struct hc_auth_id *auth_id, struct ltpk *ltpk)
{
    if (payload->length <= HC_SIGNATURE_LEN) {
        LOGE("Peer public key signature info length is %d", payload->length);
        return HC_SIGN_TOO_SHORT;
    }
    struct uint8_buff *auth_info = payload;

    auth_info->length -= HC_SIGNATURE_LEN;
    (void)memcpy_s(sign_result->signature, sizeof(sign_result->signature),
                   auth_info->val + auth_info->length, HC_SIGNATURE_LEN);
    sign_result->length = HC_SIGNATURE_LEN;
    auth_info->val[auth_info->length] = 0;
    int32_t ret = parse_auth_info(auth_info, auth_id, ltpk);
    if (ret != HC_OK) {
        LOGE("Get auth id & ltpk failed, error code is %d", ret);
        return ret;
    }

    return HC_OK;
}

typedef void (*COPY_CHALLENGE)(struct uint8_buff *sign_src_data, const struct challenge *peer_challenge,
    const struct challenge *self_challenge);
static int32_t generate_sign_src_data(const struct hichain *hichain, struct uint8_buff *auth_info,
    COPY_CHALLENGE copy_func, struct uint8_buff *sign_src_data);
static void copy_peer_self_challenge(struct uint8_buff *sign_src_data, const struct challenge *peer_challenge,
    const struct challenge *self_challenge);
static int32_t verify_peer_public_key(const struct hichain *hichain, struct uint8_buff *auth_info,
    struct signature *sign_result, struct ltpk *ltpk)
{
    struct uint8_buff sign_src_data;
    int32_t ret = generate_sign_src_data(hichain, auth_info, copy_peer_self_challenge, &sign_src_data);
    if (ret != HC_OK) {
        LOGE("Generate peer signature source data failed, error code is %d", ret);
        return ret;
    }
    enum hc_user_type peer_type = (hichain->type == HC_CENTRE) ? HC_USER_TYPE_ACCESSORY : HC_USER_TYPE_CONTROLLER;

    ret = verify_with_public_key(peer_type, &sign_src_data, (struct var_buffer *)ltpk, sign_result);
    FREE(sign_src_data.val);
    if (ret != HC_OK) {
        LOGE("Verify peer public key failed, error code is %d", ret);
        return HC_VERIFY_EXCHANGE_FAILED;
    }
    DBG_OUT("Verify peer public key success");
    return HC_OK;
}

static void copy_self_peer_challenge(struct uint8_buff *sign_src_data, const struct challenge *peer_challenge,
    const struct challenge *self_challenge);
static int32_t sign_self_public_key(const struct hichain *hichain, struct uint8_buff *auth_info,
    const struct hc_auth_id *auth_id, struct signature *sign_result)
{
    struct uint8_buff sign_src_data;
    int32_t ret = generate_sign_src_data(hichain, auth_info, copy_self_peer_challenge, &sign_src_data);
    if (ret != HC_OK) {
        LOGE("Generate self signature source data failed, error code is %d", ret);
        return ret;
    }

    struct service_id service_id = generate_service_id(hichain->pake_client->identity);
    if (service_id.length == 0) {
        FREE(sign_src_data.val);
        LOGE("Generate service id failed");
        return HC_GEN_SERVICE_ID_FAILED;
    }
#if (defined(_SUPPORT_SEC_CLONE_) || defined(_SUPPORT_SEC_CLONE_SERVER_))
    struct hc_key_alias alias = generate_key_alias(&service_id, auth_id, KEY_ALIAS_LT_KEY_PAIR);
#else
    struct hc_key_alias alias = generate_key_alias(&service_id, auth_id, KEY_ALIAS_ACCESSOR_PK);
#endif
    if (alias.length == 0) {
        LOGE("Generate key alias failed");
        FREE(sign_src_data.val);
        return HC_SIGN_EXCHANGE_FAILED;
    }
    ret = sign(&alias, &sign_src_data, sign_result);
    FREE(sign_src_data.val);
    if (ret != HC_OK) {
        LOGE("Sign self public key failed, error code is %d", ret);
        return HC_SIGN_EXCHANGE_FAILED;
    }

    DBG_OUT("Sign self public key success");
    return HC_OK;
}

static int32_t build_auth_info(struct uint8_buff *auth_info, const struct hc_auth_id *auth_id, struct ltpk *ltpk)
{
    struct exchange_auth_data exchange_auth_data;
    exchange_auth_data.auth_id = *auth_id;
    exchange_auth_data.ltpk = *ltpk;
    auth_info->val = (uint8_t *)make_exchange_data(&exchange_auth_data);
    if (auth_info->val == NULL) {
        LOGE("Make exchange data failed");
        return HC_BUILD_OBJECT_FAILED;
    }
    uint32_t tmp_len = strlen((char *)auth_info->val);
    auth_info->length = tmp_len;
    auth_info->size = tmp_len;
    return HC_OK;
}

static int32_t parse_auth_info(const struct uint8_buff *auth_info, struct hc_auth_id *auth_id, struct ltpk *ltpk)
{
    struct exchange_auth_data *auth_data = parse_exchange_data((char *)auth_info->val, JSON_STRING_DATA);
    if (auth_data == NULL) {
        LOGE("Parse auth info failed");
        return HC_DECRYPT_FAILED;
    }
    *auth_id = auth_data->auth_id;
    *ltpk = auth_data->ltpk;
    free_exchange_data(auth_data);
    return HC_OK;
}

static void copy_peer_self_challenge(struct uint8_buff *sign_src_data, const struct challenge *peer_challenge,
    const struct challenge *self_challenge)
{
    if (memcpy_s(sign_src_data->val, sign_src_data->size, peer_challenge->challenge, CHALLENGE_BUFF_LENGTH) != EOK) {
        FREE(sign_src_data->val);
        sign_src_data->size = 0;
        return;
    }
    sign_src_data->length += CHALLENGE_BUFF_LENGTH;
    if (memcpy_s(sign_src_data->val + sign_src_data->length, sign_src_data->size - sign_src_data->length,
                 self_challenge->challenge, CHALLENGE_BUFF_LENGTH) != EOK) {
        FREE(sign_src_data->val);
        sign_src_data->size = 0;
        return;
    }
    sign_src_data->length += CHALLENGE_BUFF_LENGTH;
}

static void copy_self_peer_challenge(struct uint8_buff *sign_src_data, const struct challenge *peer_challenge,
    const struct challenge *self_challenge)
{
    if (memcpy_s(sign_src_data->val, sign_src_data->size, self_challenge->challenge, CHALLENGE_BUFF_LENGTH) != EOK) {
        FREE(sign_src_data->val);
        sign_src_data->size = 0;
        return;
    }
    sign_src_data->length += CHALLENGE_BUFF_LENGTH;
    if (memcpy_s(sign_src_data->val + sign_src_data->length, sign_src_data->size - sign_src_data->length,
                 peer_challenge->challenge, CHALLENGE_BUFF_LENGTH) != EOK) {
        FREE(sign_src_data->val);
        sign_src_data->size = 0;
        return;
    }
    sign_src_data->length += CHALLENGE_BUFF_LENGTH;
}

static int32_t generate_sign_src_data(const struct hichain *hichain, struct uint8_buff *auth_info,
                                      COPY_CHALLENGE copy_func, struct uint8_buff *sign_src_data)
{
    const struct challenge *peer_challenge = &hichain->pake_client->peer_challenge;
    const struct challenge *self_challenge = &hichain->pake_client->self_challenge;

    if ((peer_challenge == NULL) || (self_challenge == NULL)) {
        LOGE("Get pake challenge failed");
        return HC_PAKE_OBJECT_ERROR;
    }
    sign_src_data->size = CHALLENGE_BUFF_LENGTH + CHALLENGE_BUFF_LENGTH + auth_info->length;
    sign_src_data->length = 0;
    sign_src_data->val = (uint8_t *)MALLOC(sign_src_data->size);
    if (sign_src_data->val == NULL) {
        LOGE("Malloc failed");
        sign_src_data->size = 0;
        return HC_MALLOC_FAILED;
    }
    copy_func(sign_src_data, peer_challenge, self_challenge);
    if (sign_src_data->size == 0) {
        LOGE("Copy failed");
        return HC_MEMCPY_ERROR;
    }
    (void)memcpy_s(sign_src_data->val + sign_src_data->length, sign_src_data->size - sign_src_data->length,
                   auth_info->val, auth_info->length);
    sign_src_data->length += auth_info->length;
    DBG_OUT("Generate peer sign src data success");
    return HC_OK;
}

#else /* _CUT_XXX_ */
#include "exchange_auth_info_client.h"
#include "log.h"

int32_t send_exchange_request(const struct hichain *hichain, struct message *send)
{
    LOGE("Donot support exchange client for add");
    (void)hichain;
    (void)send;
    return HC_UNSUPPORT;
}
#endif /* _CUT_XXX_ */
