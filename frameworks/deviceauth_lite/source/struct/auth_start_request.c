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

#if !(defined(_CUT_STS_) || defined(_CUT_STS_SERVER_))

#include "securec.h"
#include "log.h"
#include "mem_stat.h"
#include "jsonutil.h"
#include "commonutil.h"
#include "parsedata.h"
#include "key_agreement_version.h"
#include "add_auth_info.h"

void free_auth_start_request(void *obj)
{
    if (obj != NULL) {
        FREE(obj);
    }
}

static char *make_request_json_str(struct sts_start_request_data *auth_start_request,
                                   struct sts_start_request_data_hex tmp_hex)
{
    char *tmp_str = (char *)MALLOC(RET_STR_LENGTH);
    if (tmp_str == NULL) {
        return NULL;
    }
    (void)memset_s(tmp_str, RET_STR_LENGTH, 0, RET_STR_LENGTH);
    if (snprintf_s(tmp_str, RET_STR_LENGTH, RET_STR_LENGTH - 1,
        "{\"%s\":%d,\"%s\":%d,\"%s\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%d,"
        "\"%s\":{\"%s\":\"%u.%u.%u\",\"%s\":\"%u.%u.%u\"},\"%s\":\"%s\","
        "\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%d\",\"%s\":\"%u\"}}",
        FIELD_AUTH_FORM, AUTH_FORM, FIELD_MESSAGE, AUTH_START_REQUEST, FIELD_PAYLOAD,
        FIELD_CHALLENGE, tmp_hex.tmp_cha_data_hex, FIELD_EPK, tmp_hex.tmp_epk_data_hex,
        FIELD_OPERATION_CODE, auth_start_request->operation_code,
        FIELD_VERSION, FIELD_CURRENT_VERSION, auth_start_request->peer_version.first,
        auth_start_request->peer_version.second,
        auth_start_request->peer_version.third, FIELD_MIN_VERSION,
        auth_start_request->peer_support_version.first,
        auth_start_request->peer_support_version.second,
        auth_start_request->peer_support_version.third,
        FIELD_PKG_NAME, auth_start_request->package_name.name,
        FIELD_SERVICE_TYPE, tmp_hex.tmp_type_data_hex,
        FIELD_PEER_AUTH_ID, tmp_hex.tmp_auth_id_data_hex,
        FIELD_PEER_USER_TYPE, auth_start_request->peer_user_type,
        FIELD_KEY_LENGTH, auth_start_request->key_length) < 0) {
        LOGE("String generate failed");
        FREE(tmp_str);
        tmp_str = NULL;
    }
    return tmp_str;
}

char *make_auth_start_request(void *data)
{
    struct sts_start_request_data *auth_start_request = data;
    struct sts_start_request_data_hex tmp_hex = {0, 0, 0, 0};
    /* challenge */
    tmp_hex.tmp_cha_data_hex = raw_byte_to_hex_string(auth_start_request->challenge.challenge,
                                                      auth_start_request->challenge.length);
    if (tmp_hex.tmp_cha_data_hex == NULL) {
        return NULL;
    }
    /* epk */
    tmp_hex.tmp_epk_data_hex = raw_byte_to_hex_string(auth_start_request->epk.stpk, auth_start_request->epk.length);
    if (tmp_hex.tmp_epk_data_hex == NULL) {
        FREE(tmp_hex.tmp_cha_data_hex);
        return NULL;
    }
    /* service_type */
    tmp_hex.tmp_type_data_hex = raw_byte_to_hex_string(auth_start_request->service_type.type,
                                                       auth_start_request->service_type.length);
    if (tmp_hex.tmp_type_data_hex == NULL) {
        FREE(tmp_hex.tmp_epk_data_hex);
        FREE(tmp_hex.tmp_cha_data_hex);
        return NULL;
    }
    /* peerAuthId */
    tmp_hex.tmp_auth_id_data_hex = raw_byte_to_hex_string(auth_start_request->self_auth_id.auth_id,
                                                          auth_start_request->self_auth_id.length);
    if (tmp_hex.tmp_auth_id_data_hex == NULL) {
        FREE(tmp_hex.tmp_epk_data_hex);
        FREE(tmp_hex.tmp_type_data_hex);
        FREE(tmp_hex.tmp_cha_data_hex);
        return NULL;
    }
    char *ret_str = make_request_json_str(auth_start_request, tmp_hex);
    FREE(tmp_hex.tmp_epk_data_hex);
    FREE(tmp_hex.tmp_cha_data_hex);
    FREE(tmp_hex.tmp_type_data_hex);
    FREE(tmp_hex.tmp_auth_id_data_hex);
    return ret_str;
}

#else /* _CUT_XXX_ */

#include "parsedata.h"
DEFINE_EMPTY_STRUCT_FUNC(auth_start_request)

#endif /* _CUT_XXX_ */

