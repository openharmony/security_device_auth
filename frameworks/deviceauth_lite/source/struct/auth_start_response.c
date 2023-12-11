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

void *parse_auth_start_response(const char *payload, enum json_object_data_type data_type)
{
    struct sts_start_response_data *auth_start_response =
        (struct sts_start_response_data *)MALLOC(sizeof(struct sts_start_response_data));
    if (auth_start_response == NULL) {
        return NULL;
    }
    (void)memset_s(auth_start_response, sizeof(*auth_start_response), 0, sizeof(*auth_start_response));
    json_handle obj = parse_payload(payload, data_type);
    if (obj == NULL) {
        LOGE("Parse AuthStart Response parse payload failed");
        goto error;
    }
    /* authData */
    int32_t result = byte_convert(obj, FIELD_AUTH_DATA, auth_start_response->auth_data.auth_data,
                                  &auth_start_response->auth_data.length, HC_AUTH_DATA_BUFF_LEN);
    if (result != HC_OK) {
        LOGE("Parse AuthStart Response failed, field is null in authData");
        goto error;
    }

    /* challenge */
    result = byte_convert(obj, FIELD_CHALLENGE, auth_start_response->challenge.challenge,
                          &auth_start_response->challenge.length, CHALLENGE_BUFF_LENGTH);
    if (result != HC_OK) {
        LOGE("Parse AuthStart Response failed, field is null in challenge");
        goto error;
    }

    /* salt */
    result = byte_convert(obj, FIELD_SALT, auth_start_response->salt.salt,
                          (uint32_t *)&auth_start_response->salt.length, HC_SALT_BUFF_LEN);
    if (result != HC_OK) {
        LOGE("Parse AuthStart Response failed, field is null in salt");
        goto error;
    }

    /* epk */
    result = byte_convert(obj, FIELD_EPK, auth_start_response->epk.stpk,
                          &auth_start_response->epk.length, HC_ST_PUBLIC_KEY_LEN);
    if (result != HC_OK) {
        LOGE("Parse AuthStart Response failed, field is null in epk");
        goto error;
    }
    /* version */
    json_pobject obj_ver = get_json_obj(obj, FIELD_VERSION);
    bool ret = parse_version(obj_ver, &auth_start_response->self_version, &auth_start_response->self_support_version);
    if (!ret) {
        LOGE("Parse AuthStart Response failed, field is null in version");
        goto error;
    }
    free_payload(obj, data_type);
    return (void *)auth_start_response;
error:
    free_payload(obj, data_type);
    FREE(auth_start_response);
    return NULL;
}

void free_auth_start_response(void *obj)
{
    if (obj != NULL) {
        FREE(obj);
    }
}

#else /* _CUT_XXX_ */

#include "parsedata.h"
DEFINE_EMPTY_STRUCT_FUNC(auth_start_response)

#endif /* _CUT_XXX_ */
