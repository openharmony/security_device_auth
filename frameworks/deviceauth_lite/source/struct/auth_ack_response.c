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
#include "add_auth_info.h"
#include "key_agreement_version.h"

void *parse_auth_ack_response(const char *payload, enum json_object_data_type data_type)
{
    struct sts_end_response_data *auth_ack_response =
        (struct sts_end_response_data *)MALLOC(sizeof(struct sts_end_response_data));
    if (auth_ack_response == NULL) {
        return NULL;
    }
    (void)memset_s(auth_ack_response, sizeof(*auth_ack_response), 0, sizeof(*auth_ack_response));
    json_handle obj = parse_payload(payload, data_type);
    if (obj == NULL) {
        LOGE("Parse Auth ACK Response parse payload failed");
        goto error;
    }
    /* authData */
    int32_t result = byte_convert(obj, FIELD_AUTH_RETURN, auth_ack_response->auth_return.auth_return,
                                  (uint32_t *)&auth_ack_response->auth_return.length, HC_AUTH_DATA_BUFF_LEN);
    if (result != HC_OK) {
        LOGE("Parse Auth ACK Request Data failed, field is null in addId");
        goto error;
    }
    free_payload(obj, data_type);
    return (void *)auth_ack_response;
error:
    free_payload(obj, data_type);
    FREE(auth_ack_response);
    return NULL;
}

void free_auth_ack_response(void *obj)
{
    if (obj != NULL) {
        FREE(obj);
    }
}

#else /* _CUT_XXX_ */

#include "parsedata.h"
DEFINE_EMPTY_STRUCT_FUNC(auth_ack_response)

#endif /* _CUT_XXX_ */
