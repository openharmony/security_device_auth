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


void free_auth_ack_request(void *obj)
{
    if (obj != NULL) {
        FREE(obj);
    }
}

char *make_auth_ack_request(void *data)
{
    struct sts_end_request_data *auth_ack_request = data;
    /* authdata */
    uint8_t *tmp_data_hex = raw_byte_to_hex_string(auth_ack_request->auth_data.auth_data,
                                                   auth_ack_request->auth_data.length);
    if (tmp_data_hex == NULL) {
        return NULL;
    }
    char *ret_str = (char *)MALLOC(RET_STR_LENGTH);
    if (ret_str == NULL) {
        FREE(tmp_data_hex);
        return NULL;
    }
    (void)memset_s(ret_str, RET_STR_LENGTH, 0, RET_STR_LENGTH);
    if (snprintf_s(ret_str, RET_STR_LENGTH, RET_STR_LENGTH - 1, "{\"%s\":%d,\"%s\":%d,\"%s\":{\"%s\":\"%s\"}}",
        FIELD_AUTH_FORM, AUTH_FORM, FIELD_MESSAGE, AUTH_ACK_REQUEST, FIELD_PAYLOAD,
        FIELD_AUTH_DATA, tmp_data_hex) < 0) {
        LOGE("String generate failed");
        FREE(ret_str);
        ret_str = NULL;
    }
    FREE(tmp_data_hex);
    return ret_str;
}

#else /* _CUT_XXX_ */

#include "parsedata.h"
DEFINE_EMPTY_STRUCT_FUNC(auth_ack_request)

#endif /* _CUT_XXX_ */
