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

#if !(defined(_CUT_PAKE_) || defined(_CUT_PAKE_SERVER_) || defined(_CUT_EXCHANGE_) || defined(_CUT_EXCHANGE_SERVER_))

#include "securec.h"
#include "log.h"
#include "mem_stat.h"
#include "jsonutil.h"
#include "commonutil.h"
#include "parsedata.h"
#include "exchange_auth_info.h"
#include "key_agreement_version.h"


void free_exchange_request(void *obj)
{
    if (obj != NULL) {
        exchange_request_data *data = obj;
        if (data->cipher.val != NULL) {
            FREE(data->cipher.val);
        }
        FREE(data);
    }
}
char *make_exchange_request(void *data)
{
    exchange_request_data *exchange_request = data;
    /* authinfo */
    uint8_t *tmp_data_hex = raw_byte_to_hex_string(exchange_request->cipher.val, exchange_request->cipher.length);
    if (tmp_data_hex == NULL) {
        return NULL;
    }
    char *ret_str = (char *)MALLOC(RET_STR_LENGTH);
    if (ret_str == NULL) {
        FREE(tmp_data_hex);
        return NULL;
    }
    (void)memset_s(ret_str, RET_STR_LENGTH, 0, RET_STR_LENGTH);
    if (snprintf_s(ret_str, RET_STR_LENGTH, RET_STR_LENGTH - 1, "{\"%s\":%d,\"%s\":{\"%s\":\"%s\"}}", FIELD_MESSAGE,
        EXCHANGE_REQUEST, FIELD_PAYLOAD, FIELD_EX_AUTH_INFO, tmp_data_hex) < 0) {
        LOGE("String generate failed");
        FREE(ret_str);
        ret_str = NULL;
    }
    FREE(tmp_data_hex);
    return ret_str;
}

#else /* _CUT_XXX_ */

#include "parsedata.h"
DEFINE_EMPTY_STRUCT_FUNC(exchange_request)

#endif /* _CUT_XXX_ */
