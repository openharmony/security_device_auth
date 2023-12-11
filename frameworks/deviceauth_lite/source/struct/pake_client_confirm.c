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

#if !(defined(_CUT_PAKE_) || defined(_CUT_PAKE_SERVER_))

#include <log.h>
#include "securec.h"
#include "mem_stat.h"
#include "jsonutil.h"
#include "commonutil.h"
#include "pake_server.h"
#include "parsedata.h"
#include "key_agreement_version.h"

void free_pake_client_confirm(void *obj)
{
    if (obj != NULL) {
        FREE(obj);
    }
}

char *make_pake_client_confirm(void *data)
{
    struct pake_end_request_data *pake_client_confirm = data;
    /* kcfData */
    uint8_t *tmp_kcf_data_hex = raw_byte_to_hex_string(pake_client_confirm->kcf_data.hmac,
                                                       pake_client_confirm->kcf_data.length);
    if (tmp_kcf_data_hex == NULL) {
        return NULL;
    }
    /* challenge */
    uint8_t *tmp_cha_data_hex = raw_byte_to_hex_string(pake_client_confirm->challenge.challenge,
                                                       pake_client_confirm->challenge.length);
    if (tmp_cha_data_hex == NULL) {
        FREE(tmp_kcf_data_hex);
        return NULL;
    }
    /* epk */
    uint8_t *tmp_epk_data_hex = raw_byte_to_hex_string(pake_client_confirm->epk.epk,
                                                       pake_client_confirm->epk.length);
    if (tmp_epk_data_hex == NULL) {
        FREE(tmp_kcf_data_hex);
        FREE(tmp_cha_data_hex);
        return NULL;
    }
    char *ret_str = (char *)MALLOC(RET_STR_LENGTH);
    if (ret_str == NULL) {
        FREE(tmp_kcf_data_hex);
        FREE(tmp_cha_data_hex);
        FREE(tmp_epk_data_hex);
        return NULL;
    }
    (void)memset_s(ret_str, RET_STR_LENGTH, 0, RET_STR_LENGTH);
    if (snprintf_s(ret_str, RET_STR_LENGTH, RET_STR_LENGTH - 1,
        "{\"%s\":%d,\"%s\":{\"%s\":\"%s\", \"%s\":\"%s\", \"%s\":\"%s\"}}", FIELD_MESSAGE,
        PAKE_CLIENT_CONFIRM, FIELD_PAYLOAD, FIELD_KCF_DATA, tmp_kcf_data_hex, FIELD_CHALLENGE,
        tmp_cha_data_hex, FIELD_EPK, (char *)tmp_epk_data_hex) < 0) {
        LOGE("String generate failed");
        FREE(ret_str);
        ret_str = NULL;
    }
    FREE(tmp_kcf_data_hex);
    FREE(tmp_cha_data_hex);
    FREE(tmp_epk_data_hex);
    return ret_str;
}

#else /* _CUT_XXX_ */

#include "parsedata.h"
DEFINE_EMPTY_STRUCT_FUNC(pake_client_confirm)

#endif /* _CUT_XXX_ */
