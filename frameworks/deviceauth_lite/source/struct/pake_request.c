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

#include "securec.h"
#include "log.h"
#include "mem_stat.h"
#include "jsonutil.h"
#include "pake_server.h"
#include "key_agreement_version.h"
#include "parsedata.h"

void free_pake_request(void *obj)
{
    if (obj != NULL) {
        FREE(obj);
    }
}

char *make_pake_request(void *data)
{
    struct pake_start_request_data *pake_request = data;
    char *ret_str = (char *)MALLOC(RET_STR_LENGTH);
    if (ret_str == NULL) {
        return NULL;
    }
    (void)memset_s(ret_str, RET_STR_LENGTH, 0, RET_STR_LENGTH);
    if (snprintf_s(ret_str, RET_STR_LENGTH, RET_STR_LENGTH - 1,
        "{\"%s\":%d,\"%s\":{\"%s\":{\"%s\":\"%u.%u.%u\",\"%s\":\"%u.%u.%u\"},\"%s\":true,\"%s\":%d}}",
        FIELD_MESSAGE, PAKE_REQUEST, FIELD_PAYLOAD, FIELD_VERSION, FIELD_CURRENT_VERSION,
        pake_request->peer_version.first, pake_request->peer_version.second,
        pake_request->peer_version.third, FIELD_MIN_VERSION,
        pake_request->peer_support_version.first, pake_request->peer_support_version.second,
        pake_request->peer_support_version.third, FIELD_SUPPORT_256_MOD,
        FIELD_OPERATION_CODE, pake_request->operation_code) < 0) {
        LOGE("String generate failed");
        FREE(ret_str);
        ret_str = NULL;
    }
    return ret_str;
}

#else /* _CUT_XXX_ */

#include "parsedata.h"
DEFINE_EMPTY_STRUCT_FUNC(pake_request)

#endif /* _CUT_XXX_ */
