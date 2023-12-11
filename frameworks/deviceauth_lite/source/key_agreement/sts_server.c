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

#include "sts_server.h"
#include "log.h"

#if !(defined(_CUT_STS_) || defined(_CUT_STS_SERVER_))

#include "securec.h"
#include "commonutil.h"
#include "distribution.h"
#include "mem_stat.h"
#include "huks_adapter.h"

#ifdef DESC
#undef DESC
#endif
#define DESC(...) 1

#define HC_STS_REQUEST_LEN  256
#define HC_STS_RESPONSE_LEN 256


void destroy_sts_server(struct sts_server *handle)
{
    if (handle == NULL) {
        DBG_OUT("Destroy sts server object failed");
        return;
    }
    (void)memset_s(&handle->self_private_key, sizeof(struct stsk), 0, sizeof(struct stsk));
    (void)memset_s(&handle->session_key, sizeof(struct sts_session_key), 0, sizeof(struct sts_session_key));
    (void)memset_s(&handle->service_key, sizeof(struct hc_session_key), 0, sizeof(struct hc_session_key));
    FREE(handle);
    LOGI("FREE sts server object success");
}
#else /* _CUT_XXX_ */

#include "mem_stat.h"

#endif /* _CUT_XXX_ */
