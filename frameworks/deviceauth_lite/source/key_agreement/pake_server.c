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

#include "pake_server.h"
#include "log.h"

#if !(defined(_CUT_PAKE_) || defined(_CUT_PAKE_SERVER_))

#include "securec.h"
#include "huks_adapter.h"
#include "mem_stat.h"

#ifdef DESC
#undef DESC
#endif
#define DESC(...) 1


#define HICHAIN_SPEKE_BASE_INFO       "hichain_speke_base_info"
#define HICHAIN_RETURN_KEY            "hichain_return_key"
#define HICHAIN_SPEKE_SESSIONKEY_INFO "hichain_speke_sessionkey_info"

#if DESC("interface")

void destroy_pake_server(struct pake_server *pake_server)
{
    if (pake_server == NULL) {
        return;
    }

    LOGI("Destroy pake server object %u success", pake_server_sn(pake_server));
    (void)memset_s(&pake_server->pin, sizeof(struct hc_pin), 0, sizeof(struct hc_pin));
    (void)memset_s(&pake_server->self_esk, sizeof(struct esk), 0, sizeof(struct esk));
    (void)memset_s(&pake_server->session_key, sizeof(struct pake_session_key), 0, sizeof(struct pake_session_key));
    (void)memset_s(&pake_server->hmac_key, sizeof(struct pake_hmac_key), 0, sizeof(struct pake_hmac_key));
    (void)memset_s(&pake_server->service_key, sizeof(struct hc_session_key), 0, sizeof(struct hc_session_key));
    FREE(pake_server);
}

#endif /* DESC */

#if DESC("virtual") /* called by base class */

#endif /* DESC */


#else /* _CUT_XXX_ */

#include "stdlib_south.h"

#endif /* _CUT_XXX_ */
