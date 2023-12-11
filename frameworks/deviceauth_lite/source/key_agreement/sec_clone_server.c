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

#if (defined(_SUPPORT_SEC_CLONE_) || defined(_SUPPORT_SEC_CLONE_SERVER_))

#include "sec_clone_server.h"
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "huks_adapter.h"
#include "log.h"
#include "commonutil.h"
#include "distribution.h"
#include "hichain.h"

#define MAX_ITER_COUNT 10

const char *SEC_CLONE_SRV_PROOF_STR = "hichain_sec_clone_server_proof";
const char *SEC_CLONE_CHALLENGE_STR = "hichain_sec_clone_challenge";
const char *SEC_CLONE_CLONE_STR = "hichain_sec_clone_clone_data";
const char *SEC_CLONE_SEC_RESULT_STR = "hichain_sec_clone_result";

const int32_t SEC_CLONE_START_RESP_DATA_SIZE = 9216;
const int32_t SEC_CLONE_CERT_CHAIN_SIZE = 9216;

const char *CERT_NUM = "certs";
const char *CERT_LEVEL_1 = "cert1";
const char *CERT_LEVEL_2 = "cert2";
const char *CERT_LEVEL_3 = "cert3";
const char *CERT_LEVEL_4 = "cert4";

const int32_t CERT_CHAIN_NUM = 4;

static void clear_temp_key(struct hc_key_alias *temp_key_alias)
{
    int32_t ret = check_lt_public_key_exist(temp_key_alias);
    if (ret != HC_OK) {
        LOGE("temp key is not exist");
        return;
    }

    ret = delete_lt_public_key(temp_key_alias);
    if (ret != HC_OK) {
        LOGE("delete temp key failed");
    }
}

void destroy_sec_clone_server(struct sec_clone_server *handle)
{
    if (handle == NULL) {
        return;
    }

    if (handle->start_request_data.val != NULL) {
        FREE(handle->start_request_data.val);
        handle->start_request_data.val = NULL;
    }

    if (handle->client_sec_data.val != NULL) {
        FREE(handle->client_sec_data.val);
        handle->client_sec_data.val = NULL;
    }

    if (handle->need_clean_temp_key) {
        struct hc_key_alias *temp_key_alias = &(handle->cert_key_alias);
        clear_temp_key(temp_key_alias);
        handle->need_clean_temp_key = false;
    }

    FREE(handle);
}

#else

#include "sec_clone_server.h"
#include "log.h"
#include "mem_stat.h"

struct sec_clone_server *build_sec_clone_server(hc_handle hichain)
{
    LOGE("Donot support sec clone protocol");
    (void)hichain;
    return (struct sec_clone_server *)MALLOC(sizeof(struct sec_clone_server));
}

void destroy_sec_clone_server(struct sec_clone_server *handle)
{
    LOGE("Donot support sec clone protocol");
    FREE(handle);
}

#endif
