/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef COMMONUTIL_TEST_H
#define COMMONUTIL_TEST_H

#include "jsonutil_test.h"

#define HC_VERSION_DEC 10

#ifdef __cplusplus
extern "C" {
#endif

int32_t hex_string_to_byte(const char *str, int32_t len, uint8_t *hex);
void byte_to_hex_string(const uint8_t *hex, int32_t hex_len, uint8_t *buf, int32_t buf_len);

void print_bytes(uint8_t *buf, int32_t buf_len);

int32_t byte_convert(json_pobject obj, const char *field, uint8_t *hex, uint32_t *length, uint32_t max_len);
int32_t string_convert(json_pobject obj, const char *field, uint8_t *str, uint32_t *length, uint32_t max_len);

int32_t memory_copy_error(const char *fun, unsigned int line);

#ifdef __cplusplus
}
#endif

#endif