/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "mbedtls_ec_adapter.h"

#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>

#include "hal_error.h"
#include "hc_log.h"
#include "huks_adapter.h"

#define LOG_AND_RETURN_IF_MBED_FAIL(ret, fmt, ...) \
do { \
    if ((ret) != 0) { \
        LOGE(fmt, ##__VA_ARGS__); \
        return HAL_ERR_MBEDTLS; \
    } \
} while (0)

#define LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, fmt, ...) \
do { \
    if ((ret) != 0) { \
        LOGE(fmt, ##__VA_ARGS__); \
        goto CLEAN_UP; \
    } \
} while (0)

#define LEN_HALF_DIVISOR 2
#define BITS_PER_BYTE 8
#define EC_LEN 64
#define SHA256_HASH_LEN 32
#define P256_KEY_SIZE 32
#define P256_PUBLIC_SIZE 64 // P256_KEY_SIZE * 2
#define PARAM_A_INDEX 2
#define PARAM_U_INDEX 4
#define PARAM_MINUS_A_INDEX 3
#define PARAM_ONE_INDEX 5
#define HASH_TO_POINT_PARA_NUMS 6

typedef struct Blob {
    uint32_t dataSize;
    uint8_t *data;
} Blob;

static const uint8_t POINT_A[] = {
    0x04, 0x53, 0xf9, 0xe4, 0xf4, 0xbc, 0x3a, 0xb5, 0x9d, 0x44, 0x78, 0x45, 0x21, 0x13, 0x8b, 0x49,
    0xba, 0xa3, 0x1c, 0xe2, 0xa8, 0xdb, 0xbd, 0xb8, 0xd6, 0x73, 0x31, 0x46, 0x3a, 0x69, 0x53, 0xf1,
    0xed, 0xef, 0x96, 0x1e, 0xdb, 0x42, 0xbe, 0x3a, 0x24, 0x43, 0xc4, 0x08, 0x23, 0xfb, 0x58, 0xee,
    0x61, 0x24, 0x8b, 0x59, 0x64, 0x65, 0x2d, 0xbc, 0x6b, 0xa5, 0x1d, 0x6e, 0x04, 0x22, 0x53, 0xae,
    0x27
};
static const uint8_t POINT_B[] = {
    0x04, 0x03, 0x4d, 0x11, 0x11, 0xa6, 0x3f, 0x5f, 0x72, 0x43, 0x59, 0x73, 0x8b, 0x46, 0xc3, 0xfd,
    0x70, 0x58, 0xb0, 0xb6, 0x11, 0xd3, 0x4f, 0xf3, 0x49, 0xa0, 0xd2, 0x86, 0xd7, 0x35, 0x33, 0xc5,
    0x36, 0xe4, 0x99, 0xcc, 0x13, 0x47, 0xe4, 0xab, 0xde, 0x8f, 0x3a, 0xd6, 0x65, 0x1a, 0x77, 0x0b,
    0xc4, 0x82, 0xd5, 0xac, 0x4b, 0x5d, 0xe4, 0xcc, 0x48, 0xb0, 0x54, 0x6c, 0x9b, 0x76, 0x76, 0x1a,
    0xba
};

static uint8_t g_hash2pointParas[HASH_TO_POINT_PARA_NUMS][BYTE_LENGTH_CURVE_25519] = {
    { 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,    /* 0:p */
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed },
    { 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,    /* 1:divide_minus_p_1_2 */
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* 2:A */
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x6d, 0x06 },
    { 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,    /* 3:-A */
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x92, 0xe7 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* 4:u = 2 */
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* 5:1 */
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
};

static const uint8_t RANDOM_SEED_CUSTOM[] = { 0x4C, 0x54, 0x4B, 0x53 }; // LTKS means LiteKeystore

static bool IsValidBlob(const Blob *blob)
{
    return (blob != NULL) && (blob->data != NULL) && (blob->dataSize != 0);
}

static bool IsValidUint8Buff(const Uint8Buff *buff)
{
    return (buff != NULL) && (buff->val != NULL) && (buff->length != 0);
}

static void InitPointParams(mbedtls_mpi *scalarA, mbedtls_mpi *scalarB, mbedtls_ecp_point *pointA,
    mbedtls_ecp_point *pointB, mbedtls_ecp_point *result)
{
    mbedtls_mpi_init(scalarA);
    mbedtls_mpi_init(scalarB);
    mbedtls_ecp_point_init(pointA);
    mbedtls_ecp_point_init(pointB);
    mbedtls_ecp_point_init(result);
}

static void FreePointParams(mbedtls_mpi *scalarA, mbedtls_mpi *scalarB, mbedtls_ecp_point *pointA,
    mbedtls_ecp_point *pointB, mbedtls_ecp_point *result)
{
    mbedtls_mpi_free(scalarA);
    mbedtls_mpi_free(scalarB);
    mbedtls_ecp_point_free(pointA);
    mbedtls_ecp_point_free(pointB);
    mbedtls_ecp_point_free(result);
}

static void SwapEndian(uint8_t *pubKey, int len)
{
    if ((pubKey == NULL) || (len <= 0)) {
        return;
    }
    for (int i = 0; i < len / LEN_HALF_DIVISOR; ++i) {
        uint8_t tmp = pubKey[i];
        pubKey[i] = pubKey[len - i - 1];
        pubKey[len - i - 1] = tmp;
    }
}

static void FreeCleanFiveBns(mbedtls_mpi *bn1, mbedtls_mpi *bn2, mbedtls_mpi *bn3,
                             mbedtls_mpi *bn4, mbedtls_mpi *bn5)
{
    mbedtls_mpi_free(bn1);
    mbedtls_mpi_free(bn2);
    mbedtls_mpi_free(bn3);
    mbedtls_mpi_free(bn4);
    mbedtls_mpi_free(bn5);
}

static int32_t CalTmpParaX(mbedtls_mpi *tmpY, const mbedtls_mpi *tmpX, const mbedtls_mpi *modP)
{
    int32_t status;
    mbedtls_mpi tmpBnA;
    mbedtls_mpi tmpBnB;
    mbedtls_mpi tmpBnC;
    mbedtls_mpi tmpBnE;
    mbedtls_mpi paraBnA;
    mbedtls_mpi paraBnU;

    mbedtls_mpi_init(&tmpBnA);
    mbedtls_mpi_init(&tmpBnB);
    mbedtls_mpi_init(&tmpBnC);
    mbedtls_mpi_init(&tmpBnE);
    mbedtls_mpi_init(&paraBnA);
    mbedtls_mpi_init(&paraBnU);

    status = mbedtls_mpi_read_binary(&paraBnA, g_hash2pointParas[PARAM_A_INDEX], BYTE_LENGTH_CURVE_25519);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error1");

    status = mbedtls_mpi_read_binary(&paraBnU, g_hash2pointParas[PARAM_U_INDEX], BYTE_LENGTH_CURVE_25519);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error2");

    status = mbedtls_mpi_copy(&tmpBnB, tmpX);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error3");
    /* a := b ^ 3 + A * b ^ 2 + b */

    status = mbedtls_mpi_exp_mod(&tmpBnE, &tmpBnB, &paraBnU, modP, NULL);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error4"); // b^2

    status = mbedtls_mpi_mul_mpi(&tmpBnC, &tmpBnE, &tmpBnB);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error5");
    status = mbedtls_mpi_mod_mpi(&tmpBnC, &tmpBnC, modP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error6"); // b^3

    status = mbedtls_mpi_mul_mpi(&tmpBnA, &tmpBnE, &paraBnA); // A*b^2
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error7");
    status = mbedtls_mpi_mod_mpi(&tmpBnA, &tmpBnA, modP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error8");

    status = mbedtls_mpi_add_mpi(&tmpBnE, &tmpBnC, &tmpBnA); // b^3 + A*b^2
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error9");
    status = mbedtls_mpi_mod_mpi(&tmpBnE, &tmpBnE, modP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error10");

    status = mbedtls_mpi_add_mpi(tmpY, &tmpBnE, &tmpBnB); // b^3 + A*b^2 + b
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error11");
    status = mbedtls_mpi_mod_mpi(tmpY, tmpY, modP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParaX error12");

CLEAN_UP:
    FreeCleanFiveBns(&paraBnA, &tmpBnA, &tmpBnB, &tmpBnC, &tmpBnE);
    mbedtls_mpi_free(&paraBnU);
    return status;
}

static int32_t CalTmpParab(mbedtls_mpi *tmpX, const mbedtls_mpi *modP, const uint8_t *hash, uint32_t hashLen)
{
    int32_t status;
    mbedtls_mpi paraBnNegA;
    mbedtls_mpi paraBNOne;
    mbedtls_mpi paraBnU;
    mbedtls_mpi tmpBnA;
    mbedtls_mpi tmpBnB;

    mbedtls_mpi_init(&paraBnNegA);
    mbedtls_mpi_init(&paraBNOne);
    mbedtls_mpi_init(&paraBnU);
    mbedtls_mpi_init(&tmpBnA);
    mbedtls_mpi_init(&tmpBnB);

    status = mbedtls_mpi_read_binary(&paraBnNegA, g_hash2pointParas[PARAM_MINUS_A_INDEX], BYTE_LENGTH_CURVE_25519);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error1");
    status = mbedtls_mpi_read_binary(&paraBNOne, g_hash2pointParas[PARAM_ONE_INDEX], BYTE_LENGTH_CURVE_25519);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error2");
    status = mbedtls_mpi_read_binary(&paraBnU, g_hash2pointParas[PARAM_U_INDEX], BYTE_LENGTH_CURVE_25519);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error3");
    status = mbedtls_mpi_read_binary(&tmpBnA, hash, hashLen);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error4");

    /* b := -A / (1 + u * a ^ 2) */
    status = mbedtls_mpi_exp_mod(&tmpBnB, &tmpBnA, &paraBnU, modP, NULL);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error5");

    status = mbedtls_mpi_mul_mpi(&tmpBnA, &tmpBnB, &paraBnU);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error6");
    status = mbedtls_mpi_mod_mpi(&tmpBnA, &tmpBnA, modP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error7");

    status = mbedtls_mpi_add_mpi(&tmpBnB, &tmpBnA, &paraBNOne);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error8");
    status = mbedtls_mpi_mod_mpi(&tmpBnB, &tmpBnB, modP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error9");

    status = mbedtls_mpi_inv_mod(&tmpBnA, &tmpBnB, modP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error10");

    status = mbedtls_mpi_mul_mpi(tmpX, &tmpBnA, &paraBnNegA);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error11");
    status = mbedtls_mpi_mod_mpi(tmpX, tmpX, modP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "CalTmpParab error12");
CLEAN_UP:
    FreeCleanFiveBns(&paraBnNegA, &paraBNOne, &paraBnU, &tmpBnA, &tmpBnB);
    return status;
}

/*
 * hash2point function, use BoringSSL big number algorithm library;
 * p_point(little endian): the output pointer of Curve25519 point;
 * p_hash (little endian): the input pointer of string;
 */
static int32_t Elligator(unsigned char *point, int pointLength, const unsigned char *hash, int hashLength)
{
    mbedtls_mpi paraBnP;
    mbedtls_mpi paraBnSquare;
    mbedtls_mpi paraBnNegA;
    mbedtls_mpi tmpBnA;
    mbedtls_mpi tmpBnB;
    mbedtls_mpi tmpBnC;
    mbedtls_mpi tmpBnE;

    mbedtls_mpi_init(&paraBnP);
    mbedtls_mpi_init(&paraBnSquare);
    mbedtls_mpi_init(&paraBnNegA);
    mbedtls_mpi_init(&tmpBnA);
    mbedtls_mpi_init(&tmpBnB);
    mbedtls_mpi_init(&tmpBnC);
    mbedtls_mpi_init(&tmpBnE);

    int32_t status = mbedtls_mpi_read_binary(&paraBnP, g_hash2pointParas[0], BYTE_LENGTH_CURVE_25519);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error1");
    status = mbedtls_mpi_read_binary(&paraBnSquare, g_hash2pointParas[1], BYTE_LENGTH_CURVE_25519);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error2");
    status = mbedtls_mpi_read_binary(&paraBnNegA, g_hash2pointParas[PARAM_MINUS_A_INDEX], BYTE_LENGTH_CURVE_25519);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error3");

    status = CalTmpParab(&tmpBnB, &paraBnP, hash, hashLength);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error4");
    status = CalTmpParaX(&tmpBnA, &tmpBnB, &paraBnP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error5");

    status = mbedtls_mpi_sub_mpi(&tmpBnC, &paraBnP, &tmpBnB);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error6");
    status = mbedtls_mpi_mod_mpi(&tmpBnC, &tmpBnC, &paraBnP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error7");

    status = mbedtls_mpi_add_mpi(&tmpBnC, &tmpBnC, &paraBnNegA);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error8");
    status = mbedtls_mpi_mod_mpi(&tmpBnC, &tmpBnC, &paraBnP);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error9");

    status = mbedtls_mpi_exp_mod(&tmpBnE, &tmpBnA, &paraBnSquare, &paraBnP, NULL);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error10");

    status = mbedtls_mpi_safe_cond_swap(&tmpBnB, &tmpBnC, (mbedtls_mpi_cmp_mpi(&paraBnSquare, &tmpBnE) == 1));
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error11");

    status = mbedtls_mpi_write_binary(&tmpBnC, point, pointLength);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(status, "Elligator error12");

    SwapEndian(point, pointLength);
CLEAN_UP:
    mbedtls_mpi_free(&paraBnP);
    mbedtls_mpi_free(&paraBnSquare);
    FreeCleanFiveBns(&paraBnNegA, &tmpBnA, &tmpBnB, &tmpBnC, &tmpBnE);
    return status;
}

static int32_t CalculateMessageDigest(mbedtls_md_type_t type, const Blob *input, Blob *output)
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(type);
    if (info == NULL) {
        return HAL_ERR_NOT_SUPPORTED;
    }

    uint32_t outSize = mbedtls_md_get_size(info);
    if (output->dataSize < outSize) {
        return HAL_ERR_SHORT_BUFFER;
    }

    int32_t ret = mbedtls_md(info, input->data, input->dataSize, output->data);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Calculate message digest failed.\n");

    output->dataSize = outSize;
    return HAL_SUCCESS;
}

static int32_t Sha256(const Blob *input, Blob *output)
{
    if (!IsValidBlob(input) || !IsValidBlob(output)) {
        LOGE("Input params for sha256 is invalid.");
        return HAL_ERR_INVALID_PARAM;
    }
    return CalculateMessageDigest(MBEDTLS_MD_SHA256, input, output);
}

static int32_t ReadBigNums(mbedtls_mpi *x, mbedtls_mpi *y, const Blob *blob)
{
    int32_t ret = mbedtls_mpi_read_binary(x, blob->data, P256_KEY_SIZE);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Read x coordinate of public key failed.");
    ret = mbedtls_mpi_read_binary(y, blob->data + P256_KEY_SIZE, P256_KEY_SIZE);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Read y coordinate of public key failed.");
    return HAL_SUCCESS;
}

static int32_t ReadEcPublicKey(mbedtls_ecp_point *point, const Blob *publicKey)
{
    int32_t ret = ReadBigNums(&point->MBEDTLS_PRIVATE(X), &point->MBEDTLS_PRIVATE(Y), publicKey);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Read coordinate of public key failed.");
    ret = mbedtls_mpi_lset(&point->MBEDTLS_PRIVATE(Z), 1);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Lset point z failed.");
    return HAL_SUCCESS;
}

static int32_t WriteOutBigNums(const mbedtls_mpi *x, const mbedtls_mpi *y, Blob *out)
{
    int32_t ret = mbedtls_mpi_write_binary(x, out->data, P256_KEY_SIZE);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Write x coordinate of public key failed.");

    ret = mbedtls_mpi_write_binary(y, out->data + P256_KEY_SIZE, P256_KEY_SIZE);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Write y coordinate of public key failed.");

    out->dataSize = P256_PUBLIC_SIZE;
    return HAL_SUCCESS;
}

static int32_t WriteOutEcPublicKey(const mbedtls_ecp_point *point, Blob *publicKey)
{
    return WriteOutBigNums(&point->MBEDTLS_PRIVATE(X), &point->MBEDTLS_PRIVATE(Y), publicKey);
}

static int EcKeyAgreementLog(mbedtls_ecp_keypair *keyPair, mbedtls_ecp_point *p, mbedtls_ctr_drbg_context *ctrDrbg)
{
    return mbedtls_ecp_mul_restartable(&keyPair->MBEDTLS_PRIVATE(grp), p, &keyPair->MBEDTLS_PRIVATE(d),
        &keyPair->MBEDTLS_PRIVATE(Q), mbedtls_ctr_drbg_random, ctrDrbg, NULL);
}

static int32_t EcKeyAgreement(const Blob *privateKey, const Blob *publicKey, Blob *secretKey)
{
    if (!IsValidBlob(publicKey) || publicKey->dataSize != P256_PUBLIC_SIZE || !IsValidBlob(secretKey) ||
        secretKey->dataSize != P256_PUBLIC_SIZE || !IsValidBlob(privateKey)) {
        LOGE("Input params for ec key agree is invalid.");
        return HAL_ERR_INVALID_PARAM;
    }
    mbedtls_mpi *secret = HcMalloc(sizeof(mbedtls_mpi), 0);
    mbedtls_ecp_keypair *keyPair = HcMalloc(sizeof(mbedtls_ecp_keypair), 0);
    mbedtls_entropy_context *entropy = HcMalloc(sizeof(mbedtls_entropy_context), 0);
    mbedtls_ctr_drbg_context *ctrDrbg = HcMalloc(sizeof(mbedtls_ctr_drbg_context), 0);
    if ((secret == NULL) || (keyPair == NULL) || (entropy == NULL) || (ctrDrbg == NULL)) {
        LOGE("Malloc for mbedtls ec key param failed.");
        HcFree(secret);
        HcFree(keyPair);
        HcFree(entropy);
        HcFree(ctrDrbg);
        return HAL_ERR_BAD_ALLOC;
    }
    mbedtls_mpi_init(secret);
    mbedtls_ecp_keypair_init(keyPair);
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctrDrbg);
    mbedtls_ecp_point p;
    mbedtls_ecp_point_init(&p);
    int32_t ret = ReadEcPublicKey(&keyPair->MBEDTLS_PRIVATE(Q), publicKey);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read the public key failed.\n");
    ret = mbedtls_ecp_group_load(&keyPair->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Load the ecp group failed.\n");
    ret = mbedtls_mpi_read_binary(&keyPair->MBEDTLS_PRIVATE(d), privateKey->data, privateKey->dataSize);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read the private key failed.\n");
    ret = mbedtls_ctr_drbg_seed(ctrDrbg, mbedtls_entropy_func, entropy,
        RANDOM_SEED_CUSTOM, sizeof(RANDOM_SEED_CUSTOM));
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Set custom string failed.\n");
    LOG_AND_GOTO_CLEANUP_IF_FAIL(EcKeyAgreementLog(keyPair, &p, ctrDrbg), "Compute secret key failed.\n");
    LOG_AND_GOTO_CLEANUP_IF_FAIL(mbedtls_mpi_copy(secret, &p.MBEDTLS_PRIVATE(X)), "Copy secret failed.\n");
    LOG_AND_GOTO_CLEANUP_IF_FAIL(WriteOutEcPublicKey(&p, secretKey), "Write out ec public key failed.\n");
CLEAN_UP:
    mbedtls_mpi_free(secret);
    mbedtls_ecp_keypair_free(keyPair);
    mbedtls_entropy_free(entropy);
    mbedtls_ctr_drbg_free(ctrDrbg);
    mbedtls_ecp_point_free(&p);
    HcFree(secret);
    HcFree(keyPair);
    HcFree(entropy);
    HcFree(ctrDrbg);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Ec key agree failed.");
    return HAL_SUCCESS;
}

static int32_t EcHashToPoint(const Blob *hash, Blob *point)
{
    mbedtls_mpi scalarA;
    mbedtls_mpi scalarB;
    mbedtls_ecp_point pointA;
    mbedtls_ecp_point pointB;
    mbedtls_ecp_point result;
    InitPointParams(&scalarA, &scalarB, &pointA, &pointB, &result);

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    uint8_t digest[SHA256_HASH_LEN] = { 0 };
    Blob digestBlob = { sizeof(digest), digest };

    int32_t ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Load ecp group failed.\n");
    ret = mbedtls_ecp_point_read_binary(&grp, &pointA, POINT_A, sizeof(POINT_A));
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read point A failed.\n");
    ret = mbedtls_ecp_point_read_binary(&grp, &pointB, POINT_B, sizeof(POINT_B));
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read point B failed.\n");
    ret = Sha256(hash, &digestBlob);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Compute message digest failed.\n");
    ret = mbedtls_mpi_lset(&scalarA, 1);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Set number one failed.\n");
    ret = mbedtls_mpi_read_binary(&scalarB, digest, SHA256_HASH_LEN);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Read digest failed.\n");
    ret = mbedtls_ecp_muladd(&grp, &result, &scalarA, &pointA, &scalarB, &pointB);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Double-scalar multiplication failed.\n");
    ret = mbedtls_ecp_check_pubkey(&grp, &result);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Invalid point on P256 is returned.\n");
    ret = WriteOutEcPublicKey(&result, point);
    LOG_AND_GOTO_CLEANUP_IF_FAIL(ret, "Write out public key failed.\n");
CLEAN_UP:
    FreePointParams(&scalarA, &scalarB, &pointA, &pointB, &result);
    mbedtls_ecp_group_free(&grp);
    LOG_AND_RETURN_IF_MBED_FAIL(ret, "Ec hash to point failed.");
    return HAL_SUCCESS;
}

// only support P256 HashToPoint for standard system
int32_t MbedtlsHashToPoint(const Uint8Buff *hash, Uint8Buff *outEcPoint)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(hash, "hash");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(hash->val, "hash->val");
    CHECK_LEN_EQUAL_RETURN(hash->length, SHA256_LEN, "hash->length");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outEcPoint, "outEcPoint");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outEcPoint->val, "outEcPoint->val");
    CHECK_LEN_EQUAL_RETURN(outEcPoint->length, EC_LEN, "outEcPoint->length");

    struct Blob hashBlob = {
        .dataSize = hash->length,
        .data = hash->val
    };
    struct Blob pointBlob = {
        .dataSize = outEcPoint->length,
        .data = outEcPoint->val
    };

    int32_t ret = EcHashToPoint(&hashBlob, &pointBlob);
    if (ret != 0 || pointBlob.dataSize != EC_LEN) {
        LOGE("HashToPoint with mbedtls for P256 failed, ret: %d", ret);
        return HAL_FAILED;
    }

    return HAL_SUCCESS;
}

int32_t MbedtlsHashToPoint25519(const Uint8Buff *hash, Uint8Buff *outEcPoint)
{
    if (!IsValidUint8Buff(hash) || !IsValidUint8Buff(outEcPoint)) {
        return HAL_ERR_INVALID_PARAM;
    }
    if (hash->length != BYTE_LENGTH_CURVE_25519 || outEcPoint->length != BYTE_LENGTH_CURVE_25519) {
        LOGE("MbedtlsHashToPoint invalid length.");
        return HAL_ERR_INVALID_PARAM;
    }
    uint8_t hashTmp[BYTE_LENGTH_CURVE_25519] = { 0 };
    (void)memcpy_s(hashTmp, BYTE_LENGTH_CURVE_25519, hash->val, BYTE_LENGTH_CURVE_25519);

    hashTmp[BYTE_LENGTH_CURVE_25519 - 1] &= ~HASH2POINT_PARA_PREPRO;
    SwapEndian(hashTmp, BYTE_LENGTH_CURVE_25519);
    int status = Elligator(outEcPoint->val, BYTE_LENGTH_CURVE_25519, hashTmp, BYTE_LENGTH_CURVE_25519);
    if (status != 0) {
        LOGE("Elligator failed, status:%d", status);
    }
    return status;
}

// only support P256 AgreeSharedSecret for standard system
int32_t MbedtlsAgreeSharedSecret(const KeyBuff *priKey, const KeyBuff *pubKey, Uint8Buff *sharedKey)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(priKey, "priKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(priKey->key, "priKey->key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(priKey->keyLen, "priKey->keyLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKey, "devicePk");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(pubKey->key, "devicePk->key");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(pubKey->keyLen, "devicePk->keyLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(sharedKey, "sharedKey");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(sharedKey->val, "sharedKey->val");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(sharedKey->length, "sharedKey->length");

    struct Blob priKeyBlob = {
        .dataSize = priKey->keyLen,
        .data = priKey->key
    };
    struct Blob pubKeyBlob = {
        .dataSize = pubKey->keyLen,
        .data = pubKey->key
    };
    struct Blob sharedKeyBlob = {
        .dataSize = sharedKey->length,
        .data = sharedKey->val
    };
    int32_t ret = EcKeyAgreement(&priKeyBlob, &pubKeyBlob, &sharedKeyBlob);
    if (ret != 0) {
        LOGE("Agree key failed, ret = %d", ret);
        return HAL_FAILED;
    }
    return HAL_SUCCESS;
}

int32_t MbedtlsBase64Encode(const uint8_t *byte, uint32_t byteLen, char *base64Str, uint32_t strLen, uint32_t *outLen)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(byte, "byte");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(byteLen, "byteLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(base64Str, "base64Str");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(strLen, "strLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outLen, "outLen");

    size_t needBuffLen = 0;
    (void)mbedtls_base64_encode(NULL, 0, &needBuffLen, byte, byteLen);
    if (needBuffLen > strLen) {
        LOGE("The content to be written is larger than the input buffer size. Need: %zd, Buffer: %u",
            needBuffLen, strLen);
        return HAL_ERR_SHORT_BUFFER;
    }

    int res = mbedtls_base64_encode((unsigned char *)base64Str, strLen, &needBuffLen, byte, byteLen);
    if (res != 0) {
        LOGE("call mbedtls's mbedtls_base64_encode fail. res: %d", res);
        return HAL_ERR_MBEDTLS;
    }

    *outLen = needBuffLen;
    return HAL_SUCCESS;
}

int32_t MbedtlsBase64Decode(const char *base64Str, uint32_t strLen, uint8_t *byte, uint32_t byteLen, uint32_t *outLen)
{
    CHECK_PTR_RETURN_HAL_ERROR_CODE(base64Str, "base64Str");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(strLen, "strLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(byte, "byte");
    CHECK_LEN_ZERO_RETURN_ERROR_CODE(byteLen, "byteLen");
    CHECK_PTR_RETURN_HAL_ERROR_CODE(outLen, "outLen");

    size_t needBuffLen = 0;
    int res = mbedtls_base64_decode(NULL, 0, &needBuffLen, (const unsigned char *)base64Str, strLen);
    if (res == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        LOGE("The input string is not in base64 encoding format.");
        return HAL_ERR_BASE64_FORMAT;
    }

    if (needBuffLen > byteLen) {
        LOGE("The content to be written is larger than the input buffer size. Need: %zd, Buffer: %u",
            needBuffLen, byteLen);
        return HAL_ERR_SHORT_BUFFER;
    }

    res = mbedtls_base64_decode(byte, byteLen, &needBuffLen, (const unsigned char *)base64Str, strLen);
    if (res != 0) {
        LOGE("call mbedtls's mbedtls_base64_decode fail. res: %d", res);
        return HAL_ERR_MBEDTLS;
    }

    *outLen = (uint32_t)needBuffLen;
    return HAL_SUCCESS;
}
