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

#include "crypto_hash_to_point.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "hal_error.h"
#include "hc_log.h"
#include "hc_types.h"
#include "hks_type.h"

#define KEY_BYTES_CURVE25519                 32

struct CurveConstPara {
    BIGNUM *p;
    BIGNUM *one;
    BIGNUM *d;
    BIGNUM *k;
    BIGNUM *capitalA;
    BIGNUM *minusA;
    BIGNUM *u;
    BIGNUM *q;
};

/* RFC 8032, the prime of Curve25519, p = 2^255-19 */
static const uint8_t g_curveParamP[KEY_BYTES_CURVE25519] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};

/* RFC 8032, one = 1 */
static const uint8_t g_curveParamOne[KEY_BYTES_CURVE25519] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

/* RFC 8032, A non-zero element in the finite field GF(p), not equal to 1 */
static const uint8_t g_curveParamD[KEY_BYTES_CURVE25519] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
};

/* RFC 8032, k = (p - 1) / 2 */
static const uint8_t g_curveParamK[KEY_BYTES_CURVE25519] = {
    0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
};

/* RFC 8032, A = 486662 */
static const uint8_t g_curveParamCapitalA[KEY_BYTES_CURVE25519] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x6d, 0x06
};

/* RFC 8032, -A = -486662 */
static const uint8_t g_curveParamMinusA[KEY_BYTES_CURVE25519] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x92, 0xe7
};

/* RFC 8032, u = 2 */
static const uint8_t g_curveParamU[KEY_BYTES_CURVE25519] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

/* RFC 8032, q = endian_swap(k) */
static const uint8_t g_curveParamQ[KEY_BYTES_CURVE25519] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6
};

static void HcBnFree(BIGNUM *p)
{
    if (p == NULL) {
        return;
    }
    BN_free(p);
}

static void HcBnCTXFree(BN_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BN_CTX_free(ctx);
}

static void CurveFreeConstPara(struct CurveConstPara *para)
{
    HcBnFree(para->p);
    HcBnFree(para->one);
    HcBnFree(para->d);
    HcBnFree(para->k);
    HcBnFree(para->capitalA);
    HcBnFree(para->minusA);
    HcBnFree(para->u);
    HcBnFree(para->q);
}

static int32_t CurveInitConstPara(struct CurveConstPara *para)
{
    do {
        para->p = BN_new();
        if (para->p == NULL) {
            break;
        }
        para->one = BN_new();
        if (para->one == NULL) {
            break;
        }
        para->d = BN_new();
        if (para->d == NULL) {
            break;
        }
        para->k = BN_new();
        if (para->k == NULL) {
            break;
        }
        para->capitalA = BN_new();
        if (para->capitalA == NULL) {
            break;
        }
        para->minusA = BN_new();
        if (para->minusA == NULL) {
            break;
        }
        para->u = BN_new();
        if (para->u == NULL) {
            break;
        }
        para->q = BN_new();
        if (para->q == NULL) {
            break;
        }
        return HAL_SUCCESS;
    } while (0);

    CurveFreeConstPara(para);
    
    return HAL_FAILED;
}

/* b := -A / (1 + u * a ^ 2) */
static int32_t CurveHashToPointCalcB(const struct HksBlob *hash,
    const struct CurveConstPara *curvePara, BIGNUM *b, BN_CTX *ctx)
{
    BIGNUM *swap = BN_new();
    if (swap == NULL) {
        return HAL_FAILED;
    }
    
    int32_t ret = HAL_FAILED;
    do {
        if (BN_bin2bn(hash->data, hash->size, swap) == NULL) {
            break;
        }
        if (BN_mul(b, swap, swap, ctx) <= 0) {
            break;
        }
        if (BN_mod(b, b, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_mul(swap, b, curvePara->u, ctx) <= 0) {
            break;
        }
        if (BN_mod(swap, swap, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_add(b, swap, curvePara->one) <= 0) {
            break;
        }
        if (BN_mod(b, b, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_mod_inverse(swap, b, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_mul(b, swap, curvePara->minusA, ctx) <= 0) {
            break;
        }
        if (BN_mod(b, b, curvePara->p, ctx) <= 0) {
            break;
        }
        ret = HAL_SUCCESS;
    } while (0);
    HcBnFree(swap);
    return ret;
}

static int32_t CurveHashToPointCalcA(const BIGNUM *b,
    const struct CurveConstPara *curvePara, BIGNUM *a, BN_CTX *ctx)
{
    BIGNUM *swap = BN_new();
    if (swap == NULL) {
        return HAL_FAILED;
    }

    BIGNUM *result = BN_new();
    if (result == NULL) {
        HcBnFree(swap);
        return HAL_FAILED;
    }

    int32_t ret = HAL_FAILED;
    do {
        if (BN_mul(result, b, b, ctx) <= 0) {
            break;
        }
        if (BN_mod(result, result, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_mul(swap, result, b, ctx) <= 0) {
            break;
        }
        if (BN_mod(swap, swap, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_mul(a, result, curvePara->capitalA, ctx) <= 0) {
            break;
        }
        if (BN_mod(a, a, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_add(result, swap, a) <= 0) {
            break;
        }
        if (BN_mod(result, result, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_add(a, result, b) <= 0) {
            break;
        }
        if (BN_mod(a, a, curvePara->p, ctx) <= 0) {
            break;
        }
        ret = HAL_SUCCESS;
    } while (0);

    HcBnFree(swap);
    HcBnFree(result);
    return ret;
}

static int32_t CurveHashToPointCalcC(const BIGNUM *a, BIGNUM *b,
    const struct CurveConstPara *curvePara, BIGNUM *c, BN_CTX *ctx)
{
    BIGNUM *result = BN_new();
    if (result == NULL) {
        return HAL_FAILED;
    }

    int32_t ret = HAL_FAILED;
    do {
        /* If a is a quadratic residue modulo p, c := b and high_y := 1 Otherwise c := -b - A and high_y := 0 */
        if (BN_sub(c, curvePara->p, b) <= 0) {
            break;
        }
        if (BN_mod(c, c, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_add(c, c, curvePara->minusA) <= 0) {
            break;
        }
        if (BN_mod(c, c, curvePara->p, ctx) <= 0) {
            break;
        }
        /* Sliding-window exponentiation: result = a^q mod p */
        if (BN_mod_exp(result, a, curvePara->q, curvePara->p, ctx) <= 0) {
            break;
        }
        if (BN_cmp(curvePara->q, result) > 0) {
            BN_swap(b, c);
        }
        ret = HAL_SUCCESS;
    } while (0);

    HcBnFree(result);
    return ret;
}

static int32_t CurveSetConstPara(struct CurveConstPara *para)
{
    int32_t ret = HAL_FAILED;
    do {
        if (BN_bin2bn(g_curveParamP, KEY_BYTES_CURVE25519, para->p) == NULL) {
            break;
        }
        if (BN_bin2bn(g_curveParamOne, KEY_BYTES_CURVE25519, para->one) == NULL) {
            break;
        }
        if (BN_bin2bn(g_curveParamD, KEY_BYTES_CURVE25519, para->d) == NULL) {
            break;
        }
        if (BN_bin2bn(g_curveParamK, KEY_BYTES_CURVE25519, para->k) == NULL) {
            break;
        }
        if (BN_bin2bn(g_curveParamCapitalA, KEY_BYTES_CURVE25519, para->capitalA) == NULL) {
            break;
        }
        if (BN_bin2bn(g_curveParamMinusA, KEY_BYTES_CURVE25519, para->minusA) == NULL) {
            break;
        }
        if (BN_bin2bn(g_curveParamU, KEY_BYTES_CURVE25519, para->u) == NULL) {
            break;
        }
        if (BN_bin2bn(g_curveParamQ, KEY_BYTES_CURVE25519, para->q) == NULL) {
            break;
        }
        ret = HAL_SUCCESS;
    } while (0);

    return ret;
}

static int32_t CurveHashToPoint(const struct HksBlob *hash, struct HksBlob *point)
{
    struct CurveConstPara curvePara;
    (void)memset_s(&curvePara, sizeof(curvePara), 0, sizeof(curvePara));
    int32_t ret = CurveInitConstPara(&curvePara);
    if (ret != HAL_SUCCESS) {
        return HAL_ERR_BAD_ALLOC;
    }
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *c = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    do {
        if (a == NULL || b == NULL || c == NULL || ctx == NULL) {
            ret = HAL_ERR_BAD_ALLOC;
            break;
        }
        ret = CurveSetConstPara(&curvePara);
        if (ret != HAL_SUCCESS) {
            break;
        }
        ret = CurveHashToPointCalcB(hash, &curvePara, b, ctx);
        if (ret != HAL_SUCCESS) {
            break;
        }
        ret = CurveHashToPointCalcA(b, &curvePara, a, ctx);
        if (ret != HAL_SUCCESS) {
            break;
        }
        ret = CurveHashToPointCalcC(a, b, &curvePara, c, ctx);
        if (ret != HAL_SUCCESS) {
            break;
        }
        if (BN_bn2binpad(c, point->data, point->size) <= 0) {
            ret = HAL_FAILED;
            break;
        }
        ret = HAL_SUCCESS;
    } while (0);
    CurveFreeConstPara(&curvePara);
    HcBnFree(a);
    HcBnFree(b);
    HcBnFree(c);
    HcBnCTXFree(ctx);
    return ret;
}

static int32_t EndianSwap(struct HksBlob *data)
{
    uint32_t end = data->size - 1;
    const uint32_t start = 0;

    /* count the middle index of array */
    uint32_t cnt = data->size / 2; // 2 used to calculate half of the data size

    for (uint32_t i = 0; i < cnt; i++) {
        uint8_t tmp;
        tmp = data->data[start + i];
        data->data[start + i] = data->data[end - i];
        data->data[end - i] = tmp;
    }
    return HAL_SUCCESS;
}

int32_t OpensslHashToPoint(const struct HksBlob *hash, struct HksBlob *point)
{
    int32_t ret = HAL_FAILED;
    uint8_t *copyData = HcMalloc(hash->size, 0);
    if (copyData == NULL) {
        LOGE("malloc size %" LOG_PUB "u failed", hash->size);
        return HKS_ERROR_MALLOC_FAIL;
    }
    struct HksBlob hashCopy = { hash->size, copyData};

    do {
        if (memcpy_s(hashCopy.data, hashCopy.size, hash->data, hash->size) != EOK) {
            break;
        }

        hashCopy.data[hashCopy.size - 1] &= 0x3f; /* RFC 8032 */
        (void)EndianSwap(&hashCopy);
        ret = CurveHashToPoint(&hashCopy, point);
        if (ret != HAL_SUCCESS) {
            LOGE("curve hash to point failed");
            break;
        }
        (void)EndianSwap(point);
    } while (0);
    HcFree(hashCopy.data);
    return ret;
}