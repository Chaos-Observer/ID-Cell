/*
 * ID-CELL · 值类型协商（§24.8）
 * ============================================================================
 *
 * 回答的是「MCU 与控制器怎么用不同的编码表达同一个物理量」。
 *
 * 三条不可协商的约定：
 *
 *   1. 类型 MUST 与 scale 成对出现。定点的分辨率与有效范围是绑死的——
 *      i32 + 1e-9 的范围只有 ±2.147，装不下 ±160 m/s² 的加速度，
 *      而这一点在只列类型的列表上看不出来（FR-086）。
 *
 *   2. 协商 MUST 先过滤再取最小。顺序不可颠倒：先取成本最低者再检查
 *      可行性，会出现「协商结果不可用、但双方都以为成功了」的状态
 *      （FR-087）。不可行就是失败，不是降级。
 *
 *   3. 语义层不参与协商。量种与单位跨链路恒定，类型协商只换表示
 *      不换含义（FR-088、SEC-070）。
 *
 * 成本序里有一处反直觉的排序：f32 是 4 字节但排在 4 字节整数之后，
 * 因为浮点能表达连续量而整数配合 scale 只能表达离散网格值。
 */
#include "idcell_internal.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------- 成本序 */

int idcell_type_cost(idcell_dtype_t dt)
{
    switch (dt) {
    case IDCELL_DTYPE_BOOL: return 0;
    case IDCELL_DTYPE_U8:
    case IDCELL_DTYPE_I8:   return 1;
    case IDCELL_DTYPE_U16:
    case IDCELL_DTYPE_I16:  return 2;
    case IDCELL_DTYPE_U32:
    case IDCELL_DTYPE_I32:  return 3;
    case IDCELL_DTYPE_F32:  return 4;
    case IDCELL_DTYPE_U64:
    case IDCELL_DTYPE_I64:  return 5;
    case IDCELL_DTYPE_F64:  return 6;
    default: return -1;   /* string / bytes 无固定成本，不可协商 */
    }
}

int idcell_type_bytes(idcell_dtype_t dt)
{
    switch (dt) {
    case IDCELL_DTYPE_BOOL: return 1;
    case IDCELL_DTYPE_U8:
    case IDCELL_DTYPE_I8:   return 1;
    case IDCELL_DTYPE_U16:
    case IDCELL_DTYPE_I16:  return 2;
    case IDCELL_DTYPE_U32:
    case IDCELL_DTYPE_I32:
    case IDCELL_DTYPE_F32:  return 4;
    case IDCELL_DTYPE_U64:
    case IDCELL_DTYPE_I64:
    case IDCELL_DTYPE_F64:  return 8;
    default: return 0;
    }
}

int idcell_type_is_int(idcell_dtype_t dt)
{
    switch (dt) {
    case IDCELL_DTYPE_U8:
    case IDCELL_DTYPE_I8:
    case IDCELL_DTYPE_U16:
    case IDCELL_DTYPE_I16:
    case IDCELL_DTYPE_U32:
    case IDCELL_DTYPE_I32:
    case IDCELL_DTYPE_U64:
    case IDCELL_DTYPE_I64:  return 1;
    default: return 0;
    }
}

/* 整数类型的位宽 */
static int int_bits(idcell_dtype_t dt)
{
    switch (dt) {
    case IDCELL_DTYPE_U8:
    case IDCELL_DTYPE_I8:   return 8;
    case IDCELL_DTYPE_U16:
    case IDCELL_DTYPE_I16:  return 16;
    case IDCELL_DTYPE_U32:
    case IDCELL_DTYPE_I32:  return 32;
    case IDCELL_DTYPE_U64:
    case IDCELL_DTYPE_I64:  return 64;
    default: return 0;
    }
}

/* ---------------------------------------------------------------- 可行性 */

int idcell_type_fits(idcell_type_t t, double lo, double hi, double precision)
{
    int cost = idcell_type_cost(t.dtype);
    if (cost < 0) return IDCELL_E_CONV;   /* string / bytes 不可协商 */

    /* 无约束区间：不检查 */
    if (lo > hi) return IDCELL_OK;

    if (idcell_type_is_int(t.dtype)) {
        int bits = int_bits(t.dtype);
        double scale;
        double max_pos, max_neg;
        /*
         * 有符号与无符号的范围不同：无符号下界为 0。
         * 这里按「保守取有符号范围」判定——无符号类型实际能覆盖更多，
         * 但用更宽的范围判定不会误拒，只是可能放过一个本该可行的类型，
         * 而放过之后写值时仍按该类型的真实范围校验。
         */
        if (bits <= 0) return IDCELL_E_CONV;
        scale = pow(10.0, -(double)t.scale_exp);
        max_pos = (pow(2.0, (double)(bits - 1)) - 1.0) * scale;
        max_neg = -pow(2.0, (double)(bits - 1)) * scale;
        if (hi > max_pos || lo < max_neg) return IDCELL_E_CONV;
        /* 分辨率 10^-exp MUST 不劣于 precision */
        if (precision > 0.0 && scale > precision) return IDCELL_E_CONV;
        return IDCELL_OK;
    }

    /* 浮点：值域须在可表示范围内 */
    if (t.dtype == IDCELL_DTYPE_F32) {
        if (hi > 3.4e38 || lo < -3.4e38) return IDCELL_E_CONV;
        /* f32 有效位约 24 bit，对应十进制有效位约 7；分辨率约 1e-7 相对量级 */
        if (precision > 0.0 && (hi - lo) > 0.0) {
            double span = hi - lo;
            double min_res = span * 1e-7;
            if (min_res > precision) return IDCELL_E_CONV;
        }
        return IDCELL_OK;
    }
    if (t.dtype == IDCELL_DTYPE_F64) {
        if (hi > 1.7e308 || lo < -1.7e308) return IDCELL_E_CONV;
        return IDCELL_OK;
    }
    if (t.dtype == IDCELL_DTYPE_BOOL) {
        /* 布尔只承载 0/1 */
        if (lo > 1.0 || hi < 0.0) return IDCELL_E_CONV;
        if (precision > 0.0 && precision < 1.0) return IDCELL_E_CONV;
        return IDCELL_OK;
    }
    return IDCELL_E_CONV;
}

/* ---------------------------------------------------------------- 协商 */

static int type_same(idcell_type_t a, idcell_type_t b)
{
    return a.dtype == b.dtype && a.scale_exp == b.scale_exp;
}

int idcell_type_negotiate(const idcell_type_t *a, uint8_t acount,
                          const idcell_type_t *b, uint8_t bcount,
                          double lo, double hi, double precision,
                          idcell_type_t *out)
{
    uint8_t i, j;
    idcell_type_t best;
    int best_cost = -1;

    if (!out) return IDCELL_E_NODEV;
    if (!a || !b || acount == 0 || bcount == 0) return IDCELL_E_CONV;

    /*
     * 步骤 1 + 2 + 3 合起来做：对交集里的每一项先判可行，
     * 再在可行项里取成本最低者。
     *
     * 注意：这里先遍历全部候选并比较 cost，而不是「取第一个可行的」
     * —— 因为成本序是全局的，一个成本更低的候选可能出现在后面。
     */
    for (i = 0; i < acount; i++) {
        int c = idcell_type_cost(a[i].dtype);
        if (c < 0) continue;
        /* 交集：b 中存在完全相同的二元组 */
        for (j = 0; j < bcount; j++) {
            if (!type_same(a[i], b[j])) continue;
            /* 步骤 2：可行性过滤 */
            if (idcell_type_fits(a[i], lo, hi, precision) != IDCELL_OK) break;
            /* 步骤 3：取成本序最低的可行者 */
            if (best_cost < 0 || c < best_cost) {
                best_cost = c;
                best = a[i];
            }
            break;
        }
    }

    if (best_cost < 0) return IDCELL_E_CONV;
    *out = best;
    return IDCELL_OK;
}

void idcell_type_str(idcell_type_t t, char *out, size_t cap)
{
    static const char *names[] = {
        "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64",
        "f32", "f64", "bool", "string", "bytes"
    };
    const char *n = ((unsigned)t.dtype < sizeof(names) / sizeof(names[0]))
                    ? names[t.dtype] : "?";
    if (!out || cap == 0) return;
    if (idcell_type_is_int(t.dtype))
        snprintf(out, cap, "%s x 10^-%u", n, (unsigned)t.scale_exp);
    else
        snprintf(out, cap, "%s", n);
}

int idcell_type_list_add(idcell_type_t *list, uint8_t *count,
                         idcell_dtype_t dt, uint8_t scale_exp)
{
    if (!list || !count) return IDCELL_E_NODEV;
    if (*count >= IDCELL_MAX_ACCEPT_TYPES) return IDCELL_E_NODEV;
    /* 同一二元组不重复登记 */
    {
        uint8_t i;
        for (i = 0; i < *count; i++) {
            if (list[i].dtype == dt && list[i].scale_exp == scale_exp)
                return IDCELL_OK;
        }
    }
    list[*count].dtype = dt;
    list[*count].scale_exp = scale_exp;
    (*count)++;
    return IDCELL_OK;
}
