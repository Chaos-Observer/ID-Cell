/*
 * ID-CELL · 单位换算入口（§24.6 量种优先判定链）
 *
 * 关键约定（§09.2 / §24.6）：接收方声明 accept_units，发送方负责转换。
 * 因此本模块位于「发送侧」，不属于帧格式的一部分。
 *
 * 换算表是编解码层的东西，不预置进协议帧。
 *
 * v0.8 起换算 MUST 经由量种优先的路径：先比量种 ID，不同即 T0；
 * 量种相同才进入单位换算。绝不能以量纲向量相等作为可换算的判据——
 * 力的量纲与力矩的量纲在 SI 中完全一致（FR-082）。
 *
 * 量种表与单位子集在 idcell_qty.c。
 */
#include "idcell_internal.h"

int idcell_unit_convert(const char *from, const char *to,
                        double in, double *out, idcell_conv_t *cls_out)
{
    idcell_qty_t fq, tq;

    if (cls_out) *cls_out = IDCELL_CONV_T1;
    if (!from || !to) return IDCELL_E_UNIT;

    /*
     * 同单位：恒等。
     * 这一条必须在查表之前——私有单位（如 x:acme:unit）不在内置表里，
     * 但同单位并不需要换算，也不该被判成「未知单位」。
     */
    if (strcmp(from, to) == 0) {
        if (out) *out = in;
        return IDCELL_OK;
    }

    /* 未知单位：量种无法确定 -> 未知单位不得静默透传（§09.6 E_UNIT） */
    if (idcell_unit_qty(from, &fq) != IDCELL_OK) return IDCELL_E_UNIT;
    if (idcell_unit_qty(to, &tq) != IDCELL_OK) return IDCELL_E_UNIT;

    /* 量种优先判定（其余分支在 idcell_qty_convert 内） */
    return idcell_qty_convert(fq, from, tq, to, in, out, cls_out);
}
