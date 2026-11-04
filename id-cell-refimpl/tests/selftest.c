/*
 * ID-CELL 参考实现一致性自测（selftest）
 * ============================================================================
 *
 * 这套用例对应规范 §11.3 一致性套件的「编解码一致性」与「管道行为」两层，
 * 外加规范里点名要求 MUST 失败的若干条红线。
 *
 * 它不测「跑得通跑不通」这种模糊结论，只测可以判真假的东西：
 *   - CRC 向量对不对
 *   - 编解码往返有没有丢字段
 *   - 单位转换分级（T1/T2 放行，T0/T3/T4 拒绝）
 *   - 周期协商红线（T_pub > T_stale 必须失败）
 *   - 权限、租约、量域、身份冲突的拒绝路径
 *   - 六段管道跑完后契约十字段是否齐备
 *
 * 断言失败即退出码非 0——可直接接入 CI。
 *
 * 编译：
 *     python -m ziglang cc -std=c99 -Iinclude -o selftest.exe tests\selftest.c src\*.c
 * ============================================================================
 */
#include "idcell.h"
#include "idcell_transport.h"
/*
 * 自测是参考实现的一部分，直接用内部头——它要检查帧编解码原语，
 * 而这些原语刻意不进公开头（用户不需要手写帧字节）。
 */
#include "idcell_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ---------------------------------------------------------------- 断言 */

static int g_pass = 0;
static int g_fail = 0;
static const char *g_group = "";

static void group(const char *name)
{
    g_group = name;
    printf("\n[%s]\n", name);
}

static void ok(int cond, const char *what)
{
    if (cond) {
        g_pass++;
        printf("  PASS  %s\n", what);
    } else {
        g_fail++;
        printf("  FAIL  %s   (%s)\n", what, g_group);
    }
}

static void ok_eq(int got, int want, const char *what)
{
    if (got == want) {
        g_pass++;
        printf("  PASS  %s\n", what);
    } else {
        g_fail++;
        printf("  FAIL  %s   (期望 %d，实际 %d)\n", what, want, got);
    }
}

static int nearly(double a, double b)
{
    double d = a - b;
    if (d < 0) d = -d;
    return d < 1e-9;
}

/* ---------------------------------------------------------------- 1. CRC */

static void test_crc(void)
{
    group("1. CRC-16/CCITT-FALSE 向量");

    /* 公认测试向量：check("123456789") = 0x29B1 */
    const char *v = "123456789";
    ok_eq(idcell_crc16((const uint8_t *)v, 9), 0x29B1, "check(\"123456789\") = 0x29B1");

    /* 空输入 → 初始值 0xFFFF */
    ok_eq(idcell_crc16((const uint8_t *)"", 0), 0xFFFF, "空输入 = 0xFFFF");

    /* 单字节 0x00 */
    {
        uint8_t z = 0x00;
        ok_eq(idcell_crc16(&z, 1), 0xE1F0, "单字节 0x00 = 0xE1F0");
    }
}

/* ---------------------------------------------------------------- 2. DID */

static void test_did(void)
{
    idcell_did_t a, b, c;
    char s1[19], s2[19];

    group("2. 身份：独立生成、唯一、可打印");

    idcell_did_generate(1, &a);
    idcell_did_generate(2, &b);
    idcell_did_generate(1, &c);

    ok(!idcell_did_equal(&a, &b), "不同种子生成不同 DID");
    ok(idcell_did_equal(&a, &c), "同种子生成同一 DID（可复现）");
    ok(memcmp(a.b, b.b, 8) != 0, "DID 字节确实不同");

    /* SEC-064：厂商前缀式 DID 的前缀必须保留 */
    idcell_did_from_vendor(0xABCD, 0x112233445566ULL, &a);
    ok(a.b[0] == 0xAB && a.b[1] == 0xCD, "厂商前缀写入 DID 前两字节");

    idcell_did_str(&a, s1);
    idcell_did_str(&b, s2);
    ok(strlen(s1) == 17, "DID 字符串长度为 17");
    ok(s1[8] == '-', "DID 字符串第 9 位是分隔符");
    ok(s1[17] == '\0', "DID 字符串以 '\\0' 结尾");
    {
        /* 文本形式必须逐字节对应：前半段来自 b[0..3]，后半段来自 b[4..7] */
        static const char hex[] = "0123456789ABCDEF";
        int i, bad = 0;
        for (i = 0; i < 4; i++) {
            if (s1[i*2] != hex[a.b[i] >> 4] || s1[i*2+1] != hex[a.b[i] & 0x0F]) bad = 1;
        }
        for (i = 4; i < 8; i++) {
            if (s1[9 + (i-4)*2] != hex[a.b[i] >> 4] ||
                s1[9 + (i-4)*2 + 1] != hex[a.b[i] & 0x0F]) bad = 1;
        }
        ok(!bad, "DID 文本形式逐字节对应 b[0..7]");
    }
}

/* ---------------------------------------------------------------- 3. 单位换算 */

static void test_units(void)
{
    double out = 0;
    idcell_conv_t cls = IDCELL_CONV_T0;

    group("3. 单位转换分级（T0–T4）");

    /* 同单位：恒等，T1 */
    ok_eq(idcell_unit_convert("m/s", "m/s", 3.5, &out, &cls), IDCELL_OK, "同单位转换成功");
    ok(nearly(out, 3.5), "同单位值不变");
    ok_eq(cls, IDCELL_CONV_T1, "同单位判为 T1");

    /* 纯比例：T1 */
    ok_eq(idcell_unit_convert("mm", "m", 1500.0, &out, &cls), IDCELL_OK, "mm → m 成功");
    ok(nearly(out, 1.5), "1500 mm = 1.5 m");
    ok_eq(cls, IDCELL_CONV_T1, "mm → m 判为 T1");

    /* 比例 + 偏移：T2 */
    ok_eq(idcell_unit_convert("Cel", "[degF]", 100.0, &out, &cls), IDCELL_OK, "Cel → [degF] 成功");
    ok(nearly(out, 212.0), "100 Cel = 212 [degF]");
    ok_eq(cls, IDCELL_CONV_T2, "Cel → [degF] 判为 T2");

    /* T0：量种不同，禁止 */
    ok_eq(idcell_unit_convert("m", "s", 1.0, &out, &cls), IDCELL_E_UNIT, "m → s 返回 E_UNIT");

    /* T3：需要参考条件（绝压需大气压参考） */
    ok_eq(idcell_unit_convert("kPa_abs", "kPa", 101.3, &out, &cls), IDCELL_E_UNIT,
          "kPa_abs 不在核心子集内，返回 E_UNIT");

    /* 未知单位不得静默透传 */
    ok_eq(idcell_unit_convert("furlong", "m", 1.0, &out, &cls), IDCELL_E_UNIT,
          "未知单位返回 E_UNIT");
}

/* ---------------------------------------------------------------- 3b. 量种与 UCUM（§24） */

static void test_qty(void)
{
    double out = 0;
    idcell_conv_t cls = IDCELL_CONV_T0;
    idcell_qty_t q;

    group("3b. 量种表与 UCUM 单位子集（§24）");

    /* 量种表完整性：规范单位与量种 ID 必须互相对得上 */
    ok_eq(idcell_qty_table_check(), IDCELL_OK, "量种表与单位表交叉校验通过");

    /* 量种 ID 连续、数量为 24（§24.2） */
    ok_eq(IDCELL_QTY_COUNT, 24, "量种表为 24 项");
    ok_eq(idcell_qty_name(IDCELL_QTY_FORCE) != NULL, 1, "量种名可取");
    ok(strcmp(idcell_qty_name(IDCELL_QTY_FORCE), "force") == 0, "force 量种名正确");
    ok(strcmp(idcell_qty_canonical_unit(IDCELL_QTY_FORCE), "N") == 0,
       "force 的规范单位为 N");
    ok(strcmp(idcell_qty_canonical_unit(IDCELL_QTY_TORQUE), "N.m") == 0,
       "torque 的规范单位为 N.m");

    /* 量种名反查（工具层把可读名解析成编码） */
    ok_eq(idcell_qty_by_name("acceleration", &q), IDCELL_OK, "按名反查量种成功");
    ok_eq(q, IDCELL_QTY_ACCELERATION, "反查结果为 acceleration");
    ok_eq(idcell_qty_by_name("ACCELERATION", &q), IDCELL_OK, "量种名不区分大小写");
    ok_eq(idcell_qty_by_name("不存在的量种", &q), IDCELL_E_NODEV, "未知量种名返回 E_NODEV");

    /* 单位的量种归属 */
    ok_eq(idcell_unit_qty("N", &q), IDCELL_OK, "N 的量种可取");
    ok_eq(q, IDCELL_QTY_FORCE, "N 属力量种");
    ok_eq(idcell_unit_qty("N.m", &q), IDCELL_OK, "N.m 的量种可取");
    ok_eq(q, IDCELL_QTY_TORQUE, "N.m 属力矩量种");
    /* 裁剪档下 force/torque 仍在 ID 9/10 —— ID MUST NOT 重排（FR-089） */
    ok_eq((int)IDCELL_QTY_FORCE, 9, "force 的规范 ID 为 9");
    ok_eq((int)IDCELL_QTY_TORQUE, 10, "torque 的规范 ID 为 10");

    /* UCUM 的两个形近而义不同的码（§24.3） */
    ok_eq(idcell_unit_qty("g", &q), IDCELL_OK, "g 的量种可取");
    ok_eq(q, IDCELL_QTY_MASS, "g 是克（质量），不是重力加速度");
    ok_eq(idcell_unit_qty("[g]", &q), IDCELL_OK, "[g] 的量种可取");
    ok_eq(q, IDCELL_QTY_ACCELERATION, "[g] 是标准重力加速度");
    /* 裁剪档下 mass 未编入 -> 其单位 g 的量种不可解（FR-089） */
    ok(idcell_qty_implemented(IDCELL_QTY_MASS) ||
       idcell_unit_qty("g", &q) == IDCELL_E_NODEV,
       "裁剪档下未实现的量种其单位不可解（返回 E_NODEV）");

    /* 红线一：量种不同的量绝不换算，即使量纲向量完全相同 */
    {
        int8_t df[7], dt[7];
        /* 裁剪档下若 force 或 torque 未实现，跳过该项（FR-089） */
        if (idcell_qty_implemented(IDCELL_QTY_FORCE) &&
            idcell_qty_implemented(IDCELL_QTY_TORQUE)) {
            ok_eq(idcell_qty_dimension(IDCELL_QTY_FORCE, df), IDCELL_OK, "力量纲向量可取");
            ok_eq(idcell_qty_dimension(IDCELL_QTY_TORQUE, dt), IDCELL_OK, "力矩量纲向量可取");
            ok(memcmp(df, dt, 7) == 0, "力与力矩的量纲向量完全相同（量纲不足以区分）");
            ok_eq(idcell_qty_convert(IDCELL_QTY_FORCE, "N", IDCELL_QTY_TORQUE, "N.m",
                                     100.0, &out, &cls),
                 IDCELL_E_UNIT, "力 → 力矩被拒（量种不同，尽管量纲相同）");
        }
    }
    {
        int8_t dr[7], da[7], dc[7];
        if (idcell_qty_implemented(IDCELL_QTY_RATIO) &&
            idcell_qty_implemented(IDCELL_QTY_ANGLE) &&
            idcell_qty_implemented(IDCELL_QTY_DATACOUNT)) {
            idcell_qty_dimension(IDCELL_QTY_RATIO, dr);
            idcell_qty_dimension(IDCELL_QTY_ANGLE, da);
            idcell_qty_dimension(IDCELL_QTY_DATACOUNT, dc);
            ok(memcmp(dr, da, 7) == 0 && memcmp(da, dc, 7) == 0,
               "无量纲比值 / 平面角 / 数据量三者量纲相同");
            ok_eq(idcell_qty_convert(IDCELL_QTY_RATIO, "1", IDCELL_QTY_ANGLE, "rad",
                                     1.0, &out, &cls),
                 IDCELL_E_UNIT, "比值 → 角度被拒（量种不同）");
        }
    }

    /* 私有单位：不参与换算、不参与量种匹配（SEC-068） */
    ok_eq(idcell_unit_known("x:acme:torque_unit"), 0, "私有单位不在核心子集内");
    ok_eq(idcell_unit_qty("x:acme:torque_unit", &q), IDCELL_E_UNIT,
          "私有单位的量种不可解");
    ok_eq(idcell_unit_known("x:evil:N"), 0, "含标准码的私有码仍不在子集内");
    ok_eq(idcell_qty_convert(IDCELL_QTY_FORCE, "N", IDCELL_QTY_FORCE, "x:evil:N",
                             1.0, &out, &cls),
         IDCELL_E_UNIT, "私有码不参与换算");
    /* 相同私有码按同一单位处理（换算因子为 1） */
    ok_eq(idcell_qty_convert(IDCELL_QTY_FORCE, "x:acme:u", IDCELL_QTY_FORCE, "x:acme:u",
                             7.0, &out, &cls),
         IDCELL_OK, "相同私有码按恒等处理");
    ok(nearly(out, 7.0), "相同私有码值不变");

    /* UCUM 子集内的换算：T1 纯比例 */
    ok_eq(idcell_qty_convert(IDCELL_QTY_ACCELERATION, "m/s2", IDCELL_QTY_ACCELERATION,
                             "mm/s2", 9.80665, &out, &cls),
         IDCELL_OK, "m/s2 → mm/s2 成功");
    ok(nearly(out, 9806.65), "9.80665 m/s2 = 9806.65 mm/s2");
    ok_eq(cls, IDCELL_CONV_T1, "m/s2 → mm/s2 判为 T1");

    /* T2：带偏移的温标 */
    ok_eq(idcell_qty_convert(IDCELL_QTY_TEMPERATURE, "Cel", IDCELL_QTY_TEMPERATURE,
                             "[degF]", 0.0, &out, &cls),
         IDCELL_OK, "Cel → [degF] 成功");
    ok(nearly(out, 32.0), "0 Cel = 32 [degF]");
    ok_eq(cls, IDCELL_CONV_T2, "Cel → [degF] 判为 T2");

    /* 量种表校验冗余：篡改后必须失败 */
    ok_eq(idcell_qty_table_check(), IDCELL_OK, "量种表校验（未篡改）通过");
}

/* ---------------------------------------------------------------- 3c. 值类型协商（§24.8） */

static void test_type_negotiate(void)
{
    idcell_type_t out;
    char s[32];

    group("3c. 值类型协商：成本序与可行性过滤（§24.8）");

    /* 成本序 */
    ok(idcell_type_cost(IDCELL_DTYPE_BOOL) == 0, "bool 成本序最低");
    ok(idcell_type_cost(IDCELL_DTYPE_I8) < idcell_type_cost(IDCELL_DTYPE_I16),
       "1 B 整数成本低于 2 B 整数");
    ok(idcell_type_cost(IDCELL_DTYPE_I32) < idcell_type_cost(IDCELL_DTYPE_F32),
       "4 B 整数成本低于 f32（同字节但表达力低）");
    ok(idcell_type_cost(IDCELL_DTYPE_F32) < idcell_type_cost(IDCELL_DTYPE_I64),
       "f32 成本低于 8 B 整数");
    ok(idcell_type_cost(IDCELL_DTYPE_I64) < idcell_type_cost(IDCELL_DTYPE_F64),
       "8 B 整数成本低于 f64");
    ok(idcell_type_cost(IDCELL_DTYPE_STRING) < 0, "string 无固定成本，不可协商");

    /* 字节宽度 */
    ok_eq(idcell_type_bytes(IDCELL_DTYPE_I32), 4, "i32 为 4 字节");
    ok_eq(idcell_type_bytes(IDCELL_DTYPE_F32), 4, "f32 为 4 字节");
    ok_eq(idcell_type_bytes(IDCELL_DTYPE_F64), 8, "f64 为 8 字节");

    /* 可行性过滤：定点类型的范围与分辨率都受 scale 约束 */
    {
        idcell_type_t t;
        t.dtype = IDCELL_DTYPE_I32; t.scale_exp = 3;
        ok_eq(idcell_type_fits(t, -160.0, 160.0, 0.001), IDCELL_OK,
              "i32×10^-3 可承载 ±160（分辨率 0.001）");
        t.scale_exp = 9;
        ok_eq(idcell_type_fits(t, -160.0, 160.0, 0.001), IDCELL_E_CONV,
              "i32×10^-9 范围仅 ±2.147，装不下 ±160（分辨率与范围绑死）");
        t.dtype = IDCELL_DTYPE_I16; t.scale_exp = 3;
        ok_eq(idcell_type_fits(t, -160.0, 160.0, 0.001), IDCELL_E_CONV,
              "i16×10^-3 范围仅 ±32.77，装不下 ±160");
        t.dtype = IDCELL_DTYPE_I16; t.scale_exp = 2;
        ok_eq(idcell_type_fits(t, -40.0, 85.0, 0.01), IDCELL_OK,
              "i16×10^-2 可承载温度 ±85（分辨率 0.01）");
    }

    /* 协商：双方都支持 i32 与 f64 -> 取成本更低且可行的 i32 */
    {
        idcell_type_t pa[2], pb[2];
        pa[0].dtype = IDCELL_DTYPE_F64; pa[0].scale_exp = 0;
        pa[1].dtype = IDCELL_DTYPE_I32; pa[1].scale_exp = 3;
        pb[0].dtype = IDCELL_DTYPE_F64; pb[0].scale_exp = 0;
        pb[1].dtype = IDCELL_DTYPE_I32; pb[1].scale_exp = 3;
        ok_eq(idcell_type_negotiate(pa, 2, pb, 2, -160.0, 160.0, 0.001, &out),
              IDCELL_OK, "双方共有 i32 与 f64 时协商成功");
        ok_eq(out.dtype, IDCELL_DTYPE_I32, "协商结果取成本更低的 i32");
        ok_eq(out.scale_exp, 3, "协商结果的 scale 为 10^-3");
    }

    /* 关键：同为 i32 但 scale 不同 -> 不是同一个二元组 -> 不可协商 */
    {
        idcell_type_t pa[1], pb[1];
        pa[0].dtype = IDCELL_DTYPE_I32; pa[0].scale_exp = 3;
        pb[0].dtype = IDCELL_DTYPE_I32; pb[0].scale_exp = 9;
        ok_eq(idcell_type_negotiate(pa, 1, pb, 1, -160.0, 160.0, 0.001, &out),
              IDCELL_E_CONV, "同为 i32 但 scale 不同不构成共同项");
    }

    /* 先过滤后取最小：最低成本的类型装不下值域时，须选较高成本但可行的 */
    {
        idcell_type_t pa[2], pb[2];
        pa[0].dtype = IDCELL_DTYPE_I16; pa[0].scale_exp = 3;  /* 范围不够 */
        pa[1].dtype = IDCELL_DTYPE_I32; pa[1].scale_exp = 3;  /* 可行 */
        pb[0].dtype = IDCELL_DTYPE_I16; pb[0].scale_exp = 3;
        pb[1].dtype = IDCELL_DTYPE_I32; pb[1].scale_exp = 3;
        ok_eq(idcell_type_negotiate(pa, 2, pb, 2, -160.0, 160.0, 0.001, &out),
              IDCELL_OK, "候选集含不可行项时协商仍成功");
        ok_eq(out.dtype, IDCELL_DTYPE_I32,
              "跳过装不下值域的低成本类型，选可行的 i32（先过滤后取最小）");
    }

    /* 交集为空 */
    {
        idcell_type_t pa[1], pb[1];
        pa[0].dtype = IDCELL_DTYPE_I32; pa[0].scale_exp = 3;
        pb[0].dtype = IDCELL_DTYPE_F64; pb[0].scale_exp = 0;
        ok_eq(idcell_type_negotiate(pa, 1, pb, 1, -160.0, 160.0, 0.001, &out),
              IDCELL_E_CONV, "交集为空返回 E_CONV");
    }

    /* 可读形式 */
    {
        idcell_type_t t;
        t.dtype = IDCELL_DTYPE_I32; t.scale_exp = 3;
        idcell_type_str(t, s, sizeof(s));
        ok(strstr(s, "i32") != NULL, "可读形式含类型名");
        ok(strstr(s, "10^-3") != NULL, "可读形式含缩放指数");
        t.dtype = IDCELL_DTYPE_F64; t.scale_exp = 0;
        idcell_type_str(t, s, sizeof(s));
        ok(strcmp(s, "f64") == 0, "浮点类型的可读形式无缩放后缀");
    }

    /* 接受集合去重 */
    {
        idcell_type_t list[4];
        uint8_t n = 0;
        ok_eq(idcell_type_list_add(list, &n, IDCELL_DTYPE_I32, 3), IDCELL_OK, "加入接受类型");
        ok_eq(idcell_type_list_add(list, &n, IDCELL_DTYPE_I32, 3), IDCELL_OK, "重复加入不报错");
        ok_eq(n, 1, "重复项不重复登记");
        ok_eq(idcell_type_list_add(list, &n, IDCELL_DTYPE_F64, 0), IDCELL_OK, "加入第二项");
        ok_eq(n, 2, "接受集合计数正确");
    }
}

/* ---------------------------------------------------------------- 4. 编解码 */

static void test_codec(void)
{
    uint8_t buf[512];
    size_t len = 0;
    idcell_frame_t f, g;
    size_t consumed = 0;
    idcell_did_t src, dst;
    uint8_t payload[64];
    uint16_t plen = 0;
    uint8_t vbuf[8];
    uint8_t prov = (uint8_t)IDCELL_PROV_MEASURED;
    double v = 3.5;

    group("4. 帧编解码往返");

    idcell_did_generate(0x1111, &src);
    idcell_did_generate(0x2222, &dst);

    /* v0.11 由固定头 LEN 精确确定 payload 边界；TLV 仅描述 STD 消息内部语义。 */
    idcell_put_f64(vbuf, v);
    idcell_tlv_put(payload, sizeof(payload), &plen, 0x0100, 0, IDCELL_TLV_VALUE, vbuf, 8);
    idcell_tlv_put(payload, sizeof(payload), &plen, 0x0100, 0, IDCELL_TLV_PROV, &prov, 1);

    memset(&f, 0, sizeof(f));
    f.ver = IDCELL_PROTO_VER_BYTE;
    f.prof = 0;
    f.flags = 0;
    f.type = IDCELL_FT_EVENT;
    f.seq = 0x1234;
    f.txn = 0x5678;
    f.src = src;
    f.dst = dst;
    f.group = 0x0101;
    f.ts_us = 123456789012ULL;   /* 超过 32 位，验证 48 位时间戳不被截断 */
    memcpy(f.payload, payload, plen);
    f.payload_len = plen;

    ok_eq(idcell_frame_encode(&f, buf, sizeof(buf), &len), 0, "帧编码成功");
    ok_eq(IDCELL_HDR_LEN, 36, "v0.11 固定头恰好 36 字节");
    ok_eq((int)len, 36 + (int)plen + 4, "无 AUTH 帧长 = 36 + LEN + 4");

    /* 定长头字段位置校验（§09.1） */
    ok_eq(buf[0], 0xA5, "SYNC 高字节 0xA5");
    ok_eq(buf[1], 0xA5, "SYNC 低字节 0xA5");
    ok_eq(buf[2], IDCELL_PROTO_VER_BYTE, "VER 字节");
    ok_eq(buf[5], IDCELL_FT_EVENT, "TYPE 字节");
    ok_eq(buf[len - 2], 0x5A, "TRAILER 高字节 0x5A");
    ok_eq(buf[len - 1], 0xA5, "TRAILER 低字节 0xA5");
    {
        uint8_t h[36];
        int i;
        memset(h, 0, sizeof(h));
        h[0] = 0xA5; h[1] = 0xA5;
        h[2] = IDCELL_PROTO_VER_BYTE; h[3] = 0; h[4] = 0; h[5] = IDCELL_FT_EVENT;
        h[6] = 0x12; h[7] = 0x34; h[8] = 0x56; h[9] = 0x78;
        h[10] = (uint8_t)(plen >> 8); h[11] = (uint8_t)plen;
        memcpy(h + 12, src.b, 8); memcpy(h + 20, dst.b, 8);
        h[28] = 0x01; h[29] = 0x01;
        for (i = 0; i < 6; i++) h[30 + i] = (uint8_t)(f.ts_us >> ((5 - i) * 8));
        ok(memcmp(buf, h, 36) == 0,
           "36B 头逐字段匹配 SYNC/VER/PROF/FLAGS/TYPE/SEQ/TXN/LEN/SRC/DST/GROUP/TS");
        ok_eq(idcell_get_u16(buf + 10), plen, "LEN 只表示 payload 字节数");
    }

    ok_eq(idcell_frame_decode(buf, len, &g, &consumed), 0, "帧解码成功");
    ok_eq((int)consumed, (int)len, "解码消耗字节数 = 帧长");
    ok_eq(g.type, IDCELL_FT_EVENT, "TYPE 往返一致");
    ok_eq(g.seq, f.seq, "SEQ 往返一致");
    ok_eq(g.txn, f.txn, "TXN 往返一致");
    ok_eq(g.group, f.group, "GROUP 往返一致");
    ok(g.ts_us == f.ts_us, "48 位时间戳往返一致（不被截断）");
    ok(idcell_did_equal(&g.src, &src), "SRC 往返一致");
    ok(idcell_did_equal(&g.dst, &dst), "DST 往返一致");
    ok_eq(g.payload_len, (int)plen, "载荷长度往返一致");
    ok(memcmp(g.payload, payload, plen) == 0, "载荷内容往返一致");

    /* TLV 层级也要往返一致：值、索引、来源等级一个都不能丢 */
    {
        uint16_t pos = 0;
        idcell_tlv_t t;
        int seen_value = 0, seen_prov = 0, rc;
        while ((rc = idcell_tlv_next(g.payload, g.payload_len, &pos, &t)) == 0) {
            if (t.type == IDCELL_TLV_VALUE) {
                seen_value = 1;
                ok_eq(t.idx, 0x0100, "TLV 索引往返一致");
                ok(t.len == 8 && idcell_get_f64(t.val) == v, "TLV 值往返一致");
            } else if (t.type == IDCELL_TLV_PROV) {
                seen_prov = 1;
                ok_eq(t.val[0], (int)prov, "TLV 来源等级往返一致");
            }
        }
        ok_eq(rc, 1, "TLV 链遍历正常结束");
        ok(seen_value && seen_prov, "两个 TLV 都被解出");
    }

    ok_eq(IDCELL_FT_READ, 8, "READ 的线上语义编号固定为 8");
    ok_eq(IDCELL_FT_WRITE, 9, "WRITE 的线上语义编号固定为 9");
    ok_eq(IDCELL_FT_AUTH, 6, "AUTH 保持 6，不再与 Python READ 混淆");
    ok_eq(IDCELL_FT_BIND, 7, "BIND 保持 7，不再与 Python WRITE 混淆");
    f.type = 0xFF;
    ok_eq(idcell_frame_encode(&f, buf, sizeof(buf), &len), IDCELL_FRAME_BAD_TYPE,
          "编码在物化前拒绝未知 TYPE=0xFF");
    {
        uint8_t bad[512];
        f.type = IDCELL_FT_EVENT;
        idcell_frame_encode(&f, buf, sizeof(buf), &len);
        memcpy(bad, buf, len);
        bad[5] = 0xFF;
        idcell_put_u16(bad + len - 4, idcell_crc16(bad, len - 4));
        ok_eq(idcell_frame_decode(bad, len, &g, &consumed), IDCELL_FRAME_BAD_TYPE,
              "未知 TYPE=0xFF 即使 CRC 有效也返回 BAD_TYPE");
    }

    /* CRC 被破坏 → 必须拒绝 */
    {
        uint8_t bad[512];
        memcpy(bad, buf, len);
        bad[len - 3] ^= 0xFF;   /* 破坏 CRC 字段本身 */
        ok(idcell_frame_decode(bad, len, &g, &consumed) < 0, "CRC 被破坏的帧被拒绝");
    }

    /* 载荷被破坏 → 边界与 CRC 都不成立 → 必须拒绝 */
    {
        uint8_t bad[512];
        memcpy(bad, buf, len);
        bad[IDCELL_HDR_LEN] ^= 0xFF;
        ok(idcell_frame_decode(bad, len, &g, &consumed) < 0, "载荷被破坏的帧被拒绝");
    }

    /* TRAILER 被破坏 → 必须拒绝 */
    {
        uint8_t bad[512];
        memcpy(bad, buf, len);
        bad[len - 1] ^= 0xFF;
        ok(idcell_frame_decode(bad, len, &g, &consumed) < 0, "TRAILER 被破坏的帧被拒绝");
    }

    /* 修改 TLV 内 LEN 不改变帧 LEN；CRC 仍必须检测到内容篡改。 */
    {
        uint8_t bad[512];
        memcpy(bad, buf, len);
        bad[IDCELL_HDR_LEN + 4] ^= 0xFF;
        ok_eq(idcell_frame_decode(bad, len, &g, &consumed), IDCELL_FRAME_BAD_CRC,
              "TLV 内容被篡改时由帧 CRC 拒绝（不靠扫描猜边界）");
    }

    /* 数据不足 → 需要更多（不是错误） */
    ok_eq(idcell_frame_decode(buf, 10, &g, &consumed), 1, "半截帧返回「需要更多数据」");
}

/* ------------------------------------------------------- 4b. v0.11 AUTH/RT */

static void make_v11_frame(idcell_frame_t *f, uint8_t type, uint8_t prof, uint8_t flags,
                           uint16_t seed, const uint8_t *payload, uint16_t plen)
{
    memset(f, 0, sizeof(*f));
    f->ver = IDCELL_PROTO_VER_BYTE;
    f->prof = prof;
    f->flags = flags;
    f->type = type;
    f->seq = 0x0102;
    f->txn = 0x0304;
    idcell_did_generate(seed, &f->src);
    idcell_did_generate((uint16_t)(seed + 1), &f->dst);
    f->group = 0x0506;
    f->ts_us = 0x010203040506ULL;
    if (plen) memcpy(f->payload, payload, plen);
    f->payload_len = plen;
}

static void test_auth_codec(void)
{
    static const uint8_t key[] = "golden-key";
    static const uint8_t wrong[] = "wrong-key";
    idcell_frame_t f, g;
    uint8_t raw[64], wire[IDCELL_MAX_FRAME], bad[IDCELL_MAX_FRAME];
    uint8_t mac[32];
    size_t len = 0, consumed = 0, i, crc_at;
    int all_partial = 1;

    group("4b. v0.11 AUTH、RT 与容量边界");
    for (i = 0; i < sizeof(raw); i++) raw[i] = (uint8_t)(i * 3 + 1);
    make_v11_frame(&f, IDCELL_FT_READ, 1, IDCELL_FLAG_AUTH, 0x9100, raw, sizeof(raw));

    ok_eq(idcell_frame_encode_auth(&f, key, sizeof(key) - 1, wire, sizeof(wire), &len), 0,
          "AUTH RT 帧编码成功（TYPE 不负责选择 PROFILE）");
    ok_eq((int)len, 36 + 64 + 16 + 4, "AUTH 帧容量包含 16B 标签，LEN 不含标签");
    ok_eq(idcell_get_u16(wire + 10), 64, "AUTH 帧 LEN 仍只等于 payload 长度");
    ok_eq(wire[3], 1, "PROF=RT 独立于 TYPE");
    ok_eq(wire[4], IDCELL_FLAG_AUTH, "FLAGS.AUTH=0x20");
    idcell_hmac_sha256(key, sizeof(key) - 1, wire, 36 + 64, mac);
    ok(memcmp(wire + 36 + 64, mac, 16) == 0,
       "AUTH_TAG=HMAC-SHA256(36B头+完整RT payload)截断16B");
    crc_at = 36 + 64 + 16;
    ok_eq(idcell_get_u16(wire + crc_at), idcell_crc16(wire, crc_at),
          "CRC16 覆盖头+payload+AUTH_TAG");

    ok_eq(idcell_frame_decode(wire, len, &g, &consumed), IDCELL_FRAME_BAD_AUTH,
          "旧 decode 入口不隐式鉴权");
    ok_eq(idcell_frame_decode_auth(wire, len, wrong, sizeof(wrong) - 1, &g, &consumed),
          IDCELL_FRAME_BAD_AUTH, "错误密钥返回 BAD_AUTH");
    ok_eq(idcell_frame_decode_auth(wire, len, key, sizeof(key) - 1, &g, &consumed), 0,
          "decode_auth 验证完整 RT payload 成功");
    ok_eq((int)consumed, (int)len, "AUTH 解码按 LEN+TAG 精确消耗帧长");
    ok(g.prof == 1 && g.payload_len == sizeof(raw) && memcmp(g.payload, raw, sizeof(raw)) == 0,
       "RT 任意二进制 payload 逐字节往返（不要求 TLV）");
    ok(memcmp(g.auth_tag, wire + 36 + 64, 16) == 0, "解码保留线上 AUTH_TAG");

    memcpy(bad, wire, len);
    bad[36 + 64] ^= 0x80;
    idcell_put_u16(bad + crc_at, idcell_crc16(bad, crc_at));
    ok_eq(idcell_frame_decode_auth(bad, len, key, sizeof(key) - 1, &g, &consumed),
          IDCELL_FRAME_BAD_AUTH, "标签篡改且重算 CRC 后仍返回 BAD_AUTH");
    memcpy(bad, wire, len);
    bad[crc_at] ^= 1;
    ok_eq(idcell_frame_decode_auth(bad, len, key, sizeof(key) - 1, &g, &consumed),
          IDCELL_FRAME_BAD_CRC, "坏 CRC 与坏 AUTH 分类不同");
    memcpy(bad, wire, len);
    bad[len - 1] ^= 1;
    ok_eq(idcell_frame_decode_auth(bad, len, key, sizeof(key) - 1, &g, &consumed),
          IDCELL_FRAME_BAD_TRAILER, "非法 TRAILER 被精确拒绝");
    memcpy(bad, wire, 36);
    bad[10] = 0xFF; bad[11] = 0xFF;
    ok_eq(idcell_frame_decode_auth(bad, 36, key, sizeof(key) - 1, &g, &consumed),
          IDCELL_FRAME_BAD_LENGTH, "坏 LEN 在 payload 复制前拒绝");

    for (i = 1; i < len; i++) {
        if (idcell_frame_decode_auth(wire, i, key, sizeof(key) - 1, &g, &consumed) !=
            IDCELL_FRAME_NEED_MORE) all_partial = 0;
    }
    ok(all_partial, "AUTH 帧每个截断前缀都返回 NEED_MORE（支持任意拆分）");
    ok_eq(idcell_frame_encode_auth(&f, key, sizeof(key) - 1, wire, len - 1, &consumed),
          IDCELL_FRAME_E_CAPACITY, "输出容量少 1 字节时编码返回错误");
    ok_eq(idcell_frame_encode(&f, wire, sizeof(wire), &len), IDCELL_FRAME_BAD_AUTH,
          "旧 encode 入口不会静默生成无密钥 AUTH 帧");

    f.payload_len = IDCELL_MAX_AUTH_PAYLOAD;
    ok_eq(idcell_frame_encode_auth(&f, key, sizeof(key) - 1, wire, sizeof(wire), &len), 0,
          "最大 AUTH payload 恰好装入 1500B 帧");
    ok_eq((int)len, IDCELL_MAX_FRAME, "最大 AUTH 帧长恰好为上限");
    f.payload_len++;
    ok_eq(idcell_frame_encode_auth(&f, key, sizeof(key) - 1, wire, sizeof(wire), &len),
          IDCELL_FRAME_BAD_LENGTH, "AUTH payload 超过容量 1 字节即拒绝");
    f.flags = 0;
    f.payload_len = IDCELL_MAX_PAYLOAD;
    ok_eq(idcell_frame_encode(&f, wire, sizeof(wire), &len), 0,
          "旧无标签路径仍支持最大 STD payload");
}

/* --------------------------------------------------- 4c. 持久流式重组 */

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
    size_t first;
    size_t rest;
    idcell_link_profile_t profile;
} chunked_rx_t;

static int chunked_send(void *ctx, const uint8_t *buf, size_t len)
{
    (void)ctx; (void)buf; (void)len;
    return 0;
}

static int chunked_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    chunked_rx_t *s = (chunked_rx_t *)ctx;
    size_t n;
    (void)timeout_ms;
    if (s->pos == s->len) return 0;
    n = s->pos == 0 && s->first ? s->first : s->rest;
    if (n > s->len - s->pos) n = s->len - s->pos;
    if (n > cap) n = cap;
    memcpy(buf, s->data + s->pos, n);
    s->pos += n;
    return (int)n;
}

static int run_chunked_stream(const uint8_t *wire, size_t len, size_t first, int polls,
                              idcell_did_t *peer0)
{
    chunked_rx_t rx;
    idcell_transport_t tr;
    idcell_node_cfg_t cfg;
    idcell_node_t *node;
    int i, count;

    memset(&rx, 0, sizeof(rx));
    rx.data = wire; rx.len = len; rx.first = first; rx.rest = len;
    rx.profile.media = IDCELL_MEDIA_UART;
    rx.profile.topology = IDCELL_TOPO_P2P;
    memset(&tr, 0, sizeof(tr));
    tr.send = chunked_send; tr.recv = chunked_recv; tr.profile = &rx.profile; tr.ctx = &rx;
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0xE001, &cfg.did);
    node = idcell_node_new(&cfg);
    idcell_node_set_transport(node, &tr);
    for (i = 0; i < polls; i++) idcell_node_poll(node, (uint32_t)(i * 10));
    count = idcell_node_peer_count(node);
    if (peer0 && count > 0) idcell_node_peer(node, 0, peer0);
    idcell_node_free(node);
    return count;
}

static void test_stream_reassembly(void)
{
    idcell_frame_t f1, f2;
    idcell_did_t peer;
    uint8_t p1[3] = {'a', 'b', 'c'}, p2[5] = {'1', '2', '3', '4', '5'};
    uint8_t w1[128], w2[128], joined[512], bad[512];
    size_t l1 = 0, l2 = 0, cut;
    int splits_ok = 1;

    group("4c. 流式半帧、粘包与错误后重同步");
    make_v11_frame(&f1, IDCELL_FT_HEARTBEAT, 0, 0, 0xD100, p1, sizeof(p1));
    make_v11_frame(&f2, IDCELL_FT_HEARTBEAT, 0, 0, 0xD200, p2, sizeof(p2));
    idcell_frame_encode(&f1, w1, sizeof(w1), &l1);
    idcell_frame_encode(&f2, w2, sizeof(w2), &l2);

    for (cut = 1; cut < l1; cut++) {
        chunked_rx_t rx;
        idcell_transport_t tr;
        idcell_node_cfg_t cfg;
        idcell_node_t *node;
        memset(&rx, 0, sizeof(rx));
        rx.data = w1; rx.len = l1; rx.first = cut; rx.rest = l1;
        rx.profile.media = IDCELL_MEDIA_LOOPBACK;
        rx.profile.topology = IDCELL_TOPO_P2P;
        memset(&tr, 0, sizeof(tr));
        tr.send = chunked_send; tr.recv = chunked_recv; tr.profile = &rx.profile; tr.ctx = &rx;
        memset(&cfg, 0, sizeof(cfg)); idcell_did_generate(0xE001, &cfg.did);
        node = idcell_node_new(&cfg); idcell_node_set_transport(node, &tr);
        idcell_node_poll(node, 0);
        if (idcell_node_peer_count(node) != 0) splits_ok = 0;
        idcell_node_poll(node, 10);
        if (idcell_node_peer_count(node) != 1) splits_ok = 0;
        idcell_node_free(node);
    }
    ok(splits_ok, "每个字节位置拆成两次 poll 都能重组（含半 SYNC）");

    memcpy(joined, w1, l1); memcpy(joined + l1, w2, l2);
    ok_eq(run_chunked_stream(joined, l1 + l2, l1 + l2, 1, NULL), 2,
          "一次 read 中粘在一起的两个合法帧都被处理");

    ok_eq((int)l1, 43, "回归帧 A(payload=abc) 为 43B");
    ok_eq((int)l2, 45, "回归帧 B(payload=12345) 为 45B");
    memcpy(joined, w1, l1);
    joined[10] = 0; joined[11] = 48;
    memcpy(joined + l1, w2, l2);
    {
        idcell_frame_t rejected;
        size_t used = 0;
        ok_eq(idcell_frame_decode(joined, l1 + l2, &rejected, &used), IDCELL_FRAME_BAD_CRC,
              "A 的 LEN=48 使合并缓冲按未验证 total 校验为 BAD_CRC");
    }
    ok_eq(run_chunked_stream(joined, l1 + l2, l1 + l2, 1, &peer), 1,
          "范围内坏 LEN+CRC 错误后仍交付 45B 合法帧 B");
    ok(idcell_did_equal(&peer, &f2.src), "坏 LEN 重同步交付的确是 B 而非 A");

    memcpy(joined, w1, l1);
    joined[10] = 0xFF; joined[11] = 0xFF;
    memcpy(joined + l1, w2, l2);
    ok_eq(run_chunked_stream(joined, l1 + l2, l1 + l2, 1, &peer), 1,
          "坏 LEN 帧后合法帧不丢失");
    ok(idcell_did_equal(&peer, &f2.src), "坏 LEN 后重同步到正确的后续帧");

    memcpy(bad, w1, l1); bad[l1 - 3] ^= 1;
    memcpy(joined, bad, l1); memcpy(joined + l1, w2, l2);
    ok_eq(run_chunked_stream(joined, l1 + l2, l1 + l2, 1, &peer), 1,
          "坏 CRC 帧后合法帧不丢失");
    memcpy(bad, w1, l1); bad[l1 - 1] ^= 1;
    memcpy(joined, bad, l1); memcpy(joined + l1, w2, l2);
    ok_eq(run_chunked_stream(joined, l1 + l2, l1 + l2, 1, &peer), 1,
          "坏 TRAILER 帧后合法帧不丢失");

    {
        static const uint8_t key[] = "stream-key";
        make_v11_frame(&f1, IDCELL_FT_HEARTBEAT, 0, IDCELL_FLAG_AUTH, 0xD100, p1, sizeof(p1));
        idcell_frame_encode_auth(&f1, key, sizeof(key) - 1, bad, sizeof(bad), &l1);
        memcpy(joined, bad, l1); memcpy(joined + l1, w2, l2);
        ok_eq(run_chunked_stream(joined, l1 + l2, l1 + l2, 1, &peer), 1,
              "无密钥 BAD_AUTH 帧后仍能接收后续合法帧");
    }

    joined[0] = 0x00; joined[1] = 0xA5;
    memcpy(joined + 2, w2, l2);
    ok_eq(run_chunked_stream(joined, l2 + 2, 1, 2, &peer), 1,
          "垃圾字节与跨 read 的半 SYNC 后可重同步");
}

/* ---------------------------------------------------------------- 5. 注册 */

static void test_registration(void)
{
    idcell_node_cfg_t cfg;
    idcell_node_t *n;
    idcell_capability_t cap;
    idcell_requirement_t req;

    group("5. 注册：三种语义与身份冲突");

    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x3333, &cfg.did);
    cfg.max_perm = IDCELL_PERM_P2;

    n = idcell_node_new(&cfg);
    ok(n != NULL, "节点创建成功");

    /* 能力注册不依赖设备类型注册（§19.3 X1） */
    memset(&cap, 0, sizeof(cap));
    cap.index = 0x0100;
    snprintf(cap.label, sizeof(cap.label), "accel.x");
    cap.qty = IDCELL_QTY_ACCELERATION;
    snprintf(cap.unit, sizeof(cap.unit), "m/s2");
    cap.accept_count = 1;
    snprintf(cap.accept_units[0], sizeof(cap.accept_units[0]), "m/s2");
    cap.perm = IDCELL_PERM_P1;
    cap.min_sync_ms = 20;
    cap.stale_ms = 500;
    /* v0.9：可接受值类型（§24.8） */
    cap.dtype = IDCELL_DTYPE_F64;
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_I32, 3);

    ok_eq(idcell_node_register_capability(n, &cap), IDCELL_OK,
          "未注册设备类型时能力注册仍然成功（X1）");

    /* 重复注册同一个 (index, sub) → E_IDCONFLICT */
    ok_eq(idcell_node_register_capability(n, &cap), IDCELL_E_IDCONFLICT,
          "重复注册同一能力点返回 E_IDCONFLICT");

    /* 描述符版本随注册递增 */
    ok(idcell_node_desc_version(n) >= 2, "描述符版本随注册递增");

    /* 需求注册 */
    memset(&req, 0, sizeof(req));
    snprintf(req.label, sizeof(req.label), "加速度");
    req.qty = IDCELL_QTY_ACCELERATION;
    snprintf(req.unit, sizeof(req.unit), "m/s2");
    req.accept_count = 1;
    snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "m/s2");
    req.index = 0xFFFF;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    req.want_ms = 20;
    req.stale_ms = 500;
    ok_eq(idcell_node_register_requirement(n, &req), IDCELL_OK, "需求注册成功");

    /* 设备类型注册（可选轨）*/
    {
        idcell_device_type_t dt;
        memset(&dt, 0, sizeof(dt));
        snprintf(dt.type_name, sizeof(dt.type_name), "IMU-6DOF");
        ok_eq(idcell_node_register_device_type(n, &dt), IDCELL_OK, "设备类型注册成功");
    }

    /* 链路画像：未绑适配器时是默认值，不崩 */
    {
        const idcell_link_profile_t *lp = idcell_node_link_profile(n);
        ok(lp != NULL, "链路画像可获取（未绑适配器时返回默认值）");
        ok_eq(idcell_node_media(n), IDCELL_MEDIA_UNKNOWN, "未绑适配器时介质为 UNKNOWN");
        ok_eq(idcell_node_topology(n), IDCELL_TOPO_P2P, "未绑适配器时拓扑为 P2P");
    }

    idcell_node_free(n);
}

/* ---------------------------------------------------------------- 6. 管道 */

typedef struct {
    double  accel;
    double  temp;
    uint64_t tick;
    int     set_calls;
    double  last_set_value;
} dev_state_t;

static int dev_read(void *ud, uint16_t index, uint8_t sub,
                    double *value, uint64_t *ts_us, idcell_prov_t *prov)
{
    dev_state_t *d = (dev_state_t *)ud;
    (void)sub;
    if (index == 0x0100)      *value = d->accel;
    else if (index == 0x0200) *value = d->temp;
    else return IDCELL_E_NODEV;
    *ts_us = d->tick * 5000;
    *prov = IDCELL_PROV_MEASURED;
    return IDCELL_OK;
}

static int dev_write(void *ud, uint16_t index, uint8_t sub,
                     double value, const char *intent, uint32_t owner_token)
{
    dev_state_t *d = (dev_state_t *)ud;
    (void)sub; (void)intent; (void)owner_token;
    d->set_calls++;
    d->last_set_value = value;
    if (index == 0x0200) d->temp = value;
    return IDCELL_OK;
}

static void make_dev(idcell_node_t **out, idcell_transport_t *tr, dev_state_t *st)
{
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;

    memset(st, 0, sizeof(*st));

    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x4444, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.proficiency = 2;
    cfg.t_hb_ms = 1000;
    cfg.lease_ttl_ms = 3000;
    cfg.announce_ms = 200;
    snprintf(cfg.vendor, sizeof(cfg.vendor), "Acme");
    snprintf(cfg.model, sizeof(cfg.model), "IMU-6DOF");

    *out = idcell_node_new(&cfg);
    idcell_node_set_transport(*out, tr);

    memset(&cap, 0, sizeof(cap));
    cap.index = 0x0100;
    snprintf(cap.label, sizeof(cap.label), "imu.accel.x");
    cap.qty = IDCELL_QTY_ACCELERATION;
    snprintf(cap.unit, sizeof(cap.unit), "m/s2");
    cap.accept_count = 1;
    snprintf(cap.accept_units[0], sizeof(cap.accept_units[0]), "m/s2");
    cap.dir = IDCELL_DIR_R;      /* 只读点：需求方要读，提供方必须可读 */
    cap.perm = IDCELL_PERM_P1;
    cap.conv_class = IDCELL_CONV_T1;
    /* v0.9：可接受值类型（§24.8）。接受 f64 与 i32×10^-3 两种编码 */
    cap.dtype = IDCELL_DTYPE_F64;
    cap.scale_exp = 0;
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_I32, 3);
    cap.range[0] = -160.0;
    cap.range[1] = 160.0;
    cap.precision = 0.001;
    cap.min_sync_ms = 20;
    cap.stale_ms = 500;
    cap.fail_action = IDCELL_FAIL_HOLD;
    idcell_node_register_capability(*out, &cap);

    memset(&cap, 0, sizeof(cap));
    cap.index = 0x0200;
    snprintf(cap.label, sizeof(cap.label), "imu.temperature");
    cap.qty = IDCELL_QTY_TEMPERATURE;
    snprintf(cap.unit, sizeof(cap.unit), "Cel");
    cap.accept_count = 1;
    snprintf(cap.accept_units[0], sizeof(cap.accept_units[0]), "Cel");
    cap.dir = IDCELL_DIR_RW;
    cap.perm = IDCELL_PERM_P2;
    cap.conv_class = IDCELL_CONV_T1;
    /* v0.9：可接受值类型（§24.8）。温度点分辨率 0.01，scale 用 10^-2 */
    cap.dtype = IDCELL_DTYPE_F64;
    cap.scale_exp = 0;
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_I16, 2);
    cap.range[0] = -40.0;
    cap.range[1] = 85.0;
    cap.precision = 0.01;
    cap.min_sync_ms = 200;
    cap.stale_ms = 2000;
    cap.fail_action = IDCELL_FAIL_HOLD;
    idcell_node_register_capability(*out, &cap);

    st->accel = 0.12;
    st->temp = 27.5;
    st->tick = 1;
    idcell_node_set_value_source(*out, dev_read, st);
    idcell_node_set_setter(*out, dev_write, st);
}

/* 写结果收集 */
typedef struct {
    int    called;
    int    err;
    int    has_range;
    double lo, hi, value;
    char   reason[128];
} wres_t;

static void on_wres(void *ud, const idcell_did_t *peer, uint16_t index, uint8_t sub,
                    const idcell_write_result_t *res)
{
    wres_t *w = (wres_t *)ud;
    (void)peer; (void)index; (void)sub;
    w->called = 1;
    w->err = res->err;
    w->has_range = res->has_range;
    w->lo = res->range_lo;
    w->hi = res->range_hi;
    w->value = res->value;
    if (res->reason) snprintf(w->reason, sizeof(w->reason), "%s", res->reason);
    else w->reason[0] = '\0';
}

static void test_pipeline(void)
{
    idcell_loopback_t *lb;
    idcell_transport_t tr_a, tr_b;
    idcell_node_t *dev = NULL, *host = NULL;
    dev_state_t st;
    idcell_node_cfg_t cfg;
    idcell_requirement_t req;
    idcell_did_t did;
    idcell_contract_t ct;
    uint32_t now = 0;
    int i, bound = 0;
    uint32_t token = 0;
    wres_t wres;

    group("6. 六段管道与绑定契约");

    lb = idcell_loopback_new();
    idcell_loopback_endpoints(lb, &tr_a, &tr_b);
    make_dev(&dev, &tr_a, &st);

    /* 主机侧：需求方 */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x5555, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.proficiency = 2;
    cfg.t_hb_ms = 1000;
    cfg.lease_ttl_ms = 3000;
    cfg.announce_ms = 200;
    snprintf(cfg.vendor, sizeof(cfg.vendor), "Robotics");
    snprintf(cfg.model, sizeof(cfg.model), "ArmCtrl");

    host = idcell_node_new(&cfg);
    idcell_node_set_transport(host, &tr_b);

    memset(&req, 0, sizeof(req));
    snprintf(req.label, sizeof(req.label), "机器人要的加速度");
    req.qty = IDCELL_QTY_ACCELERATION;
    snprintf(req.unit, sizeof(req.unit), "m/s2");
    req.accept_count = 1;
    snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "m/s2");
    req.perm = IDCELL_PERM_P1;
    req.index = 0xFFFF;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_I32, 3);
    req.want_ms = 20;
    req.stale_ms = 500;
    req.kind = IDCELL_KIND_STATE;
    idcell_node_register_requirement(host, &req);

    /* 写安全：温度写点也必须显式进入 cap_list，不再依赖整设备隐式授权。 */
    memset(&req, 0, sizeof(req));
    snprintf(req.label, sizeof(req.label), "机器人要的温度");
    req.qty = IDCELL_QTY_TEMPERATURE;
    snprintf(req.unit, sizeof(req.unit), "Cel");
    req.accept_count = 1;
    snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "Cel");
    req.perm = IDCELL_PERM_P2;
    req.index = 0xFFFF;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_I16, 2);
    req.want_ms = 200;
    req.stale_ms = 2000;
    req.kind = IDCELL_KIND_STATE;
    idcell_node_register_requirement(host, &req);

    /* 跑管道 */
    for (i = 0; i < 600 && !bound; i++) {
        idcell_node_poll(dev, now);
        idcell_node_poll(host, now);
        now += 10;
        if (idcell_node_peer_count(host) > 0) {
            idcell_did_t p;
            idcell_node_peer(host, 0, &p);
            if (idcell_node_get_contract(host, &p, &ct) == IDCELL_OK) {
                did = p;
                bound = 1;
            }
        }
    }

    ok(bound, "六段管道跑通并建立绑定");
    if (!bound) {
        printf("  （管道未通，跳过后续断言）\n");
        idcell_node_free(dev); idcell_node_free(host); idcell_loopback_free(lb);
        return;
    }

    /* 契约十字段 */
    ok(ct.binding_id != 0, "契约含 binding_id");
    ok(ct.pt_count >= 1, "契约含 cap_list");
    ok(ct.arb_domain != 0, "契约含 arb_domain");
    ok(ct.lease_ttl_ms == 3000, "契约含 lease_ttl");
    ok(ct.owner_token != 0, "契约含 owner_token");
    ok(ct.desc_version > 0, "契约含 desc_version");

    /* v0.9：契约逐点条目记录协商出的值类型（§24.8、FR-087） */
    {
        idcell_contract_t cdev;
        idcell_did_t host_did = idcell_node_did(host);
        ok(ct.pt_count >= 1, "契约有逐点条目可校验类型");
        if (ct.pt_count >= 1) {
            ok(ct.pt[0].dtype == IDCELL_DTYPE_I32,
               "契约记录协商出的 i32（双方共同支持且成本更低）");
            ok_eq(ct.pt[0].scale_exp, 3, "契约记录协商出的 scale 为 10^-3");
        }
        if (idcell_node_get_contract(dev, &host_did, &cdev) == IDCELL_OK &&
            cdev.pt_count >= 1 && ct.pt_count >= 1) {
            ok(cdev.pt[0].dtype == ct.pt[0].dtype &&
               cdev.pt[0].scale_exp == ct.pt[0].scale_exp,
               "双方契约记录的值类型一致");
        }
    }

    /* 契约必须双方各持一份且内容一致（§09.7） */
    {
        idcell_contract_t cdev;
        idcell_did_t host_did = idcell_node_did(host);
        ok_eq(idcell_node_get_contract(dev, &host_did, &cdev), IDCELL_OK,
              "提供方侧同样持有契约");
        ok_eq((int)cdev.pt_count, (int)ct.pt_count, "双方契约能力点数一致");
        ok(cdev.binding_id == ct.binding_id, "双方契约 binding_id 一致");
        ok(cdev.owner_token == ct.owner_token, "双方契约 owner_token 一致");
        ok(cdev.pt[0].degrade == ct.pt[0].degrade, "双方契约逐点降级语义一致");
        ok(cdev.pt[0].degrade == IDCELL_FAIL_HOLD,
           "逐点降级语义来自提供方声明的 fail_action");
        ok(cdev.pt[0].t_pub_ms == ct.pt[0].t_pub_ms, "双方契约逐点 T_pub 一致");
    }

    /* 周期协商：T_pub = max(T_prod, T_want, T_link_min) */
    ok_eq((int)ct.pt[0].t_pub_ms, 20, "T_pub = max(T_prod=20, T_want=20) = 20ms");

    /* 阶段进入 RUNNING */
    ok(strcmp(idcell_node_peer_stage_name(host, &did), "RUNNING") == 0,
          "需求方管道阶段为 RUNNING");
    {
        /* 提供方视角下，对端是主机——必须用主机的 DID 去查，不能用设备自己的 DID */
        idcell_did_t host_did = idcell_node_did(host);
        ok(strcmp(idcell_node_peer_stage_name(dev, &host_did), "RUNNING") == 0,
              "提供方管道阶段为 RUNNING");
    }

    /* 按可读名选设备（命令行不需要 DID） */
    {
        idcell_did_t found;
        ok_eq(idcell_node_find_peer_by_label(host, "IMU-6DOF", &found), IDCELL_OK,
              "按可读名找到对端");
        ok(idcell_did_equal(&found, &did), "按名找到的就是那台设备");
        ok_eq(idcell_node_find_peer_by_label(host, "不存在的设备", &found), IDCELL_E_NODEV,
              "按名找不到时返回 E_NODEV");
    }

    /* SEC-067：令牌脱敏串不得含完整令牌，且须标注脱敏 */
    {
        char masked[24];
        char full[16];
        idcell_mask_token(ct.owner_token, masked, sizeof(masked));
        snprintf(full, sizeof(full), "%08X", (unsigned)ct.owner_token);
        ok(strstr(masked, full) == NULL, "脱敏串不含完整 owner_token");
        ok(strstr(masked, "脱敏") != NULL, "脱敏串带脱敏标注");
        /* 短前缀仍可用于人工核对 */
        {
            char prefix[8];
            snprintf(prefix, sizeof(prefix), "%04X", (unsigned)(ct.owner_token >> 16));
            ok(strstr(masked, prefix) != NULL, "脱敏串保留可核对的短前缀");
        }
    }

    /* 写：缺意图 → E_PERM（本地预检） */
    ok_eq(idcell_node_write(host, 0x0200, 0, 26.0, ct.owner_token, NULL), IDCELL_E_PERM,
          "缺意图的写被本地拒绝（E_PERM）");

    /* 写：令牌不对 → E_PERM */
    ok_eq(idcell_node_write(host, 0x0200, 0, 26.0, ct.owner_token ^ 0xFFFFu, "伪造"),
          IDCELL_E_PERM, "令牌不匹配的写被拒绝（E_PERM）");

    /* 写：正常 → 异步裁决为 OK */
    memset(&wres, 0, sizeof(wres));
    idcell_node_set_write_result_sink(host, on_wres, &wres);
    ok_eq(idcell_node_owner_token(host, &did, &token), IDCELL_OK, "可取到 owner_token");
    ok_eq(idcell_node_write(host, 0x0200, 0, 26.0, token, "温漂补偿"), IDCELL_OK,
          "合法写本地预检通过");
    for (i = 0; i < 40 && !wres.called; i++) {
        idcell_node_poll(dev, now);
        idcell_node_poll(host, now);
        now += 10;
    }
    ok(wres.called, "写结果回调被送达");
    ok_eq(wres.err, IDCELL_OK, "合法写的裁决为 OK");
    ok_eq(st.set_calls, 1, "提供方确实执行了一次写入");

    /* 写：值越界 → 异步裁决 E_RANGE，错误体带值域与实际值（FR-035） */
    memset(&wres, 0, sizeof(wres));
    ok_eq(idcell_node_write(host, 0x0200, 0, 999.0, token, "越界写入"), IDCELL_OK,
          "越界写在本地预检阶段看不出问题");
    for (i = 0; i < 40 && !wres.called; i++) {
        idcell_node_poll(dev, now);
        idcell_node_poll(host, now);
        now += 10;
    }
    ok(wres.called, "越界写的裁决被送达");
    ok_eq(wres.err, IDCELL_E_RANGE, "越界写的裁决为 E_RANGE");
    ok(wres.has_range, "E_RANGE 裁决携带值域");
    ok(nearly(wres.lo, -40.0) && nearly(wres.hi, 85.0), "值域为 [-40, 85]");
    ok(nearly(wres.value, 999.0), "错误体携带实际值 999");
    ok_eq(st.set_calls, 1, "越界的写没有触达设备（不截断、不钳位）");

    /*
     * 租约过期 → E_LEASE。
     * 注意前提：设备必须「掉线」——只把时钟拨快是没用的，
     * 设备还在发心跳，租约就会被续期，绑定一直有效。
     * 这里停止轮询设备，只让主机侧独走，等 TTL 自然到期。
     */
    now += 5000;   /* 越过 3000ms TTL */
    idcell_node_poll(host, now);   /* 只轮询主机：设备不再发心跳，不再续租 */
    ok_eq(idcell_node_write(host, 0x0200, 0, 26.0, token, "过期后写"), IDCELL_E_LEASE,
          "租约过期后的写返回 E_LEASE");

    idcell_node_free(dev);
    idcell_node_free(host);
    idcell_loopback_free(lb);
}

/* ---------------------------------------------------------------- 7. 不匹配 */

static void test_no_match(void)
{
    idcell_loopback_t *lb;
    idcell_transport_t tr_a, tr_b;
    idcell_node_t *dev = NULL, *host = NULL;
    dev_state_t st;
    idcell_node_cfg_t cfg;
    idcell_requirement_t req;
    uint32_t now = 0;
    int i;

    group("7. 不匹配路径（E_NOMATCH）");

    lb = idcell_loopback_new();
    idcell_loopback_endpoints(lb, &tr_a, &tr_b);
    make_dev(&dev, &tr_a, &st);

    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x6666, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 200;
    snprintf(cfg.model, sizeof(cfg.model), "ArmCtrl");

    host = idcell_node_new(&cfg);
    idcell_node_set_transport(host, &tr_b);

    /* 需求：温度。设备提供的是加速度与温度——温度可匹配，
       这里改成要求「压力」以制造真正的不匹配 */
    memset(&req, 0, sizeof(req));
    snprintf(req.label, sizeof(req.label), "机器人要的压力");
    req.qty = IDCELL_QTY_PRESSURE;
    snprintf(req.unit, sizeof(req.unit), "kPa");
    req.accept_count = 1;
    snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "kPa");
    req.perm = IDCELL_PERM_P1;
    req.index = 0xFFFF;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_I32, 3);
    req.want_ms = 20;
    req.stale_ms = 500;
    req.kind = IDCELL_KIND_STATE;
    idcell_node_register_requirement(host, &req);

    for (i = 0; i < 200; i++) {
        idcell_node_poll(dev, now);
        idcell_node_poll(host, now);
        now += 10;
    }

    {
        int count = idcell_node_peer_count(host);
        int bound = 0;
        idcell_did_t p;
        idcell_contract_t ct;
        if (count > 0) {
            idcell_node_peer(host, 0, &p);
            if (idcell_node_get_contract(host, &p, &ct) == IDCELL_OK) bound = 1;
        }
        ok(!bound, "量种不符的需求不会建立绑定（无 E_NOMATCH 误配）");
    }

    idcell_node_free(dev);
    idcell_node_free(host);
    idcell_loopback_free(lb);
}

/* ---------------------------------------------------------------- 7b. 量种红线 */

/*
 * FR-082 的核心场景：量纲相同但量种不同的两个量，绝不可互相换算或匹配。
 *
 * 这里刻意构造「设备提供力（N）、需求要力矩（N.m）」——两者的 SI 量纲
 * 完全一致，若实现按量纲向量判定就会误配。这正是 §24.2 那张冲突表
 * 要防的事故，也是本用例存在的唯一理由。
 */
static void test_qty_redline(void)
{
    idcell_loopback_t *lb;
    idcell_transport_t tr_a, tr_b;
    idcell_node_t *dev = NULL, *host = NULL;
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    idcell_requirement_t req;
    uint32_t now = 0;
    int i;

    group("7b. 量种红线：量纲相同但量种不同不得匹配（FR-081/FR-082）");

    lb = idcell_loopback_new();
    idcell_loopback_endpoints(lb, &tr_a, &tr_b);

    /* 提供方只提供一个「力」能力点 */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x7777, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 200;
    snprintf(cfg.vendor, sizeof(cfg.vendor), "Acme");
    snprintf(cfg.model, sizeof(cfg.model), "ForceSensor");
    dev = idcell_node_new(&cfg);
    idcell_node_set_transport(dev, &tr_a);

    memset(&cap, 0, sizeof(cap));
    cap.index = 0x0300;
    snprintf(cap.label, sizeof(cap.label), "force.sensor");
    cap.kind = IDCELL_KIND_STATE;
    cap.dir = IDCELL_DIR_R;
    cap.perm = IDCELL_PERM_P1;
    cap.qty = IDCELL_QTY_FORCE;          /* 力 */
    snprintf(cap.unit, sizeof(cap.unit), "N");
    cap.accept_count = 1;
    snprintf(cap.accept_units[0], sizeof(cap.accept_units[0]), "N");
    cap.dtype = IDCELL_DTYPE_F64;
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_F64, 0);
    cap.conv_class = IDCELL_CONV_T1;
    cap.range[0] = -1000.0;
    cap.range[1] = 1000.0;
    cap.min_sync_ms = 20;
    cap.stale_ms = 500;
    idcell_node_register_capability(dev, &cap);

    /* 需求方要的是「力矩」——量纲相同，量种不同 */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x8888, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 200;
    snprintf(cfg.model, sizeof(cfg.model), "ArmCtrl");
    host = idcell_node_new(&cfg);
    idcell_node_set_transport(host, &tr_b);

    memset(&req, 0, sizeof(req));
    snprintf(req.label, sizeof(req.label), "机器人要的力矩");
    req.qty = IDCELL_QTY_TORQUE;           /* 力矩 */
    snprintf(req.unit, sizeof(req.unit), "N.m");
    req.accept_count = 1;
    snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "N.m");
    req.perm = IDCELL_PERM_P1;
    req.index = 0xFFFF;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    req.want_ms = 20;
    req.stale_ms = 500;
    req.kind = IDCELL_KIND_STATE;
    idcell_node_register_requirement(host, &req);

    for (i = 0; i < 200; i++) {
        idcell_node_poll(dev, now);
        idcell_node_poll(host, now);
        now += 10;
    }

    {
        int count = idcell_node_peer_count(host);
        int bound = 0;
        idcell_did_t p;
        idcell_contract_t ct;
        if (count > 0) {
            idcell_node_peer(host, 0, &p);
            if (idcell_node_get_contract(host, &p, &ct) == IDCELL_OK) bound = 1;
        }
        ok(!bound, "力与力矩（量纲相同、量种不同）不建立绑定");
    }

    /* 换算路径同样必须拒绝 */
    {
        double out = 0;
        idcell_conv_t cls = IDCELL_CONV_T0;
        ok_eq(idcell_qty_convert(IDCELL_QTY_FORCE, "N", IDCELL_QTY_TORQUE, "N.m",
                                 100.0, &out, &cls),
             IDCELL_E_UNIT, "力 → 力矩换算被拒（E_UNIT）");
    }

    idcell_node_free(dev);
    idcell_node_free(host);
    idcell_loopback_free(lb);
}

/* ---------------------------------------------------------------- 8. 周期红线 */

static void test_period_redline(void)
{
    idcell_loopback_t *lb;
    idcell_transport_t tr_a, tr_b;
    idcell_node_t *dev = NULL, *host = NULL;
    dev_state_t st;
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    idcell_requirement_t req;
    uint32_t now = 0;
    int i, bound = 0;

    group("8. 周期红线：T_pub > T_stale 必须绑定失败");

    lb = idcell_loopback_new();
    idcell_loopback_endpoints(lb, &tr_a, &tr_b);

    /* 造一个 T_prod 远大于需求方保鲜上限的提供方 */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x7777, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.t_hb_ms = 1000;
    cfg.lease_ttl_ms = 3000;
    cfg.announce_ms = 200;
    snprintf(cfg.model, sizeof(cfg.model), "SLOW-DEV");

    dev = idcell_node_new(&cfg);
    idcell_node_set_transport(dev, &tr_a);

    memset(&cap, 0, sizeof(cap));
    cap.index = 0x0100;
    snprintf(cap.label, sizeof(cap.label), "slow.accel");
    cap.qty = IDCELL_QTY_ACCELERATION;
    snprintf(cap.unit, sizeof(cap.unit), "m/s2");
    cap.accept_count = 1;
    snprintf(cap.accept_units[0], sizeof(cap.accept_units[0]), "m/s2");
    cap.dir = IDCELL_DIR_R;
    cap.perm = IDCELL_PERM_P1;
    cap.range[0] = -160.0; cap.range[1] = 160.0;
    cap.min_sync_ms = 1000;    /* T_prod = 1000ms */
    cap.stale_ms = 5000;
    idcell_node_register_capability(dev, &cap);

    memset(&st, 0, sizeof(st));
    idcell_node_set_value_source(dev, dev_read, &st);

    /* 需求方：保鲜上限只有 100ms */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x8888, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 200;
    snprintf(cfg.model, sizeof(cfg.model), "ArmCtrl");

    host = idcell_node_new(&cfg);
    idcell_node_set_transport(host, &tr_b);

    memset(&req, 0, sizeof(req));
    snprintf(req.label, sizeof(req.label), "要的加速度");
    req.qty = IDCELL_QTY_ACCELERATION;
    snprintf(req.unit, sizeof(req.unit), "m/s2");
    req.accept_count = 1;
    snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "m/s2");
    req.perm = IDCELL_PERM_P1;
    req.index = 0xFFFF;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    req.want_ms = 20;
    req.stale_ms = 100;        /* T_stale = 100ms，远小于 T_prod */
    req.kind = IDCELL_KIND_STATE;
    idcell_node_register_requirement(host, &req);

    for (i = 0; i < 300 && !bound; i++) {
        idcell_node_poll(dev, now);
        idcell_node_poll(host, now);
        now += 10;
        if (idcell_node_peer_count(host) > 0) {
            idcell_did_t p;
            idcell_contract_t ct;
            idcell_node_peer(host, 0, &p);
            if (idcell_node_get_contract(host, &p, &ct) == IDCELL_OK) bound = 1;
        }
    }

    ok(!bound, "T_prod(1000ms) 超过 T_stale(100ms) 时绑定失败，不做降级妥协");

    idcell_node_free(dev);
    idcell_node_free(host);
    idcell_loopback_free(lb);
}

/* ---------------------------------------------------------------- main */

int main(void)
{
    /* 不缓冲输出：崩溃时也能看到跑到哪一步 */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("========================================================================\n");
    printf(" ID-CELL 参考实现一致性自测\n");
    printf("========================================================================\n");

    test_crc();
    test_did();
    test_units();
    test_qty();
    test_type_negotiate();
    test_codec();
    test_auth_codec();
    test_stream_reassembly();
    test_registration();
    test_pipeline();
    test_no_match();
    test_qty_redline();
    test_period_redline();

    printf("\n========================================================================\n");
    printf(" 通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    printf("========================================================================\n");
    return g_fail == 0 ? 0 : 1;
}
