/*
 * ID-CELL · 量种表与 UCUM 单位子集（§24）
 * ============================================================================
 *
 * 这一层解决的是「量」有名字无编码的问题。此前描述符里的 dim 与 unit
 * 都是自由字符串，能被人读懂但不能被机器判定——而 MATCH 与 NEGOTIATE
 * 的全部判定都必须由机器完成。
 *
 * 三条不可协商的约定：
 *
 *   1. 量种与单位必须分开（FR-079 / FR-081）。
 *      量种答「这是什么量」，单位答「用什么单位表达」。
 *      只统一单位码是不够的：N 与 N.m 都是合法 UCUM 码，但一个是力、
 *      一个是力矩。
 *
 *   2. T0 按量种 ID 相等性判定，MUST NOT 按量纲向量（FR-082）。
 *      力的量纲与力矩的量纲在 SI 中完全一致；无量纲比值、平面角、
 *      数据量三者的量纲同样完全一致。若按向量判等，N 会被当作 N.m
 *      自动换算，而且这个缺陷在自测里也会「通过」——因为自测若也用
 *      向量比对的话。量纲向量在本文件里的唯一用途是表的校验冗余。
 *
 *   3. 表随规范发布，不查外部注册表（FR-080）。
 *      这是 X1「接入链路零中心依赖」在语义层的直接要求。设备接入时
 *      不需要访问任何外部服务。
 *
 * 存储（§24.7）：24 量种 + 59 单位，池偏移紧凑表约 1 567 B，
 * 占 NFR-024 的 48 KB MCU 预算的 3.2 %。
 */
#include "idcell_internal.h"

/* ---------------------------------------------------------------- 量种表 */

/*
 * 量纲幂次向量的顺序固定为 M L T I Θ N J（质量、长度、时间、电流、
 * 热力学温度、物质的量、发光强度）。
 */
typedef struct {
    const char *name;         /* 量种名（人类可读）；NULL = 本地未实现 */
    const char *canonical;    /* 规范单位（UCUM 码） */
    int8_t      dim[7];       /* 量纲幂次向量 */
    const char *kind_of_qty;  /* UCUM 的 Kind of Quantity 对应词 */
} idcell_qty_row_t;

/*
 * v0.9：编译期裁剪（§24.9、FR-089）
 *
 * 定义 IDCELL_QTY_TABLE_MINIMAL 时只编入下面这份精简量种表。
 *
 * 两条硬约束：
 *   1. 裁剪 MUST NOT 重排量种 ID——本地保留的 ID 仍 MUST 是规范赋予它的
 *      那个 ID，否则跨实现互认即失效。因此这里用「显式 ID 列表」，
 *      而不是「取前 N 项」。
 *   2. 裁剪后遇到对方发来本地未实现的量种 ID，MUST 返回 E_NODEV
 *      （见 idcell_qty_name_by_id），MUST NOT 静默忽略，也 MUST NOT
 *      当作「不匹配」——「我不认识这个量」与「这个量不是我要的」对
 *      使用者是不同的问题。
 */
#ifdef IDCELL_QTY_TABLE_MINIMAL
static const idcell_qty_row_t qty_table[IDCELL_QTY_COUNT] = {
    /*
     * 严格按规范 ID 顺序排列（FR-089：裁剪 MUST NOT 重排 ID）。
     * 未编入的量种整项为 NULL，ID 位置保持空位——因此本地表里
     * force 仍在 ID 9、torque 仍在 ID 10，与全量表完全一致。
     */
    /*  0 */ { "ratio",       "1",     { 0, 0, 0, 0, 0, 0, 0 }, "dimensionless" },
    /*  1 */ { "length",      "m",     { 0, 1, 0, 0, 0, 0, 0 }, "length" },
    /*  2 */ { "angle",       "rad",   { 0, 0, 0, 0, 0, 0, 0 }, "plane angle" },
    /*  3 */ { "mass",        "g",     { 1, 0, 0, 0, 0, 0, 0 }, "mass" },
    /*  4 */ { "time",        "s",     { 0, 0, 1, 0, 0, 0, 0 }, "time" },
    /*  5 */ { "temperature", "K",     { 0, 0, 0, 0, 1, 0, 0 }, "temperature" },
    /*  6 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* current    */
    /*  7 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* charge     */
    /*  8 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* luminosity */
    /*  9 */ { "force",       "N",     { 1, 1,-2, 0, 0, 0, 0 }, "force" },
    /* 10 */ { "torque",      "N.m",   { 1, 1,-2, 0, 0, 0, 0 }, "torque" },
    /* 11 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* pressure   */
    /* 12 */ { "velocity",    "m/s",   { 0, 1,-1, 0, 0, 0, 0 }, "velocity" },
    /* 13 */ { "acceleration","m/s2",  { 0, 1,-2, 0, 0, 0, 0 }, "acceleration" },
    /* 14 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* energy     */
    /* 15 */ { "power",       "W",     { 1, 2,-3, 0, 0, 0, 0 }, "power" },
    /* 16 */ { "voltage",     "V",     { 2, 1,-3,-1, 0, 0, 0 }, "electric potential" },
    /* 17 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* resistance */
    /* 18 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* capacitance */
    /* 19 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* inductance */
    /* 20 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* frequency  */
    /* 21 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* magflux    */
    /* 22 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* magdens    */
    /* 23 */ { NULL, NULL, { 0, 0, 0, 0, 0, 0, 0 }, NULL },   /* datacount  */
};
#else
static const idcell_qty_row_t qty_table[IDCELL_QTY_COUNT] = {
    /* name         canonical  M  L  T  I  Th  N  J   kind of quantity */
    { "ratio",       "1",     { 0, 0, 0, 0, 0, 0, 0 }, "dimensionless" },
    { "length",      "m",     { 0, 1, 0, 0, 0, 0, 0 }, "length" },
    { "angle",       "rad",   { 0, 0, 0, 0, 0, 0, 0 }, "plane angle" },
    { "mass",        "g",     { 1, 0, 0, 0, 0, 0, 0 }, "mass" },
    { "time",        "s",     { 0, 0, 1, 0, 0, 0, 0 }, "time" },
    { "temperature", "K",     { 0, 0, 0, 0, 1, 0, 0 }, "temperature" },
    { "current",     "A",     { 0, 0, 0, 1, 0, 0, 0 }, "electric current" },
    { "charge",      "C",     { 0, 0, 1, 1, 0, 0, 0 }, "electric charge" },
    { "luminosity",  "cd",    { 0, 0, 0, 0, 0, 0, 1 }, "luminous intensity" },
    { "force",       "N",     { 1, 1,-2, 0, 0, 0, 0 }, "force" },
    { "torque",      "N.m",   { 1, 1,-2, 0, 0, 0, 0 }, "torque" },
    { "pressure",    "Pa",    {-1, 1,-2, 0, 0, 0, 0 }, "pressure" },
    { "velocity",    "m/s",   { 0, 1,-1, 0, 0, 0, 0 }, "velocity" },
    { "acceleration","m/s2",  { 0, 1,-2, 0, 0, 0, 0 }, "acceleration" },
    { "energy",      "J",     { 1, 2,-2, 0, 0, 0, 0 }, "energy" },
    { "power",       "W",     { 1, 2,-3, 0, 0, 0, 0 }, "power" },
    { "voltage",     "V",     { 2, 1,-3,-1, 0, 0, 0 }, "electric potential" },
    { "resistance",  "Ohm",   { 2, 1,-3,-2, 0, 0, 0 }, "electric resistance" },
    { "capacitance", "F",     {-2,-1, 4, 2, 0, 0, 0 }, "electric capacitance" },
    { "inductance",  "H",     { 1, 2,-2,-2, 0, 0, 0 }, "inductance" },
    { "frequency",   "Hz",    { 0, 0,-1, 0, 0, 0, 0 }, "frequency" },
    { "magflux",     "Wb",    { 2, 1,-2,-1, 0, 0, 0 }, "magnetic flux" },
    { "magdens",     "T",     { 0, 1,-2,-1, 0, 0, 0 }, "magnetic flux density" },
    { "datacount",   "bit",   { 0, 0, 0, 0, 0, 0, 0 }, "count / information" },
};
#endif /* IDCELL_QTY_TABLE_MINIMAL */

/* ---------------------------------------------------------------- 单位表 */

/*
 * 单位表项：
 *   factor / offset 给出到该量种规范单位的换算：规范值 = v * factor + offset
 *   needs_ctx  T3：缺参考条件（如绝压需大气压参考）
 *   lossy      T4：有损不可逆
 *   private_ok 0：私有单位不参与自动换算
 */
typedef struct {
    const char *code;         /* UCUM 规范码 */
    uint8_t     qty;          /* 量种 ID */
    double      factor;
    double      offset;
    uint8_t     needs_ctx;
    uint8_t     lossy;
} idcell_unit_row2_t;

static const idcell_unit_row2_t unit_table[] = {
    /* --- 长度 --- */
    { "m",      IDCELL_QTY_LENGTH,      1.0,                   0.0, 0, 0 },
    { "cm",     IDCELL_QTY_LENGTH,      0.01,                  0.0, 0, 0 },
    { "mm",     IDCELL_QTY_LENGTH,      0.001,                 0.0, 0, 0 },
    { "km",     IDCELL_QTY_LENGTH,      1000.0,                0.0, 0, 0 },
    { "um",     IDCELL_QTY_LENGTH,      1e-6,                  0.0, 0, 0 },
    /* --- 质量（g 是克，不是重力加速度） --- */
    { "kg",     IDCELL_QTY_MASS,        1.0,                   0.0, 0, 0 },
    { "g",      IDCELL_QTY_MASS,        0.001,                 0.0, 0, 0 },
    { "mg",     IDCELL_QTY_MASS,        1e-6,                  0.0, 0, 0 },
    /* --- 时间 --- */
    { "s",      IDCELL_QTY_TIME,        1.0,                   0.0, 0, 0 },
    { "ms",     IDCELL_QTY_TIME,        0.001,                 0.0, 0, 0 },
    { "us",     IDCELL_QTY_TIME,        1e-6,                  0.0, 0, 0 },
    { "min",    IDCELL_QTY_TIME,        60.0,                  0.0, 0, 0 },
    /* --- 角度 --- */
    { "rad",    IDCELL_QTY_ANGLE,       1.0,                   0.0, 0, 0 },
    { "deg",    IDCELL_QTY_ANGLE,       0.017453292519943295,  0.0, 0, 0 },
    { "mrad",   IDCELL_QTY_ANGLE,       0.001,                 0.0, 0, 0 },
    /* --- 温度（Cel 与 [degF] 带偏移 => T2） --- */
    { "K",      IDCELL_QTY_TEMPERATURE, 1.0,                   0.0, 0, 0 },
    { "Cel",    IDCELL_QTY_TEMPERATURE, 1.0,                 273.15, 0, 0 },
    { "[degF]", IDCELL_QTY_TEMPERATURE, 0.5555555555555556,  255.3722222222222, 0, 0 },
    /* --- 力 --- */
    { "N",      IDCELL_QTY_FORCE,       1.0,                   0.0, 0, 0 },
    { "kN",     IDCELL_QTY_FORCE,       1000.0,                0.0, 0, 0 },
    { "mN",     IDCELL_QTY_FORCE,       0.001,                 0.0, 0, 0 },
    /* --- 力矩（与力量纲相同，靠量种区分） --- */
    { "N.m",    IDCELL_QTY_TORQUE,      1.0,                   0.0, 0, 0 },
    { "mN.m",   IDCELL_QTY_TORQUE,      0.001,                 0.0, 0, 0 },
    /* --- 压力 --- */
    { "Pa",     IDCELL_QTY_PRESSURE,    1.0,                   0.0, 0, 0 },
    { "kPa",    IDCELL_QTY_PRESSURE,    1000.0,                0.0, 0, 0 },
    { "MPa",    IDCELL_QTY_PRESSURE,    1e6,                   0.0, 0, 0 },
    { "bar",    IDCELL_QTY_PRESSURE,    100000.0,              0.0, 0, 0 },
    /* --- 速度 --- */
    { "m/s",    IDCELL_QTY_VELOCITY,    1.0,                   0.0, 0, 0 },
    { "mm/s",   IDCELL_QTY_VELOCITY,    0.001,                 0.0, 0, 0 },
    { "km/h",   IDCELL_QTY_VELOCITY,    0.2777777777777778,    0.0, 0, 0 },
    /* --- 加速度（[g] = 标准重力加速度） --- */
    { "m/s2",   IDCELL_QTY_ACCELERATION,1.0,                   0.0, 0, 0 },
    { "mm/s2",  IDCELL_QTY_ACCELERATION,0.001,                 0.0, 0, 0 },
    { "[g]",    IDCELL_QTY_ACCELERATION,9.80665,               0.0, 0, 0 },
    /* --- 能量 / 功率 --- */
    { "J",      IDCELL_QTY_ENERGY,      1.0,                   0.0, 0, 0 },
    { "kJ",     IDCELL_QTY_ENERGY,      1000.0,                0.0, 0, 0 },
    { "Wh",     IDCELL_QTY_ENERGY,      3600.0,                0.0, 0, 0 },
    { "W",      IDCELL_QTY_POWER,       1.0,                   0.0, 0, 0 },
    { "kW",     IDCELL_QTY_POWER,       1000.0,                0.0, 0, 0 },
    /* --- 电学 --- */
    { "V",      IDCELL_QTY_VOLTAGE,     1.0,                   0.0, 0, 0 },
    { "mV",     IDCELL_QTY_VOLTAGE,     0.001,                 0.0, 0, 0 },
    { "kV",     IDCELL_QTY_VOLTAGE,     1000.0,                0.0, 0, 0 },
    { "A",      IDCELL_QTY_CURRENT,     1.0,                   0.0, 0, 0 },
    { "mA",     IDCELL_QTY_CURRENT,     0.001,                 0.0, 0, 0 },
    { "C",      IDCELL_QTY_CHARGE,      1.0,                   0.0, 0, 0 },
    { "mC",     IDCELL_QTY_CHARGE,      0.001,                 0.0, 0, 0 },
    { "Ohm",    IDCELL_QTY_RESISTANCE,  1.0,                   0.0, 0, 0 },
    { "kOhm",   IDCELL_QTY_RESISTANCE,  1000.0,                0.0, 0, 0 },
    { "F",      IDCELL_QTY_CAPACITANCE, 1.0,                   0.0, 0, 0 },
    { "uF",     IDCELL_QTY_CAPACITANCE, 1e-6,                  0.0, 0, 0 },
    { "H",      IDCELL_QTY_INDUCTANCE,  1.0,                   0.0, 0, 0 },
    { "mH",     IDCELL_QTY_INDUCTANCE,  0.001,                 0.0, 0, 0 },
    { "cd",     IDCELL_QTY_LUMINOSITY,  1.0,                   0.0, 0, 0 },
    { "mcd",    IDCELL_QTY_LUMINOSITY,  0.001,                 0.0, 0, 0 },
    /* --- 频率 / 磁 --- */
    { "Hz",     IDCELL_QTY_FREQUENCY,   1.0,                   0.0, 0, 0 },
    { "kHz",    IDCELL_QTY_FREQUENCY,   1000.0,                0.0, 0, 0 },
    { "T",      IDCELL_QTY_MAGDENS,     1.0,                   0.0, 0, 0 },
    { "mT",     IDCELL_QTY_MAGDENS,     0.001,                 0.0, 0, 0 },
    { "Wb",     IDCELL_QTY_MAGFLUX,     1.0,                   0.0, 0, 0 },
    /* --- 无量纲 / 数据量 --- */
    { "1",      IDCELL_QTY_RATIO,       1.0,                   0.0, 0, 0 },
    { "%",      IDCELL_QTY_RATIO,       0.01,                  0.0, 0, 0 },
    { "[ppm]",  IDCELL_QTY_RATIO,       1e-6,                  0.0, 0, 0 },
    { "bit",    IDCELL_QTY_DATACOUNT,   1.0,                   0.0, 0, 0 },
    { "B",      IDCELL_QTY_DATACOUNT,   8.0,                   0.0, 0, 0 },
};

#define UNIT_TABLE_N (sizeof(unit_table) / sizeof(unit_table[0]))

/* ---------------------------------------------------------------- 查询 */

const char *idcell_qty_name(idcell_qty_t qty)
{
    if ((unsigned)qty >= IDCELL_QTY_COUNT) return NULL;
    /* 裁剪档下未实现的量种：name 为 NULL（FR-089） */
    return qty_table[qty].name;
}

/*
 * 按 ID 取量种名，区分「越界」与「本地未实现」两种失败。
 * 未实现时返回 IDCELL_E_NODEV 且 name 置 NULL（FR-089）。
 */
int idcell_qty_name_by_id(uint8_t id, const char **name)
{
    if (!name) return IDCELL_E_NODEV;
    *name = NULL;
    if (id >= IDCELL_QTY_COUNT) return IDCELL_E_NODEV;
    if (!qty_table[id].name) return IDCELL_E_NODEV;  /* 本地未实现 */
    *name = qty_table[id].name;
    return IDCELL_OK;
}

/* 该量种在本地是否已实现（裁剪档下可能未编入） */
int idcell_qty_implemented(idcell_qty_t qty)
{
    if ((unsigned)qty >= IDCELL_QTY_COUNT) return 0;
    return qty_table[qty].name != NULL;
}

static int ci_equal(const char *a, const char *b)
{
    size_t i;
    if (!a || !b) return 0;
    for (i = 0; a[i] && b[i]; i++) {
        int ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = ca - 'A' + 'a';
        if (cb >= 'A' && cb <= 'Z') cb = cb - 'A' + 'a';
        if (ca != cb) return 0;
    }
    return a[i] == '\0' && b[i] == '\0';
}

int idcell_qty_by_name(const char *name, idcell_qty_t *out)
{
    int i;
    if (!name || !*name || !out) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_QTY_COUNT; i++) {
        if (!qty_table[i].name) continue;   /* 本地未实现 */
        if (ci_equal(qty_table[i].name, name)) {
            *out = (idcell_qty_t)i;
            return IDCELL_OK;
        }
    }
    return IDCELL_E_NODEV;
}

const char *idcell_qty_canonical_unit(idcell_qty_t qty)
{
    if ((unsigned)qty >= IDCELL_QTY_COUNT) return NULL;
    return qty_table[qty].canonical;
}

int idcell_qty_dimension(idcell_qty_t qty, int8_t out[7])
{
    int i;
    if ((unsigned)qty >= IDCELL_QTY_COUNT || !out) return IDCELL_E_NODEV;
    if (!qty_table[qty].name) return IDCELL_E_NODEV;  /* 本地未实现 */
    for (i = 0; i < 7; i++) out[i] = qty_table[qty].dim[i];
    return IDCELL_OK;
}

static const idcell_unit_row2_t *find_unit(const char *code)
{
    size_t i;
    if (!code || !*code) return NULL;
    for (i = 0; i < UNIT_TABLE_N; i++)
        if (strcmp(unit_table[i].code, code) == 0) return &unit_table[i];
    return NULL;
}

int idcell_unit_qty(const char *unit, idcell_qty_t *out)
{
    const idcell_unit_row2_t *u;
    if (!out) return IDCELL_E_NODEV;
    u = find_unit(unit);
    if (!u) return IDCELL_E_UNIT;   /* 私有单位不在表内，不参与量种匹配 */
    /* 裁剪档下：该单位所属量种本地未实现 -> E_NODEV（FR-089） */
    if (!qty_table[u->qty].name) return IDCELL_E_NODEV;
    *out = (idcell_qty_t)u->qty;
    return IDCELL_OK;
}

int idcell_unit_known(const char *unit)
{
    return find_unit(unit) != NULL;
}

/* ---------------------------------------------------------------- 表校验 */

int idcell_qty_table_check(void)
{
    size_t i;
    /*
     * 校验冗余：每项的规范单位必须能在单位表里找到，且该单位的量种
     * 必须等于本项声明的量种。用量纲向量做这项交叉检查——
     * 这正是量纲向量在本协议里的唯一用途。
     *
     * 裁剪档（IDCELL_QTY_TABLE_MINIMAL）下：
     *   - 本地未实现的量种（name 为 NULL）跳过——它们根本不在本地表里，
     *     校验它们没有意义（FR-089）；
     *   - 单位表里量种本地未实现的项也跳过——它们的量种无法解析，
     *     但这不是错误，只是「本地不认识这个量的单位」。
     */
    for (i = 0; i < UNIT_TABLE_N; i++) {
        const idcell_unit_row2_t *u = &unit_table[i];
        idcell_qty_t q;
        if (u->qty >= IDCELL_QTY_COUNT) return IDCELL_E_CRC;
        if (!qty_table[u->qty].name) continue;   /* 本地未实现该量种 */
        if (idcell_unit_qty(u->code, &q) != IDCELL_OK) return IDCELL_E_CRC;
        if (q != (idcell_qty_t)u->qty) return IDCELL_E_CRC;
    }
    /* 量种表：已实现的项，其规范单位必须存在且量种一致 */
    for (i = 0; i < IDCELL_QTY_COUNT; i++) {
        idcell_qty_t q;
        if (!qty_table[i].name) continue;         /* 本地未实现 */
        if (idcell_unit_qty(qty_table[i].canonical, &q) != IDCELL_OK)
            return IDCELL_E_CRC;
        if (q != (idcell_qty_t)i) return IDCELL_E_CRC;
    }
    return IDCELL_OK;
}

/* ---------------------------------------------------------------- 换算 */

/*
 * 量种优先的换算（§24.6）。
 *
 * 判定顺序（每一步都不可跳过）：
 *   1. 量种 ID 不同        -> E_UNIT（T0）
 *   2. 单位不在核心子集内  -> E_UNIT（未知单位不得静默透传）
 *   3. 缺参考条件          -> E_CTX（T3）
 *   4. 有损不可逆          -> E_CONV（T4）
 *   5. 其余                -> 按 factor/offset 换算，偏移非零则 T2
 *
 * 第 1 步是全文件的关键：量种不同就到此为止，绝不进入换算讨论。
 */
int idcell_qty_convert(idcell_qty_t from_qty, const char *from,
                       idcell_qty_t to_qty, const char *to,
                       double in, double *out, idcell_conv_t *cls_out)
{
    const idcell_unit_row2_t *f, *t;

    if (cls_out) *cls_out = IDCELL_CONV_T1;
    if (!from || !to) return IDCELL_E_UNIT;

    /* 1. 量种优先：不同即 T0，不进入单位换算讨论 */
    if (from_qty != to_qty) return IDCELL_E_UNIT;

    /* 同量种同单位：恒等，不查表（私有单位也走这条路） */
    if (strcmp(from, to) == 0) {
        if (out) *out = in;
        return IDCELL_OK;
    }

    /* 2. 未知单位：私有码不参与自动换算（SEC-068） */
    f = find_unit(from);
    t = find_unit(to);
    if (!f || !t) return IDCELL_E_UNIT;

    /* 交叉校验：单位表内的量种必须与调用方传入的一致 */
    if (f->qty != (uint8_t)from_qty || t->qty != (uint8_t)to_qty)
        return IDCELL_E_UNIT;

    /* 3. T3：缺参考条件 */
    if (f->needs_ctx || t->needs_ctx) return IDCELL_E_CTX;

    /* 4. T4：有损不可逆 */
    if (f->lossy || t->lossy) return IDCELL_E_CONV;

    /* 5. 换算 */
    {
        double base = in * f->factor + f->offset;
        double res = (base - t->offset) / t->factor;
        if (out) *out = res;
        if (cls_out) {
            *cls_out = (f->offset != 0.0 || t->offset != 0.0)
                     ? IDCELL_CONV_T2 : IDCELL_CONV_T1;
        }
    }
    return IDCELL_OK;
}