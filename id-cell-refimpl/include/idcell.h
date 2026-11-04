/*
 * ID-CELL 参考实现（纯 C99，零外部依赖）
 *
 * 本头文件是 ID-CELL 协议规范 §09 / §08.1 的可执行形态：规范里的每一条
 * MUST，在这里都能找到对应的一个字段或一个函数。实现者不需要读规范全文
 * 就能把设备接上协议。
 *
 * 三条不可协商的契约（违反即为不合规）：
 *   1. 能力注册 MUST NOT 依赖设备类型注册（§19.3 X1：接入链路零中心依赖）
 *   2. 能力描述符是能力的唯一权威（§19.3 X2）
 *   3. 写操作 MUST 携带 owner_token 与意图结构，且理解度不得兑换写权限
 *      （SEC-019 / SEC-014）
 *
 * 设备侧唯一执行入口：idcell_node_poll(node, now_ms)。
 */
#ifndef IDCELL_H
#define IDCELL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- 版本 */

#define IDCELL_VERSION_MAJOR 0
#define IDCELL_VERSION_MINOR 11

/* 帧头 VER 字段编码：主版本 << 4 | 次版本 */
#define IDCELL_PROTO_VER_BYTE 0x0B

/* ---------------------------------------------------------------- 常量 */

/* v0.11 固定头：SYNC(2) VER(1) PROF(1) FLAGS(1) TYPE(1) SEQ(2) TXN(2)
 * LEN(2) SRC(8) DST(8) GROUP(2) TS(6) = 36 字节，无保留字节。 */
#define IDCELL_HDR_LEN          36
/* 可选鉴权标签：HMAC-SHA256 截断 16 字节，不计入 LEN。 */
#define IDCELL_AUTH_TAG_LEN     16
/* 帧尾：CRC16(2) + TRAILER(2)，均不计入 LEN。 */
#define IDCELL_TRAILER_LEN      4
/* TLV 头：IDX(2) SUB(1) TYPE(1) LEN(2) */
#define IDCELL_TLV_HDR_LEN      6
#define IDCELL_MAX_FRAME        1500
#define IDCELL_MAX_PAYLOAD      (IDCELL_MAX_FRAME - IDCELL_HDR_LEN - IDCELL_TRAILER_LEN)
#define IDCELL_MAX_AUTH_PAYLOAD (IDCELL_MAX_PAYLOAD - IDCELL_AUTH_TAG_LEN)
/* 容量上限。全部可用 -D 覆盖，以适配 MCU 档（NFR-020 RAM ≤ 16 KB）。 */
#ifndef IDCELL_MAX_CAPS
#define IDCELL_MAX_CAPS         32
#endif
#ifndef IDCELL_MAX_REQS
#define IDCELL_MAX_REQS         16
#endif
#ifndef IDCELL_MAX_ACCEPT
#define IDCELL_MAX_ACCEPT       6
#endif
#ifndef IDCELL_MAX_DEPS
#define IDCELL_MAX_DEPS         8
#endif
#ifndef IDCELL_MAX_CONTRACT_PTS
#define IDCELL_MAX_CONTRACT_PTS 16
#endif
#ifndef IDCELL_MAX_SCHEMAS
#define IDCELL_MAX_SCHEMAS       32
#endif
#ifndef IDCELL_MAX_SCHEMA_FIELDS
#define IDCELL_MAX_SCHEMA_FIELDS 4
#endif
#ifndef IDCELL_MAX_SCHEMA_SET
#define IDCELL_MAX_SCHEMA_SET    4
#endif
#ifndef IDCELL_COMMAND_CACHE
#define IDCELL_COMMAND_CACHE     32
#endif
#ifndef IDCELL_MAX_GRANTS
#define IDCELL_MAX_GRANTS        8
#endif
#define IDCELL_MAX_VALID_FOR_MS  60000u
#define IDCELL_MAX_LEASE_TTL_MS  60000u
#ifndef IDCELL_MAX_PEERS
#define IDCELL_MAX_PEERS        4
#endif
#ifndef IDCELL_MAX_LABEL
#define IDCELL_MAX_LABEL        48
#endif
#ifndef IDCELL_MAX_UNIT
#define IDCELL_MAX_UNIT         16
#endif
#ifndef IDCELL_MAX_DIM
#define IDCELL_MAX_DIM          16
#endif
#ifndef IDCELL_CRED_LEN
#define IDCELL_CRED_LEN         32
#endif

/* ---------------------------------------------------------------- 错误码 */

typedef enum {
    IDCELL_OK = 0,
    IDCELL_E_NODEV,       /* 能力不存在 */
    IDCELL_E_VER,         /* 版本不支持 */
    IDCELL_E_CRC,         /* 校验失败 */
    IDCELL_E_NOMATCH,     /* 无匹配候选（不匹配类） */
    IDCELL_E_CONV,        /* 不可转换 */
    IDCELL_E_NEGOTIATE,   /* 协商失败（不匹配类） */
    IDCELL_E_PERM,        /* 权限不足 */
    IDCELL_E_UNSAFE,      /* 被安全策略拒绝 */
    IDCELL_E_LEASE,       /* 租约冲突或过期（不匹配类） */
    IDCELL_E_RANGE,       /* 值越界 */
    IDCELL_E_UNIT,        /* 量纲不符 */
    IDCELL_E_CTX,         /* 缺上下文参数 */
    IDCELL_E_IDCONFLICT,  /* 身份冲突 */
    IDCELL_E_SCOPE,       /* 发现 scope 不匹配 */
    IDCELL_E_UNAVAILABLE, /* 描述符暂不可用，可重试 */
    IDCELL_E_DUPLICATE,   /* 重复发现请求 */
    IDCELL_E_ASLEEP,      /* 节点休眠，须先发生对应唤醒事件 */
    IDCELL_E_RX_OFF,      /* 接收机关闭，协议帧不得隐式唤醒 */
    IDCELL_E_STATE        /* 当前状态不允许该事件 */
} idcell_err_t;

/* 错误码名（"E_PERM" 形式），未知码返回 "E_UNKNOWN" */
const char *idcell_err_name(idcell_err_t e);
/* 拒绝类返回 0（重试无意义），不匹配类返回 1（带候选值重试可能成功） */
int idcell_err_retryable(idcell_err_t e);

/* ---------------------------------------------------------------- 身份 */

/* DID：8 字节，独立生成，MUST NOT 由链路层标识派生（FR-072 / SEC-064） */
typedef struct { uint8_t b[8]; } idcell_did_t;

void idcell_did_generate(uint64_t seed, idcell_did_t *out);
/* 厂商前缀式 DID：厂商前缀(2) + 序列号(6)，前缀由注册表分配 */
void idcell_did_from_vendor(uint16_t vendor_prefix, uint64_t serial, idcell_did_t *out);
int  idcell_did_equal(const idcell_did_t *a, const idcell_did_t *b);
/* 文本形式：16 位大写十六进制 + 中间一个连字符，如 "01234567-89ABCDEF"（17 字符 + '\0'） */
void idcell_did_str(const idcell_did_t *d, char out[19]);

/* ---------------------------------------------------------------- 链路画像 */

typedef enum {
    IDCELL_MEDIA_UNKNOWN = 0,
    IDCELL_MEDIA_UART,
    IDCELL_MEDIA_CAN,
    IDCELL_MEDIA_BLE,
    IDCELL_MEDIA_WIFI,
    IDCELL_MEDIA_ZIGBEE,
    IDCELL_MEDIA_LORA,
    IDCELL_MEDIA_SUB1G,
    IDCELL_MEDIA_USB,
    IDCELL_MEDIA_ETHERNET,
    IDCELL_MEDIA_LOOPBACK
} idcell_media_t;

typedef enum {
    IDCELL_TOPO_P2P = 0,          /* 点对点 */
    IDCELL_TOPO_MULTI_DROP,       /* 一主多从轮询 */
    IDCELL_TOPO_MULTI_MASTER,     /* 多主共享总线 */
    IDCELL_TOPO_STAR_HOST_PROXY,  /* 单主机星形（可能含主机代发） */
    IDCELL_TOPO_SWITCHED,         /* 交换式广播域 */
    IDCELL_TOPO_MESH              /* mesh 多跳 */
} idcell_topology_t;

/*
 * 链路画像：绑定层对真实链路的映射（§10 链路假设表 + SEC-063）。
 * t_link_min_ms 是本机实测值，不是 §10 表里的参考值——它参与
 * T_pub = max(T_prod, T_want, T_link_min) 的第三项。
 */
typedef struct {
    idcell_media_t   media;
    idcell_topology_t topology;
    uint32_t         t_link_min_ms;
    uint16_t         mtu;         /* 0 = 该介质无 MTU 概念 */
    uint8_t          host_proxy;  /* 1 = 处于主机代发模式（SEC-063） */
} idcell_link_profile_t;

const char *idcell_media_name(idcell_media_t m);
const char *idcell_topology_name(idcell_topology_t t);

/* ---------------------------------------------------------------- 传输适配 */

typedef struct idcell_transport {
    /* 发送一帧的字节流；返回 0 成功，<0 失败 */
    int (*send)(void *ctx, const uint8_t *buf, size_t len);
    /* 读取一段字节流；返回读到的字节数，0 表示超时无数据，<0 失败 */
    int (*recv)(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout_ms);
    /* 静态链路画像，MUST 非空（SEC-063 要求声明拓扑与代发范围） */
    const idcell_link_profile_t *profile;
    void *ctx;
} idcell_transport_t;

/* ---------------------------------------------------------------- 能力描述符 */

/* §09.2 基础标识 */
typedef enum { IDCELL_KIND_STATE = 0, IDCELL_KIND_EVENT, IDCELL_KIND_COMMAND } idcell_kind_t;

/*
 * 读写方向（§09.2 的 r / w / rw）。这里用位掩码承载，便于组合判断：
 *   可读 ⇔ (dir & IDCELL_DIR_READ)  非零
 *   可写 ⇔ (dir & IDCELL_DIR_WRITE) 非零
 * 线上编码值与枚举值一致（0x01=r，0x02=w，0x03=rw）。
 */
typedef enum {
    IDCELL_DIR_R    = 0x01,
    IDCELL_DIR_W    = 0x02,
    IDCELL_DIR_RW   = 0x03,
    IDCELL_DIR_READ = 0x01,
    IDCELL_DIR_WRITE = 0x02
} idcell_dir_t;

typedef enum { IDCELL_PERM_P0 = 0, IDCELL_PERM_P1, IDCELL_PERM_P2, IDCELL_PERM_P3 } idcell_perm_t;

/* §09.2 可转换性分级 */
typedef enum {
    IDCELL_CONV_T0 = 0,  /* 量纲不同，禁止转换 */
    IDCELL_CONV_T1,      /* 纯比例，自动转换 */
    IDCELL_CONV_T2,      /* 比例 + 偏移，自动转换 */
    IDCELL_CONV_T3,      /* 需参考条件，禁止转换（E_CTX） */
    IDCELL_CONV_T4       /* 有损不可逆，禁止可写方向 */
} idcell_conv_t;

typedef enum { IDCELL_TRIG_LEVEL = 0, IDCELL_TRIG_EDGE, IDCELL_TRIG_BOTH } idcell_trigger_t;
typedef enum { IDCELL_FAIL_OFF = 0, IDCELL_FAIL_HOLD, IDCELL_FAIL_BRAKE, IDCELL_FAIL_DAMP } idcell_fail_t;
typedef enum {
    IDCELL_PROV_MEASURED = 0, IDCELL_PROV_ESTIMATED, IDCELL_PROV_DERIVED, IDCELL_PROV_SAMPLED
} idcell_prov_t;

/* ---------------------------------------------------------------- 量种（§24.2） */

/*
 * 量种（quantity kind）：「这是什么量」的受控标识，独立于单位。
 * 对齐 UCUM 的 Kind of Quantity 分类（OPC UA Part 8 Annex B 列为规范列）。
 *
 * 关键红线（FR-082）：量种不同的量绝不自动换算，且判定 MUST 按本 ID 的
 * 相等性执行，MUST NOT 按量纲向量——力的量纲与力矩的量纲在 SI 中完全
 * 一致，按向量判等会把 N 当成 N.m 换算。无量纲比值、平面角、数据量
 * 三者的量纲同样完全一致。
 */
typedef enum {
    IDCELL_QTY_RATIO = 0,   /* ratio        无量纲比值 */
    IDCELL_QTY_LENGTH,      /* length       长度 */
    IDCELL_QTY_ANGLE,       /* angle        平面角 */
    IDCELL_QTY_MASS,        /* mass         质量 */
    IDCELL_QTY_TIME,        /* time         时间 */
    IDCELL_QTY_TEMPERATURE, /* temperature  热力学温度 */
    IDCELL_QTY_CURRENT,     /* current      电流 */
    IDCELL_QTY_CHARGE,      /* charge       电荷 */
    IDCELL_QTY_LUMINOSITY,  /* luminosity   发光强度 */
    IDCELL_QTY_FORCE,       /* force        力 */
    IDCELL_QTY_TORQUE,      /* torque       力矩（量纲同力，靠量种区分） */
    IDCELL_QTY_PRESSURE,    /* pressure     压力 */
    IDCELL_QTY_VELOCITY,    /* velocity     速度 */
    IDCELL_QTY_ACCELERATION,/* acceleration 加速度 */
    IDCELL_QTY_ENERGY,      /* energy       能量 */
    IDCELL_QTY_POWER,       /* power        功率 */
    IDCELL_QTY_VOLTAGE,     /* voltage      电压 */
    IDCELL_QTY_RESISTANCE,  /* resistance   电阻 */
    IDCELL_QTY_CAPACITANCE, /* capacitance  电容 */
    IDCELL_QTY_INDUCTANCE,  /* inductance   电感 */
    IDCELL_QTY_FREQUENCY,   /* frequency    频率 */
    IDCELL_QTY_MAGFLUX,     /* magflux      磁通量 */
    IDCELL_QTY_MAGDENS,     /* magdens      磁感应强度 */
    IDCELL_QTY_DATACOUNT    /* datacount    数据量 */
} idcell_qty_t;

#define IDCELL_QTY_COUNT 24

/* ---------------------------------------------------------------- 值类型（§24.4） */

/*
 * 值的数据类型。帧内 MUST NOT 出现无类型的裸浮点字段（FR-083）。
 * 整数类型 MUST 配合 scale 使用：物理值 = raw × 10^-scale_exp。
 */
typedef enum {
    IDCELL_DTYPE_I8 = 0, IDCELL_DTYPE_U8, IDCELL_DTYPE_I16, IDCELL_DTYPE_U16,
    IDCELL_DTYPE_I32, IDCELL_DTYPE_U32, IDCELL_DTYPE_I64, IDCELL_DTYPE_U64,
    IDCELL_DTYPE_F32, IDCELL_DTYPE_F64, IDCELL_DTYPE_BOOL,
    IDCELL_DTYPE_STRING, IDCELL_DTYPE_BYTES
} idcell_dtype_t;

/*
 * 可接受值类型（二元组，§24.8）。
 *
 * 关键：类型 MUST 与 scale 成对出现。MUST NOT 只声明类型标量——
 * 定点的分辨率与有效范围是绑死的，i32 + 1e-9 的 ±2.147 范围
 * 装不下 ±160 m/s² 的加速度，而这在只列类型的列表上看不出来。
 */
typedef struct {
    idcell_dtype_t dtype;
    uint8_t        scale_exp;   /* 物理值 = raw × 10^-scale_exp */
} idcell_type_t;

#ifndef IDCELL_MAX_ACCEPT_TYPES
#define IDCELL_MAX_ACCEPT_TYPES 4
#endif

/* ---------------------------------------------------------------- 质量码（§24.5） */

/*
 * 值的可信度等级。与 provenance 正交：provenance 答「这值怎么来的」，
 * quality 答「这值当下能不能用」。MUST 为每个值显式携带，
 * MUST NOT 采用「缺省即良好」语义（FR-085、SEC-069）。
 */
typedef enum {
    IDCELL_QUALITY_GOOD = 0,
    IDCELL_QUALITY_UNCERTAIN,
    IDCELL_QUALITY_BAD
} idcell_quality_t;

typedef struct {
    uint16_t index;
    uint8_t  sub;
    char     label[IDCELL_MAX_LABEL];       /* 人类可读名 */
    idcell_kind_t kind;
    idcell_dir_t  dir;
    idcell_perm_t perm;             /* 访问该点所需的权限等级 */
    idcell_qty_t  qty;              /* 量种（§24.2 冻结表，u8 索引） */
    char     unit[IDCELL_MAX_UNIT];         /* 原生单位，UCUM 规范码 */
    char     accept_units[IDCELL_MAX_ACCEPT][IDCELL_MAX_UNIT]; /* 可接受单位集合 */
    uint8_t  accept_count;
    idcell_conv_t conv_class;
    idcell_dtype_t dtype;           /* 值的数据类型 */
    uint8_t  scale_exp;             /* 定点缩放指数：物理值 = raw × 10^-exp */
    idcell_type_t accept_types[IDCELL_MAX_ACCEPT_TYPES]; /* 可接受值类型（§24.8） */
    uint8_t  accept_type_count;
    double   range[2];              /* 值域 */
    double   precision;
    char     frame_ref[IDCELL_MAX_UNIT];     /* 坐标系/参照系 */
    uint8_t  invertible;
    uint32_t min_sync_ms;           /* T_prod */
    uint32_t stale_ms;              /* T_stale */
    uint32_t load_cap;
    idcell_trigger_t trigger;
    uint8_t  hold_semantics;        /* 0 = set, 1 = hold-with-lease */
    idcell_fail_t fail_action;
    idcell_prov_t provenance;
    char     escalate[IDCELL_MAX_UNIT];      /* 升级操作权所需理解度条件 */
    uint16_t deps[IDCELL_MAX_DEPS]; /* 依赖的能力点索引 */
    uint8_t  dep_count;
    /* 可选自定义消息结构集合；为空时使用标准标量 schema 注册表。 */
    uint64_t schema_set[IDCELL_MAX_SCHEMA_SET];
    uint8_t  schema_count;
} idcell_capability_t;

/* 需求描述：MATCH 段的输入（FR-011）。只说「我要什么」，不含设备身份。 */
typedef struct {
    char     label[IDCELL_MAX_LABEL];        /* 我要什么量 */
    idcell_qty_t qty;                         /* 要求的量种 */
    char     unit[IDCELL_MAX_UNIT];          /* 要求的单位（UCUM 码） */
    char     accept_units[IDCELL_MAX_ACCEPT][IDCELL_MAX_UNIT]; /* 我能接受的单位 */
    uint8_t  accept_count;
    idcell_type_t accept_types[IDCELL_MAX_ACCEPT_TYPES]; /* 我能接受的值类型（§24.8） */
    uint8_t  accept_type_count;
    idcell_perm_t perm;             /* 申请权限等级 */
    uint16_t index;                 /* 0xFFFF = 不限定索引 */
    uint32_t want_ms;               /* T_want */
    uint32_t stale_ms;              /* T_stale（保鲜上限） */
    double   range[2];              /* 需要的量程覆盖 */
    idcell_kind_t kind;             /* 需要 state / event / command */
    /* 与提供方 schema_set 求交；为空表示只接受自动标准标量 schema。 */
    uint64_t schema_set[IDCELL_MAX_SCHEMA_SET];
    uint8_t  schema_count;
} idcell_requirement_t;

/* 设备类型注册（§19.5 可选轨）：型号元数据，供工具链与聚合视图使用 */
typedef struct {
    char     type_name[IDCELL_MAX_LABEL];
    char     vendor[IDCELL_MAX_LABEL];
    uint16_t model_id;
    uint16_t version;
    char     capability_summary[IDCELL_MAX_LABEL]; /* 人类可读的能力类目摘要 */
} idcell_device_type_t;

/* ---------------------------------------------------------------- 单位换算 */

/*
 * 编解码层的换算表（§09.2：转换表是编解码层的一部分，不预置进协议帧）。
 * 返回 IDCELL_OK / E_UNIT（量纲不同）/ E_CONV（T0/T4）/ E_CTX（T3 缺参考条件）。
 */
int idcell_unit_convert(const char *from, const char *to,
                        double in, double *out, idcell_conv_t *cls_out);

/* ---------------------------------------------------------------- 量种与单位表 */

/*
 * 取量种名（人类可读，如 "force"）。qty 越界返回 NULL。
 * E_UNIT 错误体需要携带双方的量种名而不只是裸 ID（FR-081）。
 */
const char *idcell_qty_name(idcell_qty_t qty);

/*
 * 按量种名反查量种 ID（供工具层把人类可读名解析成编码）。
 * 找不到返回 IDCELL_E_NODEV。名称不区分大小写。
 */
int idcell_qty_by_name(const char *name, idcell_qty_t *out);

/*
 * 按 ID 取量种名，区分「越界」与「本地未实现」（§24.9、FR-089）。
 * 裁剪档下未编入的量种返回 IDCELL_E_NODEV 且 name 置 NULL。
 */
int idcell_qty_name_by_id(uint8_t id, const char **name);

/* 该量种在本地是否已实现（裁剪档下可能未编入） */
int idcell_qty_implemented(idcell_qty_t qty);

/* 取量种的规范单位（UCUM 码，如 force -> "N"）。越界返回 NULL。 */
const char *idcell_qty_canonical_unit(idcell_qty_t qty);

/*
 * 取量种的量纲幂次向量（7 个 SI 基本量，顺序 M L T I Θ N J）。
 * 仅供量种表校验冗余用，MUST NOT 作为可换算的判据（FR-082）。
 * out 至少 7 字节。越界返回 IDCELL_E_NODEV。
 */
int idcell_qty_dimension(idcell_qty_t qty, int8_t out[7]);

/*
 * 校验内置量种表未被篡改或错位。
 * 用量纲向量作为校验冗余：逐项核对规范单位与量纲向量的一致性。
 * 返回 IDCELL_OK 或 IDCELL_E_CRC。
 */
int idcell_qty_table_check(void);

/*
 * 取单位的量种。单位须在核心子集内（§24.3 的 59 项）。
 * 私有单位（x: 前缀）返回 IDCELL_E_UNIT——私有码不参与量种匹配（SEC-068）。
 * out 不得为 NULL。
 */
int idcell_unit_qty(const char *unit, idcell_qty_t *out);

/* 查单位是否在核心子集内。私有单位返回 0（不在表内，且不可自动换算）。 */
int idcell_unit_known(const char *unit);

/*
 * 量种优先的换算判定（§24.6 判定链）：
 *   from_qty != to_qty  -> IDCELL_E_UNIT（量种不同，T0）
 *   量种同、单位不可换 -> IDCELL_E_CONV
 *   量种同、缺参考条件 -> IDCELL_E_CTX
 * 其余情形按 from/to 的换算参数完成换算，cls_out 给出 T1 或 T2。
 *
 * 这条路径是发送侧唯一的换算入口：MUST NOT 以量纲向量相等为可换算条件。
 */
int idcell_qty_convert(idcell_qty_t from_qty, const char *from,
                       idcell_qty_t to_qty, const char *to,
                       double in, double *out, idcell_conv_t *cls_out);

/* ---------------------------------------------------------------- 值类型协商（§24.8） */

/*
 * 取值类型的成本序（0 = 最低代价）。
 * 序：bool → 1B 整数 → 2B 整数 → 4B 整数 → f32 → 8B 整数 → f64。
 *
 * 同字节数下浮点排在整数之后：浮点能表达连续量，32 位整数配合 scale
 * 只能表达离散网格值。字节数相同时，表达力高者成本更高。
 *
 * 字符串 / bytes 无固定成本，返回 IDCELL_E_CONV（不可协商）。
 */
int idcell_type_cost(idcell_dtype_t dt);

/* 取类型的字节宽度（f32/f64 分别为 4/8；bool 1；string/bytes 0）。 */
int idcell_type_bytes(idcell_dtype_t dt);

/* 该类型是否为整数（决定是否需要 scale）。 */
int idcell_type_is_int(idcell_dtype_t dt);

/*
 * 该类型能否承载给定的值域与精度要求（§24.8 可行性过滤）。
 *
 * 整数类型：范围上界 ≤ (2^(位宽-1) - 1) × 10^-exp 且
 *           下界 ≥ -2^(位宽-1) × 10^-exp；
 *           分辨率 10^-exp MUST 不劣于 precision（即 10^-exp ≤ precision）。
 * 浮点类型：值域可表示且有效位数不劣于 precision。
 * 区间 lo > hi 视为无约束（不检查）。
 *
 * 返回 IDCELL_OK 表示可行，IDCELL_E_CONV 表示不可行。
 */
int idcell_type_fits(idcell_type_t t, double lo, double hi, double precision);

/*
 * 两端接受集合求交并按成本序选出首个可行者（§24.8 协商规则）。
 *
 * 步骤（顺序不可颠倒）：
 *   1. 候选集 = A ∩ B（按 (dtype, scale) 完全相等匹配）
 *   2. 可行性过滤：能承载 [lo, hi] 且分辨率不劣于 precision
 *   3. 取成本序最低的可行者
 *
 * out 不得为 NULL。成功返回 IDCELL_OK 并写出选中的二元组；
 * 交集为空或全部不可行时返回 IDCELL_E_CONV。
 */
int idcell_type_negotiate(const idcell_type_t *a, uint8_t acount,
                          const idcell_type_t *b, uint8_t bcount,
                          double lo, double hi, double precision,
                          idcell_type_t *out);

/* 取类型二元组的可读形式（如 "i32×10^-3"），供工具层与错误体使用。 */
void idcell_type_str(idcell_type_t t, char *out, size_t cap);

/*
 * 往接受集合里加一项（§24.8）。
 * 返回 IDCELL_OK 或 IDCELL_E_NODEV（集合已满）。
 */
int idcell_type_list_add(idcell_type_t *list, uint8_t *count,
                         idcell_dtype_t dt, uint8_t scale_exp);

/* ---------------------------------------------------------------- schema 注册表 */

typedef struct idcell_node idcell_node_t;

/* schema_id 的高 24 bit 为 namespace，低 40 bit 为 namespace 内局部 ID。 */
uint64_t idcell_schema_id(uint32_t name_space, uint64_t local_id);
/* namespace 0 的规范固定分配；其它 dtype/scale/unit 组合必须显式扩展注册。 */
#define IDCELL_SCHEMA_STD_F64_CEL      1ULL
#define IDCELL_SCHEMA_STD_I16_CEL_2    2ULL
#define IDCELL_SCHEMA_STD_F64_ACCEL    3ULL
#define IDCELL_SCHEMA_STD_I32_ACCEL_3  4ULL
#define IDCELL_SCHEMA_STD_I32_CEL_3    5ULL

typedef struct {
    char     name[16];
    char     value_type[16];       /* 字段类型名，如 "f64"、"i16"；不是 schema 本身 */
    char     unit[IDCELL_MAX_UNIT];
    uint8_t  scale_exp;
    uint8_t  critical;
    uint8_t  required;
} idcell_schema_field_t;

typedef struct {
    uint64_t schema_id;
    uint16_t field_count;
    idcell_schema_field_t fields[IDCELL_MAX_SCHEMA_FIELDS];
    uint8_t digest[32];
} idcell_schema_def_t;

/* 自动生成标准标量 schema；quickstart 的 f64/i32/i16 等类型无需手工注册。 */
int idcell_schema_standard(idcell_dtype_t dtype, uint8_t scale_exp,
                           const char *unit, idcell_schema_def_t *out);
/* 同结构同 ID 可重复注册；同 ID 不同结构返回 E_IDCONFLICT。 */
int idcell_node_register_schema(idcell_node_t *n, const idcell_schema_def_t *def);
int idcell_node_schema(const idcell_node_t *n, uint64_t schema_id,
                       idcell_schema_def_t *out);
/* 结构变化必须换 ID 并完成重协商；未知 critical 返回 E_UNSAFE。 */
int idcell_schema_check_change(const idcell_schema_def_t *old_def,
                               const idcell_schema_def_t *new_def,
                               int renegotiated);

/* ---------------------------------------------------------------- 契约 */

typedef struct {
    uint16_t index;
    uint8_t  sub;
    char     unit[IDCELL_MAX_UNIT];
    uint32_t t_pub_ms;
    idcell_perm_t perm;
    idcell_fail_t degrade;
    idcell_prov_t prov;
    /* v0.9：协商出的值类型与定点缩放（§24.8）。接收方据此解释帧内值载荷 */
    uint8_t  dtype;
    uint8_t  scale_exp;
    /* 消息结构身份与契约内短引用；dtype/scale 只是字段编码属性。 */
    uint64_t schema_id;
    uint16_t schema_ref;
} idcell_contract_point_t;

/* 绑定契约十字段（§09.7） */
typedef struct {
    uint32_t    binding_id;
    idcell_did_t peer;
    uint32_t    desc_version;
    uint32_t    owner_token;
    uint32_t    lease_ttl_ms;
    uint32_t    arb_domain;
    idcell_perm_t perm;
    uint16_t    pt_count;
    idcell_contract_point_t pt[IDCELL_MAX_CONTRACT_PTS];
    uint64_t    session_id;
    uint64_t    grant_epoch;
    uint64_t    authority_id;
    uint64_t    authority_epoch;
    uint64_t    member_epoch;
} idcell_contract_t;

typedef enum {
    IDCELL_BIND_NONE = 0,
    IDCELL_BIND_PREPARE_SENT,
    IDCELL_BIND_PREPARED,
    IDCELL_BIND_COMMIT_SENT,
    IDCELL_BIND_ACTIVE
} idcell_bind_phase_t;

/* ---------------------------------------------------------------- 节点 */

typedef enum {
    IDCELL_WAKE_ALWAYS_ON = 0,
    IDCELL_WAKE_SCHEDULED,
    IDCELL_WAKE_RADIO,
    IDCELL_WAKE_PROXY,
    IDCELL_WAKE_RX_OFF
} idcell_wake_profile_t;

typedef enum {
    IDCELL_WAKE_EVENT_TIMER = 0,
    IDCELL_WAKE_EVENT_RADIO,
    IDCELL_WAKE_EVENT_PROXY,
    IDCELL_WAKE_EVENT_LOCAL
} idcell_wake_event_t;

typedef enum {
    IDCELL_PRESENCE_ONLINE = 0,
    IDCELL_PRESENCE_ASLEEP,
    IDCELL_PRESENCE_OFFLINE
} idcell_presence_t;

typedef struct {
    idcell_did_t did;
    uint8_t  cred[IDCELL_CRED_LEN];   /* 凭证，由注册表独立签发（SEC-064） */
    uint8_t  max_perm;                /* 本机授予的最高实权限 */
    uint8_t  proficiency;             /* 理解度（0..3），不得兑换写权限 */
    uint32_t t_hb_ms;                 /* 心跳周期，默认 1000 */
    uint32_t lease_ttl_ms;            /* 租约 TTL，默认 3000 */
    uint32_t announce_ms;             /* 未确认 ANNOUNCE 的退避基数，默认 500 */
    uint32_t announce_retry_max_ms;   /* 未确认退避上限，默认 8000 */
    uint32_t announce_steady_ms;      /* 有效响应后的固定周期，默认 announce_ms */
    uint32_t announce_jitter_ms;      /* 初次随机抖动上界，默认 announce_ms */
    uint16_t discovery_cache_capacity;/* PROBE 去重容量，默认 8 */
    uint32_t discovery_cache_ttl_ms;  /* 去重 TTL，默认 30000 */
    uint32_t discovery_response_interval_ms; /* 实际响应间隔下限，默认 20 */
    uint32_t discovery_response_jitter_ms;   /* 固定种子响应抖动上界，默认 20 */
    char     discovery_scope[IDCELL_MAX_LABEL]; /* 默认 "default" */
    idcell_wake_profile_t wake_profile; /* 默认 ALWAYS_ON */
    uint32_t listen_ms;               /* 休眠节点的监听/保活周期 */
    uint32_t checkin_ms;              /* SCHEDULED 最大 CHECK-IN 周期 */
    uint32_t wake_after_ms;           /* SCHEDULED 本次自动唤醒期限 */
    uint32_t max_wake_latency_ms;     /* 对端离线判定使用的最大唤醒上界 */
    uint16_t wake_budget;             /* 每个窗口允许的 RADIO/PROXY 唤醒次数，默认 4 */
    uint32_t wake_window_ms;          /* 唤醒预算窗口，默认 60000 */
    char     vendor[IDCELL_MAX_LABEL];
    char     model[IDCELL_MAX_LABEL];
} idcell_node_cfg_t;

/* 提供方取值回调：返回 IDCELL_OK 并写出值 */
typedef int (*idcell_value_fn)(void *ud, uint16_t index, uint8_t sub,
                               double *value, uint64_t *ts_us, idcell_prov_t *prov);

/*
 * 提供方质量回调（可选，§24.5）：返回该点当下的可信度。
 * 未设置时质量码恒为 GOOD——注意这不是「缺省即良好」的违规：
 * 协议层 MUST 为每个值显式携带质量码，未设置回调的实现仍会写出
 * GOOD 质量码，消费方能观察到「这一帧带了 GOOD」这一事实。
 * 若设备可能进入故障态，MUST 设置此回调并如实上报 UNCERTAIN / BAD
 * （FR-085）。
 */
typedef idcell_quality_t (*idcell_quality_fn)(void *ud, uint16_t index, uint8_t sub);

/* 提供方写入回调：被授权的写请求到达时调用。返回非 OK 即拒绝。 */
typedef int (*idcell_set_fn)(void *ud, uint16_t index, uint8_t sub,
                              double value, const char *intent, uint32_t owner_token);

/*
 * 消费方数据回调。
 *
 * v0.8 起增加 quality 参数（§24.5）：它与 prov 正交——
 * prov 答「这值怎么来的」，quality 答「这值当下能不能用」。
 * 质量码为 BAD 时消费侧 MUST NOT 将该值用于控制，
 * MUST 按该能力点声明的 fail_action 处置（FR-085）。
 */
typedef void (*idcell_data_fn)(void *ud, const idcell_did_t *peer,
                               uint16_t index, uint8_t sub, double value,
                               uint64_t ts_us, idcell_prov_t prov,
                               idcell_quality_t quality);

/* 事件回调 */
typedef void (*idcell_event_fn)(void *ud, const idcell_did_t *peer,
                                uint16_t index, uint8_t sub,
                                const char *text);

/*
 * 写结果（需求方侧）。
 *
 * 写是异步的：idcell_node_write() 的返回值只表示「本地预检通过、请求已发出」，
 * 最终裁决由提供方做出，经写结果回调送达（FR-035 / FR-024）。
 */
typedef struct {
    int         err;          /* IDCELL_OK / IDCELL_E_* */
    int         has_range;    /* 1 = 本次裁决带值域信息 */
    double      range_lo;     /* 值域下界（has_range=1 时有效） */
    double      range_hi;     /* 值域上界（has_range=1 时有效） */
    double      value;        /* 实际提交写入的值 */
    const char *reason;       /* 可读理由（可能为 NULL） */
} idcell_write_result_t;

/*
 * 写结果回调（需求方侧）：
 *   err == IDCELL_OK      写成功
 *   err == IDCELL_E_RANGE 值越界（提供方已拒绝，设备输出未被截断或钳位）
 *   err == IDCELL_E_PERM  权限不足
 *   err == IDCELL_E_LEASE 租约已过期
 *   err == IDCELL_E_UNSAFE 链路层不安全
 *
 * 同一对端同时只允许一笔未决写；后一笔发起时前一笔的结果不再送达。
 */
typedef void (*idcell_write_result_fn)(void *ud, const idcell_did_t *peer,
                                       uint16_t index, uint8_t sub,
                                       const idcell_write_result_t *res);

/* 节点创建：cfg 不得为空；内部按 cfg 分配固定容量，无需 malloc 之外的内存池 */
idcell_node_t *idcell_node_new(const idcell_node_cfg_t *cfg);
void           idcell_node_free(idcell_node_t *n);

/* 绑定传输适配器。适配器必须带链路画像（profile 非空）。 */
int idcell_node_set_transport(idcell_node_t *n, const idcell_transport_t *t);

/* 覆盖链路画像（当适配器共享同一 profile 时无需调用） */
void idcell_node_set_link_profile(idcell_node_t *n, const idcell_link_profile_t *p);

/* 注册能力点。产出能力描述符（§09.2 必需轨）。可重复调用以注册多个能力点。 */
int idcell_node_register_capability(idcell_node_t *n, const idcell_capability_t *cap);

/* 注册需求描述。作为需求方参与 MATCH（FR-011）。 */
int idcell_node_register_requirement(idcell_node_t *n, const idcell_requirement_t *req);

/* 注册设备类型（§19.5 可选轨）。可选；能力注册不依赖它。 */
int idcell_node_register_device_type(idcell_node_t *n, const idcell_device_type_t *dt);

/* 取链路画像 / 物理链路类型。永远可取；未绑适配器时返回默认值。 */
const idcell_link_profile_t *idcell_node_link_profile(const idcell_node_t *n);
/* 链路画像是否已由适配器显式声明（SEC-063） */
int              idcell_node_has_link_profile(const idcell_node_t *n);
idcell_media_t   idcell_node_media(const idcell_node_t *n);
idcell_topology_t idcell_node_topology(const idcell_node_t *n);
idcell_did_t     idcell_node_did(const idcell_node_t *n);
uint32_t         idcell_node_desc_version(const idcell_node_t *n);

/* 设置取值源与数据/事件回调 */
void idcell_node_set_value_source(idcell_node_t *n, idcell_value_fn fn, void *ud);
/* v0.8：注册质量码来源（§24.5）。不注册则质量码恒为 GOOD */
void idcell_node_set_quality_source(idcell_node_t *n, idcell_quality_fn fn, void *ud);
void idcell_node_set_setter(idcell_node_t *n, idcell_set_fn fn, void *ud);
void idcell_node_set_data_sink(idcell_node_t *n, idcell_data_fn fn, void *ud);
void idcell_node_set_event_sink(idcell_node_t *n, idcell_event_fn fn, void *ud);

/* 写结果回调（需求方侧）：提供方的最终裁决经此送达 */
void idcell_node_set_write_result_sink(idcell_node_t *n, idcell_write_result_fn fn, void *ud);

/*
 * 设备侧执行入口。所有收帧、定时器、周期发布、心跳、租约维护都在这里。
 * now_ms 为单调毫秒。返回值 0 表示本轮正常，负值表示内部错误。
 * 本函数不得在中断上下文调用（NFR-025）。
 */
int idcell_node_poll(idcell_node_t *n, uint32_t now_ms);

/* 主动发现。originator_id 可清零（表示本节点），非零时必须等于本节点 DID。 */
typedef struct {
    idcell_did_t originator_id;
    uint64_t query_id;       /* 非 0；(originator_id, query_id) 为跨路径去重键 */
    const char *scope;       /* NULL/空串表示节点配置的 scope */
    uint8_t hop_limit;       /* 0 只处理当前节点，不转发 */
    const char *query;       /* 空串不限；非空按能力 label/模型/摘要的大小写敏感子串过滤 */
    idcell_did_t target_id;  /* 全 0 不限；非本机 target 只转发、不做本地 HELLO */
} idcell_probe_t;

int idcell_node_probe(idcell_node_t *n, const idcell_probe_t *probe);

typedef struct {
    uint32_t next_delay_ms;
    uint32_t failures;
    uint32_t announcements;
    uint32_t cache_size;
    uint32_t descriptor_fetches;
    int confirmed;
    int last_probe_err;
} idcell_discovery_status_t;
int idcell_node_discovery_status(const idcell_node_t *n, idcell_discovery_status_t *out);

/* 休眠与 CHECK-IN。RX_OFF 只能由 LOCAL 事件唤醒，收到帧绝不隐式唤醒。 */
int idcell_node_sleep(idcell_node_t *n, uint32_t now_ms);
int idcell_node_wake(idcell_node_t *n, idcell_wake_event_t event, uint32_t now_ms);
int idcell_node_check_in(idcell_node_t *n, uint32_t now_ms);
int idcell_node_asleep(const idcell_node_t *n);
int idcell_node_last_error(const idcell_node_t *n);
int idcell_node_mailbox_count(const idcell_node_t *n);
idcell_presence_t idcell_node_peer_presence(const idcell_node_t *n,
                                             const idcell_did_t *peer,
                                             uint32_t now_ms);

/* 写一个能力点。MUST 提供有效 owner_token 与意图串（SEC-019）。 */
int idcell_node_write(idcell_node_t *n, uint16_t index, uint8_t sub,
                      double value, uint32_t owner_token, const char *intent);

typedef struct {
    uint64_t command_id;      /* (binding, session, command) 幂等键，必须非 0 */
    uint32_t valid_for_ms;    /* 相对有效期，由接收方映射到本地 deadline；1..60000ms */
} idcell_write_options_t;

/* 扩展写：自动携带当前 binding/session/grant/fencing；旧 API 自动生成命令 ID 与有限 TTL。 */
int idcell_node_write_ex(idcell_node_t *n, uint16_t index, uint8_t sub,
                         double value, uint32_t owner_token, const char *intent,
                         const idcell_write_options_t *options);

/* 显式重协商与中止；pending 状态不会替换仍 active 的旧契约。 */
int idcell_node_renegotiate(idcell_node_t *n, const idcell_did_t *peer);
int idcell_node_bind_abort(idcell_node_t *n, const idcell_did_t *peer);
/* 确认释放当前执行器 owner，使等待中的新 grant 可以激活。 */
int idcell_node_release(idcell_node_t *n, const idcell_did_t *peer);
idcell_bind_phase_t idcell_node_bind_phase(const idcell_node_t *n,
                                           const idcell_did_t *peer);

/* 重启围栏快照：只持久化最高纪元与授权指纹，绝不保存单调 deadline/token 活跃态。 */
#define IDCELL_SNAPSHOT_MAGIC 0x49434353u /* "ICCS" */
#define IDCELL_SNAPSHOT_VERSION 1u
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint64_t authority_id;
    uint64_t authority_epoch;
    uint64_t member_epoch;
    uint64_t grant_epoch_floor;
    uint64_t grant_fingerprint;
} idcell_snapshot_t;
int idcell_node_snapshot(const idcell_node_t *n, idcell_snapshot_t *out);
int idcell_node_restore(idcell_node_t *n, const idcell_snapshot_t *snapshot);

/* 读取对端某能力点的最新值（需已建立绑定）。 */
int idcell_node_read(idcell_node_t *n, const idcell_did_t *peer,
                     uint16_t index, uint8_t sub, double *value);

/* 取某对端的绑定契约；无契约返回 E_NODEV */
int idcell_node_get_contract(const idcell_node_t *n, const idcell_did_t *peer,
                              idcell_contract_t *out);

/* 取本机在某个绑定上持有的 owner_token（写操作必须携带，SEC-019） */
int idcell_node_owner_token(const idcell_node_t *n, const idcell_did_t *peer,
                            uint32_t *out);

/*
 * 把 owner_token 格式化成可安全打印的脱敏串（SEC-067）。
 *
 * 完整令牌 MUST NOT 出现在任何工具或自测的输出里；这里只保留高 16 bit
 * 作为可核对的短前缀，并标注其为脱敏值——该前缀不可直接复用为写令牌。
 *
 * out 至少 24 字节。返回写入的字符数（不含结尾 '\0'）。
 */
size_t idcell_mask_token(uint32_t token, char *out, size_t cap);

/*
 * 取对端的可读名（能力摘要，来自 HELLO 帧）。
 * 主机侧 CLI 据此做「按名选设备」，命令行因此无需出现 DID。
 */
int idcell_node_peer_label(const idcell_node_t *n, const idcell_did_t *peer,
                           char *out, size_t cap);

/* 取对端当前的管道阶段名（"IDLE"/"DISCOVER"/"DESCRIBE"/"MATCH"/…/"RUNNING"） */
const char *idcell_node_peer_stage_name(const idcell_node_t *n, const idcell_did_t *peer);

/*
 * 按可读名找对端。主机侧 CLI 用它实现「按名选设备」——
 * 命令行因此无需出现 DID（FR-011：需求描述与设备身份解耦）。
 * 先做精确匹配，找不到再做子串匹配。找不到返回 IDCELL_E_NODEV。
 */
int idcell_node_find_peer_by_label(const idcell_node_t *n, const char *label,
                                  idcell_did_t *out);

/*
 * 限定管道只与指定可读名的对端推进（NULL / "" = 不限定）。
 * 主机侧在多设备共存时用它把需求收敛到一台设备上。
 */
int idcell_node_set_target_label(idcell_node_t *n, const char *label);

/* 取对端缓存的能力点数量（来自 HELLO 帧的描述符） */
int idcell_node_peer_cap_count(const idcell_node_t *n, const idcell_did_t *peer);

/* 取对端第 idx 个能力点的可读名与原生单位 */
int idcell_node_peer_cap_info(const idcell_node_t *n, const idcell_did_t *peer, int idx,
                              char *label, size_t label_cap,
                              char *unit, size_t unit_cap);

/* 对端存在性列表 */
int idcell_node_peer_count(const idcell_node_t *n);
int idcell_node_peer(const idcell_node_t *n, int idx, idcell_did_t *out);

/* ---------------------------------------------------------------- 编解码原语 */

typedef enum {
    IDCELL_FT_DISCOVER = 0x01,
    IDCELL_FT_HELLO    = 0x02,
    IDCELL_FT_MATCH    = 0x03,
    IDCELL_FT_NEGOTIATE= 0x04,
    IDCELL_FT_RENEGOTIATE = 0x05,
    IDCELL_FT_AUTH     = 0x06,
    IDCELL_FT_BIND     = 0x07,
    IDCELL_FT_READ     = 0x08,
    IDCELL_FT_WRITE    = 0x09,
    IDCELL_FT_SUBSCRIBE= 0x0A,
    IDCELL_FT_UNSUB    = 0x0B,
    IDCELL_FT_EVENT    = 0x0C,
    IDCELL_FT_CMD      = 0x0D,
    IDCELL_FT_ACK      = 0x0E,
    IDCELL_FT_DONE     = 0x0F,
    IDCELL_FT_LEASE    = 0x10,
    IDCELL_FT_PREEMPT  = 0x11,
    IDCELL_FT_GROUP    = 0x12,
    IDCELL_FT_HEARTBEAT= 0x13,
    IDCELL_FT_OFFLINE  = 0x14,
    IDCELL_FT_STALE    = 0x15,
    IDCELL_FT_CONFIG   = 0x16,
    IDCELL_FT_PROVISION= 0x17,
    IDCELL_FT_ERROR    = 0x18
} idcell_frametype_t;

const char *idcell_frametype_name(uint8_t t);

/* FLAGS 位域（§09.1） */
#define IDCELL_FLAG_ENCRYPT   0x01
#define IDCELL_FLAG_COMPRESS  0x02
#define IDCELL_FLAG_FRAGMENT  0x04
#define IDCELL_FLAG_NEEDACK   0x08
#define IDCELL_FLAG_PREEMPT   0x10
#define IDCELL_FLAG_AUTH      0x20

/* CRC-16/CCITT-FALSE：poly 0x1021, init 0xFFFF, refin=false, refout=false, xorout=0 */
uint16_t idcell_crc16(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* IDCELL_H */
