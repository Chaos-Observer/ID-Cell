/* ID-CELL 参考实现 · 内部头文件（不对外暴露） */
#ifndef IDCELL_INTERNAL_H
#define IDCELL_INTERNAL_H

#include "idcell.h"
#include "idcell_transport.h"
#include <string.h>

/* ---------------------------------------------------------------- 帧 */

typedef struct {
    uint8_t  ver;
    uint8_t  prof;
    uint8_t  flags;
    uint8_t  type;
    uint16_t seq;
    uint16_t txn;
    idcell_did_t src;
    idcell_did_t dst;
    uint16_t group;
    uint64_t ts_us;
    uint8_t  payload[IDCELL_MAX_PAYLOAD];
    uint16_t payload_len;
    uint8_t  auth_tag[IDCELL_AUTH_TAG_LEN];
} idcell_frame_t;

/* TLV 视图 */
typedef struct {
    uint16_t idx;
    uint8_t  sub;
    uint8_t  type;
    uint16_t len;
    const uint8_t *val;
} idcell_tlv_t;

/* 帧返回码：非负值保留原 API 约定，负值可用于跨实现错误分类。 */
#define IDCELL_FRAME_OK          0
#define IDCELL_FRAME_NEED_MORE   1
#define IDCELL_FRAME_BAD_SYNC   (-1)
#define IDCELL_FRAME_BAD_LENGTH (-2)
#define IDCELL_FRAME_BAD_VERSION (-3)
#define IDCELL_FRAME_BAD_PROFILE (-4)
#define IDCELL_FRAME_BAD_TYPE   (-5)
#define IDCELL_FRAME_BAD_TRAILER (-6)
#define IDCELL_FRAME_BAD_CRC    (-7)
#define IDCELL_FRAME_BAD_AUTH   (-8)
#define IDCELL_FRAME_E_CAPACITY (-9)

/*
 * 帧编解码：旧入口不携带密钥，AUTH 帧必须由 decode_auth 显式解码。
 * decode 返回 0 成功、1 数据不足、负值见上方分类；consumed 为精确帧长。
 */
int idcell_frame_encode(const idcell_frame_t *f, uint8_t *out, size_t cap, size_t *out_len);
int idcell_frame_encode_auth(const idcell_frame_t *f, const uint8_t *key, size_t keylen,
                             uint8_t *out, size_t cap, size_t *out_len);
int idcell_frame_decode(const uint8_t *in, size_t len, idcell_frame_t *out, size_t *consumed);
int idcell_frame_decode_auth(const uint8_t *in, size_t len, const uint8_t *key, size_t keylen,
                             idcell_frame_t *out, size_t *consumed);

/* TLV 遍历：返回 0 成功，<0 失败 */
int idcell_tlv_next(const uint8_t *buf, uint16_t len, uint16_t *pos, idcell_tlv_t *out);
int idcell_tlv_put(uint8_t *buf, uint16_t cap, uint16_t *pos,
                   uint16_t idx, uint8_t sub, uint8_t type,
                   const void *val, uint16_t len);

/* 字节序辅助 */
void     idcell_put_u16(uint8_t *p, uint16_t v);
void     idcell_put_u32(uint8_t *p, uint32_t v);
void     idcell_put_u64(uint8_t *p, uint64_t v);
void     idcell_put_f64(uint8_t *p, double v);
uint16_t idcell_get_u16(const uint8_t *p);
uint32_t idcell_get_u32(const uint8_t *p);
uint64_t idcell_get_u64(const uint8_t *p);
double   idcell_get_f64(const uint8_t *p);

/* ---------------------------------------------------------------- 描述符序列化 */

/* 能力描述符在 HELLO 帧中的 TLV 类型 */
#define IDCELL_TLV_CAP_DESC   0x20
#define IDCELL_TLV_REQ_DESC   0x21
#define IDCELL_TLV_MATCH_RES  0x22
#define IDCELL_TLV_NEG_RESULT 0x23
#define IDCELL_TLV_CONTRACT   0x24
#define IDCELL_TLV_ERR_BODY   0x25
#define IDCELL_TLV_AUTH_PROOF 0x26
#define IDCELL_TLV_NONCE      0x27
#define IDCELL_TLV_VALUE      0x28
#define IDCELL_TLV_INTENT     0x29
#define IDCELL_TLV_OWNER      0x2A
#define IDCELL_TLV_SUMMARY    0x2B
#define IDCELL_TLV_DESC_VER   0x2C
#define IDCELL_TLV_DESC_CRC   0x2D
#define IDCELL_TLV_ARB        0x2E
#define IDCELL_TLV_TTL        0x2F
#define IDCELL_TLV_TPUB       0x30
#define IDCELL_TLV_UNIT       0x31
#define IDCELL_TLV_PERM       0x32
#define IDCELL_TLV_INDEX      0x33
#define IDCELL_TLV_RESULT     0x34
#define IDCELL_TLV_PROV       0x35
#define IDCELL_TLV_BIND_ID    0x36
#define IDCELL_TLV_STR        0x37
#define IDCELL_TLV_U8         0x38
#define IDCELL_TLV_U32        0x39
#define IDCELL_TLV_F64        0x3A
#define IDCELL_TLV_STALE      0x3B
/* v0.8：质量码（§24.5）。与 PROV 正交，MUST 为每个值显式携带。 */
#define IDCELL_TLV_QUALITY   0x3C
/* P0-3：两阶段 BIND、逐点 schema、会话/授权纪元与过期幂等写。 */
#define IDCELL_TLV_BIND_PHASE 0x3D
#define IDCELL_TLV_SESSION_ID 0x3E
#define IDCELL_TLV_GRANT_EPOCH 0x3F
#define IDCELL_TLV_SCHEMA_ID  0x40
#define IDCELL_TLV_SCHEMA_REF 0x41
#define IDCELL_TLV_COMMAND_ID 0x42
#define IDCELL_TLV_NOT_AFTER  0x43 /* 线值语义为 valid_for_ms（相对有效期） */
#define IDCELL_TLV_VALID_FOR  IDCELL_TLV_NOT_AFTER
#define IDCELL_TLV_AUTHORITY_ID 0x44
#define IDCELL_TLV_AUTHORITY_EPOCH 0x45
#define IDCELL_TLV_MEMBER_EPOCH 0x46
#define IDCELL_TLV_BIND_POINT 0x47
#define IDCELL_TLV_SCHEMA_DIGEST 0x48
#define IDCELL_TLV_OLD_BINDING 0x49
#define IDCELL_TLV_OLD_SESSION 0x4A
#define IDCELL_TLV_OLD_GRANT 0x4B
/* P1-1：DISCOVER 消息语义、跨路径 PROBE 与休眠在线状态。 */
#define IDCELL_TLV_MESSAGE      0x4C
#define IDCELL_TLV_ROLE         0x4D
#define IDCELL_TLV_ORIGINATOR   0x4E
#define IDCELL_TLV_QUERY_ID     0x4F
#define IDCELL_TLV_SCOPE        0x50
#define IDCELL_TLV_HOP_LIMIT    0x51
#define IDCELL_TLV_QUERY        0x52
#define IDCELL_TLV_CHECKIN      0x53
#define IDCELL_TLV_WAKE_PROFILE 0x54
#define IDCELL_TLV_CHECKIN_MS   0x55
#define IDCELL_TLV_WAKE_LATENCY 0x56
#define IDCELL_TLV_ASLEEP       0x57
#define IDCELL_TLV_TARGET       0x58
/* 公共/授权描述分离：digest 只对规范化 TLV 字节计算，不含结构体 padding/NUL。 */
#define IDCELL_TLV_PUBLIC_DIGEST 0x59
#define IDCELL_TLV_AUTH_DIGEST   0x5A
/* v0.12：时钟服务点的计数回传（§26.2）。载荷 15 字节定长：
 * u64 counter + u32 tick_ns + u16 epoch + u8 quality。 */
#define IDCELL_TLV_CLOCK         0x5B

#define IDCELL_DISCOVER_ANNOUNCE 1
#define IDCELL_DISCOVER_PROBE    2
#define IDCELL_DISCOVER_RESPONSE 3
#define IDCELL_ROLE_CAPABILITY   0x01
#define IDCELL_ROLE_REQUIREMENT  0x02
#define IDCELL_HEARTBEAT_CHECKIN 1
#define IDCELL_HEARTBEAT_SLEEP   2

#define IDCELL_BIND_PHASE_PREPARE   1
#define IDCELL_BIND_PHASE_PREPARED  2
#define IDCELL_BIND_PHASE_COMMIT    3
#define IDCELL_BIND_PHASE_COMMITTED 4
#define IDCELL_BIND_PHASE_ABORT     5
#define IDCELL_BIND_PHASE_RELEASE   6
/* 0x80..0xBF 为未知即拒绝的 critical TLV；0xC0..0xFF 为可跳过扩展。 */
#define IDCELL_TLV_CRITICAL_MIN 0x80
#define IDCELL_TLV_CRITICAL_MAX 0xBF

/* 能力描述符字段类型 */
#define IDCELL_CF_LABEL     0x40
#define IDCELL_CF_KIND      0x41
#define IDCELL_CF_DIR       0x42
#define IDCELL_CF_PERM      0x43
#define IDCELL_CF_DIM       0x44
#define IDCELL_CF_UNIT      0x45
#define IDCELL_CF_ACCEPT    0x46
#define IDCELL_CF_CONV      0x47
#define IDCELL_CF_RANGE     0x48
#define IDCELL_CF_PRECISION 0x49
#define IDCELL_CF_FRAME     0x4A
#define IDCELL_CF_INVERT    0x4B
#define IDCELL_CF_MINSYNC   0x4C
#define IDCELL_CF_STALE     0x4D
#define IDCELL_CF_LOADCAP   0x4E
#define IDCELL_CF_TRIGGER   0x4F
#define IDCELL_CF_HOLD      0x50
#define IDCELL_CF_FAIL      0x51
#define IDCELL_CF_PROV      0x52
#define IDCELL_CF_ESCALATE  0x53
#define IDCELL_CF_DEPS      0x54
/* v0.8：量种 ID 复用 DIM 槽位（语义由字符串改为 u8 索引），
 * 新增数据类型与定点缩放两个字段（§24.4）。 */
#define IDCELL_CF_DTYPE     0x55
#define IDCELL_CF_SCALE     0x56
/* v0.9：可接受值类型（§24.8），每项为 (dtype u8, scale_exp u8) */
#define IDCELL_CF_ACCEPT_T  0x57
#define IDCELL_CF_SCHEMA    0x58

/* 需求描述符字段类型 */
#define IDCELL_RF_LABEL     0x60
#define IDCELL_RF_DIM       0x61
#define IDCELL_RF_UNIT      0x62
#define IDCELL_RF_ACCEPT    0x63
#define IDCELL_RF_PERM      0x64
#define IDCELL_RF_INDEX     0x65
#define IDCELL_RF_WANT      0x66
#define IDCELL_RF_STALE     0x67
#define IDCELL_RF_RANGE     0x68
#define IDCELL_RF_KIND      0x69
/* v0.9：需求方的可接受值类型（§24.8），每项 (dtype u8, scale_exp u8) */
#define IDCELL_RF_ACCEPT_T  0x6A
#define IDCELL_RF_SCHEMA    0x6B

/* 错误体字段 */
#define IDCELL_EF_CODE      0x70
#define IDCELL_EF_OBJECT    0x71
#define IDCELL_EF_REQUIRED  0x72
#define IDCELL_EF_CURRENT   0x73
#define IDCELL_EF_REASON    0x74
#define IDCELL_EF_RETRY     0x75
/* 值域错误专用（FR-035：E_RANGE 错误体 MUST 携带值域与实际值） */
#define IDCELL_EF_RANGE_LO  0x76
#define IDCELL_EF_RANGE_HI  0x77
#define IDCELL_EF_VALUE     0x78
#define IDCELL_EF_INDEX     0x79

/* 存储型能力描述符（用于缓存对端描述符） */
typedef struct {
    uint16_t index;
    uint8_t  sub;
    char     label[IDCELL_MAX_LABEL];
    uint8_t  kind;
    uint8_t  dir;
    uint8_t  perm;
    uint8_t  qty;              /* v0.8：量种 ID（§24.2），取代原字符串 dim */
    char     unit[IDCELL_MAX_UNIT];
    char     accept[IDCELL_MAX_ACCEPT][IDCELL_MAX_UNIT];
    uint8_t  accept_count;
    uint8_t  conv;
    uint8_t  dtype;            /* v0.8：值的数据类型 */
    uint8_t  scale_exp;        /* v0.8：定点缩放指数 */
    idcell_type_t accept_types[IDCELL_MAX_ACCEPT_TYPES]; /* v0.9 */
    uint8_t  accept_type_count;
    double   range[2];
    double   precision;
    char     frame_ref[IDCELL_MAX_UNIT];
    uint8_t  invertible;
    uint32_t min_sync_ms;
    uint32_t stale_ms;
    uint32_t load_cap;
    uint8_t  trigger;
    uint8_t  hold_semantics;
    uint8_t  fail_action;
    uint8_t  provenance;
    char     escalate[IDCELL_MAX_UNIT];
    uint16_t deps[IDCELL_MAX_DEPS];
    uint8_t  dep_count;
    uint64_t schema_set[IDCELL_MAX_SCHEMA_SET];
    uint8_t  schema_count;
} idcell_cap_store_t;

/* 序列化：能力描述符 → TLV 序列（写入 buf，返回写入字节数） */
int idcell_desc_encode(const idcell_capability_t *c, uint8_t *buf, uint16_t cap);
/* 公共 HELLO 子集：只允许发现/匹配字段，严禁范围、授权策略和 schema 集合。 */
int idcell_public_desc_encode(const idcell_capability_t *c, uint8_t *buf, uint16_t cap);
int idcell_public_desc_validate(const uint8_t *buf, uint16_t len);
int idcell_authorized_desc_validate(const uint8_t *buf, uint16_t len);
void idcell_descriptor_digest(int public_desc, const uint8_t *canonical_tlvs,
                              size_t len, uint8_t out[32]);
/* 反序列化：从一段 TLV 序列恢复能力描述符 */
int idcell_desc_decode(const uint8_t *buf, uint16_t len, idcell_cap_store_t *out);
/* 需求描述符序列化 */
int idcell_req_encode(const idcell_requirement_t *r, uint8_t *buf, uint16_t cap);
int idcell_req_decode(const uint8_t *buf, uint16_t len, idcell_requirement_t *out);

/* ---------------------------------------------------------------- SHA-256 / HMAC */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} idcell_sha256_t;

void idcell_sha256_init(idcell_sha256_t *c);
void idcell_sha256_update(idcell_sha256_t *c, const void *data, size_t len);
void idcell_sha256_final(idcell_sha256_t *c, uint8_t out[32]);
void idcell_sha256(const void *data, size_t len, uint8_t out[32]);
void idcell_hmac_sha256(const uint8_t *key, size_t keylen,
                        const uint8_t *msg, size_t msglen, uint8_t out[32]);
/* 预共享 cred 模型上的 HKDF 式会话派生；不是 EDHOC，也不提供 PKI。 */
void idcell_session_key_derive(const uint8_t cred[IDCELL_CRED_LEN],
                               const uint8_t nonce[16],
                               const idcell_did_t *a, const idcell_did_t *b,
                               uint16_t auth_txn, uint32_t binding_id,
                               uint64_t session_id, uint8_t out[32]);

/* ---------------------------------------------------------------- 节点内部 */

#define IDCELL_MAX_PEER_CAPS  16
#define IDCELL_MAX_MATCH_PTS  12

typedef enum {
    IDCELL_STAGE_IDLE = 0,
    IDCELL_STAGE_DISCOVER,
    IDCELL_STAGE_DESCRIBE,
    IDCELL_STAGE_MATCH,
    IDCELL_STAGE_NEGOTIATE,
    IDCELL_STAGE_AUTHORIZE,
    IDCELL_STAGE_BIND,
    IDCELL_STAGE_RUNNING
} idcell_stage_t;

/* 一个能力点的协商结果（绑定契约 per_point 的运行时形态） */
typedef struct {
    uint16_t cap_index;      /* 能力点索引（恒为提供方口径） */
    uint16_t my_cap_idx;     /* 本节点 caps 数组下标；需求方侧为 0xFFFF */
    uint8_t  sub;
    uint8_t  perm;           /* 授予的实权限等级 */
    uint8_t  prov;           /* 允许的来源等级 */
    uint8_t  degrade;        /* 失效行为 fail_action */
    uint8_t  qty;            /* v0.8：量种 ID（换算走量种优先路径） */
    uint8_t  dtype;          /* v0.9：协商出的值类型 */
    uint8_t  scale_exp;      /* v0.9：协商出的定点缩放指数 */
    uint64_t schema_id;
    uint16_t schema_ref;
    uint8_t  schema_digest[32];
    char     unit[IDCELL_MAX_UNIT];      /* 协商后的单位 */
    char     src_unit[IDCELL_MAX_UNIT];  /* 提供方原生单位（转换前） */
    uint32_t t_prod_ms;      /* T_prod 提供方周期下限 */
    uint32_t t_want_ms;      /* T_want 需求方期望周期 */
    uint32_t t_pub_ms;       /* 协商结果 T_pub */
    uint32_t ttl_ms;         /* 数据保鲜上限 T_stale */
    uint32_t last_pub_ms;    /* 上次发布时刻（每个能力点各自计时） */
    uint8_t  subscribed;
    /* 消费侧最新值缓存 */
    double   last_value;
    uint64_t last_ts_us;
    uint8_t  value_valid;
} idcell_pt_t;

typedef struct {
    uint8_t    valid;
    uint8_t    key[32];
    uint8_t    key_id[16];
    uint64_t   session_id;
    /* 仅接收方向：bit0=max_seq，bit i=max_seq-i；随 key/session 一起轮换。 */
    uint8_t    rx_window_valid;
    uint16_t   rx_max_seq;
    uint64_t   rx_window;
} idcell_session_key_t;

/* HMAC 成功后调用；重复、超过 63 帧的旧 SEQ 和有界半环歧义均拒绝。 */
int idcell_replay_accept(idcell_session_key_t *key, uint16_t seq);

typedef struct {
    int        used;
    idcell_did_t did;
    uint32_t   desc_version;
    uint16_t   cap_count;
    idcell_cap_store_t caps[IDCELL_MAX_PEER_CAPS];

    /* 对端可读名（HELLO 帧带来的摘要），主机侧据此按名选设备 */
    char       peer_label[IDCELL_MAX_LABEL];
    char       peer_vendor[IDCELL_MAX_LABEL];

    /*
     * 角色判别：0 = 未定，1 = 我方是提供方，2 = 我方是需求方。
     * 协议本体没有 master/slave 角色，但实现层必须知道同一条 AUTH/BIND
     * 帧在自己这边是「应答」还是「请求」，否则无法分派。
     */
    uint8_t    role;

    idcell_stage_t stage;       /* 我方对该对端的管道进度 */
    idcell_stage_t peer_stage;  /* 对端报告的管道进度 */
    uint8_t    peer_perm;       /* 我授予对方的实权限 */
    uint8_t    granted_own_perm;/* 对方授予我方的实权限 */
    uint16_t   txn;             /* 我方发起的当前事务号 */

    /* active 数据面与 pending 协商面完全分离，重协商完成前旧契约继续服务。 */
    uint8_t    pt_count;
    idcell_pt_t pts[IDCELL_MAX_MATCH_PTS];
    uint8_t    pending_pt_count;
    idcell_pt_t pending_pts[IDCELL_MAX_MATCH_PTS];

    /* 契约 */
    int        has_contract;
    idcell_contract_t contract;
    idcell_contract_t pending_contract;
    idcell_bind_phase_t bind_phase;
    uint64_t   trusted_authority_id;
    uint64_t   grant_epoch_floor;
    uint64_t   authority_epoch_floor;
    uint64_t   member_epoch_floor;
    uint8_t    commit_waiting;
    uint8_t    renegotiating;
    uint32_t   reneg_old_binding;
    uint64_t   reneg_old_session;
    uint64_t   reneg_old_grant;

    /* 租约（我方持有的写权） */
    uint32_t   owner_token;
    uint32_t   lease_deadline_ms;
    uint32_t   my_arb_domain;

    /* 三时钟：收包时刻 / 心跳发送时刻 / 周期发布时刻（互不串扰） */
    uint32_t   last_rx_ms;
    uint32_t   last_hb_ms;
    uint32_t   last_pub_ms;
    uint32_t   last_hello_ms;   /* 最近一次向该对端发 HELLO 的时刻 */
    uint8_t    labeled;         /* 已拿到对端可读名（可用于按名选设备） */
    uint8_t    presence_seen;   /* 已收到合法帧，与 asleep/offline 分开记录 */
    uint8_t    asleep;          /* 对端声明的休眠状态 */
    uint8_t    wake_profile;
    uint8_t    recovery;        /* 唤醒后旧租约失效，等待重协商 */
    uint8_t    suspended;       /* 睡眠/OFFLINE 挂起，绝不能视为 active */
    uint8_t    offline;         /* 显式 FT_OFFLINE，仅有效 CHECK-IN/HELLO 可恢复 presence */
    uint32_t   checkin_ms;
    uint32_t   max_wake_latency_ms;

    /* v0.12：单跳时钟测量（§26.3）。每对端至多一次未决测量。 */
    uint8_t    meas_pending;
    uint8_t    meas_valid;
    uint16_t   meas_txn;
    uint64_t   meas_t0_ns;          /* 发起端本地发出时刻 */
    uint64_t   meas_counter;        /* 对端回传的计数原值 */
    uint32_t   meas_tick_ns;
    uint16_t   meas_epoch;
    uint8_t    meas_quality;
    uint64_t   meas_rtt_ns;
    int64_t    meas_offset_ns;
    uint32_t   meas_uncertainty_ns;

    /* 重试与拉取节拍 */
    uint32_t   next_retry_ms;   /* 管道重试节拍 */
    uint8_t    asked_desc;      /* 已向该对端拉取过描述符 */

    /* 挑战-响应 */
    uint8_t    auth_nonce[16];
    uint8_t    auth_nonce_valid;
    uint8_t    auth_used[16];
    uint8_t    auth_used_valid;
    uint16_t   auth_txn;
    /* active 服务运行期；bind 服务 AUTH 后的 BIND；next 仅在 COMMIT 前保留。 */
    idcell_session_key_t active_key;
    idcell_session_key_t bind_key;
    idcell_session_key_t next_key;
    uint8_t    authorized_digest[32];
    uint8_t    authorized_desc_valid;

    /* 未决写请求：写是异步的，最终裁决由提供方给出 */
    uint8_t    write_pending;
    uint16_t   write_txn;
    uint16_t   write_index;
    uint8_t    write_sub;
    double     write_value;
    uint64_t   write_command_id;
    uint32_t   write_binding;
    uint64_t   write_session;
    uint64_t   write_grant;
    uint64_t   write_authority;
    uint64_t   write_authority_epoch;
    uint64_t   write_member_epoch;
    uint64_t   rx_command_id;
    uint32_t   rx_binding;
    uint64_t   rx_session;
    uint64_t   rx_grant;
    uint64_t   rx_authority;
    uint64_t   rx_authority_epoch;
    uint64_t   rx_member_epoch;
    uint16_t   rx_txn;
} idcell_peer_t;

typedef struct {
    uint8_t used;
    uint32_t arb_domain;
    idcell_did_t owner;
    uint64_t session_id;
    uint64_t grant_epoch;
    uint32_t owner_token;
    uint64_t authority_id;
    uint64_t authority_epoch;
    uint64_t member_epoch;
    uint32_t deadline_ms;
} idcell_active_grant_t;

#define IDCELL_WRITE_QUEUE 8

typedef struct {
    uint8_t used;
    idcell_frame_t frame;
    uint32_t first_rx_ms;
    uint32_t deadline_ms;
} idcell_queued_write_t;

typedef struct {
    uint8_t used;
    idcell_did_t peer;
    uint32_t binding_id;
    uint64_t session_id;
    uint64_t command_id;
    uint64_t fingerprint;
    uint64_t age;
} idcell_command_done_t;

#ifndef IDCELL_DISCOVERY_CACHE
#define IDCELL_DISCOVERY_CACHE 16
#endif
#ifndef IDCELL_DISCOVERY_RESPONSES
#define IDCELL_DISCOVERY_RESPONSES 8
#endif

typedef struct {
    uint8_t used;
    idcell_did_t originator;
    uint64_t query_id;
    uint32_t expires_ms;
    uint64_t age;
    uint8_t response_done;   /* 本地 HELLO 已排队或明确无需响应 */
} idcell_discovery_seen_t;

typedef struct {
    uint8_t used;
    idcell_did_t dst;
    idcell_did_t originator;
    uint64_t query_id;
    uint32_t due_ms;
    uint8_t probe_response;
    uint8_t attempts;
} idcell_discovery_response_t;

typedef struct {
    uint8_t used;
    uint64_t query_id;
    uint64_t age;
} idcell_pending_probe_t;

struct idcell_node {
    idcell_node_cfg_t cfg;
    idcell_transport_t tr;
    int         has_tr;
    /* 所有流式传输共用的持久重组缓冲；半帧可跨多次 recv/poll 保留。 */
    uint8_t     rx_buf[IDCELL_MAX_FRAME];
    size_t      rx_len;
    idcell_link_profile_t profile;
    int         has_profile;

    idcell_capability_t caps[IDCELL_MAX_CAPS];
    uint16_t    cap_count;
    idcell_requirement_t reqs[IDCELL_MAX_REQS];
    uint16_t    req_count;
    idcell_device_type_t dev_type;
    int         has_dev_type;

    uint32_t    desc_version;
    uint16_t    seq;
    uint32_t    now_ms;
    uint64_t    ts_us;

    idcell_peer_t peers[IDCELL_MAX_PEERS];

    idcell_value_fn value_fn;
    void          *value_ud;
    idcell_quality_fn quality_fn;   /* v0.8：质量码来源（可选） */
    void          *quality_ud;
    idcell_clock_fn clock_fn;       /* v0.12：时钟服务点来源（可选） */
    void          *clock_ud;
    idcell_set_fn   set_fn;
    void          *set_ud;
    idcell_data_fn  data_fn;
    void          *data_ud;
    idcell_event_fn event_fn;
    void          *event_ud;
    idcell_write_result_fn wres_fn;
    void          *wres_ud;

    /* 发起方状态 */
    uint32_t    next_discover_ms;
    uint32_t    announce_failures;
    uint32_t    announce_count;
    uint8_t     announce_started;
    uint8_t     announce_confirmed;
    idcell_discovery_seen_t discovery_seen[IDCELL_DISCOVERY_CACHE];
    uint64_t    discovery_age;
    uint32_t    descriptor_fetches;
    uint8_t     last_probe_err;
    idcell_discovery_response_t discovery_responses[IDCELL_DISCOVERY_RESPONSES];
    uint32_t    next_response_ms;
    idcell_pending_probe_t pending_probes[IDCELL_DISCOVERY_CACHE];
    uint64_t    pending_probe_age;
    idcell_did_t pending_peer;
    int         pending_valid;

    /* 目标设备可读名：限定管道只与它推进（主机侧按名选设备） */
    char        target_label[IDCELL_MAX_LABEL];

    /* 发布调度（提供方侧） */
    uint64_t    last_pub_ts[IDCELL_MAX_CAPS];
    uint8_t     pub_valid[IDCELL_MAX_CAPS];
    uint32_t    next_publish_ms;

    /* 随机源（挑战生成用） */
    uint64_t    rnd;
    uint32_t    owner_token_counter;
    uint64_t    command_counter;
    uint64_t    grant_epoch_counter;
    uint64_t    authority_id;
    uint64_t    trusted_authority_id;
    uint64_t    authority_epoch_floor;
    uint64_t    member_epoch_floor;
    uint64_t    grant_fingerprint;
    uint64_t    command_age;
    idcell_schema_def_t schemas[IDCELL_MAX_SCHEMAS];
    uint8_t     schema_used[IDCELL_MAX_SCHEMAS];
    idcell_command_done_t completed[IDCELL_COMMAND_CACHE];
    idcell_active_grant_t grants[IDCELL_MAX_GRANTS];
    idcell_queued_write_t write_queue[IDCELL_WRITE_QUEUE];
    uint8_t     write_queue_count;
    uint8_t     asleep;
    uint32_t    wake_deadline_ms;
    uint32_t    next_checkin_ms;
    uint32_t    wake_window_start_ms;
    uint16_t    wake_events_used;
    uint8_t     last_err;
};

/* ---------------------------------------------------------------- 跨文件共享原语 */
/* 仅限本实现内部使用，不进入公开头文件 */

int  node_send(idcell_node_t *n, uint8_t type, const idcell_did_t *dst,
               uint16_t group, uint16_t txn, const uint8_t *payload, uint16_t plen);
int  node_send_from(idcell_node_t *n, uint8_t type, const idcell_did_t *src,
                    const idcell_did_t *dst, uint16_t group, uint16_t txn,
                    const uint8_t *payload, uint16_t plen);
void node_send_error(idcell_node_t *n, const idcell_did_t *dst, uint16_t txn,
                     idcell_err_t code, const char *object,
                     int required_perm, int current_perm, const char *reason);
/* E_RANGE 专用：错误体 MUST 携带值域与实际值（FR-035） */
void node_send_range_error(idcell_node_t *n, const idcell_did_t *dst, uint16_t txn,
                           const char *object, uint16_t index,
                           double lo, double hi, double value);
idcell_peer_t *peer_get_or_add(idcell_node_t *n, const idcell_did_t *did);
int  find_match(const idcell_node_t *n, const idcell_requirement_t *req,
                const char **why);
void idcell_schema_digest(idcell_schema_def_t *def);
uint64_t idcell_contract_fingerprint(const idcell_contract_t *contract);
int node_schema_select(idcell_node_t *n, const idcell_capability_t *cap,
                       const idcell_requirement_t *req, idcell_type_t type,
                       const char *unit, uint64_t *schema_id);
int node_schema_verify(idcell_node_t *n, uint64_t schema_id,
                       idcell_type_t type, const char *unit);
/* 一致性测试注入真实收帧路径；不进入公开 API。 */
void node_test_handle_frame(idcell_node_t *n, const idcell_frame_t *f);
void node_test_receive_frame(idcell_node_t *n, const idcell_frame_t *f);

#endif /* IDCELL_INTERNAL_H */
