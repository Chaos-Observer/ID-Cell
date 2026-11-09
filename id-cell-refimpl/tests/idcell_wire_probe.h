/*
 * ID-CELL · 一致性套件线缆探针（v0.11 新增）
 * ============================================================================
 *
 * 这个文件解决的是 §15.7 第二个待拍板项暴露的问题：
 *
 *   「参考实现当前的自测已在链路上做部分断言，但仍有相当比例是内部函数级
 *    断言，这一比例需要在 M5 前压到可接受水平。」
 *
 * 为什么这是个真问题。普通自测断言的是「我调自己的函数，得到我预期的返回值」
 * ——它验证的是**自洽性**，不是**符合性**。第三方实现拿这套断言无从对照，
 * 因为断言里嵌着参考实现的内部结构（cap_store、peer、pt 数组、契约结构体）。
 * 一套只能验证「参考实现符合参考实现」的套件，对生态没有价值。
 *
 * 本文件给出的替代路径是**黑盒断言**：断言的对象是链路上真实出现过的字节，
 * 而判定这些字节的工具（帧解析器、CRC 计算器）必须**独立于参考实现重新实现
 * 一遍**。因此：
 *
 *   - 若参考实现的编码与 §09.1 字段表不一致 → 独立解析器读出乱值 → 断言失败；
 *   - 若参考实现的 CRC 覆盖范围写错 → 独立 CRC 算出的值对不上 → 断言失败；
 *   - 若参考实现改了语义却忘了同步 §09.1 → 本文件里的常量与规范脱节，
 *     评审时一眼可见（这正是它存在的价值）。
 *
 * 刻意不做的事：
 *   - 不 include "idcell_internal.h"。本文件 MUST NOT 依赖参考实现的任何
 *     内部符号，否则「独立」二字立即失效。
 *   - 不复用 idcell_frame_decode / idcell_crc16。哪怕是逐行照抄也要重写，
 *     因为「照抄」在实践中会随参考实现一起漂移——那正是要避免的。
 *   - 不访问节点内部状态。探针只看线上字节。
 *
 * 探针的挂接方式是**传输层包装**（tap）：它实现 idcell_transport_t 的
 * send/recv，在转发字节的同时把副本记进环形缓冲。因此它对协议栈完全透明，
 * 被测对象不知道自己在被观测——这是黑盒断言的前提。
 *
 * 方向分离是关键设计。一条链路有两个方向的字节流：TX（本端发出）与 RX
 * （本端收到）。二者 MUST 分开记录，否则：
 *   · SEQ 断言会失败——SEQ 是**每方向独立**递增的（§09.1），混流后必然交错；
 *   · SRC / DST 断言会失败——混流后一半帧的 SRC 是对端的 DID。
 * 这两条不是断言写错，而是探针的职责要求——探针要还原「线上发生了什么」，
 * 而「方向」正是线上事实的一部分。
 *
 * 适用范围：v1 的帧结构（§09.1）与 CRC-16/CCITT-FALSE（§08.12）。
 * 若未来 §09.1 冻结物变更，MUST 先改本文件，再改参考实现。
 */
#ifndef IDCELL_WIRE_PROBE_H
#define IDCELL_WIRE_PROBE_H

#include "idcell.h"
#include "idcell_transport.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * 头文件里的工具函数大多是「按需取用」的：某个套件文件可能只用到其中几个。
 * 若不加此标注，每个只用到部分函数的编译单元都会收到 unused-function 警告。
 */
#if defined(__GNUC__) || defined(__clang__)
#  define IDWP_UNUSED __attribute__((unused))
#else
#  define IDWP_UNUSED
#endif

/* ---------------------------------------------------------------- 探针容量 */

#define IDWP_RING_CAP   16384   /* 单方向环形缓冲容量（字节） */
#define IDWP_FRAME_CAP  1600    /* 单帧最大字节数 */
#define IDWP_MAX_FRAMES 64      /* 单方向最多保留的帧记录数 */

/* ---------------------------------------------------------------- 线上常量 */

/*
 * 以下常量直接抄自 §09.1 帧字段表与 §08.12。
 * 它们是「规范的物理布局」，不是「参考实现的选择」——所以放在探针里而不是
 * 从参考实现 include 进来，正是为了让两者一旦脱节就能被发现。
 */
#define IDWP_SYNC0        0xA5
#define IDWP_SYNC1        0xA5
#define IDWP_TRAIL0       0x5A
#define IDWP_TRAIL1       0xA5

#define IDWP_OFF_SYNC     0
#define IDWP_OFF_VER      2
#define IDWP_OFF_PROF     3
#define IDWP_OFF_FLAGS    4
#define IDWP_OFF_TYPE     5
#define IDWP_OFF_SEQ      6
#define IDWP_OFF_TXN      8
#define IDWP_OFF_LEN      10
#define IDWP_OFF_SRC      12
#define IDWP_OFF_DST      20
#define IDWP_OFF_GROUP    28
#define IDWP_OFF_TS       30
#define IDWP_HDR_LEN      36
#define IDWP_AUTH_FLAG    0x20
#define IDWP_AUTH_TAG_LEN 16
#define IDWP_TRAILER_LEN  4
#define IDWP_TLV_HDR_LEN  6

/* 广播地址：8 字节全 0xFF（§09.1 的 DST 为广播时的取值） */
#define IDWP_BROADCAST_BYTE 0xFF

/*
 * 帧类型（§09.4 帧清单）。
 * 这些值抄自规范，不是从参考实现 include 来的——正是这一点让
 * 「参考实现的帧类型与规范脱节」成为可被发现的问题。
 */
#define IDWP_T_DISCOVER   0x01
#define IDWP_T_HELLO      0x02
#define IDWP_T_MATCH      0x03
#define IDWP_T_NEGOTIATE  0x04
#define IDWP_T_RENEG      0x05
#define IDWP_T_AUTH       0x06
#define IDWP_T_BIND       0x07
#define IDWP_T_READ       0x08
#define IDWP_T_WRITE      0x09
#define IDWP_T_SUBSCRIBE  0x0A
#define IDWP_T_UNSUB      0x0B
#define IDWP_T_EVENT      0x0C
#define IDWP_T_CMD        0x0D
#define IDWP_T_ACK        0x0E
#define IDWP_T_DONE       0x0F
#define IDWP_T_LEASE      0x10
#define IDWP_T_PREEMPT    0x11
#define IDWP_T_GROUP      0x12
#define IDWP_T_HEARTBEAT  0x13
#define IDWP_T_OFFLINE    0x14
#define IDWP_T_STALE      0x15
#define IDWP_T_CONFIG     0x16
#define IDWP_T_PROVISION  0x17
#define IDWP_T_ERROR      0x18

/* TLV 类型（§04.2 / §09.2 / §09.6）——探针只关心这几类被断言的 */
#define IDWP_TLV_CAP_DESC   0x20
#define IDWP_TLV_REQ_DESC   0x21
#define IDWP_TLV_MATCH_RES  0x22
#define IDWP_TLV_NEG_RESULT 0x23
#define IDWP_TLV_CONTRACT   0x24
#define IDWP_TLV_ERR_BODY   0x25
#define IDWP_TLV_VALUE      0x28
#define IDWP_TLV_INTENT     0x29
#define IDWP_TLV_OWNER      0x2A
#define IDWP_TLV_RESULT     0x34
#define IDWP_TLV_BIND_ID    0x36
/* v0.12：时钟服务点计数回传（§26.2），15 字节定长 */
#define IDWP_TLV_CLOCK       0x5B
#define IDWP_TLV_ERR_CODE    0x70
#define IDWP_TLV_ERR_REASON  0x74
#define IDWP_TLV_ERR_RANGE_LO 0x76
#define IDWP_TLV_ERR_RANGE_HI 0x77
#define IDWP_TLV_ERR_VALUE   0x78

/* 能力描述符字段（§09.2） */
#define IDWP_CF_LABEL     0x40
#define IDWP_CF_KIND      0x41
#define IDWP_CF_DIR       0x42
#define IDWP_CF_PERM      0x43
#define IDWP_CF_DIM       0x44
#define IDWP_CF_UNIT      0x45
#define IDWP_CF_ACCEPT    0x46
#define IDWP_CF_CONV      0x47
#define IDWP_CF_RANGE     0x48
#define IDWP_CF_PRECISION 0x49
#define IDWP_CF_MINSYNC   0x4C
#define IDWP_CF_STALE     0x4D
#define IDWP_CF_FAIL      0x51
#define IDWP_CF_DTYPE     0x55
#define IDWP_CF_SCALE     0x56
#define IDWP_CF_ACCEPT_T  0x57

/* ---------------------------------------------------------------- 帧视图 */

/*
 * 探针对线上字节的解析结果。它刻意**不与 idcell_frame_t 同构**——
 * 同构会诱使实现者顺手复用参考实现的结构体，独立才有独立的价值。
 */
typedef struct {
    uint8_t  ver;
    uint8_t  prof;
    uint8_t  flags;
    uint8_t  type;
    uint16_t seq;
    uint16_t txn;
    uint8_t  src[8];
    uint8_t  dst[8];
    uint16_t group;
    uint64_t ts_us;
    const uint8_t *payload;      /* 指向流内部的帧缓冲，下一帧覆盖 */
    uint16_t payload_len;
    const uint8_t *auth_tag;
    uint8_t  auth_tag_len;
    uint16_t crc_expect;         /* 线上携带的 CRC */
    uint16_t crc_calc;           /* 探针独立算出的 CRC */
    int      crc_ok;
    uint16_t raw_len;            /* 该帧的总字节数 */
} idwp_frame_t;

/* TLV 视图 */
typedef struct {
    uint16_t idx;
    uint8_t  sub;
    uint8_t  type;
    uint16_t len;
    const uint8_t *val;
} idwp_tlv_t;

/* ---------------------------------------------------------------- CRC */

/*
 * CRC-16/CCITT-FALSE：poly=0x1021 init=0xFFFF refin=false refout=false
 * xorout=0x0000。v0.11 覆盖 36B 头 + payload + 可选 AUTH_TAG。
 *
 * 独立实现，不调用 idcell_crc16——见文件头的说明。
 */
static IDWP_UNUSED uint16_t idwp_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    size_t i;
    int b;

    for (i = 0; i < len; i++) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (b = 0; b < 8; b++) {
            if (crc & 0x8000) crc = (uint16_t)((crc << 1) ^ 0x1021);
            else              crc = (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* ---------------------------------------------------------------- 字节序 */

static IDWP_UNUSED uint16_t idwp_get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static IDWP_UNUSED uint32_t idwp_get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static IDWP_UNUSED uint64_t idwp_get_u64(const uint8_t *p)
{
    return ((uint64_t)idwp_get_u32(p) << 32) | idwp_get_u32(p + 4);
}

static double idwp_get_f64(const uint8_t *p)
{
    uint64_t bits = idwp_get_u64(p);
    double v;
    memcpy(&v, &bits, sizeof(v));
    return v;
}

/* ---------------------------------------------------------------- 字节流 */

/*
 * 一个方向的线上字节流。
 *
 * 它同时承担三件事：保存字节、提供解析游标、保存已解出的帧历史。
 * 帧的原始字节存在流自己的缓冲里，因此解析结果的生命周期与流一致——
 * 不会因为「解析函数的栈帧已返回」而指向失效内存。
 */
typedef struct {
    uint8_t  ring[IDWP_RING_CAP];
    size_t   rd;                   /* 环形读位置 */
    size_t   wr;                  /* 环形写位置 */
    /* 解析游标：已消费但尚未解帧的字节数（从 rd 起算） */
    size_t   scan;
    /* 已解出的帧：原始字节 + 头部视图 */
    uint8_t  frame[IDWP_MAX_FRAMES][IDWP_FRAME_CAP];
    uint16_t frame_len[IDWP_MAX_FRAMES];
    int      frame_count;
    /* 最近一帧的原始字节（逐字节断言用；下一帧覆盖） */
    uint8_t  last[IDWP_FRAME_CAP];
    uint16_t last_len;
} idwp_stream_t;

/* 环形缓冲写入：满了就丢弃最旧的 */
static IDWP_UNUSED void idwp_ring_write(idwp_stream_t *s, const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        size_t next = s->wr + 1;
        if (next >= IDWP_RING_CAP) next = 0;
        if (next == s->rd) {
            s->rd = (s->rd + 1 >= IDWP_RING_CAP) ? 0 : s->rd + 1;
            /* 丢弃了最旧的字节，解析游标必须同步前移，否则会解出半个帧 */
            if (s->scan > 0) s->scan--;
        }
        s->ring[s->wr] = buf[i];
        s->wr = next;
    }
}

/* 字节流中尚未解析的字节数 */
static IDWP_UNUSED size_t idwp_avail(const idwp_stream_t *s)
{
    size_t total = (s->wr >= s->rd) ? (s->wr - s->rd) : (IDWP_RING_CAP - s->rd + s->wr);
    return total - s->scan;
}

/* ---------------------------------------------------------------- 帧解析 */

/*
 * v0.11：只按固定头 LEN 确定边界，绝不扫描 CRC/TRAILER 猜 payload 末尾。
 * 返回 1 成功；0 数据不足；-1 非法头或 TRAILER。
 */
static IDWP_UNUSED int idwp_parse_frame(const uint8_t *in, size_t len, idwp_frame_t *out)
{
    uint16_t payload_len;
    size_t tag_len, total, crc_at;

    if (len == 0) return 0;
    if (in[0] != IDWP_SYNC0) return -1;
    if (len == 1) return 0;
    if (in[1] != IDWP_SYNC1) return -1;
    if (len < (size_t)IDWP_HDR_LEN) return 0;

    payload_len = idwp_get_u16(in + IDWP_OFF_LEN);
    tag_len = (in[IDWP_OFF_FLAGS] & IDWP_AUTH_FLAG) ? IDWP_AUTH_TAG_LEN : 0;
    if ((size_t)payload_len + tag_len + IDWP_HDR_LEN + IDWP_TRAILER_LEN > IDWP_FRAME_CAP)
        return -1;
    total = IDWP_HDR_LEN + payload_len + tag_len + IDWP_TRAILER_LEN;
    if (len < total) return 0;
    if (in[total - 2] != IDWP_TRAIL0 || in[total - 1] != IDWP_TRAIL1) return -1;

    out->ver      = in[IDWP_OFF_VER];
    out->prof     = in[IDWP_OFF_PROF];
    out->flags    = in[IDWP_OFF_FLAGS];
    out->type     = in[IDWP_OFF_TYPE];
    out->seq      = idwp_get_u16(in + IDWP_OFF_SEQ);
    out->txn      = idwp_get_u16(in + IDWP_OFF_TXN);
    memcpy(out->src, in + IDWP_OFF_SRC, 8);
    memcpy(out->dst, in + IDWP_OFF_DST, 8);
    out->group    = idwp_get_u16(in + IDWP_OFF_GROUP);
    out->ts_us    = ((uint64_t)idwp_get_u32(in + IDWP_OFF_TS) << 16) |
                    idwp_get_u16(in + IDWP_OFF_TS + 4);
    out->payload_len = payload_len;
    out->auth_tag_len = (uint8_t)tag_len;
    crc_at = total - IDWP_TRAILER_LEN;
    out->crc_expect  = idwp_get_u16(in + crc_at);
    out->crc_calc    = idwp_crc16(in, crc_at);
    out->crc_ok      = (out->crc_expect == out->crc_calc);
    out->raw_len     = (uint16_t)total;
    return 1;
}

/* ---------------------------------------------------------------- 流操作 */

/*
 * 从字节流中提取下一帧。
 * 返回 1 找到；0 字节不足。
 *
 * 抽出的帧的原始字节保存在 s->last / s->last_len，
 * 供调用方做逐字节断言（下一帧会覆盖）。
 */
static IDWP_UNUSED int idwp_stream_next(idwp_stream_t *s, idwp_frame_t *out)
{
    uint8_t tmp[IDWP_FRAME_CAP + 256];
    size_t n = idwp_avail(s);
    size_t i;
    size_t flen;

    if (n == 0) return 0;
    if (n > sizeof(tmp)) n = sizeof(tmp);

    for (i = 0; i < n; i++) {
        size_t p = (s->rd + s->scan + i) % IDWP_RING_CAP;
        tmp[i] = s->ring[p];
    }

    if (idwp_parse_frame(tmp, n, out) != 1) return 0;

    flen = out->raw_len;

    /* 记下原始字节 */
    if (flen <= sizeof(s->last)) {
        memcpy(s->last, tmp, flen);
        s->last_len = (uint16_t)flen;
        /* 载荷指针必须指向流内部的缓冲——tmp 是栈上的临时区，返回后即失效 */
        out->payload = s->last + IDWP_HDR_LEN;
        out->auth_tag = s->last + IDWP_HDR_LEN + out->payload_len;
    } else {
        s->last_len = 0;
        out->payload = NULL;
        out->auth_tag = NULL;
    }

    /* 帧历史 */
    if (s->frame_count < IDWP_MAX_FRAMES && flen <= IDWP_FRAME_CAP) {
        memcpy(s->frame[s->frame_count], tmp, flen);
        s->frame_len[s->frame_count] = (uint16_t)flen;
        s->frame_count++;
    }

    /* 消费这一帧 */
    s->scan += flen;
    return 1;
}

/* TLV 遍历：返回 0 成功，1 正常结束，-1 截断 */
static IDWP_UNUSED int idwp_tlv_next(const uint8_t *buf, uint16_t len, uint16_t *pos, idwp_tlv_t *out)
{
    uint16_t p = *pos;

    if (p == len) return 1;
    if ((uint32_t)p + IDWP_TLV_HDR_LEN > len) return -1;

    out->idx  = idwp_get_u16(buf + p);
    out->sub  = buf[p + 2];
    out->type = buf[p + 3];
    out->len  = idwp_get_u16(buf + p + 4);
    if ((uint32_t)p + IDWP_TLV_HDR_LEN + out->len > len) return -1;
    out->val = buf + p + IDWP_TLV_HDR_LEN;
    *pos = (uint16_t)(p + IDWP_TLV_HDR_LEN + out->len);
    return 0;
}

/*
 * 在一段载荷里查找首个指定类型的 TLV。
 * 找到返回 1，未找到返回 0。
 */
static IDWP_UNUSED int idwp_payload_find_tlv(const uint8_t *payload, uint16_t len,
                                 uint8_t type, idwp_tlv_t *out)
{
    uint16_t pos = 0;
    idwp_tlv_t t;

    while (idwp_tlv_next(payload, len, &pos, &t) == 0) {
        if (t.type == type) {
            if (out) *out = t;
            return 1;
        }
    }
    return 0;
}

/*
 * 在一段载荷里统计指定类型的 TLV 出现次数。
 *
 * 注意：idwp_count_tlv 与 idwp_count_frames 会消费流（它们内部调用
 * idwp_stream_next / idwp_tlv_next 推进游标）。若要统计多种类型，
 * 优先用 idwp_count_all（帧级）或自己遍历一次并同时计数——
 * 多次调用消费型函数会得到全零结果。
 */
static IDWP_UNUSED int idwp_payload_count_tlv(const uint8_t *payload, uint16_t len, uint8_t type)
{
    uint16_t pos = 0;
    idwp_tlv_t t;
    int n = 0;

    while (idwp_tlv_next(payload, len, &pos, &t) == 0) {
        if (t.type == type) n++;
    }
    return n;
}

/* ---------------------------------------------------------------- 传输包装 */

/*
 * 一条被观测的链路。tap 把它挂在真实传输之上：
 * 字节先过 tap（记副本），再交给真实传输。
 *
 * tx / rx 分开：方向是线上事实的一部分（§09.1 的 SEQ 每方向独立）。
 */
typedef struct {
    idcell_transport_t  tap;        /* 交给协议栈的传输（send/recv 指向 tap） */
    idcell_transport_t  inner;      /* 底层真实传输 */
    idwp_stream_t       tx;         /* 本端发出的字节 */
    idwp_stream_t       rx;         /* 本端收到的字节 */
} idwp_link_t;

static IDWP_UNUSED int idwp_tap_send(void *ctx, const uint8_t *buf, size_t len)
{
    idwp_link_t *lk = (idwp_link_t *)ctx;
    int rc;

    idwp_ring_write(&lk->tx, buf, len);
    if (lk->inner.send) rc = lk->inner.send(lk->inner.ctx, buf, len);
    else rc = -1;
    return rc;
}

static IDWP_UNUSED int idwp_tap_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    idwp_link_t *lk = (idwp_link_t *)ctx;
    int n;

    if (lk->inner.recv) n = lk->inner.recv(lk->inner.ctx, buf, cap, timeout_ms);
    else n = -1;
    if (n > 0) idwp_ring_write(&lk->rx, buf, (size_t)n);
    return n;
}

/*
 * 初始化一条被观测的链路。
 * inner  : 底层真实传输（不修改它）
 * out    : 输出交给协议栈的传输（其 profile 沿用 inner 的）
 */
static IDWP_UNUSED void idwp_link_init(idwp_link_t *lk, const idcell_transport_t *inner)
{
    memset(lk, 0, sizeof(*lk));
    lk->inner = *inner;
    lk->tap.send    = idwp_tap_send;
    lk->tap.recv    = idwp_tap_recv;
    lk->tap.profile = inner->profile;
    lk->tap.ctx     = lk;
}

/* ---------------------------------------------------------------- 检索 */

/*
 * 在指定方向的流里检索第一帧指定类型的帧。
 * 找不到返回 0。
 *
 * 注意：下一帧会覆盖 s->last / s->last_len，因此调用方须立即使用。
 */
static IDWP_UNUSED int idwp_find_frame(idwp_stream_t *s, uint8_t type, idwp_frame_t *out)
{
    idwp_frame_t f;

    while (idwp_stream_next(s, &f)) {
        if (f.type == type) {
            *out = f;
            return 1;
        }
    }
    return 0;
}

/* 统计指定方向的流里某类型帧出现次数 */
static IDWP_UNUSED int idwp_count_frames(idwp_stream_t *s, uint8_t type)
{
    idwp_frame_t f;
    int n = 0;

    while (idwp_stream_next(s, &f)) {
        if (f.type == type) n++;
    }
    return n;
}

/*
 * 一次遍历统计多种帧类型的出现次数。
 *
 * 为什么不直接用 idwp_count_frames 调多次：那个函数会消费流，
 * 第二次调用时流已被前一次抽干，计数结果全为 0——这是一个
 * 极易写错且极难察觉的错误（断言会以「不存在」的形式失败，
 * 而真实原因是探针用法错误，不是协议缺陷）。
 * 因此这里提供「一次遍历、多个计数」的形态。
 *
 * counts 数组长度至少 256，下标即帧类型值。
 */
static IDWP_UNUSED void idwp_count_all(idwp_stream_t *s, unsigned counts[256])
{
    idwp_frame_t f;

    memset(counts, 0, 256 * sizeof(unsigned));
    while (idwp_stream_next(s, &f)) {
        counts[f.type]++;
    }
}

#endif /* IDCELL_WIRE_PROBE_H */
