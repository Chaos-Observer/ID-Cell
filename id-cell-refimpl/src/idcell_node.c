/*
 * ID-CELL · 节点核心：六段管道 + 运行期
 *
 * DISCOVER → DESCRIBE → MATCH → NEGOTIATE → AUTHORIZE → BIND → 运行期
 *
 * 三条贯穿全文件的红线：
 *   1. 提供方绝不用重复旧值伪装刷新（§08.5 红线二）——发布前比对时间戳
 *   2. 写操作必须携带 owner_token 与意图结构（SEC-019）
 *   3. 理解度不得直接兑换写权限（SEC-014）
 */
#include "idcell_internal.h"
#include <stdio.h>
#include <stdlib.h>

/* ---------------------------------------------------------------- 工具 */

const char *idcell_err_name(idcell_err_t e)
{
    switch (e) {
    case IDCELL_OK:           return "OK";
    case IDCELL_E_NODEV:      return "E_NODEV";
    case IDCELL_E_VER:        return "E_VER";
    case IDCELL_E_CRC:        return "E_CRC";
    case IDCELL_E_NOMATCH:    return "E_NOMATCH";
    case IDCELL_E_CONV:       return "E_CONV";
    case IDCELL_E_NEGOTIATE:  return "E_NEGOTIATE";
    case IDCELL_E_PERM:       return "E_PERM";
    case IDCELL_E_UNSAFE:     return "E_UNSAFE";
    case IDCELL_E_LEASE:      return "E_LEASE";
    case IDCELL_E_RANGE:      return "E_RANGE";
    case IDCELL_E_UNIT:       return "E_UNIT";
    case IDCELL_E_CTX:        return "E_CTX";
    case IDCELL_E_IDCONFLICT: return "E_IDCONFLICT";
    case IDCELL_E_SCOPE:      return "E_SCOPE";
    case IDCELL_E_UNAVAILABLE:return "E_UNAVAILABLE";
    case IDCELL_E_DUPLICATE:  return "E_DUPLICATE";
    case IDCELL_E_ASLEEP:     return "E_ASLEEP";
    case IDCELL_E_RX_OFF:     return "E_RX_OFF";
    case IDCELL_E_STATE:      return "E_STATE";
    }
    return "E_UNKNOWN";
}

/* §09.6：拒绝类重试无意义；不匹配类带候选值重试可能成功 */
int idcell_err_retryable(idcell_err_t e)
{
    switch (e) {
    case IDCELL_E_NOMATCH:
    case IDCELL_E_NEGOTIATE:
    case IDCELL_E_LEASE:
        return 1;
    default:
        return 0;
    }
}

const char *idcell_frametype_name(uint8_t t)
{
    switch (t) {
    case IDCELL_FT_DISCOVER:    return "DISCOVER";
    case IDCELL_FT_HELLO:       return "HELLO";
    case IDCELL_FT_MATCH:       return "MATCH";
    case IDCELL_FT_NEGOTIATE:   return "NEGOTIATE";
    case IDCELL_FT_RENEGOTIATE: return "RENEGOTIATE";
    case IDCELL_FT_AUTH:        return "AUTH";
    case IDCELL_FT_BIND:        return "BIND";
    case IDCELL_FT_READ:        return "READ";
    case IDCELL_FT_WRITE:       return "WRITE";
    case IDCELL_FT_SUBSCRIBE:   return "SUBSCRIBE";
    case IDCELL_FT_UNSUB:       return "UNSUB";
    case IDCELL_FT_EVENT:       return "EVENT";
    case IDCELL_FT_CMD:         return "CMD";
    case IDCELL_FT_ACK:         return "ACK";
    case IDCELL_FT_DONE:        return "DONE";
    case IDCELL_FT_LEASE:       return "LEASE";
    case IDCELL_FT_PREEMPT:     return "PREEMPT";
    case IDCELL_FT_GROUP:       return "GROUP";
    case IDCELL_FT_HEARTBEAT:   return "HEARTBEAT";
    case IDCELL_FT_OFFLINE:     return "OFFLINE";
    case IDCELL_FT_STALE:       return "STALE";
    case IDCELL_FT_CONFIG:      return "CONFIG";
    case IDCELL_FT_PROVISION:   return "PROVISION";
    case IDCELL_FT_ERROR:       return "ERROR";
    }
    return "UNKNOWN";
}

const char *idcell_media_name(idcell_media_t m)
{
    switch (m) {
    case IDCELL_MEDIA_UART:     return "UART";
    case IDCELL_MEDIA_CAN:      return "CAN";
    case IDCELL_MEDIA_BLE:      return "BLE";
    case IDCELL_MEDIA_WIFI:     return "Wi-Fi";
    case IDCELL_MEDIA_ZIGBEE:   return "ZigBee";
    case IDCELL_MEDIA_LORA:     return "LoRa";
    case IDCELL_MEDIA_SUB1G:    return "Sub-1G";
    case IDCELL_MEDIA_USB:      return "USB";
    case IDCELL_MEDIA_ETHERNET: return "Ethernet";
    case IDCELL_MEDIA_LOOPBACK: return "loopback";
    default:                    return "unknown";
    }
}

const char *idcell_topology_name(idcell_topology_t t)
{
    switch (t) {
    case IDCELL_TOPO_P2P:            return "点对点";
    case IDCELL_TOPO_MULTI_DROP:     return "一主多从轮询";
    case IDCELL_TOPO_MULTI_MASTER:   return "多主共享总线";
    case IDCELL_TOPO_STAR_HOST_PROXY:return "单主机星形";
    case IDCELL_TOPO_SWITCHED:       return "交换式广播域";
    case IDCELL_TOPO_MESH:           return "mesh 多跳";
    }
    return "unknown";
}

/* ---------------------------------------------------------------- DID */

static uint64_t splitmix64(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* 随机式 DID（FR-072）：与任何链路层标识无关 */
void idcell_did_generate(uint64_t seed, idcell_did_t *out)
{
    uint64_t s = seed ? seed : 0x123456789ABCDEFULL;
    uint64_t a = splitmix64(&s);
    uint64_t b = splitmix64(&s);
    /*
     * DID 共 64 bit = 8 字节。两次 splitmix 各产出 64 bit，这里各取高 32 bit 拼成 64 bit。
     * 注意：不能用 idcell_put_u64 写 out->b + 4 —— 那会越过 8 字节边界写坏栈。
     */
    idcell_put_u32(out->b, (uint32_t)(a >> 32));
    idcell_put_u32(out->b + 4, (uint32_t)(b >> 32));
    /* 广播/未指定地址保留全 0 / 全 F */
    if (a == 0 && b == 0) out->b[0] = 1;
}

/*
 * 厂商前缀式 DID（FR-072）：厂商前缀由注册表分配，序列号由厂商保证唯一。
 * 布局：厂商前缀 16 bit（b[0..1]）+ 序列号 48 bit（b[2..7]），合计 64 bit。
 * 前缀占 16 bit ≤ 24 bit、序号占 48 bit ≥ 40 bit，两条约束同时成立。
 */
void idcell_did_from_vendor(uint16_t vendor_prefix, uint64_t serial, idcell_did_t *out)
{
    idcell_put_u16(out->b, vendor_prefix);
    idcell_put_u16(out->b + 2, (uint16_t)(serial >> 32));
    idcell_put_u32(out->b + 4, (uint32_t)serial);
}

int idcell_did_equal(const idcell_did_t *a, const idcell_did_t *b)
{
    return memcmp(a->b, b->b, 8) == 0;
}

/*
 * DID 的文本形式：16 位大写十六进制，中间用一个连字符分组（8-8）。
 * 例：01234567-89ABCDEF —— 17 个字符 + '\0'。
 * 分组只是为了肉眼可读，不参与任何协议语义。
 */
void idcell_did_str(const idcell_did_t *d, char out[19])
{
    static const char hex[] = "0123456789ABCDEF";
    int i;
    /* 前 4 字节 → 前 8 个十六进制字符 */
    for (i = 0; i < 4; i++) {
        out[i*2]     = hex[d->b[i] >> 4];
        out[i*2 + 1] = hex[d->b[i] & 0x0F];
    }
    out[8] = '-';
    /* 后 4 字节 → 后 8 个十六进制字符 */
    for (i = 4; i < 8; i++) {
        out[9 + (i - 4)*2]     = hex[d->b[i] >> 4];
        out[9 + (i - 4)*2 + 1] = hex[d->b[i] & 0x0F];
    }
    out[17] = '\0';
}

/* ---------------------------------------------------------------- 生命周期 */

idcell_node_t *idcell_node_new(const idcell_node_cfg_t *cfg)
{
    idcell_node_t *n;
    int i;

    if (!cfg) return NULL;

    n = (idcell_node_t *)calloc(1, sizeof(idcell_node_t));
    if (!n) return NULL;

    n->cfg = *cfg;
    if (n->cfg.t_hb_ms == 0) n->cfg.t_hb_ms = 1000;
    if (n->cfg.lease_ttl_ms == 0) n->cfg.lease_ttl_ms = 3000;
    if (n->cfg.lease_ttl_ms > IDCELL_MAX_LEASE_TTL_MS)
        n->cfg.lease_ttl_ms = IDCELL_MAX_LEASE_TTL_MS;
    if (n->cfg.announce_ms == 0) n->cfg.announce_ms = 500;
    if (n->cfg.announce_ms > 86400000u) n->cfg.announce_ms = 86400000u;
    if (n->cfg.announce_retry_max_ms == 0) n->cfg.announce_retry_max_ms = 8000;
    if (n->cfg.announce_retry_max_ms > 86400000u) n->cfg.announce_retry_max_ms = 86400000u;
    if (n->cfg.announce_retry_max_ms < n->cfg.announce_ms)
        n->cfg.announce_retry_max_ms = n->cfg.announce_ms;
    if (n->cfg.announce_steady_ms == 0) n->cfg.announce_steady_ms = n->cfg.announce_ms;
    if (n->cfg.announce_steady_ms > 86400000u) n->cfg.announce_steady_ms = 86400000u;
    if (n->cfg.announce_jitter_ms == 0) n->cfg.announce_jitter_ms = n->cfg.announce_ms;
    if (n->cfg.announce_jitter_ms > 86400000u) n->cfg.announce_jitter_ms = 86400000u;
    if (n->cfg.discovery_cache_capacity == 0) n->cfg.discovery_cache_capacity = 8;
    if (n->cfg.discovery_cache_capacity > IDCELL_DISCOVERY_CACHE)
        n->cfg.discovery_cache_capacity = IDCELL_DISCOVERY_CACHE;
    if (n->cfg.discovery_cache_ttl_ms == 0) n->cfg.discovery_cache_ttl_ms = 30000;
    if (n->cfg.discovery_cache_ttl_ms > 86400000u) n->cfg.discovery_cache_ttl_ms = 86400000u;
    if (n->cfg.discovery_response_interval_ms == 0) n->cfg.discovery_response_interval_ms = 20;
    if (n->cfg.discovery_response_interval_ms > 60000u) n->cfg.discovery_response_interval_ms = 60000;
    if (n->cfg.discovery_response_jitter_ms == 0) n->cfg.discovery_response_jitter_ms = 20;
    if (n->cfg.discovery_response_jitter_ms > 60000u) n->cfg.discovery_response_jitter_ms = 60000;
    if (!n->cfg.discovery_scope[0]) snprintf(n->cfg.discovery_scope, sizeof(n->cfg.discovery_scope), "default");
    n->cfg.discovery_scope[sizeof(n->cfg.discovery_scope) - 1] = '\0';
    if (n->cfg.wake_profile > IDCELL_WAKE_RX_OFF) n->cfg.wake_profile = IDCELL_WAKE_ALWAYS_ON;
    if (n->cfg.listen_ms == 0) n->cfg.listen_ms = n->cfg.t_hb_ms;
    if (n->cfg.listen_ms > 86400000u) n->cfg.listen_ms = 86400000u;
    if (n->cfg.checkin_ms == 0)
        n->cfg.checkin_ms = n->cfg.listen_ms > 4320000u ? 86400000u : 20u * n->cfg.listen_ms;
    if (n->cfg.wake_after_ms == 0) n->cfg.wake_after_ms = n->cfg.checkin_ms;
    if (n->cfg.max_wake_latency_ms == 0) n->cfg.max_wake_latency_ms = n->cfg.wake_after_ms;
    if (n->cfg.checkin_ms > 86400000u) n->cfg.checkin_ms = 86400000u;
    if (n->cfg.wake_after_ms > 86400000u) n->cfg.wake_after_ms = 86400000u;
    if (n->cfg.max_wake_latency_ms > 86400000u) n->cfg.max_wake_latency_ms = 86400000u;
    if (n->cfg.wake_budget == 0) n->cfg.wake_budget = 4;
    if (n->cfg.wake_window_ms == 0) n->cfg.wake_window_ms = 60000;
    if (n->cfg.wake_window_ms > 86400000u) n->cfg.wake_window_ms = 86400000u;
    if (n->cfg.max_perm > IDCELL_PERM_P3) n->cfg.max_perm = IDCELL_PERM_P3;
    n->desc_version = 1;
    n->rnd = (uint64_t)n->cfg.did.b[0] ^ ((uint64_t)n->cfg.did.b[7] << 32) ^ 0xA5A5C0DEULL;
    n->authority_id = 0x49444CELL;
    for (i = 0; i < 8; i++) n->authority_id = (n->authority_id << 8) | n->cfg.did.b[i];
    for (i = 0; i < IDCELL_MAX_PEERS; i++) n->peers[i].used = 0;

    n->profile.media = IDCELL_MEDIA_UNKNOWN;
    n->profile.topology = IDCELL_TOPO_P2P;
    n->profile.t_link_min_ms = 0;
    n->profile.mtu = 0;
    n->profile.host_proxy = 0;

    return n;
}

void idcell_node_free(idcell_node_t *n)
{
    free(n);
}

int idcell_node_set_transport(idcell_node_t *n, const idcell_transport_t *t)
{
    if (!n || !t || !t->send || !t->recv) return IDCELL_E_NODEV;
    n->tr = *t;
    n->has_tr = 1;
    n->rx_len = 0;
    if (t->profile) {
        n->profile = *t->profile;
        n->has_profile = 1;
    }
    return IDCELL_OK;
}

void idcell_node_set_link_profile(idcell_node_t *n, const idcell_link_profile_t *p)
{
    if (!n || !p) return;
    n->profile = *p;
    n->has_profile = 1;
}

int idcell_node_register_capability(idcell_node_t *n, const idcell_capability_t *cap)
{
    uint16_t i;

    if (!n || !cap) return IDCELL_E_NODEV;
    if (n->cap_count >= IDCELL_MAX_CAPS) return IDCELL_E_RANGE;

    /* 索引唯一性：同一 (index, sub) 不得重复注册 */
    for (i = 0; i < n->cap_count; i++) {
        if (n->caps[i].index == cap->index && n->caps[i].sub == cap->sub)
            return IDCELL_E_IDCONFLICT;
    }

    /*
     * 红线（§19.3 X1）：能力注册 MUST NOT 依赖设备类型注册。
     * 此处刻意不检查 has_dev_type——设备类型是可选轨，不参与接入。
     */
    n->caps[n->cap_count++] = *cap;
    n->desc_version++;   /* 描述符版本单调递增（NFR-035） */
    return IDCELL_OK;
}

int idcell_node_register_requirement(idcell_node_t *n, const idcell_requirement_t *req)
{
    if (!n || !req) return IDCELL_E_NODEV;
    if (n->req_count >= IDCELL_MAX_REQS) return IDCELL_E_RANGE;
    n->reqs[n->req_count++] = *req;
    return IDCELL_OK;
}

int idcell_node_register_device_type(idcell_node_t *n, const idcell_device_type_t *dt)
{
    if (!n || !dt) return IDCELL_E_NODEV;
    n->dev_type = *dt;
    n->has_dev_type = 1;
    return IDCELL_OK;
}

/*
 * 取链路画像。永远可取：未绑定适配器时返回默认值
 * （介质 UNKNOWN、拓扑 P2P、T_link_min=0、MTU=0、非主机代发）。
 * 需要区分「默认」与「适配器已声明」时用 idcell_node_has_link_profile()。
 */
const idcell_link_profile_t *idcell_node_link_profile(const idcell_node_t *n)
{
    if (!n) return NULL;
    return &n->profile;
}

/* 链路画像是否由适配器显式声明（SEC-063：适配器 MUST 声明链路画像） */
int idcell_node_has_link_profile(const idcell_node_t *n)
{
    return n ? n->has_profile : 0;
}

idcell_media_t idcell_node_media(const idcell_node_t *n)
{
    if (!n) return IDCELL_MEDIA_UNKNOWN;
    return n->profile.media;
}

idcell_topology_t idcell_node_topology(const idcell_node_t *n)
{
    if (!n) return IDCELL_TOPO_P2P;
    return n->profile.topology;
}

idcell_did_t idcell_node_did(const idcell_node_t *n)
{
    idcell_did_t z;
    memset(&z, 0, sizeof(z));
    if (n) z = n->cfg.did;
    return z;
}

uint32_t idcell_node_desc_version(const idcell_node_t *n)
{
    return n ? n->desc_version : 0;
}

void idcell_node_set_value_source(idcell_node_t *n, idcell_value_fn fn, void *ud)
{
    if (!n) return;
    n->value_fn = fn;
    n->value_ud = ud;
}

/* v0.12：注册质量码来源（§24.5）。不注册则质量码恒为 GOOD。 */
void idcell_node_set_quality_source(idcell_node_t *n, idcell_quality_fn fn, void *ud)
{
    if (!n) return;
    n->quality_fn = fn;
    n->quality_ud = ud;
}

/*
 * v0.12：注册本地时钟源（§26.2）。
 * 不注册时 0xFE00 服务点不存在，READ 返回 E_NODEV——时钟服务是可选能力，
 * 不注册就不会凭空产生一个「假 µs 时钟」。
 */
void idcell_node_set_clock_source(idcell_node_t *n, idcell_clock_fn fn, void *ud)
{
    if (!n) return;
    n->clock_fn = fn;
    n->clock_ud = ud;
}

void idcell_node_set_data_sink(idcell_node_t *n, idcell_data_fn fn, void *ud)
{
    if (!n) return;
    n->data_fn = fn;
    n->data_ud = ud;
}

void idcell_node_set_setter(idcell_node_t *n, idcell_set_fn fn, void *ud)
{
    if (!n) return;
    n->set_fn = fn;
    n->set_ud = ud;
}

void idcell_node_set_event_sink(idcell_node_t *n, idcell_event_fn fn, void *ud)
{
    if (!n) return;
    n->event_fn = fn;
    n->event_ud = ud;
}

void idcell_node_set_write_result_sink(idcell_node_t *n, idcell_write_result_fn fn, void *ud)
{
    if (!n) return;
    n->wres_fn = fn;
    n->wres_ud = ud;
}

/* ---------------------------------------------------------------- 帧发送 */

static void node_fill_frame(idcell_node_t *n, idcell_frame_t *f, uint8_t type,
                            const idcell_did_t *dst, uint16_t group)
{
    memset(f, 0, sizeof(*f));
    f->ver  = IDCELL_PROTO_VER_BYTE;
    f->prof = 0;                 /* STD 模式 */
    f->type = type;
    f->seq  = n->seq++;
    f->txn  = 0;
    f->src  = n->cfg.did;
    if (dst) f->dst = *dst;
    else     memset(&f->dst, 0xFF, 8);   /* 广播 */
    f->group = group;
    f->ts_us = n->ts_us;
}

static idcell_peer_t *peer_find(idcell_node_t *n, const idcell_did_t *did);

static int node_public_type(uint8_t type)
{
    return type == IDCELL_FT_DISCOVER || type == IDCELL_FT_HELLO ||
           type == IDCELL_FT_MATCH || type == IDCELL_FT_NEGOTIATE ||
           type == IDCELL_FT_AUTH;
}

int node_send_from(idcell_node_t *n, uint8_t type, const idcell_did_t *src,
                   const idcell_did_t *dst, uint16_t group, uint16_t txn,
                   const uint8_t *payload, uint16_t plen)
{
    idcell_frame_t f;
    idcell_peer_t *p = dst ? peer_find(n, dst) : NULL;
    const idcell_session_key_t *key = NULL;
    uint8_t buf[IDCELL_MAX_FRAME];
    size_t len = 0;

    if (!n->has_tr) return IDCELL_E_NODEV;
    if (n->asleep) return n->cfg.wake_profile == IDCELL_WAKE_RX_OFF ? IDCELL_E_RX_OFF : IDCELL_E_ASLEEP;
    if (plen > IDCELL_MAX_PAYLOAD) return IDCELL_E_RANGE;

    if (type == IDCELL_FT_BIND) {
        if (p && p->bind_key.valid) key = &p->bind_key;
    } else if (type == IDCELL_FT_ERROR) {
        if (p && p->active_key.valid) key = &p->active_key;
        else if (p && p->bind_key.valid) key = &p->bind_key;
    } else if (type == IDCELL_FT_HEARTBEAT) {
        if (p && p->active_key.valid) key = &p->active_key;
    } else if (!node_public_type(type)) {
        if (p && p->active_key.valid) key = &p->active_key;
    }
    if (!node_public_type(type) && type != IDCELL_FT_HEARTBEAT && !key) return IDCELL_E_PERM;
    if (type == IDCELL_FT_HEARTBEAT && p && p->active_key.valid && !key) return IDCELL_E_PERM;
    if (key && plen > IDCELL_MAX_AUTH_PAYLOAD) return IDCELL_E_RANGE;

    node_fill_frame(n, &f, type, dst, group);
    if (src) f.src = *src;
    f.txn = txn;
    if (plen) memcpy(f.payload, payload, plen);
    f.payload_len = plen;
    if (key) f.flags |= IDCELL_FLAG_AUTH;

    if (idcell_frame_encode_auth(&f, key ? key->key : NULL, key ? sizeof(key->key) : 0,
                                 buf, sizeof(buf), &len) < 0) return IDCELL_E_RANGE;
#ifdef IDCELL_DEBUG
    fprintf(stderr, "[DBG][%s][tx] type=0x%02X plen=%u src=%02X%02X dst=%02X%02X txn=%u\n",
            n->cfg.model, type, plen,
            f.src.b[0], f.src.b[1], f.dst.b[0], f.dst.b[1], f.txn);
#endif
    if (n->tr.send(n->tr.ctx, buf, len) < 0) return IDCELL_E_UNSAFE;
    return IDCELL_OK;
}

int node_send(idcell_node_t *n, uint8_t type, const idcell_did_t *dst,
              uint16_t group, uint16_t txn, const uint8_t *payload, uint16_t plen)
{
    return node_send_from(n, type, NULL, dst, group, txn, payload, plen);
}

static void node_error_write_context(idcell_node_t *n, const idcell_did_t *dst,
                                     const char *object, uint8_t *payload,
                                     uint16_t cap, uint16_t *pos, uint16_t txn)
{
    int i;
    uint8_t b[8];
    if (!object) return;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        if (!p->used || !idcell_did_equal(&p->did, dst) ||
            !p->rx_command_id || p->rx_txn != txn) continue;
#define NODE_PUT_U32_TLV(type, value) do { \
            idcell_put_u32(b, (uint32_t)(value)); \
            idcell_tlv_put(payload, cap, pos, 0, 0, (type), b, 4); \
        } while (0)
#define NODE_PUT_U64_TLV(type, value) do { \
            idcell_put_u64(b, (uint64_t)(value)); \
            idcell_tlv_put(payload, cap, pos, 0, 0, (type), b, 8); \
        } while (0)
        NODE_PUT_U32_TLV(IDCELL_TLV_BIND_ID, p->rx_binding);
        NODE_PUT_U64_TLV(IDCELL_TLV_SESSION_ID, p->rx_session);
        NODE_PUT_U64_TLV(IDCELL_TLV_GRANT_EPOCH, p->rx_grant);
        NODE_PUT_U64_TLV(IDCELL_TLV_AUTHORITY_ID, p->rx_authority);
        NODE_PUT_U64_TLV(IDCELL_TLV_AUTHORITY_EPOCH, p->rx_authority_epoch);
        NODE_PUT_U64_TLV(IDCELL_TLV_MEMBER_EPOCH, p->rx_member_epoch);
        NODE_PUT_U64_TLV(IDCELL_TLV_COMMAND_ID, p->rx_command_id);
#undef NODE_PUT_U32_TLV
#undef NODE_PUT_U64_TLV
        return;
    }
}

/* 结构化错误帧（§09.6）：错误码 + 被拒对象 + 所需/当前权限 + 可读理由 */
void node_send_error(idcell_node_t *n, const idcell_did_t *dst, uint16_t txn,
                     idcell_err_t code, const char *object,
                     int required_perm, int current_perm, const char *reason)
{
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint16_t pos = 0;
    const char *cname = idcell_err_name(code);
    uint8_t u8v;

    idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_ERR_BODY,
                   cname, (uint16_t)strlen(cname));
    if (object)
        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_OBJECT,
                       object, (uint16_t)strlen(object));
    if (required_perm >= 0) {
        u8v = (uint8_t)required_perm;
        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_REQUIRED, &u8v, 1);
    }
    if (current_perm >= 0) {
        u8v = (uint8_t)current_perm;
        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_CURRENT, &u8v, 1);
    }
    if (reason)
        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_REASON,
                       reason, (uint16_t)strlen(reason));
    node_error_write_context(n, dst, object, payload, sizeof(payload), &pos, txn);

    node_send(n, IDCELL_FT_ERROR, dst, 0, txn, payload, pos);
}

/*
 * E_RANGE 专用错误帧（FR-035）。
 * 错误体 MUST 携带值域与实际值——只有一句「越界」不足以让需求方判断该怎么取值，
 * 更不允许实现偷偷截断或钳位到边界后当作成功。
 */
void node_send_range_error(idcell_node_t *n, const idcell_did_t *dst, uint16_t txn,
                           const char *object, uint16_t index,
                           double lo, double hi, double value)
{
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint16_t pos = 0;
    uint8_t b8[8];
    uint8_t b2[2];
    char reason[96];

    snprintf(reason, sizeof(reason), "值 %.6g 超出允许值域 [%.6g, %.6g]", value, lo, hi);

    idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_ERR_BODY,
                   "E_RANGE", 7);
    if (object)
        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_OBJECT,
                       object, (uint16_t)strlen(object));
    idcell_put_f64(b8, lo);
    idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_RANGE_LO, b8, 8);
    idcell_put_f64(b8, hi);
    idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_RANGE_HI, b8, 8);
    idcell_put_f64(b8, value);
    idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_VALUE, b8, 8);
    idcell_put_u16(b2, index);
    idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_INDEX, b2, 2);
    idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_EF_REASON,
                   reason, (uint16_t)strlen(reason));
    node_error_write_context(n, dst, object, payload, sizeof(payload), &pos, txn);

    node_send(n, IDCELL_FT_ERROR, dst, 0, txn, payload, pos);
}

/* ---------------------------------------------------------------- 对端表 */

static idcell_peer_t *peer_find(idcell_node_t *n, const idcell_did_t *did)
{
    int i;
    for (i = 0; i < IDCELL_MAX_PEERS; i++)
        if (n->peers[i].used && idcell_did_equal(&n->peers[i].did, did))
            return &n->peers[i];
    return NULL;
}

idcell_peer_t *peer_get_or_add(idcell_node_t *n, const idcell_did_t *did)
{
    idcell_peer_t *p = peer_find(n, did);
    int i;

    if (p) return p;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (!n->peers[i].used) {
            p = &n->peers[i];
            memset(p, 0, sizeof(*p));
            p->used = 1;
            p->did = *did;
            p->stage = IDCELL_STAGE_IDLE;
            p->peer_stage = IDCELL_STAGE_IDLE;
            p->owner_token = 0;
            p->my_arb_domain = 0;
            return p;
        }
    }
    return NULL;
}

int idcell_node_peer_count(const idcell_node_t *n)
{
    int i, c = 0;
    if (!n) return 0;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) if (n->peers[i].used) c++;
    return c;
}

int idcell_node_peer(const idcell_node_t *n, int idx, idcell_did_t *out)
{
    int i, c = 0;
    if (!n || !out) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (!n->peers[i].used) continue;
        if (c == idx) { *out = n->peers[i].did; return IDCELL_OK; }
        c++;
    }
    return IDCELL_E_NODEV;
}

int idcell_node_renegotiate(idcell_node_t *n, const idcell_did_t *peer)
{
    int i;
    if (!n || !peer) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        if (!p->used || !idcell_did_equal(&p->did, peer)) continue;
        if (p->role != 2) return IDCELL_E_PERM;
        memset(&p->pending_contract, 0, sizeof(p->pending_contract));
        memset(p->pending_pts, 0, sizeof(p->pending_pts));
        p->pending_pt_count = 0;
        p->bind_phase = IDCELL_BIND_NONE;
        p->renegotiating = p->has_contract ? 1 : 0;
        p->reneg_old_binding = p->contract.binding_id;
        p->reneg_old_session = p->contract.session_id;
        p->reneg_old_grant = p->contract.grant_epoch;
        p->stage = IDCELL_STAGE_DESCRIBE;
        p->peer_stage = IDCELL_STAGE_IDLE;
        p->next_retry_ms = n->now_ms;
        p->last_hello_ms = 0;
        if (p->renegotiating) {
            uint8_t payload[64];
            uint8_t b[8];
            uint16_t pos = 0;
            idcell_put_u32(b, p->reneg_old_binding);
            idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_OLD_BINDING, b, 4);
            idcell_put_u64(b, p->reneg_old_session);
            idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_OLD_SESSION, b, 8);
            idcell_put_u64(b, p->reneg_old_grant);
            idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_OLD_GRANT, b, 8);
            return node_send(n, IDCELL_FT_RENEGOTIATE, &p->did, 0, ++p->txn, payload, pos);
        }
        return IDCELL_OK;
    }
    return IDCELL_E_NODEV;
}

idcell_bind_phase_t idcell_node_bind_phase(const idcell_node_t *n,
                                           const idcell_did_t *peer)
{
    int i;
    if (!n || !peer) return IDCELL_BIND_NONE;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (n->peers[i].used && idcell_did_equal(&n->peers[i].did, peer)) {
            if (n->peers[i].suspended || n->peers[i].recovery || n->peers[i].offline)
                return IDCELL_BIND_NONE;
            return n->peers[i].has_contract ? IDCELL_BIND_ACTIVE : n->peers[i].bind_phase;
        }
    }
    return IDCELL_BIND_NONE;
}

int idcell_node_get_contract(const idcell_node_t *n, const idcell_did_t *peer,
                              idcell_contract_t *out)
{
    int i;
    if (!n || !peer || !out) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (n->peers[i].used && idcell_did_equal(&n->peers[i].did, peer) &&
            n->peers[i].has_contract) {
            *out = n->peers[i].contract;
            return IDCELL_OK;
        }
    }
    return IDCELL_E_NODEV;
}

int idcell_node_owner_token(const idcell_node_t *n, const idcell_did_t *peer,
                            uint32_t *out)
{
    int i;
    if (!n || !peer || !out) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (n->peers[i].used && idcell_did_equal(&n->peers[i].did, peer) &&
            n->peers[i].has_contract && n->peers[i].owner_token) {
            *out = n->peers[i].owner_token;
            return IDCELL_OK;
        }
    }
    return IDCELL_E_NODEV;
}

size_t idcell_mask_token(uint32_t token, char *out, size_t cap)
{
    int n;
    if (!out || cap == 0) return 0;
    /* 只保留高 16 bit 作为可核对前缀；完整令牌 MUST NOT 出现在输出里 */
    n = snprintf(out, cap, "0x%04X…（脱敏）", (unsigned)(token >> 16));
    if (n < 0) { out[0] = '\0'; return 0; }
    return ((size_t)n < cap) ? (size_t)n : (cap - 1);
}

int idcell_node_peer_label(const idcell_node_t *n, const idcell_did_t *peer,
                           char *out, size_t cap)
{
    int i;
    if (!n || !peer || !out || cap == 0) return IDCELL_E_NODEV;
    out[0] = '\0';
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (n->peers[i].used && idcell_did_equal(&n->peers[i].did, peer)) {
            if (n->peers[i].peer_label[0])
                snprintf(out, cap, "%s", n->peers[i].peer_label);
            else if (cap >= 19)
                idcell_did_str(peer, out);   /* DID 文本形式需要 18 字节 + '\0' */
            else
                snprintf(out, cap, "%s", "?(DID)");
            return IDCELL_OK;
        }
    }
    return IDCELL_E_NODEV;
}

const char *idcell_node_peer_stage_name(const idcell_node_t *n, const idcell_did_t *peer)
{
    static const char *names[] = {
        "IDLE", "DISCOVER", "DESCRIBE", "MATCH", "NEGOTIATE", "AUTHORIZE", "BIND", "RUNNING"
    };
    int i;
    if (!n || !peer) return "IDLE";
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (n->peers[i].used && idcell_did_equal(&n->peers[i].did, peer)) {
            unsigned s = (unsigned)n->peers[i].stage;
            return (s < sizeof(names)/sizeof(names[0])) ? names[s] : "IDLE";
        }
    }
    return "IDLE";
}

/*
 * 按可读名找对端。主机侧 CLI 用它实现「按名选设备」。
 *
 * 为什么不让用户输入 DID：需求描述必须与设备身份解耦（FR-011）——
 * 「我要一个能提供加速度的设备」和「那是哪一台设备」是两件事，
 * 前者写在需求里，后者由发现过程给出。用户只该面对前者。
 */
int idcell_node_find_peer_by_label(const idcell_node_t *n, const char *label,
                                  idcell_did_t *out)
{
    int i;
    if (!n || !label || !*label || !out) return IDCELL_E_NODEV;

    /* 先精确匹配 */
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (!n->peers[i].used) continue;
        if (n->peers[i].peer_label[0] && strcmp(n->peers[i].peer_label, label) == 0) {
            *out = n->peers[i].did;
            return IDCELL_OK;
        }
    }
    /* 再子串匹配：允许只输入型号的一部分 */
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (!n->peers[i].used) continue;
        if (n->peers[i].peer_label[0] && strstr(n->peers[i].peer_label, label)) {
            *out = n->peers[i].did;
            return IDCELL_OK;
        }
    }
    return IDCELL_E_NODEV;
}

int idcell_node_set_target_label(idcell_node_t *n, const char *label)
{
    if (!n) return IDCELL_E_NODEV;
    if (!label || !*label) {
        n->target_label[0] = '\0';
        return IDCELL_OK;
    }
    snprintf(n->target_label, sizeof(n->target_label), "%s", label);
    return IDCELL_OK;
}

int idcell_node_peer_cap_count(const idcell_node_t *n, const idcell_did_t *peer)
{
    int i;
    if (!n || !peer) return 0;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (n->peers[i].used && idcell_did_equal(&n->peers[i].did, peer))
            return (int)n->peers[i].cap_count;
    }
    return 0;
}

int idcell_node_peer_cap_info(const idcell_node_t *n, const idcell_did_t *peer, int idx,
                              char *label, size_t label_cap,
                              char *unit, size_t unit_cap)
{
    int i;
    if (!n || !peer || idx < 0) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        if (!n->peers[i].used || !idcell_did_equal(&n->peers[i].did, peer)) continue;
        if (idx >= (int)n->peers[i].cap_count) return IDCELL_E_NODEV;
        if (label && label_cap)
            snprintf(label, label_cap, "%s", n->peers[i].caps[idx].label);
        if (unit && unit_cap)
            snprintf(unit, unit_cap, "%s", n->peers[i].caps[idx].unit);
        return IDCELL_OK;
    }
    return IDCELL_E_NODEV;
}

/* ---------------------------------------------------------------- 匹配 */

/*
 * MATCH 判定（§08.1）：需求描述与能力描述符的结构化比对。
 * 硬约束：量种、单位可转换性、方向、权限、值域覆盖、周期可行。
 * 返回匹配到的能力点下标，未命中返回 -1 并给出未满足的约束名。
 *
 * v0.8 起第一道判据是量种 ID 相等性，MUST NOT 按量纲向量——
 * 力的量纲与力矩的量纲在 SI 中完全一致，按向量判等会把 N 与 N.m
 * 误判为可换算（FR-081、FR-082）。
 */
static int match_capability(const idcell_requirement_t *req,
                            const idcell_capability_t *cap, const char **why)
{
    int i;

    /* 量种：不同量种绝不自动换算（§24.2 / FR-081） */
    if (req->qty != cap->qty) {
        *why = "量种不符";
        return -1;
    }

    /* 类型 */
    if (req->kind != IDCELL_KIND_STATE && req->kind != cap->kind) {
        *why = "能力类型不符";
        return -1;
    }

    /* 方向：需求方要读，提供方必须可读 */
    if (req->kind == IDCELL_KIND_STATE && !(cap->dir & IDCELL_DIR_READ)) {
        *why = "方向不符（提供方不可读）";
        return -1;
    }

    /* 权限：需求方申请的权限必须覆盖能力点要求的权限 */
    if ((uint8_t)req->perm < cap->perm) {
        *why = "权限等级不足";
        return -1;
    }

    /* 单位：必须落在 accept_units 内，或与原生单位相同 */
    if (req->unit[0]) {
        int ok = (strcmp(req->unit, cap->unit) == 0);
        for (i = 0; !ok && i < cap->accept_count; i++)
            if (strcmp(req->unit, cap->accept_units[i]) == 0) ok = 1;
        if (!ok) {
            /* 单位不同但可转换（T1/T2）且转换类在能力点声明的允许范围内。
             * 换算走量种优先路径：量种已在上一步判等，此处只关心 T 级。 */
            idcell_conv_t cls = IDCELL_CONV_T0;
            double dummy;
            if (idcell_qty_convert(cap->qty, cap->unit, req->qty, req->unit,
                                    0.0, &dummy, &cls) == IDCELL_OK &&
                (cls == IDCELL_CONV_T1 || cls == IDCELL_CONV_T2) &&
                cap->conv_class != IDCELL_CONV_T0 &&
                cap->conv_class != IDCELL_CONV_T3 &&
                cap->conv_class != IDCELL_CONV_T4) {
                ok = 1;
            }
        }
        if (!ok) {
            *why = "单位不可接受";
            return -1;
        }
    }

    /* 值域覆盖：需求方要的区间必须被能力点覆盖 */
    if (req->range[0] != req->range[1]) {
        if (cap->range[0] > req->range[0] + 1e-12 || cap->range[1] < req->range[1] - 1e-12) {
            *why = "值域未覆盖";
            return -1;
        }
    }

    /* 周期可行：提供方周期下限必须能满足需求方的保鲜上限 */
    if (req->stale_ms && cap->min_sync_ms > req->stale_ms) {
        *why = "提供方周期慢于保鲜上限";
        return -1;
    }

    return 0;
}

/* 在本节点的能力点里找满足需求的第一个 */
int find_match(const idcell_node_t *n, const idcell_requirement_t *req,
               const char **why)
{
    int i;
    for (i = 0; i < n->cap_count; i++) {
        if (n->caps[i].kind != req->kind && req->kind != IDCELL_KIND_STATE) continue;
        if (req->index != 0xFFFF && n->caps[i].index != req->index) continue;
        if (match_capability(req, &n->caps[i], why) == 0) return i;
    }
    if (!*why) *why = "无满足全部硬约束的能力点";
    return -1;
}
