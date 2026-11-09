/*
 * ID-CELL · 节点核心（续）：六段管道的收发处理 + 运行期 + poll 入口
 *
 * 管道：DISCOVER → DESCRIBE → MATCH → NEGOTIATE → AUTHORIZE → BIND → 运行期
 *
 * 贯穿全文件的四条红线：
 *   1. 提供方绝不用重复旧值伪装刷新（§08.5 红线二）——发布前比对时间戳
 *   2. T_pub 超过保鲜上限 T_stale 时绑定必须失败，返回 E_NEGOTIATE（§08.5 红线一）
 *   3. 写操作必须携带 owner_token 与意图结构（SEC-019）
 *   4. 理解度不得直接兑换写权限（SEC-014）
 */
#include "idcell_internal.h"
#include <stdio.h>
#include <math.h>
#include <string.h>

/* ---------------------------------------------------------------- 前置声明 */

static uint32_t negotiate_t_pub(uint32_t t_prod, uint32_t t_want, uint32_t t_link_min);
static uint32_t derive_arb_domain(idcell_node_t *n, uint16_t index, uint8_t sub);
static int node_sleep_error(idcell_node_t *n);

/* ---------------------------------------------------------------- 工具 */

static int time_reached(uint32_t now, uint32_t deadline)
{
    return (int32_t)(now - deadline) >= 0;
}

static uint64_t node_rand(idcell_node_t *n)
{
    uint64_t s = n->rnd;
    uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    n->rnd = z ^ (z >> 31);
    return n->rnd;
}

static void put_u8_tlv(uint8_t *buf, uint16_t cap, uint16_t *pos, uint8_t type, uint8_t v)
{
    idcell_tlv_put(buf, cap, pos, 0, 0, type, &v, 1);
}

static void put_u32_tlv(uint8_t *buf, uint16_t cap, uint16_t *pos, uint8_t type, uint32_t v)
{
    uint8_t b[4];
    idcell_put_u32(b, v);
    idcell_tlv_put(buf, cap, pos, 0, 0, type, b, 4);
}

static void put_u64_tlv(uint8_t *buf, uint16_t cap, uint16_t *pos, uint8_t type, uint64_t v)
{
    uint8_t b[8];
    idcell_put_u64(b, v);
    idcell_tlv_put(buf, cap, pos, 0, 0, type, b, 8);
}

static void put_u16_tlv(uint8_t *buf, uint16_t cap, uint16_t *pos, uint8_t type, uint16_t v)
{
    uint8_t b[2];
    idcell_put_u16(b, v);
    idcell_tlv_put(buf, cap, pos, 0, 0, type, b, 2);
}

/* 带能力点索引的数值 TLV：数据的 IDX/SUB 必须带上，消费侧才知道是哪个点 */
/*
 * 值载荷编码（§24.4、FR-083）。
 *
 * v0.9 起按协商出的 (dtype, scale) 编码，而不是一律 f64——
 * 这正是「帧内不传裸浮点数」的落地：整数类型走定点原始码，
 * MCU 侧不必经过浮点往返（FR-084）。
 */
static void put_value_tlv(uint8_t *buf, uint16_t cap, uint16_t *pos,
                          uint16_t idx, uint8_t sub, double v,
                          idcell_dtype_t dt, uint8_t scale_exp)
{
    uint8_t b[8];
    uint16_t n = 0;

    switch (dt) {
    case IDCELL_DTYPE_BOOL:
        b[0] = (v != 0.0) ? 1 : 0;
        n = 1;
        break;
    case IDCELL_DTYPE_I8: {
        double sc = pow(10.0, -(double)scale_exp);
        long long r = (long long)llround(v / sc);
        if (r < -128) r = -128; if (r > 127) r = 127;
        b[0] = (uint8_t)(int8_t)r; n = 1;
        break;
    }
    case IDCELL_DTYPE_U8: {
        double sc = pow(10.0, -(double)scale_exp);
        long long r = (long long)llround(v / sc);
        if (r < 0) r = 0; if (r > 255) r = 255;
        b[0] = (uint8_t)r; n = 1;
        break;
    }
    case IDCELL_DTYPE_I16: {
        double sc = pow(10.0, -(double)scale_exp);
        long long r = (long long)llround(v / sc);
        if (r < -32768) r = -32768; if (r > 32767) r = 32767;
        idcell_put_u16(b, (uint16_t)(int16_t)r); n = 2;
        break;
    }
    case IDCELL_DTYPE_U16: {
        double sc = pow(10.0, -(double)scale_exp);
        long long r = (long long)llround(v / sc);
        if (r < 0) r = 0; if (r > 65535) r = 65535;
        idcell_put_u16(b, (uint16_t)r); n = 2;
        break;
    }
    case IDCELL_DTYPE_I32: {
        double sc = pow(10.0, -(double)scale_exp);
        long long r = (long long)llround(v / sc);
        if (r < -2147483647LL - 1) r = -2147483647LL - 1;
        if (r > 2147483647LL) r = 2147483647LL;
        idcell_put_u32(b, (uint32_t)(int32_t)r); n = 4;
        break;
    }
    case IDCELL_DTYPE_U32: {
        double sc = pow(10.0, -(double)scale_exp);
        long long r = (long long)llround(v / sc);
        if (r < 0) r = 0; if (r > 4294967295LL) r = 4294967295LL;
        idcell_put_u32(b, (uint32_t)r); n = 4;
        break;
    }
    case IDCELL_DTYPE_I64: {
        double sc = pow(10.0, -(double)scale_exp);
        long long r = (long long)llround(v / sc);
        idcell_put_u32(b, (uint32_t)((uint64_t)r & 0xFFFFFFFFu));
        idcell_put_u32(b + 4, (uint32_t)(((uint64_t)r >> 32) & 0xFFFFFFFFu));
        n = 8;
        break;
    }
    case IDCELL_DTYPE_U64: {
        double sc = pow(10.0, -(double)scale_exp);
        unsigned long long r = (unsigned long long)llround(v / sc);
        idcell_put_u32(b, (uint32_t)(r & 0xFFFFFFFFu));
        idcell_put_u32(b + 4, (uint32_t)((r >> 32) & 0xFFFFFFFFu));
        n = 8;
        break;
    }
    case IDCELL_DTYPE_F32: {
        float f = (float)v;
        uint32_t bits;
        memcpy(&bits, &f, 4);
        idcell_put_u32(b, bits); n = 4;
        break;
    }
    case IDCELL_DTYPE_F64:
    default:
        idcell_put_f64(b, v);
        n = 8;
        break;
    }
    idcell_tlv_put(buf, cap, pos, idx, sub, IDCELL_TLV_VALUE, b, n);
}

static void put_str_tlv(uint8_t *buf, uint16_t cap, uint16_t *pos, uint8_t type, const char *s)
{
    uint16_t n = s ? (uint16_t)strlen(s) : 0;
    idcell_tlv_put(buf, cap, pos, 0, 0, type, s ? (const uint8_t *)s : (const uint8_t *)"", n);
}

static uint8_t  tlv_u8(const idcell_tlv_t *t, uint8_t def)
{ return (t->len >= 1) ? t->val[0] : def; }

static uint32_t tlv_u32(const idcell_tlv_t *t, uint32_t def)
{ return (t->len >= 4) ? idcell_get_u32(t->val) : def; }

static uint64_t tlv_u64(const idcell_tlv_t *t, uint64_t def)
{ return (t->len == 8) ? idcell_get_u64(t->val) : def; }

static uint16_t tlv_u16(const idcell_tlv_t *t, uint16_t def)
{ return (t->len == 2) ? idcell_get_u16(t->val) : def; }

static double tlv_f64(const idcell_tlv_t *t, double def)
{ return (t->len >= 8) ? idcell_get_f64(t->val) : def; }

/*
 * 按协商出的 (dtype, scale) 解码值载荷（§24.8）。
 *
 * 帧内不再一律是 f64——接收方按契约里记录的二元组解释。
 * 长度不足时返回 def（MUST NOT 猜测）。
 */
static double tlv_value(const idcell_tlv_t *t, idcell_dtype_t dt,
                        uint8_t scale_exp, double def)
{
    double sc = pow(10.0, -(double)scale_exp);
    switch (dt) {
    case IDCELL_DTYPE_BOOL:
        return (t->len >= 1) ? (t->val[0] ? 1.0 : 0.0) : def;
    case IDCELL_DTYPE_I8:
        return (t->len >= 1) ? (double)(int8_t)t->val[0] * sc : def;
    case IDCELL_DTYPE_U8:
        return (t->len >= 1) ? (double)t->val[0] * sc : def;
    case IDCELL_DTYPE_I16:
        return (t->len >= 2) ? (double)(int16_t)idcell_get_u16(t->val) * sc : def;
    case IDCELL_DTYPE_U16:
        return (t->len >= 2) ? (double)idcell_get_u16(t->val) * sc : def;
    case IDCELL_DTYPE_I32:
        return (t->len >= 4) ? (double)(int32_t)idcell_get_u32(t->val) * sc : def;
    case IDCELL_DTYPE_U32:
        return (t->len >= 4) ? (double)idcell_get_u32(t->val) * sc : def;
    case IDCELL_DTYPE_I64:
    case IDCELL_DTYPE_U64:
        if (t->len < 8) return def;
        {
            uint64_t raw = (uint64_t)idcell_get_u32(t->val) |
                           ((uint64_t)idcell_get_u32(t->val + 4) << 32);
            if (dt == IDCELL_DTYPE_I64) return (double)(int64_t)raw * sc;
            return (double)raw * sc;
        }
    case IDCELL_DTYPE_F32:
        if (t->len < 4) return def;
        {
            uint32_t bits = idcell_get_u32(t->val);
            float f;
            memcpy(&f, &bits, 4);
            return (double)f;
        }
    case IDCELL_DTYPE_F64:
    default:
        return tlv_f64(t, def);
    }
}

static int decode_value(const idcell_tlv_t *t, idcell_dtype_t dt,
                        uint8_t scale_exp, double *out)
{
    int need = idcell_type_bytes(dt);
    double value;
    if (!out || need <= 0 || t->len != (uint16_t)need) return IDCELL_E_UNSAFE;
    value = tlv_value(t, dt, scale_exp, 0.0);
    *out = value;
    return IDCELL_OK;
}

static void tlv_str(const idcell_tlv_t *t, char *out, size_t cap)
{
    size_t n = t->len;
    if (n >= cap) n = cap - 1;
    if (n) memcpy(out, t->val, n);
    out[n] = '\0';
}

/* 挑战-响应的 MAC：DID 序归一化，保证两端算出同一个值 */
static void auth_mac(const uint8_t *cred, const uint8_t *nonce,
                     const idcell_did_t *a, const idcell_did_t *b,
                     uint16_t txn, uint8_t out[32])
{
    uint8_t msg[48];
    uint16_t k = 0;
    int a_first = (memcmp(a->b, b->b, 8) <= 0);

    memcpy(msg, nonce, 16); k += 16;
    memcpy(msg + k, a_first ? a->b : b->b, 8); k += 8;
    memcpy(msg + k, a_first ? b->b : a->b, 8); k += 8;
    idcell_put_u16(msg + k, txn); k += 2;
    idcell_hmac_sha256(cred, IDCELL_CRED_LEN, msg, k, out);
}

static void key_wipe(idcell_session_key_t *slot)
{
    volatile uint8_t *p = (volatile uint8_t *)slot;
    size_t i;
    for (i = 0; i < sizeof(*slot); i++) p[i] = 0;
}

static void peer_derive_key(idcell_node_t *n, idcell_peer_t *p,
                            idcell_session_key_t *slot,
                            uint32_t binding_id, uint64_t session_id)
{
    static const char id_domain[] = "IDCELL-KEY-ID-V1";
    uint8_t msg[sizeof(id_domain) - 1 + 8];
    uint8_t id[32];
    key_wipe(slot);
    idcell_session_key_derive(n->cfg.cred, p->auth_nonce, &n->cfg.did, &p->did,
                              p->auth_txn, binding_id, session_id, slot->key);
    slot->session_id = session_id;
    memcpy(msg, id_domain, sizeof(id_domain) - 1);
    idcell_put_u64(msg + sizeof(id_domain) - 1, session_id);
    idcell_hmac_sha256(slot->key, sizeof(slot->key), msg, sizeof(msg), id);
    memcpy(slot->key_id, id, sizeof(slot->key_id));
    slot->valid = 1;
    memset(id, 0, sizeof(id));
}

int idcell_replay_accept(idcell_session_key_t *key, uint16_t seq)
{
    uint16_t delta, age;
    uint64_t bit;
    if (!key || !key->valid) return 0;
    if (!key->rx_window_valid) {
        key->rx_window_valid = 1;
        key->rx_max_seq = seq;
        key->rx_window = 1;
        return 1;
    }
    delta = (uint16_t)(seq - key->rx_max_seq);
    if (!delta) return 0;
    if (delta < 0x8000u) {
        if (delta >= 64) key->rx_window = 1;
        else key->rx_window = (key->rx_window << delta) | 1ULL;
        key->rx_max_seq = seq;
        return 1;
    }
    age = (uint16_t)(key->rx_max_seq - seq);
    if (age >= 64) return 0;
    bit = 1ULL << age;
    if (key->rx_window & bit) return 0;
    key->rx_window |= bit;
    return 1;
}

static idcell_peer_t *peer_existing(idcell_node_t *n, const idcell_did_t *did)
{
    int i;
    for (i = 0; i < IDCELL_MAX_PEERS; i++)
        if (n->peers[i].used && idcell_did_equal(&n->peers[i].did, did)) return &n->peers[i];
    return NULL;
}

/* ---------------------------------------------------------------- DISCOVER / DESCRIBE */

/* DISCOVER 同时承载 ANNOUNCE 与主动 PROBE；TYPE 表保持不变。 */
static uint8_t node_role(const idcell_node_t *n)
{
    uint8_t role = 0;
    if (n->cap_count) role |= IDCELL_ROLE_CAPABILITY;
    if (n->req_count) role |= IDCELL_ROLE_REQUIREMENT;
    return role;
}

static void put_presence_tlvs(idcell_node_t *n, uint8_t *payload, uint16_t cap, uint16_t *pos)
{
    put_u8_tlv(payload, cap, pos, IDCELL_TLV_WAKE_PROFILE, (uint8_t)n->cfg.wake_profile);
    put_u32_tlv(payload, cap, pos, IDCELL_TLV_CHECKIN_MS, n->cfg.checkin_ms);
    put_u32_tlv(payload, cap, pos, IDCELL_TLV_WAKE_LATENCY, n->cfg.max_wake_latency_ms);
    put_u8_tlv(payload, cap, pos, IDCELL_TLV_ASLEEP, n->asleep ? 1 : 0);
}

static int node_send_discover_message(idcell_node_t *n, uint8_t message,
                                      const idcell_did_t *src, const idcell_did_t *dst,
                                      const idcell_did_t *originator, uint64_t query_id,
                                      const char *scope, uint8_t hop_limit, const char *query,
                                      const idcell_did_t *target)
{
    uint8_t payload[512];
    uint16_t pos = 0;
    const char *label;

    label = n->has_dev_type ? n->dev_type.capability_summary : n->cfg.model;
    if (!label || !*label) label = n->cfg.model;
    put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_MESSAGE, message);
    put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_ROLE,
               (uint8_t)(node_role(n) | (message == IDCELL_DISCOVER_PROBE ? IDCELL_ROLE_REQUIREMENT : 0)));
    put_str_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_SUMMARY, label);
    put_str_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_STR, n->cfg.vendor);
    put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_DESC_VER, n->desc_version);
    put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_U32, n->cap_count);
    put_presence_tlvs(n, payload, sizeof(payload), &pos);
    if (message == IDCELL_DISCOVER_PROBE) {
        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_ORIGINATOR,
                       originator->b, 8);
        put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_QUERY_ID, query_id);
        put_str_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_SCOPE, scope);
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_HOP_LIMIT, hop_limit);
        put_str_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_QUERY, query ? query : "");
        if (target)
            idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_TARGET, target->b, 8);
    }
    return node_send_from(n, IDCELL_FT_DISCOVER, src, dst, 0, 0, payload, pos);
}

static int node_send_discover(idcell_node_t *n)
{
    return node_send_discover_message(n, IDCELL_DISCOVER_ANNOUNCE, NULL, NULL,
                                      NULL, 0, NULL, 0, NULL, NULL);
}

/* HELLO 只携带公共匹配子集；完整授权描述在 AUTH 后的 BIND PREPARED 提供。 */
static int node_send_hello(idcell_node_t *n, const idcell_did_t *dst,
                           const idcell_did_t *originator, uint64_t query_id,
                           int probe_response)
{
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint8_t canonical[IDCELL_MAX_PAYLOAD];
    uint16_t pos = 0, cpos = 0;
    uint8_t inner[IDCELL_MAX_PAYLOAD];
    uint8_t digest[32];
    const char *label;
    int i;

    label = n->has_dev_type ? n->dev_type.capability_summary : n->cfg.model;
    if (!label || !*label) label = n->cfg.model;
    put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_MESSAGE,
               probe_response ? IDCELL_DISCOVER_RESPONSE : IDCELL_DISCOVER_ANNOUNCE);
    put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_ROLE, node_role(n));
    put_str_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_SUMMARY, label);
    put_str_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_STR, n->cfg.vendor);
    put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_DESC_VER, n->desc_version);
    put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_U32, n->cap_count);
    put_presence_tlvs(n, payload, sizeof(payload), &pos);
    if (probe_response) {
        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_ORIGINATOR,
                       originator->b, 8);
        put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_QUERY_ID, query_id);
    }

    for (i = 0; i < n->cap_count; i++) {
        int len = idcell_public_desc_encode(&n->caps[i], inner, sizeof(inner));
        if (len < 0) return IDCELL_E_UNAVAILABLE;
        if (idcell_tlv_put(payload, sizeof(payload), &pos, n->caps[i].index, n->caps[i].sub,
                           IDCELL_TLV_CAP_DESC, inner, (uint16_t)len) < 0 ||
            idcell_tlv_put(canonical, sizeof(canonical), &cpos, n->caps[i].index, n->caps[i].sub,
                           IDCELL_TLV_CAP_DESC, inner, (uint16_t)len) < 0)
            return IDCELL_E_UNAVAILABLE;
    }
    idcell_descriptor_digest(1, canonical, cpos, digest);
    if (idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0,
                       IDCELL_TLV_PUBLIC_DIGEST, digest, 32) < 0) return IDCELL_E_UNAVAILABLE;
    return node_send(n, IDCELL_FT_HELLO, dst, 0, 0, payload, pos);
}

static int node_descriptors_available(idcell_node_t *n)
{
    uint8_t inner[IDCELL_MAX_PAYLOAD];
    int i;
    if (!n->cap_count) return 0;
    for (i = 0; i < n->cap_count; i++)
        if (idcell_public_desc_encode(&n->caps[i], inner, sizeof(inner)) < 0) return 0;
    return 1;
}

static void discovery_purge(idcell_node_t *n)
{
    int i;
    for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++) {
        idcell_discovery_seen_t *d = &n->discovery_seen[i];
        if (d->used && time_reached(n->now_ms, d->expires_ms)) memset(d, 0, sizeof(*d));
    }
}

static idcell_discovery_seen_t *discovery_find(idcell_node_t *n,
                                                const idcell_did_t *originator,
                                                uint64_t query_id, int touch)
{
    int i;
    for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++) {
        idcell_discovery_seen_t *d = &n->discovery_seen[i];
        if (d->used && d->query_id == query_id && idcell_did_equal(&d->originator, originator)) {
            if (touch) d->age = ++n->discovery_age; /* LRU 刷新，不延长 TTL */
            return d;
        }
    }
    return NULL;
}

static idcell_discovery_seen_t *discovery_remember(idcell_node_t *n,
                                                    const idcell_did_t *originator, uint64_t query_id)
{
    idcell_discovery_seen_t *d = NULL;
    uint32_t count = 0;
    int i;
    for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++) {
        if (!n->discovery_seen[i].used) { if (!d) d = &n->discovery_seen[i]; }
        else count++;
    }
    if (count >= n->cfg.discovery_cache_capacity) {
        uint64_t oldest = UINT64_MAX;
        d = NULL;
        for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++) {
            if (n->discovery_seen[i].used && n->discovery_seen[i].age < oldest) {
                oldest = n->discovery_seen[i].age;
                d = &n->discovery_seen[i];
            }
        }
    }
    if (!d) return NULL;
    memset(d, 0, sizeof(*d));
    d->used = 1;
    d->originator = *originator;
    d->query_id = query_id;
    d->expires_ms = n->now_ms + n->cfg.discovery_cache_ttl_ms;
    d->age = ++n->discovery_age;
    return d;
}

static void discovery_forget(idcell_node_t *n, const idcell_did_t *originator, uint64_t query_id)
{
    idcell_discovery_seen_t *d = discovery_find(n, originator, query_id, 0);
    if (d) memset(d, 0, sizeof(*d));
}

static void discovery_cancel_response(idcell_node_t *n, const idcell_did_t *originator, uint64_t query_id)
{
    int i;
    for (i = 0; i < IDCELL_DISCOVERY_RESPONSES; i++) {
        idcell_discovery_response_t *r = &n->discovery_responses[i];
        if (r->used && r->probe_response && r->query_id == query_id &&
            idcell_did_equal(&r->originator, originator)) memset(r, 0, sizeof(*r));
    }
}

static int discovery_queue_response(idcell_node_t *n, const idcell_did_t *dst,
                                    const idcell_did_t *originator, uint64_t query_id,
                                    int probe_response)
{
    idcell_discovery_response_t *r = NULL;
    uint32_t start, jitter;
    int i;
    for (i = 0; i < IDCELL_DISCOVERY_RESPONSES; i++)
        if (!n->discovery_responses[i].used) { r = &n->discovery_responses[i]; break; }
    if (!r) return 0;
    start = time_reached(n->now_ms, n->next_response_ms) ? n->now_ms : n->next_response_ms;
    jitter = n->cfg.discovery_response_jitter_ms ?
             (uint32_t)(node_rand(n) % ((uint64_t)n->cfg.discovery_response_jitter_ms + 1u)) : 0;
    memset(r, 0, sizeof(*r));
    r->used = 1;
    r->dst = *dst;
    r->originator = *originator;
    r->query_id = query_id;
    r->due_ms = start + jitter;
    r->probe_response = probe_response ? 1 : 0;
    /* 下一次限流从本次实际响应时刻计算，而不是从请求到达时刻计算。 */
    n->next_response_ms = r->due_ms + n->cfg.discovery_response_interval_ms;
    return 1;
}

static int node_query_matches(const idcell_node_t *n, const char *query)
{
    int i;
    if (!query || !query[0]) return 1;
    if (strstr(n->cfg.model, query) || strstr(n->cfg.vendor, query)) return 1;
    if (n->has_dev_type && (strstr(n->dev_type.capability_summary, query) ||
                            strstr(n->dev_type.type_name, query))) return 1;
    for (i = 0; i < n->cap_count; i++) if (strstr(n->caps[i].label, query)) return 1;
    return 0;
}

static int did_is_zero(const idcell_did_t *did)
{
    static const idcell_did_t zero = {{0}};
    return idcell_did_equal(did, &zero);
}

static void node_try_local_response(idcell_node_t *n, const idcell_did_t *dst,
                                    const idcell_did_t *originator, uint64_t query_id,
                                    const idcell_did_t *target, const char *query,
                                    idcell_discovery_seen_t *seen)
{
    if (seen && seen->response_done) {
        n->last_probe_err = IDCELL_E_DUPLICATE;
        return;
    }
    /* target/query 不匹配是明确的本地无响应，不得读取公共描述符。 */
    if ((target && !did_is_zero(target) && !idcell_did_equal(target, &n->cfg.did)) ||
        !node_query_matches(n, query)) {
        if (seen) seen->response_done = 1;
        n->last_probe_err = seen ? IDCELL_OK : n->last_probe_err;
        return;
    }
    if (!node_descriptors_available(n)) {
        n->last_probe_err = IDCELL_E_UNAVAILABLE;
        return;
    }
    n->descriptor_fetches++;
    if (!discovery_queue_response(n, dst, originator, query_id, seen != NULL)) {
        n->last_probe_err = IDCELL_E_UNAVAILABLE;
        return;
    }
    if (seen) seen->response_done = 1;
    n->last_probe_err = IDCELL_OK;
}

static int node_forward_probe(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_frame_t out = *f;
    uint8_t wire[IDCELL_MAX_FRAME];
    size_t len = 0;
    uint16_t pos = 0;
    idcell_tlv_t t;
    int rc;
    if (!n->has_tr) return IDCELL_E_NODEV;
    if (n->asleep) return n->cfg.wake_profile == IDCELL_WAKE_RX_OFF ? IDCELL_E_RX_OFF : IDCELL_E_ASLEEP;
    while ((rc = idcell_tlv_next(out.payload, out.payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_HOP_LIMIT) {
            size_t off = (size_t)(t.val - out.payload);
            if (t.len != 1 || out.payload[off] == 0) return IDCELL_E_RANGE;
            out.payload[off]--;
            if (idcell_frame_encode(&out, wire, sizeof(wire), &len) < 0) return IDCELL_E_RANGE;
            return n->tr.send(n->tr.ctx, wire, len) < 0 ? IDCELL_E_UNSAFE : IDCELL_OK;
        }
    }
    return IDCELL_E_UNSAFE;
}

static void node_on_discover(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    idcell_did_t originator, target;
    idcell_discovery_seen_t *seen;
    uint64_t query_id = 0;
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint8_t message = IDCELL_DISCOVER_ANNOUNCE, hop_limit = 0;
    char scope[IDCELL_MAX_LABEL], query[129];
    int rc, have_originator = 0, have_query_id = 0, have_scope = 0, have_hop = 0, have_role = 0;

    if (!p) return;
    snprintf(scope, sizeof(scope), "default");
    query[0] = '\0';
    memset(&originator, 0, sizeof(originator));
    memset(&target, 0, sizeof(target));
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_SUMMARY) {
            tlv_str(&t, p->peer_label, sizeof(p->peer_label));
            p->labeled = 1;
        } else if (t.type == IDCELL_TLV_STR) {
            tlv_str(&t, p->peer_vendor, sizeof(p->peer_vendor));
        } else if (t.type == IDCELL_TLV_DESC_VER) {
            p->desc_version = tlv_u32(&t, 0);
        } else if (t.type == IDCELL_TLV_MESSAGE) {
            message = tlv_u8(&t, 0);
        } else if (t.type == IDCELL_TLV_ROLE && t.len == 1) {
            have_role = tlv_u8(&t, 0) != 0;
        } else if (t.type == IDCELL_TLV_ORIGINATOR && t.len == 8) {
            memcpy(originator.b, t.val, 8); have_originator = 1;
        } else if (t.type == IDCELL_TLV_QUERY_ID) {
            query_id = tlv_u64(&t, 0); have_query_id = t.len == 8;
        } else if (t.type == IDCELL_TLV_SCOPE && t.len < sizeof(scope)) {
            tlv_str(&t, scope, sizeof(scope)); have_scope = 1;
        } else if (t.type == IDCELL_TLV_HOP_LIMIT && t.len == 1) {
            hop_limit = tlv_u8(&t, 0); have_hop = 1;
        } else if (t.type == IDCELL_TLV_QUERY && t.len < sizeof(query)) {
            tlv_str(&t, query, sizeof(query));
        } else if (t.type == IDCELL_TLV_TARGET && t.len == 8) {
            memcpy(target.b, t.val, 8);
        }
    }
    if (rc < 0 || (message != IDCELL_DISCOVER_ANNOUNCE && message != IDCELL_DISCOVER_PROBE)) return;
    if (message == IDCELL_DISCOVER_PROBE &&
        (!have_originator || !have_query_id || !query_id || !have_scope || !have_hop || !have_role)) return;
    if (strcmp(scope, n->cfg.discovery_scope) != 0) {
        if (message == IDCELL_DISCOVER_PROBE) n->last_probe_err = IDCELL_E_SCOPE;
        return;
    }
    discovery_purge(n);
    if (message == IDCELL_DISCOVER_ANNOUNCE) {
        node_try_local_response(n, &f->src, &originator, 0, NULL, NULL, NULL);
        if (!p->asked_desc) {
            p->asked_desc = 1;
            (void)node_send(n, IDCELL_FT_DISCOVER, &f->src, 0, 0, NULL, 0);
        }
        return;
    }

    seen = discovery_find(n, &originator, query_id, 1);
    if (!seen) {
        seen = discovery_remember(n, &originator, query_id);
        if (!seen) { n->last_probe_err = IDCELL_E_UNAVAILABLE; return; }
        if (hop_limit > 0) {
            /* 端到端 SRC/DST 原样保留；中继只减少 hop_limit。 */
            rc = node_forward_probe(n, f);
            if (rc != IDCELL_OK) {
                discovery_cancel_response(n, &originator, query_id);
                discovery_forget(n, &originator, query_id);
                n->last_probe_err = (uint8_t)rc;
                return;
            }
        }
    } else {
        n->last_probe_err = IDCELL_E_DUPLICATE;
    }
    /* 无 cap/req 的中继仍完成上述 dedup/转发；本地不可用只影响 HELLO。 */
    node_try_local_response(n, &originator, &originator, query_id, &target, query, seen);
}

static void pending_probe_remember(idcell_node_t *n, uint64_t query_id)
{
    idcell_pending_probe_t *p = NULL;
    int i;
    for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++) {
        if (n->pending_probes[i].used && n->pending_probes[i].query_id == query_id) {
            p = &n->pending_probes[i]; break;
        }
        if (!n->pending_probes[i].used && !p) p = &n->pending_probes[i];
    }
    if (!p) {
        uint64_t oldest = UINT64_MAX;
        for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++) {
            if (n->pending_probes[i].age < oldest) {
                oldest = n->pending_probes[i].age; p = &n->pending_probes[i];
            }
        }
    }
    memset(p, 0, sizeof(*p)); p->used = 1; p->query_id = query_id; p->age = ++n->pending_probe_age;
}

static int pending_probe_match(idcell_node_t *n, const idcell_did_t *originator,
                               uint64_t query_id, int consume)
{
    int i;
    if (!idcell_did_equal(originator, &n->cfg.did) || !query_id) return 0;
    for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++) {
        idcell_pending_probe_t *p = &n->pending_probes[i];
        if (!p->used || p->query_id != query_id) continue;
        if (consume) memset(p, 0, sizeof(*p));
        return 1;
    }
    return 0;
}

int idcell_node_probe(idcell_node_t *n, const idcell_probe_t *probe)
{
    const char *scope;
    int rc;
    if (!n || !probe || !probe->query_id) return IDCELL_E_NODEV;
    if (n->asleep) {
        rc = n->cfg.wake_profile == IDCELL_WAKE_RX_OFF ? IDCELL_E_RX_OFF : IDCELL_E_ASLEEP;
        n->last_err = (uint8_t)rc;
        return rc;
    }
    if (!did_is_zero(&probe->originator_id) &&
        !idcell_did_equal(&probe->originator_id, &n->cfg.did)) return IDCELL_E_PERM;
    scope = (probe->scope && probe->scope[0]) ? probe->scope : n->cfg.discovery_scope;
    if (strlen(scope) >= IDCELL_MAX_LABEL || (probe->query && strlen(probe->query) > 128))
        return IDCELL_E_RANGE;
    rc = node_send_discover_message(n, IDCELL_DISCOVER_PROBE, NULL, NULL, &n->cfg.did,
                                    probe->query_id, scope, probe->hop_limit, probe->query,
                                    &probe->target_id);
    if (rc == IDCELL_OK) pending_probe_remember(n, probe->query_id);
    n->last_probe_err = (uint8_t)rc;
    n->last_err = (uint8_t)rc;
    return rc;
}

int idcell_node_discovery_status(const idcell_node_t *n, idcell_discovery_status_t *out)
{
    uint32_t count = 0;
    int i;
    if (!n || !out) return IDCELL_E_NODEV;
    memset(out, 0, sizeof(*out));
    out->next_delay_ms = time_reached(n->now_ms, n->next_discover_ms) ? 0 : n->next_discover_ms - n->now_ms;
    out->failures = n->announce_failures;
    out->announcements = n->announce_count;
    out->descriptor_fetches = n->descriptor_fetches;
    out->confirmed = n->announce_confirmed;
    out->last_probe_err = n->last_probe_err;
    for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++) if (n->discovery_seen[i].used) count++;
    out->cache_size = count;
    return IDCELL_OK;
}

/* HELLO 必须先完整验证公共响应及 digest；敏感 TLV 一律不进入公共缓存。 */
static void node_on_hello(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    idcell_cap_store_t caps[IDCELL_MAX_PEER_CAPS];
    idcell_did_t originator;
    char label[IDCELL_MAX_LABEL], vendor[IDCELL_MAX_LABEL];
    uint32_t desc_version = 0, declared = 0;
    uint64_t query_id = 0;
    uint16_t pos = 0, cap_count = 0, cpos = 0;
    uint8_t canonical[IDCELL_MAX_PAYLOAD];
    uint8_t digest[32], expect[32];
    idcell_tlv_t t;
    uint8_t message = 0, role = 0;
    int rc, have_message = 0, have_role = 0, have_summary = 0, have_desc = 0, have_count = 0;
    int have_digest = 0;

    if (!p) return;
    memset(caps, 0, sizeof(caps)); memset(&originator, 0, sizeof(originator));
    memset(digest, 0, sizeof(digest));
    label[0] = '\0'; vendor[0] = '\0';
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        switch (t.type) {
        case IDCELL_TLV_MESSAGE:
            if (t.len != 1) return;
            message = tlv_u8(&t, 0); have_message = 1; break;
        case IDCELL_TLV_ROLE:
            if (t.len != 1) return;
            role = tlv_u8(&t, 0); have_role = 1; break;
        case IDCELL_TLV_SUMMARY:
            if (!t.len || t.len >= sizeof(label) || memchr(t.val, 0, t.len)) return;
            tlv_str(&t, label, sizeof(label)); have_summary = 1; break;
        case IDCELL_TLV_STR:
            if (t.len >= sizeof(vendor) || memchr(t.val, 0, t.len)) return;
            tlv_str(&t, vendor, sizeof(vendor)); break;
        case IDCELL_TLV_DESC_VER:
            if (t.len != 4) return;
            desc_version = tlv_u32(&t, 0); have_desc = 1; break;
        case IDCELL_TLV_U32:
            if (t.len != 4) return;
            declared = tlv_u32(&t, 0); have_count = 1; break;
        case IDCELL_TLV_ORIGINATOR:
            if (t.len != 8) return;
            memcpy(originator.b, t.val, 8); break;
        case IDCELL_TLV_QUERY_ID:
            if (t.len != 8) return;
            query_id = tlv_u64(&t, 0); break;
        case IDCELL_TLV_WAKE_PROFILE:
        case IDCELL_TLV_ASLEEP:
            if (t.len != 1) return;
            break;
        case IDCELL_TLV_CHECKIN_MS:
        case IDCELL_TLV_WAKE_LATENCY:
            if (t.len != 4) return;
            break;
        case IDCELL_TLV_PUBLIC_DIGEST:
            if (t.len != 32 || have_digest) return;
            memcpy(digest, t.val, 32); have_digest = 1; break;
        case IDCELL_TLV_CAP_DESC: {
            idcell_cap_store_t cs;
            int i;
            if (cap_count >= IDCELL_MAX_PEER_CAPS ||
                idcell_public_desc_validate(t.val, t.len) < 0 ||
                idcell_desc_decode(t.val, t.len, &cs) < 0 ||
                (uint32_t)cpos + IDCELL_TLV_HDR_LEN + t.len > sizeof(canonical)) return;
            cs.index = t.idx; cs.sub = t.sub;
            if (!cs.label[0]) return;
            for (i = 0; i < cap_count; i++)
                if (caps[i].index == cs.index && caps[i].sub == cs.sub) return;
            caps[cap_count++] = cs;
            memcpy(canonical + cpos, t.val - IDCELL_TLV_HDR_LEN,
                   IDCELL_TLV_HDR_LEN + t.len);
            cpos = (uint16_t)(cpos + IDCELL_TLV_HDR_LEN + t.len);
            break;
        }
        default:
            return; /* scope、授权策略、fail_action 等不得混入公共 HELLO。 */
        }
    }
    if (rc < 0 || !have_message || !have_role || !have_summary || !have_desc || !have_count ||
        !have_digest || !desc_version || !declared || declared != cap_count ||
        !(role & IDCELL_ROLE_CAPABILITY) ||
        (message != IDCELL_DISCOVER_ANNOUNCE && message != IDCELL_DISCOVER_RESPONSE)) return;
    idcell_descriptor_digest(1, canonical, cpos, expect);
    if (memcmp(expect, digest, 32) != 0) return;
    if (message == IDCELL_DISCOVER_RESPONSE && !pending_probe_match(n, &originator, query_id, 0)) return;

    memcpy(p->caps, caps, sizeof(caps));
    p->cap_count = cap_count;
    p->desc_version = desc_version;
    snprintf(p->peer_label, sizeof(p->peer_label), "%s", label);
    snprintf(p->peer_vendor, sizeof(p->peer_vendor), "%s", vendor);
    p->labeled = 1;
    p->last_rx_ms = n->now_ms;
    p->presence_seen = 1;
    p->offline = 0;
    p->asleep = 0;
    if (p->stage < IDCELL_STAGE_DESCRIBE) p->stage = IDCELL_STAGE_DESCRIBE;
    if (message == IDCELL_DISCOVER_RESPONSE) (void)pending_probe_match(n, &originator, query_id, 1);
    n->announce_confirmed = 1;
    n->announce_failures = 0;
    n->next_discover_ms = n->now_ms + n->cfg.announce_steady_ms;
}

static void node_send_due_responses(idcell_node_t *n)
{
    int i;
    for (i = 0; i < IDCELL_DISCOVERY_RESPONSES; i++) {
        idcell_discovery_response_t *r = &n->discovery_responses[i];
        idcell_peer_t *p;
        if (!r->used || !time_reached(n->now_ms, r->due_ms)) continue;
        {
            idcell_did_t originator = r->originator;
            uint64_t query_id = r->query_id;
            int probe_response = r->probe_response;
            int rc = node_send_hello(n, &r->dst, &r->originator, r->query_id, r->probe_response);
            if (rc != IDCELL_OK) {
                if (r->attempts < 3) {
                    r->attempts++;
                    r->due_ms = n->now_ms + n->cfg.discovery_response_interval_ms;
                    n->next_response_ms = r->due_ms;
                    return; /* 有界重试，entry 与 dedup 均保留。 */
                }
                if (probe_response) {
                    discovery_cancel_response(n, &originator, query_id);
                    discovery_forget(n, &originator, query_id);
                }
                memset(r, 0, sizeof(*r));
                n->next_response_ms = n->now_ms + n->cfg.discovery_response_interval_ms;
                return; /* 最终放弃后允许同 query 在 TTL 内重新进入。 */
            }
        }
        p = peer_get_or_add(n, &r->dst);
        if (p) p->last_hello_ms = n->now_ms;
        memset(r, 0, sizeof(*r));
        n->next_response_ms = n->now_ms + n->cfg.discovery_response_interval_ms;
        /* poll 迟到时也不能把多个过期响应挤在同一实际时刻发出。 */
        for (i = 0; i < IDCELL_DISCOVERY_RESPONSES; i++) {
            r = &n->discovery_responses[i];
            if (r->used && time_reached(n->next_response_ms, r->due_ms)) r->due_ms = n->next_response_ms;
        }
        return; /* 每轮最多一个响应，保持实际发送间隔可观测。 */
    }
}

/* ---------------------------------------------------------------- MATCH */

/*
 * MATCH_RES 的值编码（自描述，逐点独立）：
 *   u16 cap_index | u8 sub | u8 perm | u8 degrade | u32 T_prod | u32 T_stale | u8 unit_len | unit
 *
 * degrade（fail_action）必须在这里带上：契约的降级语义是逐点的，
 * 而且要写在契约里而不是靠对端声明——对端可能已经死了（§09.7）。
 */
static void encode_match_res(uint8_t *buf, uint16_t cap, uint16_t *pos,
                             uint16_t cap_index, uint8_t sub, uint8_t perm,
                             uint8_t degrade,
                             uint32_t t_prod, uint32_t t_stale, const char *unit,
                             uint8_t dtype, uint8_t scale_exp, uint64_t schema_id)
{
    uint8_t v[64];
    uint16_t n = 0;
    uint16_t ul = unit ? (uint16_t)strlen(unit) : 0;

    if (ul > 15) ul = 15;
    idcell_put_u16(v, cap_index); n += 2;
    v[n++] = sub;
    v[n++] = perm;
    v[n++] = degrade;
    idcell_put_u32(v + n, t_prod); n += 4;
    idcell_put_u32(v + n, t_stale); n += 4;
    v[n++] = (uint8_t)ul;
    if (ul) { memcpy(v + n, unit, ul); n += ul; }
    /* v0.9：协商出的值类型与定点缩放（§24.8） */
    v[n++] = dtype;
    v[n++] = scale_exp;
    idcell_put_u64(v + n, schema_id); n += 8;

    idcell_tlv_put(buf, cap, pos, 0, 0, IDCELL_TLV_MATCH_RES, v, n);
}

/* 收到 MATCH 请求：我方是提供方，在自己的能力点里找满足者 */
static void node_on_match(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint16_t opos = 0;
    int rc, matched = 0;

    if (!p) return;
    p->last_rx_ms = n->now_ms;
    p->role = 1;   /* 我方是提供方 */

    p->pending_pt_count = 0;

    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        idcell_requirement_t req;
        const char *why = NULL;
        int mi;

        if (t.type != IDCELL_TLV_REQ_DESC) continue;
        if (idcell_req_decode(t.val, t.len, &req) < 0) continue;

        mi = find_match(n, &req, &why);
        if (mi < 0) {
            /* 逐条列出未满足的约束（§09.6 E_NOMATCH 必带字段） */
            node_send_error(n, &f->src, f->txn, IDCELL_E_NOMATCH,
                            req.label[0] ? req.label : NULL, -1, -1,
                            why ? why : "不匹配");
            continue;
        }

        if (p->pending_pt_count >= IDCELL_MAX_MATCH_PTS) break;

        {
            idcell_capability_t *cap = &n->caps[mi];
            idcell_pt_t *pt = &p->pending_pts[p->pending_pt_count];
            char neg_unit[IDCELL_MAX_UNIT];
            uint8_t granted;

            memset(pt, 0, sizeof(*pt));
            pt->cap_index  = cap->index;
            pt->my_cap_idx = (uint16_t)mi;
            pt->sub        = cap->sub;
            pt->prov       = (uint8_t)cap->provenance;
            pt->degrade    = (uint8_t)cap->fail_action;
            pt->t_prod_ms  = cap->min_sync_ms;
            pt->t_want_ms  = req.want_ms;
            pt->ttl_ms     = cap->stale_ms ? cap->stale_ms : n->cfg.lease_ttl_ms;

            /* 协商单位：需求方要的单位若可转换则采用需求方单位（§09.2 转换方向）
             * v0.8：换算走量种优先路径，量种不同直接判 T0（FR-081） */
            snprintf(neg_unit, sizeof(neg_unit), "%s", cap->unit);
            if (req.unit[0] && strcmp(req.unit, cap->unit) != 0) {
                idcell_conv_t cls = IDCELL_CONV_T0;
                double dummy = 0.0;
                if (idcell_qty_convert(cap->qty, cap->unit, req.qty, req.unit,
                                       dummy, &dummy, &cls) == IDCELL_OK &&
                    (cls == IDCELL_CONV_T1 || cls == IDCELL_CONV_T2))
                    snprintf(neg_unit, sizeof(neg_unit), "%s", req.unit);
            }
            pt->qty = (uint8_t)cap->qty;
            snprintf(pt->src_unit, sizeof(pt->src_unit), "%s", cap->unit);
            snprintf(pt->unit, sizeof(pt->unit), "%s", neg_unit);

            /*
             * v0.9：协商值类型（§24.8、FR-087）。
             *
             * 步骤不可颠倒：先取双方 accept_types 的交集，
             * 再以「能承载 range 且分辨率不劣于 precision」过滤，
             * 最后取成本序最低的可行者。
             *
             * 候选集为空或全部不可行时 MUST 返回 E_CONV——不可行就是失败，
             * 不是降级（与 FR-021 的 T_pub 红线同型）。
             */
            {
                idcell_type_t chosen;
                /* 提供方自己的接受集合：未声明时退化为「仅原生类型」 */
                idcell_type_t prov_types[IDCELL_MAX_ACCEPT_TYPES];
                uint8_t prov_count = 0;
                uint8_t k;

                if (cap->accept_type_count > 0) {
                    for (k = 0; k < cap->accept_type_count && k < IDCELL_MAX_ACCEPT_TYPES; k++)
                        prov_types[prov_count++] = cap->accept_types[k];
                } else {
                    /* 未声明接受集合：只接受自己原生的那种编码 */
                    prov_types[0].dtype = cap->dtype;
                    prov_types[0].scale_exp = cap->scale_exp;
                    prov_count = 1;
                }

                if (idcell_type_negotiate(prov_types, prov_count,
                                         req.accept_types, req.accept_type_count,
                                         cap->range[0], cap->range[1],
                                         cap->precision, &chosen) != IDCELL_OK) {
                    node_send_error(n, &f->src, f->txn, IDCELL_E_CONV,
                                    req.label[0] ? req.label : NULL, -1, -1,
                                    "值类型不可协商：双方接受集合无共同可行项");
                    continue;
                }
                pt->dtype     = (uint8_t)chosen.dtype;
                pt->scale_exp = chosen.scale_exp;
                if (node_schema_select(n, cap, &req, chosen, neg_unit,
                                       &pt->schema_id) != IDCELL_OK) {
                    node_send_error(n, &f->src, f->txn, IDCELL_E_NEGOTIATE,
                                    req.label, -1, -1, "没有双方共同理解的 schema");
                    continue;
                }
                {
                    idcell_schema_def_t selected_schema;
                    if (idcell_node_schema(n, pt->schema_id, &selected_schema) != IDCELL_OK) {
                        node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE,
                                        req.label, -1, -1, "schema 未注册");
                        continue;
                    }
                    memcpy(pt->schema_digest, selected_schema.digest, 32);
                }
            }

            /* 授予权限 = min(本机上限, 需求方申请) */
            granted = (uint8_t)n->cfg.max_perm;
            if (req.perm < granted) granted = (uint8_t)req.perm;
            pt->perm = granted;
            pt->t_pub_ms = negotiate_t_pub(cap->min_sync_ms, req.want_ms,
                                            n->profile.t_link_min_ms);
            pt->subscribed = 1;

            p->pending_pt_count++;
            matched++;

            encode_match_res(payload, sizeof(payload), &opos,
                             cap->index, cap->sub, granted, (uint8_t)cap->fail_action,
                             cap->min_sync_ms, pt->ttl_ms, neg_unit,
                             pt->dtype, pt->scale_exp, pt->schema_id);
        }
    }

    if (matched == 0) return;   /* 全部未命中：E_NOMATCH 已逐条发出 */

    p->stage = IDCELL_STAGE_MATCH;
    p->peer_stage = IDCELL_STAGE_MATCH;   /* 对端（需求方）也到达匹配段 */
    node_send(n, IDCELL_FT_MATCH, &f->src, 0, f->txn, payload, opos);
}

/* 收到 MATCH 响应：我方是需求方 */
static void node_on_match_result(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    int rc;

    if (!p) return;
    p->last_rx_ms = n->now_ms;
    p->role = 2;   /* 我方是需求方 */
    p->pending_pt_count = 0;

    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        uint16_t cap_index;
        uint8_t sub, perm, degrade, ul;
        uint32_t t_prod, t_stale;
        char unit[IDCELL_MAX_UNIT];
        uint8_t r_dtype = 0, r_scale = 0;
        uint64_t r_schema = 0;

        if (t.type != IDCELL_TLV_MATCH_RES) continue;
        if (p->pending_pt_count >= IDCELL_MAX_MATCH_PTS) break;
        if (t.len < 14) continue;

        cap_index = idcell_get_u16(t.val);
        sub   = t.val[2];
        perm  = t.val[3];
        degrade = t.val[4];
        t_prod = idcell_get_u32(t.val + 5);
        t_stale = idcell_get_u32(t.val + 9);
        ul = t.val[13];
        if (ul >= sizeof(unit) || 24u + ul > t.len) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "MATCH", -1, -1,
                            "MATCH_RES 长度或 schema 字段无效");
            return;
        }
        memcpy(unit, t.val + 14, ul);
        unit[ul] = '\0';
        /* v0.9：协商出的值类型与缩放（可选字段，旧实现不带） */
        if (t.len >= 16u + ul) {
            r_dtype = t.val[14 + ul];
            r_scale = t.val[15 + ul];
        }
        if (t.len >= 24u + ul)
            r_schema = idcell_get_u64(t.val + 16 + ul);
        if (!r_schema) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, unit, -1, -1,
                            "匹配结果缺少逐点 schema_id");
            return;
        }

        /* 需求方侧校验：返回的单位必须落在自己声明的可接受集合内 */
        {
            int i, j, ok = 0;
            for (i = 0; i < n->req_count && !ok; i++) {
                const idcell_requirement_t *req = &n->reqs[i];
                if (req->unit[0] && strcmp(req->unit, unit) == 0) { ok = 1; break; }
                for (j = 0; j < req->accept_count; j++)
                    if (strcmp(req->accept_units[j], unit) == 0) { ok = 1; break; }
            }
            if (!ok && unit[0]) {
                node_send_error(n, &f->src, f->txn, IDCELL_E_CONV, unit, -1, -1,
                                "对端返回的单位不在需求方可接受集合内");
                return;
            }
        }

        /*
         * v0.9：校验协商出的值类型必须落在需求方自己的接受集合内
         * （FR-087、FR-088）。
         *
         * 语义层（单位、量种）在此之前已被上面的单位校验拦住；这里
         * 校验的是编码层。若对端返回了一个我没接受的类型，说明协商
         * 被绕过或对端实现有误——MUST 检出而非静默接受。
         */
        if (r_dtype != 0 || r_scale != 0) {
            int i, j, ok = 0;
            for (i = 0; i < n->req_count && !ok; i++) {
                const idcell_requirement_t *req = &n->reqs[i];
                for (j = 0; j < req->accept_type_count; j++) {
                    if (req->accept_types[j].dtype == (idcell_dtype_t)r_dtype &&
                        req->accept_types[j].scale_exp == r_scale) { ok = 1; break; }
                }
            }
            if (!ok) {
                char ts[32];
                idcell_type_t got;
                got.dtype = (idcell_dtype_t)r_dtype;
                got.scale_exp = r_scale;
                idcell_type_str(got, ts, sizeof(ts));
                node_send_error(n, &f->src, f->txn, IDCELL_E_CONV, unit, -1, -1,
                                "对端返回的值类型不在需求方可接受集合内");
                return;
            }
        }

        {
            idcell_type_t selected;
            int i, j, accepted = 0;
            selected.dtype = (idcell_dtype_t)r_dtype;
            selected.scale_exp = r_scale;
            if (node_schema_verify(n, r_schema, selected, unit) != IDCELL_OK) {
                node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, unit, -1, -1,
                                "未知或与 dtype/scale/unit 不匹配的 schema");
                return;
            }
            for (i = 0; i < n->req_count && !accepted; i++) {
                const idcell_requirement_t *req = &n->reqs[i];
                if (!req->schema_count) {
                    idcell_schema_def_t standard;
                    if (idcell_schema_standard(selected.dtype, selected.scale_exp,
                                               unit, &standard) == IDCELL_OK &&
                        standard.schema_id == r_schema) accepted = 1;
                }
                for (j = 0; j < req->schema_count; j++)
                    if (req->schema_set[j] == r_schema) { accepted = 1; break; }
            }
            if (!accepted) {
                node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, unit, -1, -1,
                                "对端替换了未协商的 schema_id");
                return;
            }
        }

        {
            idcell_pt_t *pt = &p->pending_pts[p->pending_pt_count++];
            memset(pt, 0, sizeof(*pt));
            pt->cap_index  = cap_index;
            pt->my_cap_idx = 0xFFFF;      /* 我方不是该点的提供方 */
            pt->sub        = sub;
            pt->perm       = perm;
            pt->prov       = IDCELL_PROV_MEASURED;
            pt->degrade    = degrade;      /* 提供方声明的逐点 fail_action */
            pt->t_prod_ms  = t_prod;
            pt->t_pub_ms   = t_prod;
            pt->ttl_ms     = t_stale;
            pt->dtype      = r_dtype;
            pt->scale_exp  = r_scale;
            pt->schema_id  = r_schema;
            {
                idcell_schema_def_t selected_schema;
                if (idcell_node_schema(n, r_schema, &selected_schema) != IDCELL_OK) return;
                memcpy(pt->schema_digest, selected_schema.digest, 32);
            }
            snprintf(pt->unit, sizeof(pt->unit), "%s", unit);
        }
    }
    (void)rc;

    if (p->pending_pt_count > 0) {
        p->stage = IDCELL_STAGE_MATCH;
        p->peer_stage = IDCELL_STAGE_MATCH;
    }
}

/* ---------------------------------------------------------------- NEGOTIATE */

/*
 * NEGOTIATE：敲定单位、换算规则、T_pub、租约 TTL、仲裁域。
 * T_pub = max(T_prod, T_want, T_link_min)（§08.5）。
 * 红线一：若 T_pub > T_stale，绑定失败，返回 E_NEGOTIATE。
 */
static uint32_t negotiate_t_pub(uint32_t t_prod, uint32_t t_want, uint32_t t_link_min)
{
    uint32_t t = t_prod;
    if (t_want > t) t = t_want;
    if (t_link_min > t) t = t_link_min;
    return t;
}

static void put_bind_point(uint8_t *buf, uint16_t cap, uint16_t *pos,
                           const idcell_pt_t *pt, uint16_t schema_ref)
{
    uint8_t v[96];
    uint16_t n = 0;
    uint16_t ul = (uint16_t)strlen(pt->unit);
    if (ul > IDCELL_MAX_UNIT - 1) ul = IDCELL_MAX_UNIT - 1;
    v[n++] = pt->perm;
    v[n++] = pt->degrade;
    v[n++] = pt->prov;
    v[n++] = pt->dtype;
    v[n++] = pt->scale_exp;
    idcell_put_u64(v + n, pt->schema_id); n += 8;
    idcell_put_u16(v + n, schema_ref); n += 2;
    memcpy(v + n, pt->schema_digest, 32); n += 32;
    idcell_put_u32(v + n, pt->t_pub_ms); n += 4;
    idcell_put_u32(v + n, pt->ttl_ms); n += 4;
    v[n++] = (uint8_t)ul;
    memcpy(v + n, pt->unit, ul); n += ul;
    idcell_tlv_put(buf, cap, pos, pt->cap_index, pt->sub,
                   IDCELL_TLV_BIND_POINT, v, n);
}

static int bind_point_matches(const idcell_tlv_t *t, const idcell_pt_t *pt,
                              uint16_t expected_ref)
{
    uint8_t ul;
    if (!t || !pt || t->type != IDCELL_TLV_BIND_POINT || t->len < 56 ||
        t->idx != pt->cap_index || t->sub != pt->sub) return 0;
    ul = t->val[55];
    if ((uint32_t)56u + ul != t->len || ul >= IDCELL_MAX_UNIT) return 0;
    return t->val[0] == pt->perm && t->val[1] == pt->degrade &&
           t->val[2] == pt->prov && t->val[3] == pt->dtype && t->val[4] == pt->scale_exp &&
           idcell_get_u64(t->val + 5) == pt->schema_id &&
           idcell_get_u16(t->val + 13) == expected_ref &&
           memcmp(t->val + 15, pt->schema_digest, 32) == 0 &&
           idcell_get_u32(t->val + 47) == pt->t_pub_ms &&
           idcell_get_u32(t->val + 51) == pt->ttl_ms &&
           strlen(pt->unit) == ul && memcmp(t->val + 56, pt->unit, ul) == 0;
}

static int verify_bind_points(const idcell_frame_t *f, idcell_pt_t *pts,
                              uint8_t count, int assign_refs)
{
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint8_t seen[IDCELL_MAX_MATCH_PTS];
    int rc, i;
    memset(seen, 0, sizeof(seen));
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type != IDCELL_TLV_BIND_POINT) continue;
        for (i = 0; i < count; i++) {
            uint16_t ref = assign_refs ? (uint16_t)(i + 1) : pts[i].schema_ref;
            if (pts[i].cap_index != t.idx || pts[i].sub != t.sub) continue;
            if (seen[i] || !bind_point_matches(&t, &pts[i], ref)) return IDCELL_E_UNSAFE;
            seen[i] = 1;
            if (assign_refs) pts[i].schema_ref = ref;
            break;
        }
        if (i == count) return IDCELL_E_NODEV;
    }
    if (rc < 0) return IDCELL_E_UNSAFE;
    for (i = 0; i < count; i++) if (!seen[i]) return IDCELL_E_UNSAFE;
    return IDCELL_OK;
}

static const idcell_capability_t *authorized_cap_for_point(idcell_node_t *n,
                                                            const idcell_pt_t *pt)
{
    int i;
    if (pt->my_cap_idx != 0xFFFF && pt->my_cap_idx < n->cap_count)
        return &n->caps[pt->my_cap_idx];
    for (i = 0; i < n->cap_count; i++)
        if (n->caps[i].index == pt->cap_index && n->caps[i].sub == pt->sub) return &n->caps[i];
    return NULL;
}

/* 由提供方本地权威描述生成 PREPARED 授权子集及其规范化 digest。 */
static int put_authorized_descriptors(idcell_node_t *n, idcell_peer_t *p,
                                      uint8_t *payload, uint16_t cap, uint16_t *pos)
{
    uint8_t canonical[IDCELL_MAX_PAYLOAD];
    uint8_t inner[IDCELL_MAX_PAYLOAD];
    uint16_t cpos = 0;
    int i;
    for (i = 0; i < p->pending_pt_count; i++) {
        const idcell_capability_t *c = authorized_cap_for_point(n, &p->pending_pts[i]);
        int len;
        if (!c) return IDCELL_E_UNSAFE;
        len = idcell_desc_encode(c, inner, sizeof(inner));
        if (len < 0 || idcell_authorized_desc_validate(inner, (uint16_t)len) < 0 ||
            idcell_tlv_put(payload, cap, pos, c->index, c->sub,
                           IDCELL_TLV_CAP_DESC, inner, (uint16_t)len) < 0 ||
            idcell_tlv_put(canonical, sizeof(canonical), &cpos, c->index, c->sub,
                           IDCELL_TLV_CAP_DESC, inner, (uint16_t)len) < 0)
            return IDCELL_E_UNSAFE;
    }
    if (!p->pending_pt_count) return IDCELL_E_UNSAFE;
    idcell_descriptor_digest(0, canonical, cpos, p->authorized_digest);
    p->authorized_desc_valid = 1;
    return idcell_tlv_put(payload, cap, pos, 0, 0, IDCELL_TLV_AUTH_DIGEST,
                          p->authorized_digest, 32) < 0 ? IDCELL_E_UNSAFE : IDCELL_OK;
}

static int authorized_point_matches(idcell_node_t *n, const idcell_cap_store_t *cs,
                                    const idcell_pt_t *pt)
{
    idcell_schema_def_t schema;
    idcell_type_t selected;
    int i, accepted;
    double converted;
    idcell_conv_t conv;
    if (cs->fail_action != pt->degrade || cs->provenance != pt->prov ||
        cs->perm > pt->perm ||
        (cs->min_sync_ms && pt->t_pub_ms < cs->min_sync_ms) ||
        (cs->stale_ms && pt->ttl_ms > cs->stale_ms)) return 0;
    if (strcmp(cs->unit, pt->unit) != 0 &&
        idcell_qty_convert((idcell_qty_t)cs->qty, cs->unit, (idcell_qty_t)pt->qty,
                           pt->unit, 0.0, &converted, &conv) != IDCELL_OK) return 0;
    selected.dtype = (idcell_dtype_t)pt->dtype;
    selected.scale_exp = pt->scale_exp;
    accepted = cs->dtype == pt->dtype && cs->scale_exp == pt->scale_exp;
    for (i = 0; !accepted && i < cs->accept_type_count; i++)
        if (cs->accept_types[i].dtype == selected.dtype &&
            cs->accept_types[i].scale_exp == selected.scale_exp) accepted = 1;
    if (!accepted || idcell_node_schema(n, pt->schema_id, &schema) != IDCELL_OK ||
        memcmp(schema.digest, pt->schema_digest, 32) != 0) return 0;
    if (cs->schema_count) {
        accepted = 0;
        for (i = 0; i < cs->schema_count; i++)
            if (cs->schema_set[i] == pt->schema_id) { accepted = 1; break; }
    } else {
        accepted = idcell_schema_standard(selected.dtype, selected.scale_exp, pt->unit, &schema) == IDCELL_OK &&
                   schema.schema_id == pt->schema_id;
    }
    return accepted;
}

/* 完整验证后才合并授权缓存；缺失、额外点、digest 或逐点不一致均无副作用。 */
static int verify_authorized_descriptors(idcell_node_t *n, idcell_peer_t *p,
                                         const idcell_frame_t *f)
{
    idcell_cap_store_t got[IDCELL_MAX_MATCH_PTS];
    uint8_t canonical[IDCELL_MAX_PAYLOAD];
    uint8_t digest[32], expect[32];
    uint16_t pos = 0, cpos = 0;
    uint8_t count = 0, have_digest = 0;
    idcell_tlv_t t;
    int rc, i, j;
    memset(got, 0, sizeof(got));
    memset(digest, 0, sizeof(digest));
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_AUTH_DIGEST) {
            if (have_digest || t.len != 32) return IDCELL_E_UNSAFE;
            memcpy(digest, t.val, 32); have_digest = 1;
        } else if (t.type == IDCELL_TLV_CAP_DESC) {
            if (count >= p->pending_pt_count || count >= IDCELL_MAX_MATCH_PTS ||
                t.idx != p->pending_pts[count].cap_index || t.sub != p->pending_pts[count].sub ||
                idcell_authorized_desc_validate(t.val, t.len) < 0 ||
                idcell_desc_decode(t.val, t.len, &got[count]) < 0 ||
                (uint32_t)cpos + IDCELL_TLV_HDR_LEN + t.len > sizeof(canonical))
                return IDCELL_E_UNSAFE;
            got[count].index = t.idx; got[count].sub = t.sub;
            memcpy(canonical + cpos, t.val - IDCELL_TLV_HDR_LEN,
                   IDCELL_TLV_HDR_LEN + t.len);
            cpos = (uint16_t)(cpos + IDCELL_TLV_HDR_LEN + t.len);
            count++;
        }
    }
    if (rc < 0 || !have_digest || count != p->pending_pt_count || !count) return IDCELL_E_UNSAFE;
    idcell_descriptor_digest(0, canonical, cpos, expect);
    if (memcmp(expect, digest, 32) != 0) return IDCELL_E_UNSAFE;
    for (i = 0; i < count; i++) {
        for (j = 0; j < p->pending_pt_count; j++)
            if (p->pending_pts[j].cap_index == got[i].index &&
                p->pending_pts[j].sub == got[i].sub) break;
        if (j == p->pending_pt_count || !authorized_point_matches(n, &got[i], &p->pending_pts[j]))
            return IDCELL_E_UNSAFE;
    }
    for (i = 0; i < count; i++) {
        for (j = 0; j < p->pending_pt_count; j++) {
            if (p->pending_pts[j].cap_index != got[i].index || p->pending_pts[j].sub != got[i].sub)
                continue;
            snprintf(p->pending_pts[j].src_unit, sizeof(p->pending_pts[j].src_unit), "%s", got[i].unit);
            p->pending_pts[j].qty = got[i].qty;
            break;
        }
        for (j = 0; j < p->cap_count; j++) {
            if (p->caps[j].index == got[i].index && p->caps[j].sub == got[i].sub) {
                p->caps[j] = got[i];
                break;
            }
        }
    }
    memcpy(p->authorized_digest, digest, 32);
    p->authorized_desc_valid = 1;
    return IDCELL_OK;
}

static int verify_bind_digest(const idcell_peer_t *p, const idcell_frame_t *f)
{
    uint16_t pos = 0;
    idcell_tlv_t t;
    int rc, seen = 0;
    if (!p->authorized_desc_valid) return 0;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type != IDCELL_TLV_AUTH_DIGEST) continue;
        if (seen || t.len != 32 || memcmp(t.val, p->authorized_digest, 32) != 0) return 0;
        seen = 1;
    }
    return rc >= 0 && seen;
}

static void node_on_negotiate(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint16_t opos = 0;
    uint32_t want_lease = n->cfg.lease_ttl_ms;
    uint32_t want[IDCELL_MAX_MATCH_PTS];
    uint32_t stale[IDCELL_MAX_MATCH_PTS];
    int nwant = 0, nstale = 0, rc, i;

    if (!p) return;
    p->last_rx_ms = n->now_ms;

    memset(want, 0, sizeof(want));
    memset(stale, 0, sizeof(stale));

    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_TPUB) {
            if (nwant < IDCELL_MAX_MATCH_PTS) want[nwant++] = tlv_u32(&t, 0);
        } else if (t.type == IDCELL_TLV_STALE) {
            if (nstale < IDCELL_MAX_MATCH_PTS) stale[nstale++] = tlv_u32(&t, 0);
        } else if (t.type == IDCELL_TLV_TTL) {
            want_lease = tlv_u32(&t, want_lease);
        }
    }
    if (rc < 0 || nwant != p->pending_pt_count || nstale != p->pending_pt_count) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_NEGOTIATE, "NEGOTIATE", -1, -1,
                        "每点必须给出最终 T_want/T_stale");
        return;
    }

    for (i = 0; i < p->pending_pt_count; i++) {
        idcell_pt_t *pt = &p->pending_pts[i];
        uint32_t t_want = (i < nwant) ? want[i] : 0;
        uint32_t t_stale_req = (i < nstale) ? stale[i] : 0;

        pt->t_want_ms = t_want;
        pt->t_pub_ms  = negotiate_t_pub(pt->t_prod_ms, t_want, n->profile.t_link_min_ms);

        /* 保鲜上限取双方更严者 */
        if (t_stale_req && (pt->ttl_ms == 0 || t_stale_req < pt->ttl_ms))
            pt->ttl_ms = t_stale_req;

        /* 红线一：T_pub 超过保鲜上限即失败 */
        if (pt->ttl_ms && pt->t_pub_ms > pt->ttl_ms) {
            char reason[96];
            snprintf(reason, sizeof(reason),
                     "T_pub=%ums 超过保鲜上限 %ums", pt->t_pub_ms, pt->ttl_ms);
            node_send_error(n, &f->src, f->txn, IDCELL_E_NEGOTIATE,
                            pt->unit, -1, -1, reason);
            return;
        }
    }

    /* 租约 TTL 取更严者：本机上限与对端请求 */
    if (want_lease == 0 || want_lease > n->cfg.lease_ttl_ms)
        want_lease = n->cfg.lease_ttl_ms;
    if (!want_lease || want_lease > IDCELL_MAX_LEASE_TTL_MS) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_NEGOTIATE, "NEGOTIATE", -1, -1,
                        "租约 TTL 超出有界范围");
        return;
    }
    p->pending_contract.lease_ttl_ms = want_lease;
    p->pending_contract.arb_domain = derive_arb_domain(n, 0, 0);
    p->pending_contract.desc_version = n->desc_version;
    p->pending_contract.perm = (idcell_perm_t)n->cfg.max_perm;

    put_u32_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_TTL, want_lease);
    put_u32_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_ARB, p->pending_contract.arb_domain);
    put_u32_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_DESC_VER, n->desc_version);
    put_u8_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_PERM,
               (uint8_t)p->pending_contract.perm);
    for (i = 0; i < p->pending_pt_count; i++) {
        put_u32_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_TPUB, p->pending_pts[i].t_pub_ms);
        put_u32_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_STALE, p->pending_pts[i].ttl_ms);
        p->pending_pts[i].schema_ref = (uint16_t)(i + 1);
        put_bind_point(payload, sizeof(payload), &opos, &p->pending_pts[i],
                       p->pending_pts[i].schema_ref);
    }

    p->stage = IDCELL_STAGE_NEGOTIATE;
    p->peer_stage = IDCELL_STAGE_NEGOTIATE;   /* 对端已进入协商段 */
    node_send(n, IDCELL_FT_NEGOTIATE, &f->src, 0, f->txn, payload, opos);
}

static void node_on_negotiate_result(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint32_t tpub[IDCELL_MAX_MATCH_PTS];
    uint32_t stale[IDCELL_MAX_MATCH_PTS];
    int np = 0, ns = 0, rc, i;

    if (!p) return;
    p->last_rx_ms = n->now_ms;

    memset(tpub, 0, sizeof(tpub));
    memset(stale, 0, sizeof(stale));

    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_TPUB) {
            if (np < IDCELL_MAX_MATCH_PTS) tpub[np++] = tlv_u32(&t, 0);
        } else if (t.type == IDCELL_TLV_STALE) {
            if (ns < IDCELL_MAX_MATCH_PTS) stale[ns++] = tlv_u32(&t, 0);
        } else if (t.type == IDCELL_TLV_TTL) {
            p->pending_contract.lease_ttl_ms = tlv_u32(&t, p->pending_contract.lease_ttl_ms);
        } else if (t.type == IDCELL_TLV_ARB) {
            p->pending_contract.arb_domain = tlv_u32(&t, 0);
        } else if (t.type == IDCELL_TLV_DESC_VER) {
            p->pending_contract.desc_version = tlv_u32(&t, 0);
        } else if (t.type == IDCELL_TLV_PERM) {
            p->pending_contract.perm = (idcell_perm_t)tlv_u8(&t, 0);
        }
    }
    if (rc < 0 || np != p->pending_pt_count || ns != p->pending_pt_count ||
        !p->pending_contract.lease_ttl_ms || !p->pending_contract.desc_version ||
        p->pending_contract.lease_ttl_ms > IDCELL_MAX_LEASE_TTL_MS) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "NEGOTIATE", -1, -1,
                        "NEGOTIATE 缺少最终 ARB/TTL/desc_version/T_stale");
        return;
    }

    for (i = 0; i < p->pending_pt_count; i++) {
        if (i < np && tpub[i]) p->pending_pts[i].t_pub_ms = tpub[i];
        if (i < ns && stale[i]) p->pending_pts[i].ttl_ms = stale[i];
    }
    if (verify_bind_points(f, p->pending_pts, p->pending_pt_count, 1) != IDCELL_OK) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "NEGOTIATE", -1, -1,
                        "逐点 schema_id/schema_ref 与协商结果不一致");
        return;
    }

    if (p->pending_pt_count) {
        p->stage = IDCELL_STAGE_NEGOTIATE;
        p->peer_stage = IDCELL_STAGE_NEGOTIATE;   /* 对端已完成协商 */
    }
}

/* ---------------------------------------------------------------- AUTHORIZE */

/*
 * 挑战-响应（FR-022）：AUTH 帧先由需求方发起（携带 nonce），
 * 提供方返回 HMAC 证明。证明 MUST NOT 携带可重放的静态明文凭证，
 * 同一 nonce 的响应 MUST 只被接受一次。
 */
static void node_on_auth(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint16_t opos = 0;
    uint8_t nonce[16];
    uint8_t mac[32];
    int rc, have_nonce = 0;

    if (!p) return;
    p->last_rx_ms = n->now_ms;

    memset(nonce, 0, sizeof(nonce));
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_NONCE && t.len == 16) {
            memcpy(nonce, t.val, 16);
            have_nonce = 1;
        }
    }
    (void)rc;

    if (!have_nonce) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, "AUTH", -1, -1, "缺少挑战随机数");
        return;
    }

    /* 重放防护：同一 nonce 只接受一次 */
    if (p->auth_used_valid && memcmp(p->auth_used, nonce, 16) == 0) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "AUTH", -1, -1,
                        "挑战已使用，拒绝重放");
        return;
    }

    /* HMAC 覆盖 nonce + 双方 DID（序归一化）+ 事务号：会话绑定（SEC-009） */
    auth_mac(n->cfg.cred, nonce, &n->cfg.did, &f->src, f->txn, mac);

    memcpy(p->auth_used, nonce, 16);
    p->auth_used_valid = 1;
    memcpy(p->auth_nonce, nonce, 16);
    p->auth_nonce_valid = 1;
    p->auth_txn = f->txn;
    peer_derive_key(n, p, &p->bind_key, 0, 0);
    key_wipe(&p->next_key);
    p->authorized_desc_valid = 0;

    idcell_tlv_put(payload, sizeof(payload), &opos, 0, 0, IDCELL_TLV_AUTH_PROOF, mac, 32);
    put_u8_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_PERM, n->cfg.max_perm);
    put_str_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_RESULT, "OK");

    p->peer_perm = n->cfg.max_perm;
    p->stage = IDCELL_STAGE_AUTHORIZE;
    p->peer_stage = IDCELL_STAGE_AUTHORIZE;   /* 对端已完成鉴权 */
    node_send(n, IDCELL_FT_AUTH, &f->src, 0, f->txn, payload, opos);
}

/* 收到 AUTH 证明：校验并授予实权限 */
static void node_on_auth_result(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint8_t mac[32];
    uint8_t expect[32];
    int rc, have = 0;
    uint8_t perm = 0;

    if (!p) return;
    p->last_rx_ms = n->now_ms;

    memset(mac, 0, sizeof(mac));
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_AUTH_PROOF && t.len == 32) {
            memcpy(mac, t.val, 32);
            have = 1;
        } else if (t.type == IDCELL_TLV_PERM) {
            perm = tlv_u8(&t, 0);
        }
    }
    (void)rc;

    if (!have) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, "AUTH", -1, -1, "缺少鉴权证明");
        return;
    }
    if (!p->auth_nonce_valid) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, "AUTH", -1, -1, "没有待校验的挑战");
        return;
    }

    auth_mac(n->cfg.cred, p->auth_nonce, &n->cfg.did, &f->src, f->txn, expect);

    {
        uint8_t diff = 0;
        int i;
        for (i = 0; i < 32; i++) diff |= (uint8_t)(expect[i] ^ mac[i]);
        if (diff != 0) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, "AUTH", -1, -1, "鉴权证明不匹配");
            return;
        }
    }

    peer_derive_key(n, p, &p->bind_key, 0, 0);
    key_wipe(&p->next_key);
    p->authorized_desc_valid = 0;
    /* 理解度不得直接兑换写权限（SEC-014）：实权限只由对端授权决定 */
    p->granted_own_perm = perm;
    p->stage = IDCELL_STAGE_AUTHORIZE;
    p->peer_stage = IDCELL_STAGE_AUTHORIZE;   /* 对端鉴权通过 */
}

/* ---------------------------------------------------------------- BIND */

/* 写能力点必须归属某个仲裁域（§09.7） */
static uint32_t derive_arb_domain(idcell_node_t *n, uint16_t index, uint8_t sub)
{
    uint32_t h = 0x811C9DC5u;
    h ^= (uint32_t)index; h *= 0x01000193u;
    h ^= (uint32_t)sub;  h *= 0x01000193u;
    h ^= n->cfg.did.b[0]; h *= 0x01000193u;
    return h & 0x7FFFFFFFu;
}

static idcell_active_grant_t *grant_find(idcell_node_t *n, uint32_t domain, int create)
{
    int i, free_slot = -1;
    for (i = 0; i < IDCELL_MAX_GRANTS; i++) {
        if (n->grants[i].used && n->grants[i].arb_domain == domain) return &n->grants[i];
        if (!n->grants[i].used && free_slot < 0) free_slot = i;
    }
    if (create && free_slot >= 0) {
        memset(&n->grants[free_slot], 0, sizeof(n->grants[free_slot]));
        n->grants[free_slot].used = 1;
        n->grants[free_slot].arb_domain = domain;
        return &n->grants[free_slot];
    }
    return NULL;
}

static int grant_can_activate(idcell_node_t *n, const idcell_peer_t *p)
{
    idcell_active_grant_t *g = grant_find(n, p->pending_contract.arb_domain, 0);
    if (!g) return 1;
    if (time_reached(n->now_ms, g->deadline_ms)) {
        memset(g, 0, sizeof(*g));
        return 1;
    }
    return 0;
}

static int grant_activate(idcell_node_t *n, idcell_peer_t *p)
{
    idcell_active_grant_t *g = grant_find(n, p->contract.arb_domain, 1);
    if (!g) return IDCELL_E_RANGE;
    g->owner = p->did;
    g->session_id = p->contract.session_id;
    g->grant_epoch = p->contract.grant_epoch;
    g->owner_token = p->contract.owner_token;
    g->authority_id = p->contract.authority_id;
    g->authority_epoch = p->contract.authority_epoch;
    g->member_epoch = p->contract.member_epoch;
    g->deadline_ms = n->now_ms + p->contract.lease_ttl_ms;
    return IDCELL_OK;
}

static int grant_validate(idcell_node_t *n, const idcell_peer_t *p,
                          const idcell_did_t *owner, uint64_t session,
                          uint64_t epoch, uint32_t token, uint64_t authority,
                          uint64_t authority_epoch, uint64_t member)
{
    idcell_active_grant_t *g = grant_find(n, p->contract.arb_domain, 0);
    if (!g || time_reached(n->now_ms, g->deadline_ms)) return IDCELL_E_LEASE;
    if (!idcell_did_equal(&g->owner, owner) || g->session_id != session ||
        g->grant_epoch != epoch || g->owner_token != token ||
        g->authority_id != authority || g->authority_epoch != authority_epoch ||
        g->member_epoch != member) return IDCELL_E_LEASE;
    return IDCELL_OK;
}

static void fill_pending_points(idcell_peer_t *p)
{
    int i;
    p->pending_contract.pt_count = 0;
    for (i = 0; i < p->pending_pt_count && i < IDCELL_MAX_CONTRACT_PTS; i++) {
        idcell_pt_t *pt = &p->pending_pts[i];
        idcell_contract_point_t *cp = &p->pending_contract.pt[p->pending_contract.pt_count++];
        cp->index = pt->cap_index;
        cp->sub = pt->sub;
        cp->perm = (idcell_perm_t)pt->perm;
        cp->degrade = (idcell_fail_t)pt->degrade;
        cp->prov = (idcell_prov_t)pt->prov;
        cp->t_pub_ms = pt->t_pub_ms;
        cp->dtype = pt->dtype;
        cp->scale_exp = pt->scale_exp;
        cp->schema_id = pt->schema_id;
        cp->schema_ref = pt->schema_ref;
        snprintf(cp->unit, sizeof(cp->unit), "%s", pt->unit);
    }
}

static void send_bind_phase(idcell_node_t *n, idcell_peer_t *p, uint16_t txn,
                            uint8_t phase, int with_points)
{
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint16_t pos = 0;
    int i;
    const idcell_contract_t *c = (phase == IDCELL_BIND_PHASE_COMMITTED ||
                                  phase == IDCELL_BIND_PHASE_RELEASE)
                                 ? &p->contract : &p->pending_contract;
    put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_BIND_PHASE, phase);
    if (phase == IDCELL_BIND_PHASE_PREPARED || phase == IDCELL_BIND_PHASE_COMMIT ||
        phase == IDCELL_BIND_PHASE_COMMITTED || phase == IDCELL_BIND_PHASE_ABORT ||
        phase == IDCELL_BIND_PHASE_RELEASE) {
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_BIND_ID, c->binding_id);
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_DESC_VER, c->desc_version);
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_TTL, c->lease_ttl_ms);
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_ARB, c->arb_domain);
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_OWNER, c->owner_token);
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_PERM, (uint8_t)c->perm);
        put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_SESSION_ID, c->session_id);
        put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_GRANT_EPOCH, c->grant_epoch);
        put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_AUTHORITY_ID, c->authority_id);
        put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_AUTHORITY_EPOCH, c->authority_epoch);
        put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_MEMBER_EPOCH, c->member_epoch);
    }
    if (with_points) {
        for (i = 0; i < p->pending_pt_count; i++)
            put_bind_point(payload, sizeof(payload), &pos, &p->pending_pts[i],
                           p->pending_pts[i].schema_ref);
        if (put_authorized_descriptors(n, p, payload, sizeof(payload), &pos) != IDCELL_OK) {
            p->authorized_desc_valid = 0;
            return;
        }
    } else if (phase == IDCELL_BIND_PHASE_COMMIT || phase == IDCELL_BIND_PHASE_COMMITTED) {
        if (!p->authorized_desc_valid ||
            idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_AUTH_DIGEST,
                           p->authorized_digest, 32) < 0) return;
    }
    node_send(n, IDCELL_FT_BIND, &p->did, 0, txn, payload, pos);
    if (phase == IDCELL_BIND_PHASE_ABORT && p->next_key.valid) {
        /* PREPARED 后一端可能已切新钥、另一端仍持旧钥；ABORT 两侧都要可撤销。 */
        idcell_session_key_t previous = p->bind_key;
        p->bind_key = p->next_key;
        node_send(n, IDCELL_FT_BIND, &p->did, 0, txn, payload, pos);
        p->bind_key = previous;
    }
}

static void send_abort_instance(idcell_node_t *n, idcell_peer_t *p, uint16_t txn,
                                const idcell_contract_t *instance)
{
    uint8_t payload[64];
    uint16_t pos = 0;
    put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_BIND_PHASE,
               IDCELL_BIND_PHASE_ABORT);
    put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_BIND_ID, instance->binding_id);
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_SESSION_ID, instance->session_id);
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_GRANT_EPOCH, instance->grant_epoch);
    node_send(n, IDCELL_FT_BIND, &p->did, 0, txn, payload, pos);
}

static void clear_pending(idcell_peer_t *p)
{
    memset(&p->pending_contract, 0, sizeof(p->pending_contract));
    memset(p->pending_pts, 0, sizeof(p->pending_pts));
    p->pending_pt_count = 0;
    p->commit_waiting = 0;
    p->renegotiating = 0;
    p->reneg_old_binding = 0;
    p->reneg_old_session = 0;
    p->reneg_old_grant = 0;
    p->bind_phase = p->has_contract ? IDCELL_BIND_ACTIVE : IDCELL_BIND_NONE;
    p->stage = p->has_contract ? IDCELL_STAGE_RUNNING : IDCELL_STAGE_DESCRIBE;
    p->peer_stage = p->stage;
    key_wipe(&p->bind_key);
    key_wipe(&p->next_key);
    p->authorized_desc_valid = 0;
}

static int activate_pending(idcell_node_t *n, idcell_peer_t *p)
{
    idcell_session_key_t selected;
    if (!p->authorized_desc_valid) return IDCELL_E_UNSAFE;
    if (p->next_key.valid && p->next_key.session_id == p->pending_contract.session_id)
        selected = p->next_key;
    else if (p->bind_key.valid && p->bind_key.session_id == p->pending_contract.session_id)
        selected = p->bind_key;
    else
        return IDCELL_E_PERM;
    key_wipe(&p->active_key);
    p->active_key = selected;
    p->bind_key = selected;
    key_wipe(&p->next_key);
    p->contract = p->pending_contract;
    p->pt_count = p->pending_pt_count;
    memcpy(p->pts, p->pending_pts, sizeof(p->pts));
    p->owner_token = p->contract.owner_token;
    p->has_contract = 1;
    p->bind_phase = IDCELL_BIND_ACTIVE;
    p->stage = IDCELL_STAGE_RUNNING;
    p->peer_stage = IDCELL_STAGE_RUNNING;
    p->lease_deadline_ms = n->now_ms + p->contract.lease_ttl_ms;
    if (p->role == 1) (void)grant_activate(n, p);
    if (p->contract.grant_epoch > n->grant_epoch_counter)
        n->grant_epoch_counter = p->contract.grant_epoch;
    if (p->contract.authority_epoch > n->authority_epoch_floor)
        n->authority_epoch_floor = p->contract.authority_epoch;
    if (p->contract.member_epoch > n->member_epoch_floor)
        n->member_epoch_floor = p->contract.member_epoch;
    n->trusted_authority_id = p->contract.authority_id;
    p->trusted_authority_id = p->contract.authority_id;
    p->grant_epoch_floor = p->contract.grant_epoch;
    p->authority_epoch_floor = p->contract.authority_epoch;
    p->member_epoch_floor = p->contract.member_epoch;
    n->grant_fingerprint = idcell_contract_fingerprint(&p->contract);
    memset(&p->pending_contract, 0, sizeof(p->pending_contract));
    memset(p->pending_pts, 0, sizeof(p->pending_pts));
    p->pending_pt_count = 0;
    p->renegotiating = 0;
    p->recovery = 0;
    p->suspended = 0;
    p->offline = 0;
    p->reneg_old_binding = 0;
    p->reneg_old_session = 0;
    p->reneg_old_grant = 0;
    return IDCELL_OK;
}

static int bind_parameters_match(const idcell_contract_t *a, const idcell_contract_t *b)
{
    return a->desc_version == b->desc_version && a->lease_ttl_ms == b->lease_ttl_ms &&
           a->arb_domain == b->arb_domain && a->perm == b->perm;
}

static int bind_identity_matches(const idcell_contract_t *a, const idcell_contract_t *b)
{
    return a->binding_id == b->binding_id && a->session_id == b->session_id &&
           a->grant_epoch == b->grant_epoch && a->owner_token == b->owner_token &&
           a->authority_id == b->authority_id &&
           a->authority_epoch == b->authority_epoch && a->member_epoch == b->member_epoch;
}

static void node_activate_waiters(idcell_node_t *n)
{
    int i;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        if (!p->used || !p->commit_waiting || !grant_can_activate(n, p)) continue;
        p->commit_waiting = 0;
        if (activate_pending(n, p) != IDCELL_OK) continue;
        send_bind_phase(n, p, p->txn, IDCELL_BIND_PHASE_COMMITTED, 0);
    }
}

static void node_on_bind(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint8_t phase = IDCELL_BIND_PHASE_PREPARE;
    uint32_t desc = 0, ttl = 0, arb = 0, old_binding = 0, binding = 0;
    uint64_t old_session = 0, old_grant = 0, session = 0, grant = 0;
    uint8_t perm = 0;
    int rc;
    if (!p) return;
    p->last_rx_ms = n->now_ms;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_BIND_PHASE) phase = tlv_u8(&t, 0);
        else if (t.type == IDCELL_TLV_DESC_VER) desc = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_TTL) ttl = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_ARB) arb = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_PERM) perm = tlv_u8(&t, 0);
        else if (t.type == IDCELL_TLV_OLD_BINDING) old_binding = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_OLD_SESSION) old_session = tlv_u64(&t, 0);
        else if (t.type == IDCELL_TLV_OLD_GRANT) old_grant = tlv_u64(&t, 0);
        else if (t.type == IDCELL_TLV_BIND_ID) binding = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_SESSION_ID) session = tlv_u64(&t, 0);
        else if (t.type == IDCELL_TLV_GRANT_EPOCH) grant = tlv_u64(&t, 0);
    }
    if (rc < 0) return;

    if (phase == IDCELL_BIND_PHASE_RELEASE) {
        idcell_active_grant_t *g;
        if (!p->has_contract || binding != p->contract.binding_id ||
            session != p->contract.session_id || grant != p->contract.grant_epoch)
            return;
        g = grant_find(n, p->contract.arb_domain, 0);
        if (!g || !idcell_did_equal(&g->owner, &f->src) ||
            g->session_id != session || g->grant_epoch != grant ||
            g->owner_token != p->contract.owner_token) return;
        memset(g, 0, sizeof(*g));
        p->owner_token = 0;
        node_activate_waiters(n);
        return;
    }
    if (phase == IDCELL_BIND_PHASE_ABORT) {
        if (p->pending_contract.binding_id == binding &&
            p->pending_contract.session_id == session &&
            p->pending_contract.grant_epoch == grant && binding && session)
            clear_pending(p);
        return;
    }
    if (phase == IDCELL_BIND_PHASE_PREPARE) {
        uint64_t epoch;
        uint32_t negotiated_lease = p->pending_contract.lease_ttl_ms;
        uint32_t negotiated_desc = p->pending_contract.desc_version;
        uint32_t negotiated_arb = p->pending_contract.arb_domain;
        idcell_perm_t negotiated_perm = p->pending_contract.perm;
        if (!p->bind_key.valid || p->bind_key.session_id != 0 || !p->auth_nonce_valid ||
            !p->pending_pt_count || p->pending_pt_count > IDCELL_MAX_CONTRACT_PTS ||
            desc != p->pending_contract.desc_version || ttl != p->pending_contract.lease_ttl_ms ||
            arb != p->pending_contract.arb_domain || perm != (uint8_t)p->pending_contract.perm ||
            (p->renegotiating && (!p->has_contract || old_binding != p->contract.binding_id ||
             old_session != p->contract.session_id || old_grant != p->contract.grant_epoch)) ||
            verify_bind_points(f, p->pending_pts, p->pending_pt_count, 0) != IDCELL_OK) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "BIND", -1, -1,
                            "PREPARE 的 cap_list/schema 与协商结果不一致");
            return;
        }
        if (p->bind_phase == IDCELL_BIND_PREPARED && p->pending_contract.binding_id) {
            send_bind_phase(n, p, f->txn, IDCELL_BIND_PHASE_PREPARED, 1);
            return;
        }
        memset(&p->pending_contract, 0, sizeof(p->pending_contract));
        p->pending_contract.binding_id = (uint32_t)(node_rand(n) & 0x7FFFFFFFu);
        if (!p->pending_contract.binding_id) p->pending_contract.binding_id = 1;
        p->pending_contract.peer = f->src;
        p->pending_contract.desc_version = negotiated_desc;
        p->pending_contract.lease_ttl_ms = negotiated_lease ? negotiated_lease : n->cfg.lease_ttl_ms;
        p->pending_contract.perm = negotiated_perm;
        p->pending_contract.arb_domain = negotiated_arb;
        p->pending_contract.owner_token = (uint32_t)(node_rand(n) & 0x7FFFFFFFu);
        if (!p->pending_contract.owner_token) p->pending_contract.owner_token = 1;
        p->pending_contract.session_id = node_rand(n);
        if (!p->pending_contract.session_id) p->pending_contract.session_id = 1;
        epoch = n->grant_epoch_counter + 1;
        if (epoch <= n->authority_epoch_floor) epoch = n->authority_epoch_floor + 1;
        if (epoch <= n->member_epoch_floor) epoch = n->member_epoch_floor + 1;
        p->pending_contract.grant_epoch = epoch;
        p->pending_contract.authority_id = n->authority_id;
        p->pending_contract.authority_epoch = epoch;
        p->pending_contract.member_epoch = epoch;
        fill_pending_points(p);
        peer_derive_key(n, p, &p->next_key, p->pending_contract.binding_id,
                        p->pending_contract.session_id);
        p->bind_phase = IDCELL_BIND_PREPARED;
        p->stage = IDCELL_STAGE_BIND;
        send_bind_phase(n, p, f->txn, IDCELL_BIND_PHASE_PREPARED, 1);
        return;
    }
    if (phase == IDCELL_BIND_PHASE_COMMIT) {
        idcell_contract_t got = p->pending_contract;
        if (!verify_bind_digest(p, f)) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "BIND", -1, -1,
                            "COMMIT 缺少或不匹配授权描述 digest");
            return;
        }
        uint32_t binding = 0;
        uint64_t session = 0, grant = 0, authority = 0, authority_epoch = 0, member = 0;
        uint32_t owner = 0;
        pos = 0;
        while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
            if (t.type == IDCELL_TLV_BIND_ID) binding = tlv_u32(&t, 0);
            else if (t.type == IDCELL_TLV_SESSION_ID) session = tlv_u64(&t, 0);
            else if (t.type == IDCELL_TLV_GRANT_EPOCH) grant = tlv_u64(&t, 0);
            else if (t.type == IDCELL_TLV_AUTHORITY_ID) authority = tlv_u64(&t, 0);
            else if (t.type == IDCELL_TLV_AUTHORITY_EPOCH) authority_epoch = tlv_u64(&t, 0);
            else if (t.type == IDCELL_TLV_MEMBER_EPOCH) member = tlv_u64(&t, 0);
            else if (t.type == IDCELL_TLV_OWNER) owner = tlv_u32(&t, 0);
            else if (t.type == IDCELL_TLV_DESC_VER) got.desc_version = tlv_u32(&t, 0);
            else if (t.type == IDCELL_TLV_TTL) got.lease_ttl_ms = tlv_u32(&t, 0);
            else if (t.type == IDCELL_TLV_ARB) got.arb_domain = tlv_u32(&t, 0);
            else if (t.type == IDCELL_TLV_PERM) got.perm = (idcell_perm_t)tlv_u8(&t, 0);
        }
        got.binding_id = binding; got.session_id = session; got.grant_epoch = grant;
        got.authority_id = authority; got.authority_epoch = authority_epoch;
        got.member_epoch = member; got.owner_token = owner;
        if (p->has_contract && bind_identity_matches(&got, &p->contract)) {
            send_bind_phase(n, p, f->txn, IDCELL_BIND_PHASE_COMMITTED, 0);
            return;
        }
        if (p->bind_phase != IDCELL_BIND_PREPARED || !p->next_key.valid ||
            p->next_key.session_id != session ||
            !bind_identity_matches(&got, &p->pending_contract) ||
            !bind_parameters_match(&got, &p->pending_contract)) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "BIND", -1, -1,
                            "COMMIT 与 prepared 会话/授权不一致");
            return;
        }
        if (!grant_can_activate(n, p)) {
            p->commit_waiting = 1;
            p->next_retry_ms = n->now_ms + 1000;
            return;
        }
        p->commit_waiting = 0;
        if (activate_pending(n, p) != IDCELL_OK) return;
        send_bind_phase(n, p, f->txn, IDCELL_BIND_PHASE_COMMITTED, 0);
        return;
    }
    node_send_error(n, &f->src, f->txn, IDCELL_E_NEGOTIATE, "BIND", -1, -1,
                    "非法 BIND phase");
}

int idcell_node_release(idcell_node_t *n, const idcell_did_t *peer)
{
    int i;
    if (!n || !peer) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        if (!p->used || !idcell_did_equal(&p->did, peer) || !p->has_contract) continue;
        if (!p->owner_token) return IDCELL_E_LEASE;
        send_bind_phase(n, p, ++p->txn, IDCELL_BIND_PHASE_RELEASE, 0);
        p->owner_token = 0;
        return IDCELL_OK;
    }
    return IDCELL_E_NODEV;
}

/* 需求方接收 PREPARED/COMMITTED；只有 COMMITTED 才使契约对外可见。 */
static void node_on_bind_result(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    idcell_contract_t got;
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint8_t phase = IDCELL_BIND_PHASE_PREPARED;
    int rc;
    if (!p) return;
    p->last_rx_ms = n->now_ms;
    memset(&got, 0, sizeof(got));
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        switch (t.type) {
        case IDCELL_TLV_BIND_PHASE: phase = tlv_u8(&t, 0); break;
        case IDCELL_TLV_BIND_ID: got.binding_id = tlv_u32(&t, 0); break;
        case IDCELL_TLV_DESC_VER: got.desc_version = tlv_u32(&t, 0); break;
        case IDCELL_TLV_TTL: got.lease_ttl_ms = tlv_u32(&t, 0); break;
        case IDCELL_TLV_ARB: got.arb_domain = tlv_u32(&t, 0); break;
        case IDCELL_TLV_OWNER: got.owner_token = tlv_u32(&t, 0); break;
        case IDCELL_TLV_PERM: got.perm = (idcell_perm_t)tlv_u8(&t, 0); break;
        case IDCELL_TLV_SESSION_ID: got.session_id = tlv_u64(&t, 0); break;
        case IDCELL_TLV_GRANT_EPOCH: got.grant_epoch = tlv_u64(&t, 0); break;
        case IDCELL_TLV_AUTHORITY_ID: got.authority_id = tlv_u64(&t, 0); break;
        case IDCELL_TLV_AUTHORITY_EPOCH: got.authority_epoch = tlv_u64(&t, 0); break;
        case IDCELL_TLV_MEMBER_EPOCH: got.member_epoch = tlv_u64(&t, 0); break;
        default: break;
        }
    }
    if (rc < 0) return;
    if (phase == IDCELL_BIND_PHASE_ABORT) {
        if (p->pending_contract.binding_id == got.binding_id &&
            p->pending_contract.session_id == got.session_id &&
            p->pending_contract.grant_epoch == got.grant_epoch &&
            got.binding_id && got.session_id)
            clear_pending(p);
        return;
    }
    got.peer = f->src;
    if (phase == IDCELL_BIND_PHASE_PREPARED) {
        uint64_t grant_floor = p->grant_epoch_floor;
        uint64_t authority_floor = p->authority_epoch_floor;
        uint64_t member_floor = p->member_epoch_floor;
        if (!p->trusted_authority_id && n->trusted_authority_id == got.authority_id) {
            if (n->grant_epoch_counter > grant_floor) grant_floor = n->grant_epoch_counter;
            if (n->authority_epoch_floor > authority_floor) authority_floor = n->authority_epoch_floor;
            if (n->member_epoch_floor > member_floor) member_floor = n->member_epoch_floor;
        }
        if (!got.binding_id || !got.session_id || !got.grant_epoch || !got.owner_token ||
            got.grant_epoch <= grant_floor ||
            (p->trusted_authority_id && got.authority_id != p->trusted_authority_id) ||
            got.authority_epoch < authority_floor || got.member_epoch < member_floor ||
            !bind_parameters_match(&got, &p->pending_contract) ||
            verify_bind_points(f, p->pending_pts, p->pending_pt_count, 0) != IDCELL_OK ||
            verify_authorized_descriptors(n, p, f) != IDCELL_OK) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "BIND", -1, -1,
                            "PREPARED 含旧纪元、缺失/篡改授权描述或不一致 schema");
            send_abort_instance(n, p, f->txn, &got);
            clear_pending(p);
            return;
        }
        got.pt_count = p->pending_contract.pt_count;
        p->pending_contract = got;
        fill_pending_points(p);
        peer_derive_key(n, p, &p->bind_key, got.binding_id, got.session_id);
        key_wipe(&p->next_key);
        p->bind_phase = IDCELL_BIND_COMMIT_SENT;
        p->next_retry_ms = n->now_ms + 1000;
        /* 本地 commit 已决定，但对端 committed 前仍不可读写。 */
        send_bind_phase(n, p, f->txn, IDCELL_BIND_PHASE_COMMIT, 0);
        return;
    }
    if (phase == IDCELL_BIND_PHASE_COMMITTED) {
        if (!verify_bind_digest(p, f)) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "BIND", -1, -1,
                            "COMMITTED 缺少或不匹配授权描述 digest");
            return;
        }
        if (p->has_contract && bind_identity_matches(&got, &p->contract)) return;
        if (p->bind_phase != IDCELL_BIND_COMMIT_SENT ||
            !bind_identity_matches(&got, &p->pending_contract) ||
            !bind_parameters_match(&got, &p->pending_contract)) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "BIND", -1, -1,
                            "COMMITTED 与本地 commit 不一致");
            return;
        }
        if (activate_pending(n, p) != IDCELL_OK) return;
        return;
    }
    node_send_error(n, &f->src, f->txn, IDCELL_E_NEGOTIATE, "BIND", -1, -1,
                    "非法 BIND 应答 phase");
}

int idcell_node_bind_abort(idcell_node_t *n, const idcell_did_t *peer)
{
    int i;
    if (!n || !peer) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        if (!p->used || !idcell_did_equal(&p->did, peer)) continue;
        if (p->bind_phase == IDCELL_BIND_NONE || p->bind_phase == IDCELL_BIND_ACTIVE)
            return IDCELL_E_NODEV;
        send_bind_phase(n, p, p->txn, IDCELL_BIND_PHASE_ABORT, 0);
        clear_pending(p);
        return IDCELL_OK;
    }
    return IDCELL_E_NODEV;
}

/* ---------------------------------------------------------------- 运行期 */

static idcell_contract_point_t *contract_point(idcell_peer_t *p,
                                                uint16_t index, uint8_t sub)
{
    int i;
    if (!p || !p->has_contract) return NULL;
    for (i = 0; i < p->contract.pt_count; i++) {
        if (p->contract.pt[i].index == index && p->contract.pt[i].sub == sub)
            return &p->contract.pt[i];
    }
    return NULL;
}

static int peer_lease_valid(const idcell_node_t *n, const idcell_peer_t *p)
{
    return p && !n->asleep && !p->suspended && !p->recovery && !p->offline &&
           p->has_contract && p->owner_token && !time_reached(n->now_ms, p->lease_deadline_ms);
}

static void put_write_context(uint8_t *payload, uint16_t cap, uint16_t *pos,
                              const idcell_contract_t *c)
{
    put_u32_tlv(payload, cap, pos, IDCELL_TLV_BIND_ID, c->binding_id);
    put_u64_tlv(payload, cap, pos, IDCELL_TLV_SESSION_ID, c->session_id);
    put_u64_tlv(payload, cap, pos, IDCELL_TLV_GRANT_EPOCH, c->grant_epoch);
    put_u64_tlv(payload, cap, pos, IDCELL_TLV_AUTHORITY_ID, c->authority_id);
    put_u64_tlv(payload, cap, pos, IDCELL_TLV_AUTHORITY_EPOCH, c->authority_epoch);
    put_u64_tlv(payload, cap, pos, IDCELL_TLV_MEMBER_EPOCH, c->member_epoch);
}

int idcell_node_write(idcell_node_t *n, uint16_t index, uint8_t sub,
                      double value, uint32_t owner_token, const char *intent)
{
    idcell_write_options_t options;
    if (!n) return IDCELL_E_NODEV;
    options.command_id = ++n->command_counter;
    if (!options.command_id) options.command_id = ++n->command_counter;
    options.valid_for_ms = n->cfg.lease_ttl_ms;
    return idcell_node_write_ex(n, index, sub, value, owner_token, intent, &options);
}

int idcell_node_write_ex(idcell_node_t *n, uint16_t index, uint8_t sub,
                         double value, uint32_t owner_token, const char *intent,
                         const idcell_write_options_t *options)
{
    idcell_peer_t *p = NULL;
    idcell_contract_point_t *cp;
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint16_t pos = 0;
    uint16_t txn;
    int i, any = 0;

    if (!n || !options) return IDCELL_E_NODEV;
    if (n->asleep) return node_sleep_error(n);
    if (!intent || !*intent || owner_token == 0) return IDCELL_E_PERM;
    if (!isfinite(value)) return IDCELL_E_RANGE;
    if (!options->command_id || !options->valid_for_ms ||
        options->valid_for_ms > IDCELL_MAX_VALID_FOR_MS) return IDCELL_E_LEASE;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *cand = &n->peers[i];
        if (!cand->used || !cand->has_contract) continue;
        any = 1;
        if (time_reached(n->now_ms, cand->lease_deadline_ms)) return IDCELL_E_LEASE;
        if (cand->owner_token == owner_token) { p = cand; break; }
    }
    if (!p) return any ? IDCELL_E_PERM : IDCELL_E_NODEV;
    if (!peer_lease_valid(n, p)) return IDCELL_E_LEASE;
    cp = contract_point(p, index, sub);
    if (!cp) return IDCELL_E_NODEV;
    if (p->contract.perm < IDCELL_PERM_P2 || cp->perm < IDCELL_PERM_P2)
        return IDCELL_E_PERM;

    put_value_tlv(payload, sizeof(payload), &pos, index, sub, value,
                  (idcell_dtype_t)cp->dtype, cp->scale_exp);
    {
        uint8_t original[8];
        idcell_put_f64(original, value);
        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_F64, original, 8);
    }
    put_u16_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_SCHEMA_REF, cp->schema_ref);
    put_write_context(payload, sizeof(payload), &pos, &p->contract);
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_COMMAND_ID, options->command_id);
    put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_VALID_FOR, options->valid_for_ms);
    put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_OWNER, owner_token);
    put_str_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_INTENT, intent);

    txn = ++p->txn;
    p->write_pending = 1;
    p->write_txn = txn;
    p->write_index = index;
    p->write_sub = sub;
    p->write_value = value;
    p->write_command_id = options->command_id;
    p->write_binding = p->contract.binding_id;
    p->write_session = p->contract.session_id;
    p->write_grant = p->contract.grant_epoch;
    p->write_authority = p->contract.authority_id;
    p->write_authority_epoch = p->contract.authority_epoch;
    p->write_member_epoch = p->contract.member_epoch;
    node_send(n, IDCELL_FT_WRITE, &p->did, 0, txn, payload, pos);
    return IDCELL_OK;
}

int idcell_node_read(idcell_node_t *n, const idcell_did_t *peer,
                     uint16_t index, uint8_t sub, double *value)
{
    int i;
    if (!n || !peer || !value) return IDCELL_E_NODEV;
    if (n->asleep) return node_sleep_error(n);
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        idcell_contract_point_t *cp;
        int k;
        if (!p->used || !idcell_did_equal(&p->did, peer)) continue;
        if (!peer_lease_valid(n, p)) return IDCELL_E_LEASE;
        cp = contract_point(p, index, sub);
        if (!cp) return IDCELL_E_NODEV;
        if (p->contract.perm < cp->perm) return IDCELL_E_PERM;
        for (k = 0; k < p->pt_count; k++) {
            if (p->pts[k].cap_index != index || p->pts[k].sub != sub) continue;
            if (p->pts[k].value_valid) {
                *value = p->pts[k].last_value;
                return IDCELL_OK;
            }
            {
                uint8_t payload[256];
                uint16_t pos = 0;
                idcell_tlv_put(payload, sizeof(payload), &pos, index, sub,
                               IDCELL_TLV_VALUE, NULL, 0);
                put_u16_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_SCHEMA_REF, cp->schema_ref);
                put_write_context(payload, sizeof(payload), &pos, &p->contract);
                node_send(n, IDCELL_FT_READ, &p->did, 0, ++p->txn, payload, pos);
            }
            return IDCELL_E_NODEV;
        }
        return IDCELL_E_NODEV;
    }
    return IDCELL_E_NODEV;
}

/* ---------------------------------------------------------------- 时钟测量 */

/*
 * v0.12：发起一次单跳测量（§26.3）。
 *
 * 线上只有一帧 READ + 一帧 READ 响应，两者都是既有帧类型；没有新增
 * 帧类型、没有 SYNC 帧、没有改写 SRC/DST。t0 用发起端本地计数记录，
 * rtt 完全在发起端单侧时钟上量得——这一步不需要任何跨节点同步。
 */
int idcell_node_measure_clock(idcell_node_t *n, const idcell_did_t *peer,
                              uint32_t now_ms)
{
    int i;
    if (!n || !peer) return IDCELL_E_NODEV;
    if (n->asleep) return node_sleep_error(n);
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        uint8_t payload[128];
        uint16_t pos = 0;
        if (!p->used || !idcell_did_equal(&p->did, peer)) continue;
        if (!p->has_contract || !peer_lease_valid(n, p)) return IDCELL_E_LEASE;
        if (p->contract.perm < IDCELL_PERM_P1) return IDCELL_E_PERM;
        idcell_tlv_put(payload, sizeof(payload), &pos, IDCELL_SVC_CLOCK_INDEX, 0,
                       IDCELL_TLV_VALUE, NULL, 0);
        put_write_context(payload, sizeof(payload), &pos, &p->contract);
        n->now_ms = now_ms;
        n->ts_us = (uint64_t)now_ms * 1000ULL;
        p->meas_t0_ns = n->ts_us * 1000ULL;
        p->meas_txn = ++p->txn;
        p->meas_pending = 1;
        p->meas_valid = 0;
        if (node_send(n, IDCELL_FT_READ, &p->did, 0, p->meas_txn, payload, pos)
            != IDCELL_OK) {
            p->meas_pending = 0;
            return IDCELL_E_UNSAFE;
        }
        return IDCELL_OK;
    }
    return IDCELL_E_NODEV;
}

int idcell_node_measure_clock_result(const idcell_node_t *n,
                                      const idcell_did_t *peer,
                                      idcell_clock_measure_t *out)
{
    int i;
    if (!n || !peer || !out) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        const idcell_peer_t *p = &n->peers[i];
        if (!p->used || !idcell_did_equal(&p->did, peer)) continue;
        if (p->meas_pending) return 0;
        if (!p->meas_valid) return IDCELL_E_NODEV;
        out->counter         = p->meas_counter;
        out->tick_ns         = p->meas_tick_ns;
        out->epoch           = p->meas_epoch;
        out->quality         = p->meas_quality;
        out->rtt_ns          = p->meas_rtt_ns;
        out->offset_ns       = p->meas_offset_ns;
        out->uncertainty_ns  = p->meas_uncertainty_ns;
        return 1;
    }
    return IDCELL_E_NODEV;
}

int64_t idcell_clock_map_ns(const idcell_clock_measure_t *m, uint64_t counter)
{
    uint32_t tick = 1u;
    if (!m) return 0;
    if (m->tick_ns) tick = m->tick_ns;
    return (int64_t)(counter * (uint64_t)tick) - m->offset_ns;
}

static uint64_t write_payload_fingerprint(const idcell_frame_t *f)
{
    uint64_t h = 0xCBF29CE484222325ULL;
    uint16_t i;
    for (i = 0; i < f->payload_len; i++) {
        h ^= f->payload[i];
        h *= 0x100000001B3ULL;
    }
    return h ? h : 1;
}

static idcell_command_done_t *find_completed(idcell_node_t *n, const idcell_did_t *peer,
                                              uint32_t binding, uint64_t session,
                                              uint64_t command)
{
    int i;
    for (i = 0; i < IDCELL_COMMAND_CACHE; i++) {
        idcell_command_done_t *d = &n->completed[i];
        if (d->used && d->binding_id == binding && d->session_id == session &&
            d->command_id == command && idcell_did_equal(&d->peer, peer)) return d;
    }
    return NULL;
}

static int completed_has_space(const idcell_node_t *n)
{
    int i;
    for (i = 0; i < IDCELL_COMMAND_CACHE; i++) if (!n->completed[i].used) return 1;
    return 0;
}

static int remember_completed(idcell_node_t *n, const idcell_did_t *peer,
                              uint32_t binding, uint64_t session, uint64_t command,
                              uint64_t fingerprint)
{
    idcell_command_done_t *d = NULL;
    int i;
    for (i = 0; i < IDCELL_COMMAND_CACHE; i++) {
        if (!n->completed[i].used) { d = &n->completed[i]; break; }
    }
    if (!d) return 0;
    memset(d, 0, sizeof(*d));
    d->used = 1; d->peer = *peer; d->binding_id = binding;
    d->session_id = session; d->command_id = command;
    d->fingerprint = fingerprint; d->age = ++n->command_age;
    return 1;
}

static void send_write_done(idcell_node_t *n, const idcell_peer_t *p,
                            const idcell_did_t *dst, uint16_t txn, uint64_t command)
{
    uint8_t payload[256];
    uint16_t pos = 0;
    put_str_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_RESULT, "OK");
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_COMMAND_ID, command);
    put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_BIND_ID, p->rx_binding);
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_SESSION_ID, p->rx_session);
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_GRANT_EPOCH, p->rx_grant);
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_AUTHORITY_ID, p->rx_authority);
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_AUTHORITY_EPOCH, p->rx_authority_epoch);
    put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_MEMBER_EPOCH, p->rx_member_epoch);
    node_send(n, IDCELL_FT_DONE, dst, 0, txn, payload, pos);
}

/* 提供方 WRITE：收帧先入有界队列，执行前再次检查本地期限和 active grant。 */
static void node_write_process(idcell_node_t *n, const idcell_frame_t *f,
                               uint32_t first_rx_ms, uint32_t command_deadline,
                               int allow_queue)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    idcell_contract_point_t *cp;
    idcell_command_done_t *done;
    uint16_t pos = 0;
    idcell_tlv_t t;
    const idcell_tlv_t *value_tlv = NULL;
    idcell_tlv_t value_copy;
    double value = 0.0, attempted = 0.0;
    uint32_t owner = 0, binding = 0, valid_for = 0;
    uint64_t session = 0, grant = 0, command = 0, authority = 0, authority_epoch = 0, member = 0;
    uint64_t schema_id = 0, fingerprint;
    uint16_t schema_ref = 0;
    char intent[64];
    int rc, have_owner = 0, have_command = 0, have_valid_for = 0, have_attempted = 0;
    uint16_t idx = 0;
    uint8_t sub = 0;
    int i, found = 0;

    if (!p) return;
    p->last_rx_ms = n->now_ms;
    intent[0] = '\0';
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        switch (t.type) {
        case IDCELL_TLV_VALUE: value_copy = t; value_tlv = &value_copy; idx = t.idx; sub = t.sub; break;
        case IDCELL_TLV_F64: attempted = tlv_f64(&t, 0.0); have_attempted = 1; break;
        case IDCELL_TLV_OWNER: owner = tlv_u32(&t, 0); have_owner = 1; break;
        case IDCELL_TLV_INTENT: tlv_str(&t, intent, sizeof(intent)); break;
        case IDCELL_TLV_BIND_ID: binding = tlv_u32(&t, 0); break;
        case IDCELL_TLV_SESSION_ID: session = tlv_u64(&t, 0); break;
        case IDCELL_TLV_GRANT_EPOCH: grant = tlv_u64(&t, 0); break;
        case IDCELL_TLV_COMMAND_ID: command = tlv_u64(&t, 0); have_command = 1; break;
        case IDCELL_TLV_VALID_FOR: valid_for = tlv_u32(&t, 0); have_valid_for = 1; break;
        case IDCELL_TLV_AUTHORITY_ID: authority = tlv_u64(&t, 0); break;
        case IDCELL_TLV_AUTHORITY_EPOCH: authority_epoch = tlv_u64(&t, 0); break;
        case IDCELL_TLV_MEMBER_EPOCH: member = tlv_u64(&t, 0); break;
        case IDCELL_TLV_SCHEMA_REF: schema_ref = tlv_u16(&t, 0); break;
        case IDCELL_TLV_SCHEMA_ID: schema_id = tlv_u64(&t, 0); break;
        default: break;
        }
    }
    p->rx_command_id = command;
    p->rx_binding = binding;
    p->rx_session = session;
    p->rx_grant = grant;
    p->rx_authority = authority;
    p->rx_authority_epoch = authority_epoch;
    p->rx_member_epoch = member;
    p->rx_txn = f->txn;
    if (rc < 0 || !value_tlv) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "WRITE", -1, -1, "写入值或 TLV 结构无效");
        return;
    }
    if (!p->has_contract || binding != p->contract.binding_id) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_NODEV, "WRITE", -1, -1, "binding_id 无 active 契约");
        return;
    }
    if (session != p->contract.session_id || grant != p->contract.grant_epoch ||
        authority != p->contract.authority_id || authority_epoch != p->contract.authority_epoch ||
        member != p->contract.member_epoch) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "WRITE", -1, -1,
                        "旧 session/grant/authority/member epoch");
        return;
    }
    if (!have_owner || !owner || owner != p->contract.owner_token) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, "WRITE",
                        IDCELL_PERM_P2, p->contract.perm, "旧 owner_token 或令牌缺失");
        return;
    }
    if (!have_command || !command || !have_valid_for || !intent[0]) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, "WRITE", -1, -1,
                        "缺少 command_id/valid_for_ms/意图");
        return;
    }
    if (grant_validate(n, p, &f->src, session, grant, owner, authority,
                       authority_epoch, member) != IDCELL_OK) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "WRITE", -1, -1,
                        "执行器 active grant 不匹配或已过期");
        return;
    }
    cp = contract_point(p, idx, sub);
    if (!cp) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_NODEV, "WRITE", -1, -1,
                        "能力点不在 active cap_list");
        return;
    }
    if ((schema_ref && schema_ref != cp->schema_ref) ||
        (schema_id && schema_id != cp->schema_id) ||
        decode_value(value_tlv, (idcell_dtype_t)cp->dtype, cp->scale_exp, &value) != IDCELL_OK) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "WRITE", -1, -1,
                        "schema 引用或值布局与契约不匹配");
        return;
    }
    if (!have_attempted) attempted = value;
    if (!isfinite(value) || !isfinite(attempted)) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_RANGE, "WRITE", -1, -1,
                        "NaN/Inf 在入队和执行前均拒绝");
        return;
    }
    fingerprint = write_payload_fingerprint(f);
    done = find_completed(n, &f->src, binding, session, command);
    if (done) {
        if (done->fingerprint != fingerprint) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_IDCONFLICT, "WRITE", -1, -1,
                            "同一命令键对应不同 payload");
            return;
        }
        send_write_done(n, p, &f->src, f->txn, command);
        return;
    }
    if (allow_queue) command_deadline = n->now_ms + valid_for;
    if (!valid_for || valid_for > IDCELL_MAX_VALID_FOR_MS ||
        time_reached(n->now_ms, command_deadline) ||
        (!(allow_queue && n->asleep && p->suspended && !p->offline) && !peer_lease_valid(n, p))) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "WRITE", -1, -1,
                        "命令或本地租约已过期");
        return;
    }
    if (allow_queue) {
        idcell_queued_write_t *q;
        if (n->write_queue_count >= IDCELL_WRITE_QUEUE) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "WRITE", -1, -1,
                            "写命令队列已满，fail-closed");
            return;
        }
        q = &n->write_queue[n->write_queue_count++];
        memset(q, 0, sizeof(*q));
        q->used = 1;
        q->frame = *f;
        q->first_rx_ms = n->now_ms;
        q->deadline_ms = command_deadline;
        return;
    }
    (void)first_rx_ms;
    for (i = 0; i < n->cap_count; i++) {
        if (n->caps[i].index != idx || n->caps[i].sub != sub) continue;
        found = 1;
        if (!(n->caps[i].dir & IDCELL_DIR_WRITE) || p->contract.perm < n->caps[i].perm ||
            cp->perm < n->caps[i].perm) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, n->caps[i].label,
                            n->caps[i].perm, p->contract.perm, "能力点不可写或权限不足");
            return;
        }
        if (value < n->caps[i].range[0] || value > n->caps[i].range[1]) {
            node_send_range_error(n, &f->src, f->txn, n->caps[i].label,
                                  idx, n->caps[i].range[0], n->caps[i].range[1], attempted);
            return;
        }
        break;
    }
    if (!found) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_NODEV, "WRITE", -1, -1, "能力点不存在");
        return;
    }
    if (!completed_has_space(n)) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "WRITE", -1, -1,
                        "完成缓存已满，fail-closed 拒绝新命令");
        return;
    }
    if (n->set_fn) {
        int r = n->set_fn(n->set_ud, idx, sub, value, intent, owner);
        if (r != IDCELL_OK) {
            node_send_error(n, &f->src, f->txn, (idcell_err_t)r, "WRITE", -1, -1,
                            "提供方拒绝了写入");
            return;
        }
    }
    (void)remember_completed(n, &f->src, binding, session, command, fingerprint);
    send_write_done(n, p, &f->src, f->txn, command);
}

static void node_on_write(idcell_node_t *n, const idcell_frame_t *f)
{
    node_write_process(n, f, n->now_ms, 0, 1);
}

static int node_write_queue_blocked(const idcell_node_t *n)
{
    int i;
    if (n->asleep) return 1;
    for (i = 0; i < IDCELL_MAX_PEERS; i++)
        if (n->peers[i].used && n->peers[i].recovery) return 1;
    return 0;
}

static void node_execute_queued_write(idcell_node_t *n)
{
    idcell_queued_write_t q;
    if (!n->write_queue_count || node_write_queue_blocked(n)) return;
    q = n->write_queue[0];
    n->write_queue_count--;
    if (n->write_queue_count) {
        memmove(n->write_queue, n->write_queue + 1,
                (size_t)n->write_queue_count * sizeof(n->write_queue[0]));
    }
    memset(&n->write_queue[n->write_queue_count], 0, sizeof(n->write_queue[0]));
    node_write_process(n, &q.frame, q.first_rx_ms, q.deadline_ms, 0);
}

/* 提供方收到 READ：cap_list、方向和权限全部在 value_fn 之前裁决。 */
static void node_on_read(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    idcell_contract_point_t *cp;
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint16_t idx = 0, schema_ref = 0;
    uint8_t sub = 0;
    uint32_t binding = 0;
    uint64_t session = 0, grant = 0, schema_id = 0;
    int rc, requested = 0, i;

    if (!p) return;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_VALUE) { idx = t.idx; sub = t.sub; requested = 1; }
        else if (t.type == IDCELL_TLV_BIND_ID) binding = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_SESSION_ID) session = tlv_u64(&t, 0);
        else if (t.type == IDCELL_TLV_GRANT_EPOCH) grant = tlv_u64(&t, 0);
        else if (t.type == IDCELL_TLV_SCHEMA_REF) schema_ref = tlv_u16(&t, 0);
        else if (t.type == IDCELL_TLV_SCHEMA_ID) schema_id = tlv_u64(&t, 0);
    }
    if (rc < 0 || !requested) return;
    if (!peer_lease_valid(n, p) || binding != p->contract.binding_id) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "READ", -1, -1, "无有效绑定/租约");
        return;
    }
    if (session != p->contract.session_id || grant != p->contract.grant_epoch) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_LEASE, "READ", -1, -1, "旧会话或授权纪元");
        return;
    }
    /*
     * v0.12：0xFE00 是协议保留服务点（§26.2），不参与 MATCH，也不在
     * cap_list 里。它只对「已通过绑定/会话/授权纪元校验」的对端开放，
     * 因此上面的三道校验必须先过。未注册时钟源时按 E_NODEV 拒绝。
     */
    if (idx == IDCELL_SVC_CLOCK_INDEX && sub == 0) {
        idcell_clock_sample_t cs;
        uint8_t payload[160], raw[15];
        uint16_t opos = 0;

        if (!n->clock_fn) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_NODEV, "CLOCK", -1, -1,
                            "时钟服务未启用");
            return;
        }
        if (p->contract.perm < IDCELL_PERM_P1) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, "CLOCK",
                            IDCELL_PERM_P1, p->contract.perm, "时钟服务权限不足");
            return;
        }
        memset(&cs, 0, sizeof(cs));
        if (n->clock_fn(n->clock_ud, &cs) != IDCELL_OK) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_NODEV, "CLOCK", -1, -1,
                            "取时钟失败");
            return;
        }
        memset(raw, 0, sizeof(raw));
        idcell_put_u64(raw, cs.counter);
        idcell_put_u32(raw + 8, cs.tick_ns);
        idcell_put_u16(raw + 12, cs.epoch);
        raw[14] = cs.quality;
        idcell_tlv_put(payload, sizeof(payload), &opos, 0, 0,
                       IDCELL_TLV_CLOCK, raw, (uint16_t)sizeof(raw));
        put_write_context(payload, sizeof(payload), &opos, &p->contract);
        node_send(n, IDCELL_FT_READ, &f->src, 0, f->txn, payload, opos);
        return;
    }
    cp = contract_point(p, idx, sub);
    if (!cp) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_NODEV, "READ", -1, -1,
                        "能力点不在 active cap_list");
        return;
    }
    if ((schema_ref && schema_ref != cp->schema_ref) || (schema_id && schema_id != cp->schema_id)) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "READ", -1, -1, "schema 引用不属于契约点");
        return;
    }
    for (i = 0; i < n->cap_count; i++) {
        double v = 0.0;
        uint64_t ts = 0;
        idcell_prov_t prov = IDCELL_PROV_MEASURED;
        uint8_t payload[256];
        uint16_t opos = 0;
        if (n->caps[i].index != idx || n->caps[i].sub != sub) continue;
        if (!(n->caps[i].dir & IDCELL_DIR_READ) || p->contract.perm < n->caps[i].perm ||
            cp->perm < n->caps[i].perm) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_PERM, n->caps[i].label,
                            n->caps[i].perm, p->contract.perm, "能力点不可读或权限不足");
            return;
        }
        if (n->value_fn && n->value_fn(n->value_ud, idx, sub, &v, &ts, &prov) != IDCELL_OK) {
            node_send_error(n, &f->src, f->txn, IDCELL_E_NODEV, "READ", -1, -1, "取值失败");
            return;
        }
        put_value_tlv(payload, sizeof(payload), &opos, idx, sub, v,
                      (idcell_dtype_t)cp->dtype, cp->scale_exp);
        put_u16_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_SCHEMA_REF, cp->schema_ref);
        put_write_context(payload, sizeof(payload), &opos, &p->contract);
        put_u8_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_PROV, (uint8_t)prov);
        put_u8_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_QUALITY,
                   (uint8_t)(n->quality_fn ? n->quality_fn(n->quality_ud, idx, sub)
                                           : IDCELL_QUALITY_GOOD));
        node_send(n, IDCELL_FT_READ, &f->src, 0, f->txn, payload, opos);
        return;
    }
    node_send_error(n, &f->src, f->txn, IDCELL_E_NODEV, "READ", -1, -1, "能力点不存在");
}

/* 提供方周期发布：绝不重复发送旧值伪装刷新（§08.5 红线二） */
static void node_publish(idcell_node_t *n, uint32_t now)
{
    int i, p;

    if (!n->value_fn) return;

    for (p = 0; p < IDCELL_MAX_PEERS; p++) {
        idcell_peer_t *peer = &n->peers[p];

        if (!peer_lease_valid(n, peer)) continue;

        for (i = 0; i < peer->pt_count; i++) {
            idcell_pt_t *pt = &peer->pts[i];
            idcell_contract_point_t *cp = contract_point(peer, pt->cap_index, pt->sub);
            if (!cp) continue;
            double v = 0.0;
            uint64_t ts = 0;
            idcell_prov_t prov = IDCELL_PROV_MEASURED;
            uint8_t payload[256];
            uint16_t opos = 0;

            if (pt->my_cap_idx == 0xFFFF || pt->my_cap_idx >= n->cap_count) continue;
            if (!(n->caps[pt->my_cap_idx].dir & IDCELL_DIR_READ) ||
                peer->contract.perm < n->caps[pt->my_cap_idx].perm ||
                cp->perm < n->caps[pt->my_cap_idx].perm) continue;
            if (!pt->subscribed) continue;
            if (!pt->t_pub_ms) continue;
            /* 每个能力点按自己的 T_pub 计时 */
            if (pt->last_pub_ms && now < pt->last_pub_ms + pt->t_pub_ms) continue;

            /*
             * 回调给用户的是「能力点索引」，不是内部数组下标——
             * 用户注册时用什么 index，回调里就看到什么 index。
             */
            if (n->value_fn(n->value_ud, pt->cap_index, pt->sub, &v, &ts, &prov) != IDCELL_OK)
                continue;

            /* 红线二：值未更新就不发，绝不重复旧值伪装刷新 */
            if (n->pub_valid[pt->my_cap_idx] && n->last_pub_ts[pt->my_cap_idx] == ts)
                continue;
            n->last_pub_ts[pt->my_cap_idx] = ts;
            n->pub_valid[pt->my_cap_idx] = 1;

            /* 单位转换：发送方负责转换（§09.2 转换方向）
             * v0.8：走量种优先路径，量种不同不得换算（FR-081） */
            if (pt->src_unit[0] && pt->unit[0] && strcmp(pt->src_unit, pt->unit) != 0) {
                double cv = 0.0;
                idcell_conv_t cls;
                if (idcell_qty_convert((idcell_qty_t)pt->qty, pt->src_unit,
                                       (idcell_qty_t)pt->qty, pt->unit,
                                       v, &cv, &cls) == IDCELL_OK)
                    v = cv;
            }

            put_value_tlv(payload, sizeof(payload), &opos, pt->cap_index, pt->sub, v,
                        (idcell_dtype_t)cp->dtype, cp->scale_exp);
            put_u16_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_SCHEMA_REF, cp->schema_ref);
            put_write_context(payload, sizeof(payload), &opos, &peer->contract);
            put_u8_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_PROV, (uint8_t)prov);
            /* v0.8：质量码 MUST 为每个值显式携带（FR-085） */
            put_u8_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_QUALITY,
                       (uint8_t)(n->quality_fn
                                 ? n->quality_fn(n->quality_ud, pt->cap_index, pt->sub)
                                 : IDCELL_QUALITY_GOOD));
            node_send(n, IDCELL_FT_EVENT, &peer->did, 0, 0, payload, opos);

            pt->last_pub_ms = now;
            peer->last_pub_ms = now;
        }
    }
}

/* 心跳：携带租约。释放由 TTL 触发，不由心跳触发（§09.4） */
static void node_heartbeat(idcell_node_t *n, uint32_t now)
{
    int p;
    for (p = 0; p < IDCELL_MAX_PEERS; p++) {
        idcell_peer_t *peer = &n->peers[p];
        uint8_t payload[256];
        uint16_t opos = 0;

        if (!peer_lease_valid(n, peer)) continue;
        if (peer->last_hb_ms && now - peer->last_hb_ms < n->cfg.t_hb_ms) continue;

        put_u32_tlv(payload, sizeof(payload), &opos, IDCELL_TLV_TTL, peer->contract.lease_ttl_ms);
        put_write_context(payload, sizeof(payload), &opos, &peer->contract);
        node_send(n, IDCELL_FT_HEARTBEAT, &peer->did, 0, 0, payload, opos);
        peer->last_hb_ms = now;
    }
}

/* ---------------------------------------------------------------- 发起侧管道 */

/* 需求方：对每个已知对端发起 MATCH（若尚未绑定） */
static void node_drive_match(idcell_node_t *n, uint32_t now)
{
    uint8_t payload[IDCELL_MAX_PAYLOAD];
    uint16_t pos;
    int i, j;

    if (n->req_count == 0) return;

    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        uint16_t txn;

        if (!p->used) continue;
        if (p->has_contract && p->stage == IDCELL_STAGE_RUNNING) continue;
        /*
         * 只推进「我方是需求方」的对端。
         * 对同一条连接，两端角色是互补的：一方提供能力，另一方提出需求。
         * 如果不判别，提供方会反过来跑需求方的管道（发出 AUTH 挑战与 BIND），
         * 造成双方同时推进、契约错乱。
         */
        if (p->role == 1) continue;
        /* 只有还在「等对端出现 / 等重试」阶段才发需求 */
        if (p->stage != IDCELL_STAGE_IDLE && p->stage != IDCELL_STAGE_DESCRIBE) continue;
        if (now < p->next_retry_ms) continue;

        /*
         * 目标收敛：主机侧指定了设备可读名时，只推进那台设备。
         * 用户按名选设备，不必、也不该在命令行里写 DID（FR-011）。
         */
        if (n->target_label[0]) {
            if (!p->labeled) continue;   /* 还没拿到名字，等 HELLO 再说 */
            if (strcmp(p->peer_label, n->target_label) != 0 &&
                !strstr(p->peer_label, n->target_label)) continue;
        }

        txn = ++p->txn;
        pos = 0;
        for (j = 0; j < n->req_count; j++) {
            uint8_t inner[IDCELL_MAX_PAYLOAD];
            int len = idcell_req_encode(&n->reqs[j], inner, sizeof(inner));
            if (len < 0) continue;
            idcell_tlv_put(payload, sizeof(payload), &pos, (uint16_t)j, 0,
                           IDCELL_TLV_REQ_DESC, inner, (uint16_t)len);
        }
        node_send(n, IDCELL_FT_MATCH, &p->did, 0, txn, payload, pos);
        p->role = 2;
        p->stage = IDCELL_STAGE_MATCH;
        p->next_retry_ms = now + 1000;
        return;   /* 一次只推进一个对端 */
    }
}

/* 需求方：MATCH 有结果 → 发 NEGOTIATE */
static void node_drive_negotiate(idcell_node_t *n, uint32_t now)
{
    int i;
    (void)now;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        uint8_t payload[IDCELL_MAX_PAYLOAD];
        uint16_t pos = 0;
        int k;

        if (!p->used || p->stage != IDCELL_STAGE_MATCH) continue;
        if (p->role == 1) continue;                        /* 我方是提供方，不主动协商 */
        if (p->peer_stage < IDCELL_STAGE_MATCH) continue;   /* 对端尚未完成匹配 */
        if (p->pending_pt_count == 0) continue;

        for (k = 0; k < p->pending_pt_count; k++) {
            /* T_want：需求方自己声明的期望周期 */
            uint32_t want = p->pending_pts[k].t_want_ms;
            if (!want) want = p->pending_pts[k].t_prod_ms;
            put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_TPUB, want);
            put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_STALE,
                        p->pending_pts[k].ttl_ms ? p->pending_pts[k].ttl_ms : n->cfg.lease_ttl_ms);
        }
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_TTL, n->cfg.lease_ttl_ms);

        node_send(n, IDCELL_FT_NEGOTIATE, &p->did, 0, ++p->txn, payload, pos);
        p->stage = IDCELL_STAGE_NEGOTIATE;
        return;
    }
}

/* 需求方：NEGOTIATE 完成 → 发 AUTH 挑战 */
static void node_drive_auth(idcell_node_t *n, uint32_t now)
{
    int i;
    (void)now;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        uint8_t payload[64];
        uint16_t pos = 0;
        uint8_t nonce[16];
        int k;

        if (!p->used || p->stage != IDCELL_STAGE_NEGOTIATE) continue;
        if (p->role == 1) continue;                              /* 我方是提供方 */
        if (p->peer_stage < IDCELL_STAGE_NEGOTIATE) continue;    /* 对端尚未完成协商 */

        for (k = 0; k < 16; k++) nonce[k] = (uint8_t)(node_rand(n) >> ((k % 8) * 8));
        memcpy(p->auth_nonce, nonce, 16);
        p->auth_nonce_valid = 1;

        idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_NONCE, nonce, 16);
        p->auth_txn = (uint16_t)(p->txn + 1);
        node_send(n, IDCELL_FT_AUTH, &p->did, 0, ++p->txn, payload, pos);
        p->stage = IDCELL_STAGE_AUTHORIZE;
        return;
    }
}

/* 需求方：AUTH 通过 → 发 BIND */
static void node_drive_bind(idcell_node_t *n, uint32_t now)
{
    int i;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        uint8_t payload[IDCELL_MAX_PAYLOAD];
        uint16_t pos = 0;
        int k;

        if (p->used && p->stage == IDCELL_STAGE_BIND &&
            p->bind_phase == IDCELL_BIND_COMMIT_SENT && now >= p->next_retry_ms) {
            send_bind_phase(n, p, p->txn, IDCELL_BIND_PHASE_COMMIT, 0);
            p->next_retry_ms = now + 1000;
            return;
        }
        if (!p->used || p->stage != IDCELL_STAGE_AUTHORIZE) continue;
        if (p->role == 1) continue;                                /* 我方是提供方 */
        if (p->peer_stage < IDCELL_STAGE_AUTHORIZE) continue;      /* 对端尚未完成鉴权 */

        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_BIND_PHASE,
                   IDCELL_BIND_PHASE_PREPARE);
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_DESC_VER,
                    p->pending_contract.desc_version);
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_TTL,
                    p->pending_contract.lease_ttl_ms);
        put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_ARB,
                    p->pending_contract.arb_domain);
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_PERM,
                   (uint8_t)p->pending_contract.perm);
        if (p->renegotiating) {
            put_u32_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_OLD_BINDING, p->reneg_old_binding);
            put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_OLD_SESSION, p->reneg_old_session);
            put_u64_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_OLD_GRANT, p->reneg_old_grant);
        }
        for (k = 0; k < p->pending_pt_count; k++)
            put_bind_point(payload, sizeof(payload), &pos, &p->pending_pts[k],
                           p->pending_pts[k].schema_ref);
        node_send(n, IDCELL_FT_BIND, &p->did, 0, ++p->txn, payload, pos);
        p->bind_phase = IDCELL_BIND_PREPARE_SENT;
        p->stage = IDCELL_STAGE_BIND;
        return;
    }
}

/* ---------------------------------------------------------------- 休眠与在线状态 */

int idcell_node_asleep(const idcell_node_t *n)
{
    return n ? n->asleep : 0;
}

int idcell_node_last_error(const idcell_node_t *n)
{
    return n ? n->last_err : IDCELL_E_NODEV;
}

int idcell_node_mailbox_count(const idcell_node_t *n)
{
    return n ? n->write_queue_count : 0;
}

static int node_sleep_error(idcell_node_t *n)
{
    int err = n->cfg.wake_profile == IDCELL_WAKE_RX_OFF ? IDCELL_E_RX_OFF : IDCELL_E_ASLEEP;
    n->last_err = (uint8_t)err;
    return err;
}

int idcell_node_check_in(idcell_node_t *n, uint32_t now_ms)
{
    int i, sent = 0;
    if (!n) return IDCELL_E_NODEV;
    n->now_ms = now_ms;
    n->ts_us = (uint64_t)now_ms * 1000ULL;
    if (n->asleep) return node_sleep_error(n);
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        uint8_t payload[256];
        uint16_t pos = 0;
        if (!p->used) continue;
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_CHECKIN, IDCELL_HEARTBEAT_CHECKIN);
        put_presence_tlvs(n, payload, sizeof(payload), &pos);
        if (p->has_contract) put_write_context(payload, sizeof(payload), &pos, &p->contract);
        (void)node_send(n, IDCELL_FT_HEARTBEAT, &p->did, 0, 0, payload, pos);
        sent++;
    }
    if (!sent) {
        uint8_t payload[128];
        uint16_t pos = 0;
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_CHECKIN, IDCELL_HEARTBEAT_CHECKIN);
        put_presence_tlvs(n, payload, sizeof(payload), &pos);
        (void)node_send(n, IDCELL_FT_HEARTBEAT, NULL, 0, 0, payload, pos);
    }
    n->next_checkin_ms = now_ms + n->cfg.checkin_ms;
    n->last_err = IDCELL_OK;
    return n->has_tr ? IDCELL_OK : IDCELL_E_NODEV;
}

int idcell_node_sleep(idcell_node_t *n, uint32_t now_ms)
{
    int i, sent = 0;
    if (!n) return IDCELL_E_NODEV;
    if (n->cfg.wake_profile == IDCELL_WAKE_ALWAYS_ON) return IDCELL_E_STATE;
    if (n->asleep) return IDCELL_OK;
    n->now_ms = now_ms;
    n->ts_us = (uint64_t)now_ms * 1000ULL;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        uint8_t payload[160];
        uint16_t pos = 0;
        if (!p->used) continue;
        p->suspended = 1;
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_CHECKIN, IDCELL_HEARTBEAT_SLEEP);
        put_presence_tlvs(n, payload, sizeof(payload), &pos);
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_ASLEEP, 1);
        (void)node_send(n, IDCELL_FT_HEARTBEAT, &p->did, 0, 0, payload, pos);
        sent++;
    }
    if (!sent) {
        uint8_t payload[128];
        uint16_t pos = 0;
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_CHECKIN, IDCELL_HEARTBEAT_SLEEP);
        put_presence_tlvs(n, payload, sizeof(payload), &pos);
        put_u8_tlv(payload, sizeof(payload), &pos, IDCELL_TLV_ASLEEP, 1);
        (void)node_send(n, IDCELL_FT_HEARTBEAT, NULL, 0, 0, payload, pos);
    }
    n->asleep = 1;
    n->wake_deadline_ms = now_ms + n->cfg.wake_after_ms;
    n->last_err = IDCELL_OK;
    return IDCELL_OK;
}

static void node_recover_suspended_contracts(idcell_node_t *n)
{
    int i;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        idcell_peer_t *p = &n->peers[i];
        if (!p->used || !p->has_contract || !p->suspended) continue;
        /* 每次睡眠都使旧运行上下文失效，而不只是 TTL 已过期的情况。 */
        p->recovery = 1;
        p->owner_token = 0;
        p->stage = IDCELL_STAGE_DESCRIBE;
        p->peer_stage = IDCELL_STAGE_IDLE;
        p->next_retry_ms = n->now_ms;
        if (p->role == 2) {
            (void)idcell_node_renegotiate(n, &p->did);
        } else {
            uint8_t payload[64];
            uint8_t b[8];
            uint16_t pos = 0;
            idcell_put_u32(b, p->contract.binding_id);
            idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_OLD_BINDING, b, 4);
            idcell_put_u64(b, p->contract.session_id);
            idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_OLD_SESSION, b, 8);
            idcell_put_u64(b, p->contract.grant_epoch);
            idcell_tlv_put(payload, sizeof(payload), &pos, 0, 0, IDCELL_TLV_OLD_GRANT, b, 8);
            (void)node_send(n, IDCELL_FT_RENEGOTIATE, &p->did, 0, ++p->txn, payload, pos);
        }
    }
}

static int wake_budget_allow(idcell_node_t *n, idcell_wake_event_t event, uint32_t now_ms)
{
    if (event != IDCELL_WAKE_EVENT_RADIO && event != IDCELL_WAKE_EVENT_PROXY) return 1;
    if (now_ms - n->wake_window_start_ms >= n->cfg.wake_window_ms) {
        n->wake_window_start_ms = now_ms;
        n->wake_events_used = 0;
    }
    if (n->wake_events_used >= n->cfg.wake_budget) return 0;
    n->wake_events_used++;
    return 1;
}

int idcell_node_wake(idcell_node_t *n, idcell_wake_event_t event, uint32_t now_ms)
{
    int allowed = 0;
    if (!n) return IDCELL_E_NODEV;
    n->now_ms = now_ms;
    n->ts_us = (uint64_t)now_ms * 1000ULL;
    if (!n->asleep) return IDCELL_OK;
    switch (n->cfg.wake_profile) {
    case IDCELL_WAKE_SCHEDULED:
        allowed = event == IDCELL_WAKE_EVENT_TIMER || event == IDCELL_WAKE_EVENT_LOCAL;
        break;
    case IDCELL_WAKE_RADIO:
        allowed = event == IDCELL_WAKE_EVENT_RADIO || event == IDCELL_WAKE_EVENT_LOCAL;
        break;
    case IDCELL_WAKE_PROXY:
        allowed = event == IDCELL_WAKE_EVENT_PROXY || event == IDCELL_WAKE_EVENT_LOCAL;
        break;
    case IDCELL_WAKE_RX_OFF:
        allowed = event == IDCELL_WAKE_EVENT_LOCAL;
        if (!allowed) return node_sleep_error(n);
        break;
    default:
        return IDCELL_E_STATE;
    }
    if (!allowed || !wake_budget_allow(n, event, now_ms)) {
        n->last_err = IDCELL_E_STATE;
        return IDCELL_E_STATE;
    }
    n->asleep = 0;
    n->last_err = IDCELL_OK;
    node_recover_suspended_contracts(n);
    (void)idcell_node_check_in(n, now_ms);
    return IDCELL_OK;
}

idcell_presence_t idcell_node_peer_presence(const idcell_node_t *n,
                                             const idcell_did_t *peer,
                                             uint32_t now_ms)
{
    int i;
    if (!n || !peer) return IDCELL_PRESENCE_OFFLINE;
    for (i = 0; i < IDCELL_MAX_PEERS; i++) {
        const idcell_peer_t *p = &n->peers[i];
        uint32_t limit, elapsed;
        if (!p->used || !idcell_did_equal(&p->did, peer)) continue;
        if (p->offline || !p->presence_seen) return IDCELL_PRESENCE_OFFLINE;
        limit = 3u * n->cfg.t_hb_ms;
        if (p->wake_profile == IDCELL_WAKE_SCHEDULED) {
            limit = p->checkin_ms > p->max_wake_latency_ms ? p->checkin_ms : p->max_wake_latency_ms;
            if (!limit) limit = 3u * n->cfg.t_hb_ms;
        }
        elapsed = now_ms - p->last_rx_ms;
        if (elapsed >= limit) return IDCELL_PRESENCE_OFFLINE;
        return p->asleep ? IDCELL_PRESENCE_ASLEEP : IDCELL_PRESENCE_ONLINE;
    }
    return IDCELL_PRESENCE_OFFLINE;
}

static void node_note_valid_frame(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    int rc, asleep = 0, checkin = 0;
    if (!p || f->type == IDCELL_FT_OFFLINE) return;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_ASLEEP) asleep = tlv_u8(&t, 0) ? 1 : 0;
        else if (t.type == IDCELL_TLV_WAKE_PROFILE) p->wake_profile = tlv_u8(&t, IDCELL_WAKE_ALWAYS_ON);
        else if (t.type == IDCELL_TLV_CHECKIN_MS) p->checkin_ms = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_WAKE_LATENCY) p->max_wake_latency_ms = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_CHECKIN) {
            uint8_t kind = tlv_u8(&t, 0);
            if (kind == IDCELL_HEARTBEAT_SLEEP) asleep = 1;
            else if (kind == IDCELL_HEARTBEAT_CHECKIN) checkin = 1;
        }
    }
    if (rc < 0) return;
    p->last_rx_ms = n->now_ms;
    if (p->offline) {
        /* OFFLINE 是粘性状态；普通帧、ANNOUNCE 和空 HELLO 均不能恢复。 */
        if (f->type == IDCELL_FT_HEARTBEAT && checkin) {
            p->offline = 0; p->presence_seen = 1; p->asleep = 0;
        }
        return;
    }
    p->presence_seen = 1;
    p->asleep = (uint8_t)asleep;
}

/* ---------------------------------------------------------------- 帧分发 */

static void node_on_offline(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    if (!p) return;
    p->offline = 1;
    p->suspended = 1;
    p->owner_token = 0;
    p->write_pending = 0;
    p->stage = IDCELL_STAGE_DESCRIBE;
    p->peer_stage = IDCELL_STAGE_IDLE;
    if (p->has_contract) {
        idcell_active_grant_t *g = grant_find(n, p->contract.arb_domain, 0);
        if (g && idcell_did_equal(&g->owner, &p->did) &&
            g->session_id == p->contract.session_id) memset(g, 0, sizeof(*g));
    }
}

static void node_on_renegotiate(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p = peer_get_or_add(n, &f->src);
    uint16_t pos = 0;
    idcell_tlv_t t;
    uint32_t binding = 0;
    uint64_t session = 0, grant = 0;
    int rc;
    if (!p) return;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_OLD_BINDING) binding = tlv_u32(&t, 0);
        else if (t.type == IDCELL_TLV_OLD_SESSION) session = tlv_u64(&t, 0);
        else if (t.type == IDCELL_TLV_OLD_GRANT) grant = tlv_u64(&t, 0);
    }
    if (rc < 0 || !p->has_contract || binding != p->contract.binding_id ||
        session != p->contract.session_id || grant != p->contract.grant_epoch) return;
    if (p->renegotiating && p->reneg_old_binding == binding &&
        p->reneg_old_session == session && p->reneg_old_grant == grant) return;
    clear_pending(p);
    p->renegotiating = 1;
    p->reneg_old_binding = binding;
    p->reneg_old_session = session;
    p->reneg_old_grant = grant;
    p->stage = IDCELL_STAGE_DESCRIBE;
    p->peer_stage = IDCELL_STAGE_IDLE;
    p->last_hello_ms = 0;
}

static void node_on_runtime_value(idcell_node_t *n, const idcell_frame_t *f,
                                  idcell_peer_t *p)
{
    const idcell_tlv_t *value_tlv = NULL;
    const idcell_tlv_t *clock_tlv = NULL;
    idcell_tlv_t value_copy, clock_copy;
    idcell_contract_point_t *cp;
    idcell_pt_t *pt = NULL;
    uint16_t pos = 0, idx = 0, schema_ref = 0;
    uint8_t sub = 0;
    uint32_t binding = 0;
    uint64_t session = 0, grant = 0, schema_id = 0;
    idcell_tlv_t t;
    idcell_prov_t prov = IDCELL_PROV_MEASURED;
    idcell_quality_t quality = IDCELL_QUALITY_GOOD;
    double value;
    int rc, i;

    if (!p || !peer_lease_valid(n, p)) return;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        switch (t.type) {
        case IDCELL_TLV_VALUE: value_copy = t; value_tlv = &value_copy; idx = t.idx; sub = t.sub; break;
        case IDCELL_TLV_CLOCK: clock_copy = t; clock_tlv = &clock_copy; break;
        case IDCELL_TLV_PROV: prov = (idcell_prov_t)tlv_u8(&t, 0); break;
        case IDCELL_TLV_QUALITY: quality = (idcell_quality_t)tlv_u8(&t, 0); break;
        case IDCELL_TLV_BIND_ID: binding = tlv_u32(&t, 0); break;
        case IDCELL_TLV_SESSION_ID: session = tlv_u64(&t, 0); break;
        case IDCELL_TLV_GRANT_EPOCH: grant = tlv_u64(&t, 0); break;
        case IDCELL_TLV_SCHEMA_REF: schema_ref = tlv_u16(&t, 0); break;
        case IDCELL_TLV_SCHEMA_ID: schema_id = tlv_u64(&t, 0); break;
        default: break;
        }
    }
    if (rc < 0 || binding != p->contract.binding_id ||
        session != p->contract.session_id || grant != p->contract.grant_epoch)
        return;
    /*
     * v0.12：时钟服务点的响应不是「能力点的值」，它没有 VALUE TLV，
     * 也不进 pt/cap_list。这里只认「本对端确实有一次未决测量，且 txn 相同」
     * 的 CLOCK 回包，避免把服务帧误当成普通读数（§26.3）。
     */
    if (clock_tlv) {
        if (clock_tlv->len >= 15 && p->meas_pending && f->txn == p->meas_txn) {
            uint64_t rtt_ns, d_ns, counter_ns;
            uint32_t tick_ns = idcell_get_u32(clock_tlv->val + 8);

            p->meas_counter  = idcell_get_u64(clock_tlv->val);
            p->meas_tick_ns  = tick_ns;
            p->meas_epoch    = idcell_get_u16(clock_tlv->val + 12);
            p->meas_quality  = clock_tlv->val[14];
            rtt_ns = n->ts_us * 1000ULL - p->meas_t0_ns;
            p->meas_rtt_ns = rtt_ns;
            d_ns = rtt_ns / 2;
            /* tick_ns 未声明时按 1 ns 计，但 uncertainty 会被标成不可信 */
            counter_ns = p->meas_counter * (uint64_t)(tick_ns ? tick_ns : 1u);
            p->meas_offset_ns = (int64_t)counter_ns -
                                (int64_t)(p->meas_t0_ns + d_ns);
            p->meas_uncertainty_ns = (uint32_t)((tick_ns ? tick_ns / 2 : 0u) + 1000u);
            p->meas_pending = 0;
            p->meas_valid = 1;
        }
        return;
    }
    if (!value_tlv) return;
    cp = contract_point(p, idx, sub);
    if (!cp || (schema_ref && schema_ref != cp->schema_ref) ||
        (schema_id && schema_id != cp->schema_id)) return;
    {
        int found = 0;
        for (i = 0; i < p->cap_count; i++) {
            if (p->caps[i].index != idx || p->caps[i].sub != sub) continue;
            found = 1;
            if (!(p->caps[i].dir & IDCELL_DIR_READ) ||
                p->contract.perm < p->caps[i].perm || cp->perm < p->caps[i].perm) return;
            break;
        }
        if (!found) return;
    }
    if (decode_value(value_tlv, (idcell_dtype_t)cp->dtype, cp->scale_exp, &value) != IDCELL_OK)
        return;
    for (i = 0; i < p->pt_count; i++) {
        if (p->pts[i].cap_index == idx && p->pts[i].sub == sub) { pt = &p->pts[i]; break; }
    }
    if (!pt) return;
    pt->last_value = value;
    pt->last_ts_us = f->ts_us;
    pt->value_valid = 1;
    if (n->data_fn)
        n->data_fn(n->data_ud, &f->src, idx, sub, value, f->ts_us, prov, quality);
}

static int reject_unknown_critical(const idcell_frame_t *f)
{
    uint16_t pos = 0;
    idcell_tlv_t t;
    int rc;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type >= IDCELL_TLV_CRITICAL_MIN && t.type <= IDCELL_TLV_CRITICAL_MAX) return 1;
    }
    return rc < 0;
}

typedef struct {
    uint32_t binding;
    uint64_t session, grant, authority, authority_epoch, member, command;
} write_receipt_ctx_t;

static void receipt_ctx_tlv(write_receipt_ctx_t *ctx, const idcell_tlv_t *t)
{
    if (t->type == IDCELL_TLV_BIND_ID) ctx->binding = tlv_u32(t, 0);
    else if (t->type == IDCELL_TLV_SESSION_ID) ctx->session = tlv_u64(t, 0);
    else if (t->type == IDCELL_TLV_GRANT_EPOCH) ctx->grant = tlv_u64(t, 0);
    else if (t->type == IDCELL_TLV_AUTHORITY_ID) ctx->authority = tlv_u64(t, 0);
    else if (t->type == IDCELL_TLV_AUTHORITY_EPOCH) ctx->authority_epoch = tlv_u64(t, 0);
    else if (t->type == IDCELL_TLV_MEMBER_EPOCH) ctx->member = tlv_u64(t, 0);
    else if (t->type == IDCELL_TLV_COMMAND_ID) ctx->command = tlv_u64(t, 0);
}

static int receipt_matches(const idcell_peer_t *p, const idcell_frame_t *f,
                           const write_receipt_ctx_t *ctx)
{
    return p && p->write_pending && p->write_txn == f->txn && ctx->command &&
           ctx->command == p->write_command_id && ctx->binding == p->write_binding &&
           ctx->session == p->write_session && ctx->grant == p->write_grant &&
           ctx->authority == p->write_authority &&
           ctx->authority_epoch == p->write_authority_epoch &&
           ctx->member == p->write_member_epoch;
}

static void node_handle_frame(idcell_node_t *n, const idcell_frame_t *f)
{
    idcell_peer_t *p;

    /* SEC-064：链路层标识不得作身份——这里只信 DID，不信任何链路地址 */
    if (memcmp(f->src.b, n->cfg.did.b, 8) == 0) return;   /* 回声 */
    if (n->asleep && n->cfg.wake_profile == IDCELL_WAKE_RX_OFF) {
        (void)node_sleep_error(n);
        return; /* RX_OFF：线上帧既不是唤醒事件，也不更新 presence。 */
    }
    if ((f->type == IDCELL_FT_BIND || f->type == IDCELL_FT_NEGOTIATE ||
         f->type == IDCELL_FT_RENEGOTIATE ||
         f->type == IDCELL_FT_READ || f->type == IDCELL_FT_WRITE ||
         f->type == IDCELL_FT_EVENT) && reject_unknown_critical(f)) {
        node_send_error(n, &f->src, f->txn, IDCELL_E_UNSAFE, "TLV", -1, -1,
                        "未知 critical TLV 或畸形载荷");
        return;
    }
    /* 可解码帧不是授权唤醒事件；RADIO/PROXY 必须由绑定层显式调用 wake API。 */
    node_note_valid_frame(n, f);

#ifdef IDCELL_DEBUG
    {
        idcell_peer_t *dp = peer_get_or_add(n, &f->src);
        fprintf(stderr, "[DBG][%s][rx] type=0x%02X plen=%u role=%u stage=%u\n",
                n->cfg.model, f->type, f->payload_len,
                dp ? dp->role : 9, dp ? dp->stage : 9);
    }
#endif

    switch (f->type) {
    case IDCELL_FT_DISCOVER:
        node_on_discover(n, f);
        break;

    case IDCELL_FT_HELLO:
        node_on_hello(n, f);
        break;

    case IDCELL_FT_MATCH:
        p = peer_get_or_add(n, &f->src);
        if (p && p->role == 2) {
            node_on_match_result(n, f);   /* 我方是需求方，收到的是应答 */
        } else {
            node_on_match(n, f);          /* 我方是提供方 */
        }
        break;

    case IDCELL_FT_RENEGOTIATE:
        node_on_renegotiate(n, f);
        break;

    case IDCELL_FT_NEGOTIATE:
        p = peer_get_or_add(n, &f->src);
        if (p && p->role == 2) node_on_negotiate_result(n, f);
        else                   node_on_negotiate(n, f);
        break;

    case IDCELL_FT_AUTH:
        p = peer_get_or_add(n, &f->src);
        if (p && p->role == 2) node_on_auth_result(n, f);
        else                   node_on_auth(n, f);
        break;

    case IDCELL_FT_BIND:
        p = peer_get_or_add(n, &f->src);
        if (p && p->role == 2) node_on_bind_result(n, f);
        else                   node_on_bind(n, f);
        break;

    case IDCELL_FT_READ:
        p = peer_get_or_add(n, &f->src);
        if (p && p->role == 2) node_on_runtime_value(n, f, p);
        else node_on_read(n, f);
        break;

    case IDCELL_FT_WRITE:
        node_on_write(n, f);
        break;

    case IDCELL_FT_EVENT:
        p = peer_get_or_add(n, &f->src);
        node_on_runtime_value(n, f, p);
        break;

    case IDCELL_FT_OFFLINE:
        node_on_offline(n, f);
        break;

    case IDCELL_FT_HEARTBEAT: {
        uint32_t binding = 0;
        uint64_t session = 0, grant = 0;
        uint16_t pos = 0;
        idcell_tlv_t t;
        int rc;
        p = peer_get_or_add(n, &f->src);
        while (p && (rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
            if (t.type == IDCELL_TLV_BIND_ID) binding = tlv_u32(&t, 0);
            else if (t.type == IDCELL_TLV_SESSION_ID) session = tlv_u64(&t, 0);
            else if (t.type == IDCELL_TLV_GRANT_EPOCH) grant = tlv_u64(&t, 0);
        }
        if (p && peer_lease_valid(n, p) && binding == p->contract.binding_id &&
            session == p->contract.session_id && grant == p->contract.grant_epoch) {
            int renewable = 1;
            if (p->role == 1) {
                idcell_active_grant_t *g = grant_find(n, p->contract.arb_domain, 0);
                if (!g || !idcell_did_equal(&g->owner, &f->src) ||
                    g->session_id != session || g->grant_epoch != grant ||
                    g->owner_token != p->contract.owner_token ||
                    time_reached(n->now_ms, g->deadline_ms)) renewable = 0;
                else g->deadline_ms = n->now_ms + p->contract.lease_ttl_ms;
            }
            if (renewable) {
                p->last_rx_ms = n->now_ms;
                p->lease_deadline_ms = n->now_ms + p->contract.lease_ttl_ms;
            }
        }
        break;
    }

    case IDCELL_FT_ERROR: {
        /* 结构化错误：提取错误码、理由与值域信息 */
        uint16_t pos = 0;
        idcell_tlv_t t;
        char code[24];
        char reason[128];
        char object[32];
        write_receipt_ctx_t ctx;
        double lo = 0.0, hi = 0.0, val = 0.0;
        int has_lo = 0, has_hi = 0, has_val = 0;
        int rc, got = 0;
        reason[0] = '\0'; object[0] = '\0';
        memset(&ctx, 0, sizeof(ctx));
        while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
            receipt_ctx_tlv(&ctx, &t);
            if (t.type == IDCELL_TLV_ERR_BODY) {
                tlv_str(&t, code, sizeof(code));
                got = 1;
            } else if (t.type == IDCELL_EF_OBJECT) {
                tlv_str(&t, object, sizeof(object));
            } else if (t.type == IDCELL_EF_REASON) {
                tlv_str(&t, reason, sizeof(reason));
            } else if (t.type == IDCELL_EF_RANGE_LO) {
                lo = tlv_f64(&t, 0.0); has_lo = 1;
            } else if (t.type == IDCELL_EF_RANGE_HI) {
                hi = tlv_f64(&t, 0.0); has_hi = 1;
            } else if (t.type == IDCELL_EF_VALUE) {
                val = tlv_f64(&t, 0.0); has_val = 1;
            }
        }
        (void)rc;
        if (got) {
            idcell_err_t e = IDCELL_E_NODEV;
            p = peer_get_or_add(n, &f->src);
            if ((strcmp(object, "WRITE") == 0 || ctx.command) &&
                !receipt_matches(p, f, &ctx)) break;
            if (strcmp(code, "E_NOMATCH") == 0)        e = IDCELL_E_NOMATCH;
            else if (strcmp(code, "E_NEGOTIATE") == 0) e = IDCELL_E_NEGOTIATE;
            else if (strcmp(code, "E_PERM") == 0)      e = IDCELL_E_PERM;
            else if (strcmp(code, "E_LEASE") == 0)     e = IDCELL_E_LEASE;
            else if (strcmp(code, "E_CONV") == 0)      e = IDCELL_E_CONV;
            else if (strcmp(code, "E_RANGE") == 0)     e = IDCELL_E_RANGE;
            else if (strcmp(code, "E_UNSAFE") == 0)    e = IDCELL_E_UNSAFE;
            else if (strcmp(code, "E_UNIT") == 0)      e = IDCELL_E_UNIT;
            else if (strcmp(code, "E_CTX") == 0)       e = IDCELL_E_CTX;
            else if (strcmp(code, "E_NODEV") == 0)     e = IDCELL_E_NODEV;
            else if (strcmp(code, "E_IDCONFLICT") == 0)e = IDCELL_E_IDCONFLICT;
            n->last_err = (uint8_t)e;

            /* 写回执：完整上下文匹配后才交付。 */
            if (ctx.command) {
                idcell_write_result_t res;
                memset(&res, 0, sizeof(res));
                res.err = (int)e;
                res.reason = reason[0] ? reason : NULL;
                res.value = has_val ? val : p->write_value;
                if (has_lo && has_hi) {
                    res.has_range = 1;
                    res.range_lo = lo;
                    res.range_hi = hi;
                }
                p->write_pending = 0;
                if (n->wres_fn)
                    n->wres_fn(n->wres_ud, &f->src, p->write_index, p->write_sub, &res);
            }

            /* 不匹配类错误：回退管道，带候选值重试可能成功 */
            if (idcell_err_retryable(e)) {
                if (p && !p->has_contract) {
                    p->stage = IDCELL_STAGE_DESCRIBE;
                    p->next_retry_ms = n->now_ms + 1000;
                }
            }
        }
        break;
    }

    case IDCELL_FT_DONE: {
        write_receipt_ctx_t ctx;
        uint16_t pos = 0;
        idcell_tlv_t t;
        int rc;
        memset(&ctx, 0, sizeof(ctx));
        while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0)
            receipt_ctx_tlv(&ctx, &t);
        p = peer_get_or_add(n, &f->src);
        if (receipt_matches(p, f, &ctx)) {
            idcell_write_result_t res;
            memset(&res, 0, sizeof(res));
            res.err = IDCELL_OK;
            res.value = p->write_value;
            p->write_pending = 0;
            p->peer_stage = IDCELL_STAGE_RUNNING;
            if (n->wres_fn)
                n->wres_fn(n->wres_ud, &f->src, p->write_index, p->write_sub, &res);
        }
        break;
    }

    default:
        break;
    }
}

/* ---------------------------------------------------------------- poll */

void node_test_handle_frame(idcell_node_t *n, const idcell_frame_t *f)
{
    if (n && f) {
        node_handle_frame(n, f);
        if (!n->asleep) node_execute_queued_write(n);
    }
}

void node_test_receive_frame(idcell_node_t *n, const idcell_frame_t *f)
{
    if (n && f) node_handle_frame(n, f);
}

static int rx_public_type(uint8_t type)
{
    return type == IDCELL_FT_DISCOVER || type == IDCELL_FT_HELLO ||
           type == IDCELL_FT_MATCH || type == IDCELL_FT_NEGOTIATE ||
           type == IDCELL_FT_AUTH;
}

static uint8_t rx_bind_phase(const uint8_t *wire, size_t len)
{
    uint16_t payload_len, pos = 0;
    idcell_tlv_t t;
    int rc;
    if (len < IDCELL_HDR_LEN) return 0;
    payload_len = idcell_get_u16(wire + 10);
    if (payload_len > IDCELL_MAX_PAYLOAD || (size_t)payload_len > len - IDCELL_HDR_LEN) return 0;
    while ((rc = idcell_tlv_next(wire + IDCELL_HDR_LEN, payload_len, &pos, &t)) == 0)
        if (t.type == IDCELL_TLV_BIND_PHASE && t.len == 1) return t.val[0];
    return 0;
}

static int rx_heartbeat_has_contract(const idcell_frame_t *f)
{
    uint16_t pos = 0;
    idcell_tlv_t t;
    int rc;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0)
        if (t.type == IDCELL_TLV_BIND_ID || t.type == IDCELL_TLV_SESSION_ID ||
            t.type == IDCELL_TLV_GRANT_EPOCH) return 1;
    return 0;
}

/* 处理持久接收缓冲；敏感帧在任何业务 handler 前完成 SRC 选钥和 HMAC 验证。 */
static void node_process_rx(idcell_node_t *n)
{
    size_t off = 0;

    while (off < n->rx_len) {
        idcell_frame_t f;
        idcell_peer_t *p = NULL;
        idcell_session_key_t *key = NULL;
        size_t remain = n->rx_len - off;
        size_t consumed = 0;
        uint8_t type, flags;
        int rc, sensitive;

        /* 保留末尾半个 SYNC；其余垃圾逐字节越过。 */
        if (remain < 2) {
            if (n->rx_buf[off] == 0xA5) break;
            off++;
            continue;
        }
        if (n->rx_buf[off] != 0xA5 || n->rx_buf[off + 1] != 0xA5) {
            off++;
            continue;
        }
        if (remain < IDCELL_HDR_LEN) break;

        type = n->rx_buf[off + 5];
        flags = n->rx_buf[off + 4];
        sensitive = !rx_public_type(type) && type != IDCELL_FT_HEARTBEAT;
        if (sensitive && !n->cap_count && !n->req_count &&
            (n->profile.topology == IDCELL_TOPO_SWITCHED ||
             n->profile.topology == IDCELL_TOPO_MESH ||
             n->profile.topology == IDCELL_TOPO_STAR_HOST_PROXY)) {
            static const uint8_t broadcast[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            const uint8_t *dst = n->rx_buf + off + 20;
            if (memcmp(dst, n->cfg.did.b, 8) != 0 && memcmp(dst, broadcast, 8) != 0) {
                size_t total = IDCELL_HDR_LEN + idcell_get_u16(n->rx_buf + off + 10) +
                               ((flags & IDCELL_FLAG_AUTH) ? IDCELL_AUTH_TAG_LEN : 0) +
                               IDCELL_TRAILER_LEN;
                if (total > IDCELL_MAX_FRAME) { off++; continue; }
                if (remain < total) break;
                /* 无密钥纯中继不解码、不改写、不验签；终端仍执行完整认证。 */
                if (!n->asleep) (void)n->tr.send(n->tr.ctx, n->rx_buf + off, total);
                off += total;
                continue;
            }
        }
        if (sensitive && !(flags & IDCELL_FLAG_AUTH)) {
            off++; /* 无标签敏感帧直接拒绝，不能用 decode 成功代替鉴权。 */
            continue;
        }
        if ((sensitive || (flags & IDCELL_FLAG_AUTH)) && type != IDCELL_FT_HEARTBEAT) {
            idcell_did_t src;
            memcpy(src.b, n->rx_buf + off + 12, 8);
            p = peer_existing(n, &src);
            if (type == IDCELL_FT_BIND && p) {
                if (rx_bind_phase(n->rx_buf + off, remain) == IDCELL_BIND_PHASE_COMMIT &&
                    p->next_key.valid) key = &p->next_key;
                else if (p->bind_key.valid) key = &p->bind_key;
            } else if (type == IDCELL_FT_ERROR && p && !p->active_key.valid && p->bind_key.valid) {
                key = &p->bind_key;
            } else if (p && p->active_key.valid) {
                key = &p->active_key;
            }
        } else if (type == IDCELL_FT_HEARTBEAT && (flags & IDCELL_FLAG_AUTH)) {
            idcell_did_t src;
            memcpy(src.b, n->rx_buf + off + 12, 8);
            p = peer_existing(n, &src);
            if (p && p->active_key.valid) key = &p->active_key;
        }

        if (key) {
            rc = idcell_frame_decode_auth(n->rx_buf + off, remain, key->key, sizeof(key->key),
                                          &f, &consumed);
        } else if (sensitive || (flags & IDCELL_FLAG_AUTH)) {
            off++; /* 缺 key 或公共帧意外带标签：不物化、不进入业务。 */
            continue;
        } else {
            rc = idcell_frame_decode(n->rx_buf + off, remain, &f, &consumed);
        }
        if (rc == IDCELL_FRAME_NEED_MORE) break;
        if (rc < 0) {
            /* 错 key、篡改和旧 key 与 CRC 错误一样，均无业务副作用。 */
            off++;
            continue;
        }
        if (key && !idcell_replay_accept(key, f.seq)) {
            /* HMAC 之后、presence/租约/缓存及所有业务 handler 之前统一拒绝。 */
            off += consumed;
            continue;
        }
        if (type == IDCELL_FT_HEARTBEAT && !(f.flags & IDCELL_FLAG_AUTH) &&
            rx_heartbeat_has_contract(&f)) {
            off += consumed;
            continue;
        }
        node_handle_frame(n, &f);
        off += consumed;
    }

    if (off) {
        n->rx_len -= off;
        if (n->rx_len) memmove(n->rx_buf, n->rx_buf + off, n->rx_len);
    }
}

/*
 * 设备侧执行入口。所有收帧、定时器、周期发布、心跳、租约维护都在这里。
 * 不得在中断上下文调用（NFR-025）。
 */
int idcell_node_poll(idcell_node_t *n, uint32_t now_ms)
{
    if (!n) return IDCELL_E_NODEV;
    n->now_ms = now_ms;
    n->ts_us = (uint64_t)now_ms * 1000ULL;

    if (n->asleep && n->cfg.wake_profile == IDCELL_WAKE_SCHEDULED &&
        time_reached(now_ms, n->wake_deadline_ms))
        (void)idcell_node_wake(n, IDCELL_WAKE_EVENT_TIMER, now_ms);
    if (n->asleep && n->cfg.wake_profile == IDCELL_WAKE_RX_OFF) return node_sleep_error(n);

    if (n->has_tr) {
        for (;;) {
            size_t free_cap;
            int got;

            node_process_rx(n);
            free_cap = sizeof(n->rx_buf) - n->rx_len;
            if (free_cap == 0) break;
            got = n->tr.recv(n->tr.ctx, n->rx_buf + n->rx_len, free_cap, 0);
            if (got <= 0) break;
            n->rx_len += (size_t)got;
            node_process_rx(n);
            if ((size_t)got < free_cap) break;
        }
    }

    /* 休眠 mailbox 不在睡眠中执行；唤醒后仍由同一个单写者逐条复验。 */
    if (!n->asleep) node_execute_queued_write(n);
    if (!n->asleep) node_send_due_responses(n);
    if (n->asleep) return IDCELL_OK;

    /* 所有节点（包括无 cap/req 的纯中继）共用同一 ANNOUNCE 调度。 */
    {
        if (!n->announce_started) {
            n->announce_started = 1;
            n->next_discover_ms = now_ms + (n->cfg.announce_jitter_ms ?
                (uint32_t)(node_rand(n) % ((uint64_t)n->cfg.announce_jitter_ms + 1u)) : 0);
        } else if (time_reached(now_ms, n->next_discover_ms)) {
            uint32_t delay = n->cfg.announce_steady_ms;
            node_send_discover(n);
            n->announce_count++;
            if (!n->announce_confirmed) {
                uint64_t cap = n->cfg.announce_ms;
                uint32_t shift = n->announce_failures < 32 ? n->announce_failures : 32;
                cap <<= shift;
                if (cap > n->cfg.announce_retry_max_ms) cap = n->cfg.announce_retry_max_ms;
                delay = cap ? (uint32_t)(node_rand(n) % (cap + 1u)) : 0;
                if (n->announce_failures != UINT32_MAX) n->announce_failures++;
            }
            n->next_discover_ms = now_ms + delay;
        }
    }

    /* 需求方：推进管道 */
    node_drive_match(n, now_ms);
    node_drive_negotiate(n, now_ms);
    node_drive_auth(n, now_ms);
    node_drive_bind(n, now_ms);

    /* 管道超时：对端不响应则回退重试 */
    {
        int i;
        for (i = 0; i < IDCELL_MAX_PEERS; i++) {
            idcell_peer_t *p = &n->peers[i];
            if (!p->used || p->commit_waiting ||
                (p->has_contract && p->stage == IDCELL_STAGE_RUNNING)) continue;
            if (p->stage != IDCELL_STAGE_MATCH &&
                p->stage != IDCELL_STAGE_NEGOTIATE &&
                p->stage != IDCELL_STAGE_AUTHORIZE &&
                p->stage != IDCELL_STAGE_BIND) continue;
            if (!p->presence_seen) continue;
            if (now_ms - p->last_rx_ms < 2000) continue;
            clear_pending(p);
            p->next_retry_ms = now_ms;
        }
    }

    /* 运行期：旧 owner TTL 到期后才允许等待中的新 grant 接管。 */
    node_activate_waiters(n);
    node_publish(n, now_ms);
    node_heartbeat(n, now_ms);
    if (n->cfg.wake_profile != IDCELL_WAKE_ALWAYS_ON && time_reached(now_ms, n->next_checkin_ms))
        (void)idcell_node_check_in(n, now_ms);

    /* 租约到期：释放所有权（由 TTL 触发，不由心跳触发） */
    {
        int i;
        for (i = 0; i < IDCELL_MAX_PEERS; i++) {
            idcell_peer_t *p = &n->peers[i];
            if (!p->used || !p->has_contract) continue;
            if (p->owner_token && time_reached(now_ms, p->lease_deadline_ms)) {
                p->owner_token = 0;
            }
        }
    }

    return IDCELL_OK;
}
