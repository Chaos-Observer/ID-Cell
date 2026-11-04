/* 公共/授权描述、会话密钥与线上认证的独立 C99 行为测试。 */
#include "idcell_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_FRAMES 160
#define QUEUE_CAP  65536

static int g_pass, g_fail;
static void ok(int cond, const char *name)
{
    if (cond) { g_pass++; printf("PASS %s\n", name); }
    else { g_fail++; printf("FAIL %s\n", name); }
}
static void eq(int got, int want, const char *name)
{
    if (got == want) { g_pass++; printf("PASS %s\n", name); }
    else { g_fail++; printf("FAIL %s got=%d want=%d\n", name, got, want); }
}

typedef struct {
    uint8_t data[QUEUE_CAP];
    size_t len;
} channel_t;

typedef struct {
    channel_t *in, *out;
    idcell_link_profile_t profile;
    uint8_t log[LOG_FRAMES][IDCELL_MAX_FRAME];
    size_t log_len[LOG_FRAMES];
    int log_count;
} endpoint_t;

typedef struct {
    int set_calls, read_calls;
    double value;
    uint64_t tick;
} device_state_t;

typedef struct {
    channel_t dev_to_host, host_to_dev;
    endpoint_t dev_ep, host_ep;
    idcell_node_t *dev, *host;
    idcell_did_t dev_did, host_did;
    device_state_t state;
    int data_calls;
    double last_data;
    uint32_t now;
} scene_t;

static int ep_send(void *ctx, const uint8_t *buf, size_t len)
{
    endpoint_t *ep = (endpoint_t *)ctx;
    if (ep->out->len + len > sizeof(ep->out->data)) return -1;
    memcpy(ep->out->data + ep->out->len, buf, len);
    ep->out->len += len;
    if (ep->log_count < LOG_FRAMES && len <= IDCELL_MAX_FRAME) {
        memcpy(ep->log[ep->log_count], buf, len);
        ep->log_len[ep->log_count++] = len;
    }
    return 0;
}

static int ep_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout)
{
    endpoint_t *ep = (endpoint_t *)ctx;
    size_t n;
    (void)timeout;
    if (!ep->in->len) return 0;
    n = ep->in->len < cap ? ep->in->len : cap;
    memcpy(buf, ep->in->data, n);
    ep->in->len -= n;
    if (ep->in->len) memmove(ep->in->data, ep->in->data + n, ep->in->len);
    return (int)n;
}

static int value_fn(void *ud, uint16_t index, uint8_t sub,
                    double *value, uint64_t *ts, idcell_prov_t *prov)
{
    device_state_t *s = (device_state_t *)ud;
    (void)sub;
    if (index != 0x0200) return IDCELL_E_NODEV;
    s->read_calls++;
    *value = s->value;
    *ts = ++s->tick * 1000;
    *prov = IDCELL_PROV_MEASURED;
    return IDCELL_OK;
}

static int set_fn(void *ud, uint16_t index, uint8_t sub, double value,
                  const char *intent, uint32_t owner)
{
    device_state_t *s = (device_state_t *)ud;
    (void)sub; (void)intent; (void)owner;
    if (index != 0x0200) return IDCELL_E_NODEV;
    s->set_calls++;
    s->value = value;
    return IDCELL_OK;
}

static void data_fn(void *ud, const idcell_did_t *peer, uint16_t index, uint8_t sub,
                    double value, uint64_t ts, idcell_prov_t prov, idcell_quality_t quality)
{
    scene_t *s = (scene_t *)ud;
    (void)peer; (void)index; (void)sub; (void)ts; (void)prov; (void)quality;
    s->data_calls++;
    s->last_data = value;
}

static void fill_cap(idcell_capability_t *cap)
{
    memset(cap, 0, sizeof(*cap));
    cap->index = 0x0200;
    snprintf(cap->label, sizeof(cap->label), "temperature");
    cap->kind = IDCELL_KIND_STATE;
    cap->dir = IDCELL_DIR_RW;
    cap->perm = IDCELL_PERM_P2;
    cap->qty = IDCELL_QTY_TEMPERATURE;
    snprintf(cap->unit, sizeof(cap->unit), "Cel");
    cap->accept_count = 1;
    snprintf(cap->accept_units[0], sizeof(cap->accept_units[0]), "Cel");
    cap->conv_class = IDCELL_CONV_T1;
    cap->dtype = IDCELL_DTYPE_F64;
    idcell_type_list_add(cap->accept_types, &cap->accept_type_count, IDCELL_DTYPE_F64, 0);
    cap->range[0] = -40; cap->range[1] = 85;
    cap->precision = 0.01;
    cap->min_sync_ms = 20; cap->stale_ms = 1000;
    cap->fail_action = IDCELL_FAIL_HOLD;
    cap->provenance = IDCELL_PROV_MEASURED;
}

static void scene_init(scene_t *s)
{
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    idcell_requirement_t req;
    memset(s, 0, sizeof(*s));
    s->dev_ep.in = &s->host_to_dev; s->dev_ep.out = &s->dev_to_host;
    s->host_ep.in = &s->dev_to_host; s->host_ep.out = &s->host_to_dev;
    s->dev_ep.profile.media = IDCELL_MEDIA_LOOPBACK;
    s->dev_ep.profile.topology = IDCELL_TOPO_P2P;
    s->host_ep.profile = s->dev_ep.profile;
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x5101, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 100; cfg.announce_jitter_ms = 1;
    cfg.discovery_response_interval_ms = 1; cfg.discovery_response_jitter_ms = 1;
    cfg.lease_ttl_ms = 10000;
    snprintf(cfg.model, sizeof(cfg.model), "security-device");
    s->dev = idcell_node_new(&cfg);
    {
        idcell_transport_t tr;
        tr.send = ep_send; tr.recv = ep_recv; tr.profile = &s->dev_ep.profile; tr.ctx = &s->dev_ep;
        idcell_node_set_transport(s->dev, &tr);
    }
    fill_cap(&cap);
    idcell_node_register_capability(s->dev, &cap);
    s->state.value = 20;
    idcell_node_set_value_source(s->dev, value_fn, &s->state);
    idcell_node_set_setter(s->dev, set_fn, &s->state);

    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x5102, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 100; cfg.announce_jitter_ms = 1;
    cfg.discovery_response_interval_ms = 1; cfg.discovery_response_jitter_ms = 1;
    cfg.lease_ttl_ms = 10000;
    snprintf(cfg.model, sizeof(cfg.model), "security-host");
    s->host = idcell_node_new(&cfg);
    {
        idcell_transport_t tr;
        tr.send = ep_send; tr.recv = ep_recv; tr.profile = &s->host_ep.profile; tr.ctx = &s->host_ep;
        idcell_node_set_transport(s->host, &tr);
    }
    idcell_node_set_data_sink(s->host, data_fn, s);
    memset(&req, 0, sizeof(req));
    req.index = 0xFFFF; req.kind = IDCELL_KIND_STATE;
    req.qty = IDCELL_QTY_TEMPERATURE; req.perm = IDCELL_PERM_P2;
    snprintf(req.unit, sizeof(req.unit), "Cel");
    req.accept_count = 1; snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "Cel");
    req.want_ms = 20; req.stale_ms = 1000;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_node_register_requirement(s->host, &req);
    s->dev_did = idcell_node_did(s->dev); s->host_did = idcell_node_did(s->host);
}

static void scene_free(scene_t *s)
{
    if (s->dev) idcell_node_free(s->dev);
    if (s->host) idcell_node_free(s->host);
    memset(s, 0, sizeof(*s));
}

static void scene_step(scene_t *s)
{
    idcell_node_poll(s->dev, s->now);
    idcell_node_poll(s->host, s->now);
    s->now += 10;
}

static int scene_bind(scene_t *s)
{
    int i;
    idcell_contract_t c;
    for (i = 0; i < 600; i++) {
        scene_step(s);
        if (idcell_node_get_contract(s->dev, &s->host_did, &c) == IDCELL_OK &&
            idcell_node_get_contract(s->host, &s->dev_did, &c) == IDCELL_OK) return 1;
    }
    return 0;
}

static int scene_rebind(scene_t *s, uint64_t old_session)
{
    int i;
    idcell_contract_t a, b;
    for (i = 0; i < 1500; i++) {
        scene_step(s);
        if (idcell_node_get_contract(s->dev, &s->host_did, &a) == IDCELL_OK &&
            idcell_node_get_contract(s->host, &s->dev_did, &b) == IDCELL_OK &&
            a.session_id != old_session && b.session_id == a.session_id) return 1;
    }
    return 0;
}

static size_t wire_size(const uint8_t *wire)
{
    return IDCELL_HDR_LEN + idcell_get_u16(wire + 10) +
           ((wire[4] & IDCELL_FLAG_AUTH) ? IDCELL_AUTH_TAG_LEN : 0) + IDCELL_TRAILER_LEN;
}

static int channel_extract(channel_t *c, uint8_t type, uint8_t *out, size_t *out_len)
{
    size_t off = 0, found_off = 0, found_len = 0;
    int found = 0;
    while (off + IDCELL_HDR_LEN <= c->len) {
        size_t n;
        if (c->data[off] != 0xA5 || c->data[off + 1] != 0xA5) { off++; continue; }
        n = wire_size(c->data + off);
        if (n > IDCELL_MAX_FRAME || off + n > c->len) break;
        if (c->data[off + 5] == type) { found = 1; found_off = off; found_len = n; }
        off += n;
    }
    if (!found || found_len > IDCELL_MAX_FRAME) return 0;
    memcpy(out, c->data + found_off, found_len);
    memmove(c->data + found_off, c->data + found_off + found_len,
            c->len - found_off - found_len);
    c->len -= found_off + found_len <= c->len ? found_len : 0;
    *out_len = found_len;
    return 1;
}

static void channel_inject(channel_t *c, const uint8_t *wire, size_t len)
{
    if (c->len + len <= sizeof(c->data)) {
        memcpy(c->data + c->len, wire, len);
        c->len += len;
    }
}

static int log_find(const endpoint_t *ep, uint8_t type, uint8_t *out, size_t *out_len)
{
    int i;
    for (i = ep->log_count - 1; i >= 0; i--) {
        if (ep->log[i][5] != type) continue;
        memcpy(out, ep->log[i], ep->log_len[i]);
        *out_len = ep->log_len[i];
        return 1;
    }
    return 0;
}

static void put32(uint8_t *payload, uint16_t *pos, uint8_t type, uint32_t v)
{
    uint8_t b[4]; idcell_put_u32(b, v);
    idcell_tlv_put(payload, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, b, 4);
}
static void put64(uint8_t *payload, uint16_t *pos, uint8_t type, uint64_t v)
{
    uint8_t b[8]; idcell_put_u64(b, v);
    idcell_tlv_put(payload, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, b, 8);
}
static void put16(uint8_t *payload, uint16_t *pos, uint8_t type, uint16_t v)
{
    uint8_t b[2]; idcell_put_u16(b, v);
    idcell_tlv_put(payload, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, b, 2);
}

static int make_heartbeat(scene_t *s, int from_host, idcell_frame_t *f, uint16_t seq,
                          uint8_t *wire, size_t *wire_len)
{
    idcell_contract_t c;
    idcell_session_key_t *key;
    uint16_t pos = 0;
    memset(f, 0, sizeof(*f));
    if (from_host) {
        if (idcell_node_get_contract(s->dev, &s->host_did, &c) != IDCELL_OK) return 0;
        key = &s->host->peers[0].active_key;
        f->src = s->host_did; f->dst = s->dev_did;
    } else {
        if (idcell_node_get_contract(s->host, &s->dev_did, &c) != IDCELL_OK) return 0;
        key = &s->dev->peers[0].active_key;
        f->src = s->dev_did; f->dst = s->host_did;
    }
    f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_HEARTBEAT;
    f->flags = IDCELL_FLAG_AUTH; f->seq = seq;
    put32(f->payload, &pos, IDCELL_TLV_TTL, c.lease_ttl_ms);
    put32(f->payload, &pos, IDCELL_TLV_BIND_ID, c.binding_id);
    put64(f->payload, &pos, IDCELL_TLV_SESSION_ID, c.session_id);
    put64(f->payload, &pos, IDCELL_TLV_GRANT_EPOCH, c.grant_epoch);
    f->payload_len = pos;
    return key->valid && idcell_frame_encode_auth(f, key->key, 32, wire, IDCELL_MAX_FRAME, wire_len) == IDCELL_FRAME_OK;
}

static int make_event(scene_t *s, idcell_frame_t *f, uint16_t seq, double value,
                      uint8_t *wire, size_t *wire_len)
{
    idcell_contract_t c;
    idcell_session_key_t *key;
    uint16_t pos = 0;
    uint8_t b[8], one;
    if (idcell_node_get_contract(s->host, &s->dev_did, &c) != IDCELL_OK) return 0;
    key = &s->dev->peers[0].active_key;
    memset(f, 0, sizeof(*f));
    f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_EVENT;
    f->flags = IDCELL_FLAG_AUTH; f->seq = seq; f->src = s->dev_did; f->dst = s->host_did;
    idcell_put_f64(b, value);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0x0200, 0, IDCELL_TLV_VALUE, b, 8);
    put16(f->payload, &pos, IDCELL_TLV_SCHEMA_REF, c.pt[0].schema_ref);
    put32(f->payload, &pos, IDCELL_TLV_BIND_ID, c.binding_id);
    put64(f->payload, &pos, IDCELL_TLV_SESSION_ID, c.session_id);
    put64(f->payload, &pos, IDCELL_TLV_GRANT_EPOCH, c.grant_epoch);
    one = IDCELL_PROV_MEASURED;
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0, IDCELL_TLV_PROV, &one, 1);
    one = IDCELL_QUALITY_GOOD;
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0, IDCELL_TLV_QUALITY, &one, 1);
    f->payload_len = pos;
    return key->valid && idcell_frame_encode_auth(f, key->key, 32, wire, IDCELL_MAX_FRAME, wire_len) == IDCELL_FRAME_OK;
}

static int make_write(scene_t *s, idcell_frame_t *f, double value, uint64_t command)
{
    idcell_contract_t c;
    uint16_t pos = 0;
    uint8_t b[8];
    if (idcell_node_get_contract(s->host, &s->dev_did, &c) != IDCELL_OK) return 0;
    memset(f, 0, sizeof(*f));
    f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_WRITE; f->flags = IDCELL_FLAG_AUTH;
    f->src = s->host_did; f->dst = s->dev_did; f->txn = (uint16_t)command;
    idcell_put_f64(b, value);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0x0200, 0, IDCELL_TLV_VALUE, b, 8);
    idcell_put_f64(b, value);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0, IDCELL_TLV_F64, b, 8);
    put32(f->payload, &pos, IDCELL_TLV_BIND_ID, c.binding_id);
    put64(f->payload, &pos, IDCELL_TLV_SESSION_ID, c.session_id);
    put64(f->payload, &pos, IDCELL_TLV_GRANT_EPOCH, c.grant_epoch);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_ID, c.authority_id);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_EPOCH, c.authority_epoch);
    put64(f->payload, &pos, IDCELL_TLV_MEMBER_EPOCH, c.member_epoch);
    put64(f->payload, &pos, IDCELL_TLV_COMMAND_ID, command);
    put32(f->payload, &pos, IDCELL_TLV_VALID_FOR, 500);
    put32(f->payload, &pos, IDCELL_TLV_OWNER, c.owner_token);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0,
                   IDCELL_TLV_INTENT, "security", 8);
    f->payload_len = pos;
    return 1;
}

static void test_public_hello(void)
{
    scene_t s;
    uint8_t wire[IDCELL_MAX_FRAME], canonical[IDCELL_MAX_PAYLOAD], digest[32];
    idcell_frame_t f;
    idcell_tlv_t t;
    size_t len = 0, used = 0;
    uint16_t pos = 0, cpos = 0;
    int rc, sensitive = 0, have_digest = 0;
    printf("[public HELLO]\n");
    scene_init(&s);
    for (s.now = 0; s.now < 1000 && !log_find(&s.dev_ep, IDCELL_FT_HELLO, wire, &len); s.now += 10) {
        idcell_node_poll(s.dev, s.now); idcell_node_poll(s.host, s.now);
    }
    ok(len != 0, "real public HELLO captured");
    eq(idcell_frame_decode(wire, len, &f, &used), IDCELL_FRAME_OK, "public HELLO needs no session key");
    while ((rc = idcell_tlv_next(f.payload, f.payload_len, &pos, &t)) == 0) {
        if (t.type == IDCELL_TLV_PUBLIC_DIGEST && t.len == 32) have_digest = 1;
        if (t.type == IDCELL_TLV_SCOPE || t.type == IDCELL_TLV_AUTH_DIGEST) sensitive = 1;
        if (t.type == IDCELL_TLV_CAP_DESC) {
            uint16_t ipos = 0;
            idcell_tlv_t it;
            memcpy(canonical + cpos, t.val - IDCELL_TLV_HDR_LEN, IDCELL_TLV_HDR_LEN + t.len);
            cpos = (uint16_t)(cpos + IDCELL_TLV_HDR_LEN + t.len);
            while (idcell_tlv_next(t.val, t.len, &ipos, &it) == 0) {
                if (it.type == IDCELL_CF_RANGE || it.type == IDCELL_CF_FAIL ||
                    it.type == IDCELL_CF_PERM || it.type == IDCELL_CF_SCHEMA ||
                    it.type == IDCELL_CF_ESCALATE || it.type == IDCELL_CF_DEPS) sensitive = 1;
            }
        }
    }
    ok(!sensitive, "HELLO excludes scope/range/fail/policy/sensitive-schema TLVs");
    ok(have_digest && cpos != 0, "HELLO carries public digest and canonical descriptors");
    idcell_descriptor_digest(1, canonical, cpos, digest);
    {
        const uint8_t *found = NULL;
        pos = 0;
        while (idcell_tlv_next(f.payload, f.payload_len, &pos, &t) == 0)
            if (t.type == IDCELL_TLV_PUBLIC_DIGEST) found = t.val;
        ok(found && memcmp(found, digest, 32) == 0, "public digest matches normalized TLV bytes");
    }
    scene_free(&s);
}

static int drive_prepared(scene_t *s)
{
    int i;
    for (i = 0; i < 600; i++) {
        idcell_node_poll(s->dev, s->now);
        if (s->dev->peers[0].used && s->dev->peers[0].bind_phase == IDCELL_BIND_PREPARED)
            return 1;
        idcell_node_poll(s->host, s->now);
        s->now += 10;
    }
    return 0;
}

static void test_prepared_rejection(int tamper)
{
    scene_t s;
    idcell_frame_t f;
    idcell_contract_t c;
    uint8_t wire[IDCELL_MAX_FRAME];
    size_t len = 0, used;
    printf(tamper ? "[tampered authorized descriptor]\n" : "[missing authorized descriptor]\n");
    scene_init(&s);
    ok(drive_prepared(&s), "provider reaches PREPARED before consumer");
    ok(channel_extract(&s.dev_to_host, IDCELL_FT_BIND, wire, &len), "intercept real PREPARED bytes");
    eq(idcell_frame_decode_auth(wire, len, s.dev->peers[0].bind_key.key, 32, &f, &used),
       IDCELL_FRAME_OK, "PREPARED authenticates with pre-BIND key");
    if (tamper) {
        uint16_t pos = 0;
        idcell_tlv_t t;
        int changed = 0;
        while (idcell_tlv_next(f.payload, f.payload_len, &pos, &t) == 0 && !changed) {
            if (t.type == IDCELL_TLV_CAP_DESC) {
                uint16_t ipos = 0;
                idcell_tlv_t it;
                while (idcell_tlv_next(t.val, t.len, &ipos, &it) == 0) {
                    if (it.type == IDCELL_CF_FAIL) {
                        f.payload[(size_t)(it.val - f.payload)] ^= 1;
                        changed = 1; break;
                    }
                }
            }
        }
        ok(changed, "mutate authorized fail_action without updating digest");
    } else {
        uint8_t replacement[IDCELL_MAX_PAYLOAD];
        uint16_t pos = 0, out = 0;
        idcell_tlv_t t;
        while (idcell_tlv_next(f.payload, f.payload_len, &pos, &t) == 0) {
            if (t.type == IDCELL_TLV_CAP_DESC) continue;
            idcell_tlv_put(replacement, sizeof(replacement), &out, t.idx, t.sub, t.type, t.val, t.len);
        }
        memcpy(f.payload, replacement, out); f.payload_len = out;
        ok(1, "remove complete authorized descriptor set");
    }
    eq(idcell_frame_encode_auth(&f, s.dev->peers[0].bind_key.key, 32, wire, sizeof(wire), &len),
       IDCELL_FRAME_OK, "re-sign semantic mutation to isolate descriptor validation");
    channel_inject(&s.dev_to_host, wire, len);
    idcell_node_poll(s.host, s.now);
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_E_NODEV,
       "missing/tampered authorized description cannot activate consumer");
    idcell_node_poll(s.dev, ++s.now);
    eq(idcell_node_get_contract(s.dev, &s.host_did, &c), IDCELL_E_NODEV,
       "missing/tampered authorized description cannot activate provider");
    scene_free(&s);
}

static void test_key_rotation_and_authenticated_runtime(void)
{
    scene_t s;
    idcell_frame_t f;
    idcell_contract_t c;
    idcell_session_key_t k0;
    uint8_t wire[IDCELL_MAX_FRAME];
    size_t len = 0, used;
    printf("[COMMIT/COMMITTED key rotation]\n");
    scene_init(&s);
    ok(drive_prepared(&s), "PREPARED creates pending session key");
    k0 = s.dev->peers[0].bind_key;
    ok(k0.valid && s.dev->peers[0].next_key.valid &&
       memcmp(k0.key, s.dev->peers[0].next_key.key, 32) != 0,
       "new session id derives a different 32B key");
    ok(channel_extract(&s.dev_to_host, IDCELL_FT_BIND, wire, &len), "capture PREPARED for key assertion");
    eq(idcell_frame_decode_auth(wire, len, k0.key, 32, &f, &used), IDCELL_FRAME_OK,
       "PREPARED remains on old key until consumer accepts context");
    channel_inject(&s.dev_to_host, wire, len);
    idcell_node_poll(s.host, s.now);
    eq(s.host->peers[0].bind_phase, IDCELL_BIND_COMMIT_SENT, "consumer switches before COMMIT");
    ok(channel_extract(&s.host_to_dev, IDCELL_FT_BIND, wire, &len), "capture COMMIT");
    eq(idcell_frame_decode_auth(wire, len, s.host->peers[0].bind_key.key, 32, &f, &used),
       IDCELL_FRAME_OK, "COMMIT authenticates with new session key");
    ok(idcell_frame_decode_auth(wire, len, k0.key, 32, &f, &used) == IDCELL_FRAME_BAD_AUTH,
       "COMMIT cannot be verified by old key");
    channel_inject(&s.host_to_dev, wire, len);
    idcell_node_poll(s.dev, ++s.now);
    ok(channel_extract(&s.dev_to_host, IDCELL_FT_BIND, wire, &len), "capture COMMITTED");
    eq(idcell_frame_decode_auth(wire, len, s.dev->peers[0].active_key.key, 32, &f, &used),
       IDCELL_FRAME_OK, "COMMITTED uses new active key on both ends");
    channel_inject(&s.dev_to_host, wire, len);
    idcell_node_poll(s.host, s.now);
    ok(s.dev->peers[0].active_key.valid && s.host->peers[0].active_key.valid &&
       memcmp(s.dev->peers[0].active_key.key, s.host->peers[0].active_key.key, 32) == 0 &&
       s.dev->peers[0].active_key.session_id == s.host->peers[0].active_key.session_id &&
       memcmp(s.dev->peers[0].active_key.key_id, s.host->peers[0].active_key.key_id, 16) == 0,
       "both peers store identical key_id/session_id/key");
    ok(memcmp(s.dev->peers[0].active_key.key, s.dev->cfg.cred, 32) != 0,
       "session key is derived rather than raw cred");
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_OK, "rotated contract activates");
    scene_free(&s);
}

static void test_sensitive_rejection(void)
{
    scene_t s;
    idcell_frame_t f;
    uint8_t original[IDCELL_MAX_FRAME], wire[IDCELL_MAX_FRAME], wrong[32];
    size_t len = 0, used;
    int base;
    printf("[wrong key/tamper/no-tag/no-key rejection]\n");
    scene_init(&s); ok(scene_bind(&s), "bind sensitive-frame scene");
    eq(idcell_node_write(s.host, 0x0200, 0, 24, s.host->peers[0].owner_token, "security"),
       IDCELL_OK, "issue real authenticated WRITE");
    ok(channel_extract(&s.host_to_dev, IDCELL_FT_WRITE, original, &len), "capture real WRITE bytes");
    eq(idcell_frame_decode_auth(original, len, s.host->peers[0].active_key.key, 32, &f, &used),
       IDCELL_FRAME_OK, "WRITE verifies before adversarial mutations");
    base = s.state.set_calls;
    memset(wrong, 0xA5, sizeof(wrong));
    eq(idcell_frame_encode_auth(&f, wrong, sizeof(wrong), wire, sizeof(wire), &used), IDCELL_FRAME_OK,
       "encode wrong-key variant");
    channel_inject(&s.host_to_dev, wire, used); idcell_node_poll(s.dev, ++s.now);
    eq(s.state.set_calls, base, "wrong key rejected before setter side effect");

    memcpy(wire, original, len); wire[IDCELL_HDR_LEN + 6] ^= 1;
    idcell_put_u16(wire + len - 4, idcell_crc16(wire, len - 4));
    channel_inject(&s.host_to_dev, wire, len); idcell_node_poll(s.dev, ++s.now);
    eq(s.state.set_calls, base, "payload tamper with repaired CRC rejected by HMAC");

    f.flags &= (uint8_t)~IDCELL_FLAG_AUTH;
    eq(idcell_frame_encode(&f, wire, sizeof(wire), &used), IDCELL_FRAME_OK, "encode no-tag sensitive variant");
    channel_inject(&s.host_to_dev, wire, used); idcell_node_poll(s.dev, ++s.now);
    eq(s.state.set_calls, base, "no-tag WRITE rejected before handler");

    f.flags |= IDCELL_FLAG_AUTH;
    idcell_did_generate(0x9999, &f.src);
    eq(idcell_frame_encode_auth(&f, s.host->peers[0].active_key.key, 32, wire, sizeof(wire), &used),
       IDCELL_FRAME_OK, "encode unknown-SRC variant");
    channel_inject(&s.host_to_dev, wire, used); idcell_node_poll(s.dev, ++s.now);
    eq(s.state.set_calls, base, "missing per-peer key rejected without creating peer or side effect");

    channel_inject(&s.host_to_dev, original, len); idcell_node_poll(s.dev, ++s.now);
    eq(s.state.set_calls, base + 1, "original authenticated WRITE still executes exactly once");
    scene_free(&s);
}

static int check_sensitive_class(scene_t *s, uint8_t type)
{
    int e, i, count = 0, bad = 0;
    for (e = 0; e < 2; e++) {
        const endpoint_t *ep = e ? &s->host_ep : &s->dev_ep;
        const idcell_session_key_t *key = e ? &s->host->peers[0].active_key : &s->dev->peers[0].active_key;
        for (i = 0; i < ep->log_count; i++) {
            idcell_frame_t f;
            size_t used;
            const uint8_t *wire = ep->log[i];
            size_t len = ep->log_len[i];
            if (wire[5] != type) continue;
            count++;
            if (!(wire[4] & IDCELL_FLAG_AUTH) ||
                len != IDCELL_HDR_LEN + idcell_get_u16(wire + 10) + 16 + IDCELL_TRAILER_LEN ||
                !key->valid || idcell_frame_decode_auth(wire, len, key->key, 32, &f, &used) != IDCELL_FRAME_OK)
                bad++;
        }
    }
    return count && !bad;
}

static void test_sensitive_frame_classes(void)
{
    scene_t s;
    idcell_contract_t c;
    double read_value = 0.0;
    int i, e, k, key_on_wire = 0;
    printf("[all sensitive frame classes]\n");
    scene_init(&s); ok(scene_bind(&s), "bind frame-class scene");
    idcell_node_get_contract(s.host, &s.dev_did, &c);
    s.host->peers[0].pts[0].value_valid = 0;
    (void)idcell_node_read(s.host, &s.dev_did, 0x0200, 0, &read_value);
    eq(idcell_node_write(s.host, 0x0200, 0, 23, c.owner_token, "security-ok"), IDCELL_OK,
       "issue DONE-producing write");
    for (i = 0; i < 4; i++) scene_step(&s);
    eq(idcell_node_write(s.host, 0x0200, 0, 999, c.owner_token, "security-range"), IDCELL_OK,
       "issue ERROR-producing write");
    for (i = 0; i < 4; i++) scene_step(&s);
    eq(idcell_node_renegotiate(s.host, &s.dev_did), IDCELL_OK, "issue authenticated RENEGOTIATE");
    ok(check_sensitive_class(&s, IDCELL_FT_RENEGOTIATE), "RENEGOTIATE uses valid FLAGS.AUTH and 16B tag");
    ok(check_sensitive_class(&s, IDCELL_FT_READ), "READ request/response use valid authentication");
    ok(check_sensitive_class(&s, IDCELL_FT_WRITE), "WRITE uses valid authentication");
    ok(check_sensitive_class(&s, IDCELL_FT_DONE), "DONE uses valid authentication");
    ok(check_sensitive_class(&s, IDCELL_FT_ERROR), "ERROR uses valid authentication");
    ok(check_sensitive_class(&s, IDCELL_FT_EVENT), "EVENT uses valid authentication");
    ok(check_sensitive_class(&s, IDCELL_FT_HEARTBEAT), "authorized HEARTBEAT uses valid authentication");
    for (e = 0; e < 2; e++) {
        const endpoint_t *ep = e ? &s.host_ep : &s.dev_ep;
        const idcell_session_key_t *key = e ? &s.host->peers[0].active_key : &s.dev->peers[0].active_key;
        for (i = 0; i < ep->log_count; i++) {
            if ((ep->log[i][5] == IDCELL_FT_DISCOVER || ep->log[i][5] == IDCELL_FT_HELLO ||
                 ep->log[i][5] == IDCELL_FT_MATCH || ep->log[i][5] == IDCELL_FT_NEGOTIATE ||
                 ep->log[i][5] == IDCELL_FT_AUTH) && (ep->log[i][4] & IDCELL_FLAG_AUTH))
                key_on_wire = 1;
            for (k = 0; k + 32 <= (int)ep->log_len[i]; k++)
                if (memcmp(ep->log[i] + k, key->key, 32) == 0) key_on_wire = 1;
        }
    }
    ok(!key_on_wire, "public frames stay untagged and raw session key never appears on wire");
    scene_free(&s);
}

static void test_replay_restore_and_relay(void)
{
    scene_t s;
    idcell_frame_t f;
    idcell_snapshot_t snap;
    uint8_t original[IDCELL_MAX_FRAME], second[IDCELL_MAX_FRAME], relayed[IDCELL_MAX_FRAME];
    size_t len = 0, len2 = 0;
    uint64_t old_session;
    int base;
    printf("[old-key replay/restore/raw relay]\n");
    scene_init(&s); ok(scene_bind(&s), "bind replay scene");
    old_session = s.host->peers[0].contract.session_id;
    ok(make_write(&s, &f, 25, 700), "build old-session command");
    eq(idcell_frame_encode_auth(&f, s.host->peers[0].active_key.key, 32, original, sizeof(original), &len),
       IDCELL_FRAME_OK, "sign old-session command without delivering it");
    eq(idcell_node_renegotiate(s.host, &s.dev_did), IDCELL_OK, "start reauthorization");
    eq(idcell_node_release(s.host, &s.dev_did), IDCELL_OK, "release old executor before recommit");
    ok(scene_rebind(&s, old_session), "new session activates on both ends");
    ok(old_session != s.host->peers[0].contract.session_id, "session id really rotated");
    base = s.state.set_calls;
    channel_inject(&s.host_to_dev, original, len); idcell_node_poll(s.dev, ++s.now);
    eq(s.state.set_calls, base, "late old-key frame rejected after rotation");

    eq(idcell_node_snapshot(s.dev, &snap), IDCELL_OK, "snapshot restart floors");
    eq(idcell_node_restore(s.dev, &snap), IDCELL_OK, "restore clears live security state");
    ok(!s.dev->peers[0].used && !s.dev->peers[0].active_key.valid &&
       !s.dev->peers[0].bind_key.valid && !s.dev->peers[0].next_key.valid,
       "restart/restore erases every per-peer key slot");
    channel_inject(&s.host_to_dev, original, len); idcell_node_poll(s.dev, ++s.now);
    eq(s.state.set_calls, base, "restored node rejects pre-restart key");

    scene_free(&s); scene_init(&s); ok(scene_bind(&s), "bind raw-relay scene");
    ok(make_write(&s, &f, 26, 701), "build relayed command");
    eq(idcell_frame_encode_auth(&f, s.host->peers[0].active_key.key, 32, original, sizeof(original), &len),
       IDCELL_FRAME_OK, "sign relayed command");
    ok(make_write(&s, &f, 27, 702), "build second relayed command");
    eq(idcell_frame_encode_auth(&f, s.host->peers[0].active_key.key, 32, second, sizeof(second), &len2),
       IDCELL_FRAME_OK, "sign second relayed command");
    {
        channel_t input, output;
        endpoint_t ep;
        idcell_node_t *relay;
        idcell_node_cfg_t cfg;
        idcell_transport_t tr;
        memset(&input, 0, sizeof(input)); memset(&output, 0, sizeof(output)); memset(&ep, 0, sizeof(ep));
        ep.in = &input; ep.out = &output; ep.profile.media = IDCELL_MEDIA_LOOPBACK;
        ep.profile.topology = IDCELL_TOPO_SWITCHED;
        memset(&cfg, 0, sizeof(cfg)); idcell_did_generate(0x7777, &cfg.did);
        cfg.announce_ms = 60000;
        relay = idcell_node_new(&cfg);
        tr.send = ep_send; tr.recv = ep_recv; tr.profile = &ep.profile; tr.ctx = &ep;
        idcell_node_set_transport(relay, &tr);
        relay->announce_started = 1; relay->next_discover_ms = 60000;
        channel_inject(&input, original, len);
        idcell_node_poll(relay, 0);
        ok(output.len == len && memcmp(output.data, original, len) == 0,
           "keyless relay forwards exact original authenticated bytes");
        eq(idcell_node_peer_count(relay), 0, "raw relay creates no peer session state");
        memcpy(relayed, output.data, len);
        channel_inject(&s.host_to_dev, relayed, len);
        base = s.state.set_calls; idcell_node_poll(s.dev, ++s.now);
        eq(s.state.set_calls, base + 1, "untouched relayed frame accepted by final receiver");

        second[IDCELL_HDR_LEN + 6] ^= 1;
        idcell_put_u16(second + len2 - 4, idcell_crc16(second, len2 - 4));
        input.len = output.len = 0; ep.log_count = 0;
        channel_inject(&input, second, len2); idcell_node_poll(relay, 1);
        ok(output.len == len2 && memcmp(output.data, second, len2) == 0,
           "relay preserves even end-to-end tampered bytes verbatim");
        channel_inject(&s.host_to_dev, output.data, output.len);
        idcell_node_poll(s.dev, ++s.now);
        eq(s.state.set_calls, base + 1, "final receiver rejects relayed tamper before side effect");
        idcell_node_free(relay);
    }
    scene_free(&s);
}

static void test_replay_heartbeat_window(void)
{
    scene_t s;
    idcell_frame_t f;
    uint8_t wire[IDCELL_MAX_FRAME];
    size_t len;
    uint32_t lease, grant;
    printf("[HEARTBEAT replay/window]\n");
    scene_init(&s); ok(scene_bind(&s), "bind heartbeat replay scene");
    s.host_to_dev.len = 0; /* 隔离绑定完成后残留的周期帧，仅注入本组线上字节。 */
    s.dev->rx_len = 0;
    ok(make_heartbeat(&s, 1, &f, 100, wire, &len), "sign heartbeat seq100");
    channel_inject(&s.host_to_dev, wire, len); s.now += 10; idcell_node_poll(s.dev, s.now);
    lease = s.dev->peers[0].lease_deadline_ms; grant = s.dev->grants[0].deadline_ms;
    channel_inject(&s.host_to_dev, wire, len); s.now += 10; idcell_node_poll(s.dev, s.now);
    eq((int)s.dev->peers[0].lease_deadline_ms, (int)lease, "duplicate HEARTBEAT does not renew peer lease");
    eq((int)s.dev->grants[0].deadline_ms, (int)grant, "duplicate HEARTBEAT does not extend active grant");

    ok(make_heartbeat(&s, 1, &f, 102, wire, &len), "sign newer heartbeat seq102");
    channel_inject(&s.host_to_dev, wire, len); s.now += 10; idcell_node_poll(s.dev, s.now);
    lease = s.dev->peers[0].lease_deadline_ms;
    ok(make_heartbeat(&s, 1, &f, 101, wire, &len), "sign out-of-order heartbeat seq101");
    channel_inject(&s.host_to_dev, wire, len); s.now += 10; idcell_node_poll(s.dev, s.now);
    ok(s.dev->peers[0].lease_deadline_ms > lease, "in-window older frame is accepted after newer frame");

    ok(make_heartbeat(&s, 1, &f, 38, wire, &len), "sign 64-old heartbeat");
    lease = s.dev->peers[0].lease_deadline_ms;
    channel_inject(&s.host_to_dev, wire, len); s.now += 10; idcell_node_poll(s.dev, s.now);
    eq((int)s.dev->peers[0].lease_deadline_ms, (int)lease, "64-old HEARTBEAT rejected before lease renewal");
    ok(make_heartbeat(&s, 1, &f, 39, wire, &len), "sign 63-old heartbeat");
    channel_inject(&s.host_to_dev, wire, len); s.now += 10; idcell_node_poll(s.dev, s.now);
    ok(s.dev->peers[0].lease_deadline_ms > lease, "63-old frame accepted while 64-old was rejected");
    eq(s.dev->peers[0].active_key.rx_max_seq, 102, "older frames do not move max_seq backwards");
    scene_free(&s);
}

static void test_replay_u16_wrap(void)
{
    static const uint16_t seqs[] = {65534, 65535, 0, 65533, 1, 65473, 65474, 0};
    static const int accept[] = {1, 1, 1, 1, 1, 0, 1, 0};
    scene_t s;
    idcell_frame_t f;
    uint8_t wire[IDCELL_MAX_FRAME];
    size_t len;
    uint32_t previous;
    int i;
    printf("[u16 serial wrap]\n");
    scene_init(&s); ok(scene_bind(&s), "bind serial-wrap scene");
    s.host_to_dev.len = 0;
    s.dev->rx_len = 0;
    s.dev->peers[0].active_key.rx_window_valid = 0;
    s.dev->peers[0].active_key.rx_window = 0;
    for (i = 0; i < 8; i++) {
        char name[80];
        ok(make_heartbeat(&s, 1, &f, seqs[i], wire, &len), "build wrap heartbeat vector");
        snprintf(name, sizeof(name), "serial vector seq=%u accept=%d", seqs[i], accept[i]);
        previous = s.dev->peers[0].lease_deadline_ms;
        channel_inject(&s.host_to_dev, wire, len); s.now += 10; idcell_node_poll(s.dev, s.now);
        ok((s.dev->peers[0].lease_deadline_ms > previous) == accept[i], name);
    }
    eq(s.dev->peers[0].active_key.rx_max_seq, 1, "wrap max_seq follows 0/1 rather than numeric maximum");
    ok(s.dev->peers[0].active_key.rx_window == 0x800000000000001FULL,
       "wrap bitmap retains in-window older entries and rejects age64");
    scene_free(&s);
}

static void test_event_replay_and_session_isolation(void)
{
    scene_t s;
    idcell_frame_t f;
    uint8_t newer[IDCELL_MAX_FRAME], older[IDCELL_MAX_FRAME];
    size_t newer_len, older_len;
    uint64_t old_session;
    int base;
    printf("[EVENT replay/session isolation]\n");
    scene_init(&s); ok(scene_bind(&s), "bind event replay scene");
    s.dev_to_host.len = 0;
    s.host->rx_len = 0;
    base = s.data_calls;
    ok(make_event(&s, &f, 999, 99.0, older, &older_len), "sign original EVENT seq999");
    channel_inject(&s.dev_to_host, older, older_len); s.now += 10; idcell_node_poll(s.host, s.now);
    eq(s.data_calls, base + 1, "original EVENT delivered once");
    ok(make_event(&s, &f, 1000, 30.0, newer, &newer_len), "sign newer EVENT seq1000");
    channel_inject(&s.dev_to_host, newer, newer_len); s.now += 10; idcell_node_poll(s.host, s.now);
    eq(s.data_calls, base + 2, "newer EVENT is also accepted");
    channel_inject(&s.dev_to_host, older, older_len); s.now += 10; idcell_node_poll(s.host, s.now);
    eq(s.data_calls, base + 2, "replayed old EVENT cannot repeat data_fn after newer EVENT");
    ok(s.last_data == 30.0 && s.host->peers[0].pts[0].last_value == 30.0,
       "replayed old EVENT cannot overwrite newer value cache");

    old_session = s.host->peers[0].contract.session_id;
    eq(idcell_node_renegotiate(s.host, &s.dev_did), IDCELL_OK, "rotate event session");
    eq(idcell_node_release(s.host, &s.dev_did), IDCELL_OK, "release event executor");
    ok(scene_rebind(&s, old_session), "new event session active");
    s.dev_to_host.len = 0;
    s.host->rx_len = 0;
    base = s.data_calls;
    ok(make_event(&s, &f, 1000, 42.0, newer, &newer_len), "same SEQ accepted with new session key");
    channel_inject(&s.dev_to_host, newer, newer_len); s.now += 10; idcell_node_poll(s.host, s.now);
    eq(s.data_calls, base + 1, "new session window is independent of old session");
    channel_inject(&s.dev_to_host, older, older_len); s.now += 10; idcell_node_poll(s.host, s.now);
    eq(s.data_calls, base + 1, "old session EVENT replay remains rejected");
    scene_free(&s);
}

static int drive_commit_sent(scene_t *s)
{
    uint8_t wire[IDCELL_MAX_FRAME];
    size_t len;
    if (!drive_prepared(s)) return 0;
    if (!channel_extract(&s->dev_to_host, IDCELL_FT_BIND, wire, &len)) return 0;
    channel_inject(&s->dev_to_host, wire, len);
    idcell_node_poll(s->host, s->now);
    return s->host->peers[0].bind_phase == IDCELL_BIND_COMMIT_SENT;
}

static void test_commit_retry(void)
{
    scene_t s;
    idcell_contract_t c;
    uint8_t first[IDCELL_MAX_FRAME], retry[IDCELL_MAX_FRAME], committed[IDCELL_MAX_FRAME];
    size_t first_len, retry_len = 0, committed_len;
    uint16_t first_seq, retry_seq = 0;
    int i, found = 0;
    printf("[lost COMMIT retry with new SEQ]\n");
    scene_init(&s); ok(drive_commit_sent(&s), "first COMMIT produced");
    ok(channel_extract(&s.host_to_dev, IDCELL_FT_BIND, first, &first_len), "drop first COMMIT");
    first_seq = idcell_get_u16(first + 6);
    eq(idcell_node_get_contract(s.dev, &s.host_did, &c), IDCELL_E_NODEV, "dropped COMMIT leaves provider inactive");
    for (i = 0; i < 200 && !found; i++) {
        s.now += 10; idcell_node_poll(s.host, s.now);
        if (channel_extract(&s.host_to_dev, IDCELL_FT_BIND, retry, &retry_len)) {
            retry_seq = idcell_get_u16(retry + 6);
            found = retry_seq != first_seq;
        }
    }
    ok(found, "retry COMMIT uses a fresh SEQ");
    channel_inject(&s.host_to_dev, retry, retry_len); idcell_node_poll(s.dev, ++s.now);
    ok(channel_extract(&s.dev_to_host, IDCELL_FT_BIND, committed, &committed_len), "provider accepts retried COMMIT");
    channel_inject(&s.dev_to_host, committed, committed_len); idcell_node_poll(s.host, s.now);
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_OK, "fresh-SEQ COMMIT retry completes binding");
    scene_free(&s);
}

static void test_committed_retry(void)
{
    scene_t s;
    idcell_contract_t c;
    uint8_t commit[IDCELL_MAX_FRAME], first[IDCELL_MAX_FRAME], retry[IDCELL_MAX_FRAME];
    size_t commit_len, first_len, retry_len = 0;
    uint16_t first_seq, retry_seq = 0;
    int i, found = 0;
    printf("[lost COMMITTED retry with new SEQ]\n");
    scene_init(&s); ok(drive_commit_sent(&s), "COMMIT ready for COMMITTED loss");
    ok(channel_extract(&s.host_to_dev, IDCELL_FT_BIND, commit, &commit_len), "deliver initial COMMIT");
    channel_inject(&s.host_to_dev, commit, commit_len); idcell_node_poll(s.dev, ++s.now);
    ok(channel_extract(&s.dev_to_host, IDCELL_FT_BIND, first, &first_len), "drop first COMMITTED");
    first_seq = idcell_get_u16(first + 6);
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_E_NODEV, "dropped COMMITTED leaves consumer inactive");
    for (i = 0; i < 250 && !found; i++) {
        s.now += 10; idcell_node_poll(s.host, s.now);
        if (channel_extract(&s.host_to_dev, IDCELL_FT_BIND, commit, &commit_len)) {
            channel_inject(&s.host_to_dev, commit, commit_len);
            idcell_node_poll(s.dev, s.now);
            if (channel_extract(&s.dev_to_host, IDCELL_FT_BIND, retry, &retry_len)) {
                retry_seq = idcell_get_u16(retry + 6);
                found = retry_seq != first_seq;
            }
        }
    }
    ok(found, "COMMITTED regenerated by fresh-SEQ COMMIT uses fresh SEQ");
    channel_inject(&s.dev_to_host, retry, retry_len); idcell_node_poll(s.host, s.now);
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_OK, "fresh-SEQ COMMITTED completes binding");
    scene_free(&s);
}

static void test_kdf_domain_separation(void)
{
    uint8_t cred[IDCELL_CRED_LEN], nonce[16], a[32], b[32], c[32];
    idcell_did_t da, db, dc;
    int i;
    printf("[KDF domain separation]\n");
    for (i = 0; i < IDCELL_CRED_LEN; i++) cred[i] = (uint8_t)i;
    for (i = 0; i < 16; i++) nonce[i] = (uint8_t)(0xA0 + i);
    idcell_did_from_vendor(0x0102, 0x030405060708ULL, &da);
    idcell_did_from_vendor(0x1112, 0x131415161718ULL, &db);
    idcell_did_from_vendor(0x2122, 0x232425262728ULL, &dc);
    idcell_session_key_derive(cred, nonce, &da, &db, 0x1234, 0x89ABCDEF,
                              0x0102030405060708ULL, a);
    idcell_session_key_derive(cred, nonce, &db, &da, 0x1234, 0x89ABCDEF,
                              0x0102030405060708ULL, b);
    ok(memcmp(a, b, 32) == 0, "DID order normalization gives both ends same key");
    idcell_session_key_derive(cred, nonce, &da, &db, 0x1234, 0x89ABCDEF,
                              0x0102030405060709ULL, b);
    idcell_session_key_derive(cred, nonce, &da, &dc, 0x1234, 0x89ABCDEF,
                              0x0102030405060708ULL, c);
    ok(memcmp(a, b, 32) != 0 && memcmp(a, c, 32) != 0 && memcmp(b, c, 32) != 0,
       "different session or peer produces different key");
    ok(memcmp(a, cred, 32) != 0, "KDF never aliases cred as session key");
}

static void print_hex(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) printf("%02X", p[i]);
}

static int vector_kdf(void)
{
    uint8_t cred[IDCELL_CRED_LEN], nonce[16], key[32], rotated[32], other[32], id[32];
    uint8_t msg[sizeof("IDCELL-KEY-ID-V1") - 1 + 8];
    idcell_did_t a, b, c;
    idcell_capability_t cap;
    uint8_t inner[IDCELL_MAX_PAYLOAD], canonical[IDCELL_MAX_PAYLOAD], digest[32];
    uint16_t pos = 0;
    int i, len;
    for (i = 0; i < IDCELL_CRED_LEN; i++) cred[i] = (uint8_t)i;
    for (i = 0; i < 16; i++) nonce[i] = (uint8_t)(0xA0 + i);
    idcell_did_from_vendor(0x0102, 0x030405060708ULL, &a);
    idcell_did_from_vendor(0x1112, 0x131415161718ULL, &b);
    idcell_did_from_vendor(0x2122, 0x232425262728ULL, &c);
    idcell_session_key_derive(cred, nonce, &a, &b, 0x1234, 0, 0, key);
    idcell_session_key_derive(cred, nonce, &a, &b, 0x1234, 0x89ABCDEF,
                              0x0102030405060708ULL, rotated);
    idcell_session_key_derive(cred, nonce, &a, &c, 0x1234, 0x89ABCDEF,
                              0x0102030405060708ULL, other);
    memcpy(msg, "IDCELL-KEY-ID-V1", sizeof("IDCELL-KEY-ID-V1") - 1);
    idcell_put_u64(msg + sizeof("IDCELL-KEY-ID-V1") - 1, 0x0102030405060708ULL);
    idcell_hmac_sha256(rotated, 32, msg, sizeof(msg), id);
    printf("key="); print_hex(key, 32); printf(" rotated="); print_hex(rotated, 32);
    printf(" other="); print_hex(other, 32); printf(" key_id="); print_hex(id, 16);
    fill_cap(&cap);
    len = idcell_public_desc_encode(&cap, inner, sizeof(inner));
    idcell_tlv_put(canonical, sizeof(canonical), &pos, cap.index, cap.sub,
                   IDCELL_TLV_CAP_DESC, inner, (uint16_t)len);
    idcell_descriptor_digest(1, canonical, pos, digest);
    printf(" public_wire="); print_hex(canonical, pos); printf(" public="); print_hex(digest, 32);
    pos = 0; len = idcell_desc_encode(&cap, inner, sizeof(inner));
    idcell_tlv_put(canonical, sizeof(canonical), &pos, cap.index, cap.sub,
                   IDCELL_TLV_CAP_DESC, inner, (uint16_t)len);
    idcell_descriptor_digest(0, canonical, pos, digest);
    printf(" authorized_wire="); print_hex(canonical, pos); printf(" authorized="); print_hex(digest, 32);
    printf("\n");
    return 1;
}

static int vector_wire(void)
{
    uint8_t cred[IDCELL_CRED_LEN], nonce[16], key[32], wrong[32], mac[32];
    uint8_t wire[IDCELL_MAX_FRAME], tampered[IDCELL_MAX_FRAME];
    idcell_did_t a, b;
    idcell_frame_t f, out;
    size_t len = 0, consumed = 0;
    int i, valid, wrong_rc, tamper_rc;
    for (i = 0; i < IDCELL_CRED_LEN; i++) cred[i] = (uint8_t)i;
    for (i = 0; i < 16; i++) nonce[i] = (uint8_t)(0xA0 + i);
    idcell_did_from_vendor(0x0102, 0x030405060708ULL, &a);
    idcell_did_from_vendor(0x1112, 0x131415161718ULL, &b);
    idcell_session_key_derive(cred, nonce, &a, &b, 0x1234, 0x89ABCDEF,
                              0x0102030405060708ULL, key);
    memset(&f, 0, sizeof(f));
    f.ver = IDCELL_PROTO_VER_BYTE; f.type = IDCELL_FT_READ; f.flags = IDCELL_FLAG_AUTH;
    f.seq = 0x2345; f.txn = 0x3456; f.src = a; f.dst = b; f.group = 0x4567;
    f.ts_us = 0xABCDEF010203ULL;
    for (i = 0; i < 24; i++) f.payload[i] = (uint8_t)(i * 7);
    f.payload_len = 24;
    idcell_frame_encode_auth(&f, key, 32, wire, sizeof(wire), &len);
    valid = idcell_frame_decode_auth(wire, len, key, 32, &out, &consumed);
    memset(wrong, 0xA5, sizeof(wrong));
    wrong_rc = idcell_frame_decode_auth(wire, len, wrong, 32, &out, &consumed);
    memcpy(tampered, wire, len); tampered[IDCELL_HDR_LEN] ^= 1;
    idcell_put_u16(tampered + len - 4, idcell_crc16(tampered, len - 4));
    tamper_rc = idcell_frame_decode_auth(tampered, len, key, 32, &out, &consumed);
    idcell_hmac_sha256(key, 32, wire, IDCELL_HDR_LEN + f.payload_len, mac);
    printf("wire="); print_hex(wire, len); printf(" tag="); print_hex(mac, 16);
    printf(" valid=%d wrong=%d tamper=%d\n", valid, wrong_rc, tamper_rc);
    return 1;
}

static void replay_run(const uint16_t *seq, int count, idcell_session_key_t *key,
                       char *accepted, uint16_t *max_seq, uint64_t *bitmap)
{
    int i;
    for (i = 0; i < count; i++) accepted[i] = idcell_replay_accept(key, seq[i]) ? '1' : '0';
    accepted[count] = '\0';
    *max_seq = key->rx_max_seq;
    *bitmap = key->rx_window;
}

static int vector_replay(void)
{
    static const uint16_t a[] = {100, 101, 99, 99, 38, 37, 102};
    static const uint16_t b[] = {65534, 65535, 0, 65533, 1, 65473, 65474, 0};
    static const uint16_t c[] = {0, 32768, 32767};
    idcell_session_key_t key;
    char accepted[16];
    uint16_t max_seq;
    uint64_t bitmap;
    memset(&key, 0, sizeof(key)); key.valid = 1;
    replay_run(a, 7, &key, accepted, &max_seq, &bitmap);
    printf("a=%s amax=%u abits=%llX ", accepted, max_seq, (unsigned long long)bitmap);
    memset(&key, 0, sizeof(key)); key.valid = 1;
    replay_run(b, 8, &key, accepted, &max_seq, &bitmap);
    printf("b=%s bmax=%u bbits=%llX ", accepted, max_seq, (unsigned long long)bitmap);
    memset(&key, 0, sizeof(key)); key.valid = 1;
    replay_run(c, 3, &key, accepted, &max_seq, &bitmap);
    printf("c=%s cmax=%u cbits=%llX ", accepted, max_seq, (unsigned long long)bitmap);
    memset(&key, 0, sizeof(key)); key.valid = 1;
    printf("reset=%d\n", idcell_replay_accept(&key, 100));
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--vector") == 0) {
        if (strcmp(argv[2], "kdf") == 0) return vector_kdf() ? 0 : 2;
        if (strcmp(argv[2], "wire") == 0) return vector_wire() ? 0 : 2;
        if (strcmp(argv[2], "replay") == 0) return vector_replay() ? 0 : 2;
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    test_public_hello();
    test_prepared_rejection(0);
    test_prepared_rejection(1);
    test_key_rotation_and_authenticated_runtime();
    test_sensitive_rejection();
    test_sensitive_frame_classes();
    test_replay_restore_and_relay();
    test_replay_heartbeat_window();
    test_replay_u16_wrap();
    test_event_replay_and_session_isolation();
    test_commit_retry();
    test_committed_retry();
    test_kdf_domain_separation();
    printf("SUMMARY pass=%d fail=%d\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
