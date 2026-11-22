package ng.onshore;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Onshore client for Java 17+, with no dependencies. Handles token refresh,
 * batching and retries. Reveals fail closed: when the vault cannot answer they
 * throw, and never return a token as if it were the value. Safe to share across threads.
 */
public final class VaultClient {
    /** An API error. It never holds a sensitive value. */
    public static final class VaultException extends RuntimeException {
        public final int status;
        public final String code;
        /** The access rule that refused, when one did. */
        public final String policy;
        /** Identifies the call in the audit log. */
        public final String requestId;

        public VaultException(int status, String code, String message) {
            this(status, code, message, null, null);
        }

        public VaultException(int status, String code, String message, String policy, String requestId) {
            super(code + ": " + message);
            this.status = status;
            this.code = code;
            this.policy = policy;
            this.requestId = requestId;
        }
    }

    /** One value to store. {@code subjectRef} may be null. */
    public record Item(String field, String value, String subjectRef) {
        public Item(String field, String value) { this(field, value, null); }
    }

    /** Why one item in a batch failed, with continueOnError. */
    public record ItemError(String code, String message, String policy) {}

    /** One stored value. {@code token} is null on error or in a dry run. */
    public record TokenResult(int index, String token, boolean existing, ItemError error) {}

    /** One token to reveal. {@code redaction} ("masked" or "token_only") may be null. */
    public record RevealItem(String token, String redaction) {
        public RevealItem(String token) { this(token, null); }
    }

    /** One revealed value. {@code value} is null when denied; {@code errorCode} is set when the item failed. */
    public record Reveal(int index, String decision, String value, String policy, String errorCode) {}

    public record StoredRecord(String id, Map<String, String> tokens) {}

    public record Subject(String id, String ref, int fieldCount, String createdAt, String lastAccessed, int reveals30d, boolean restricted) {}

    public record SubjectField(String field, String dataType, String token, String masked, String decision, String recordId) {}

    public record SubjectDetail(Subject subject, List<SubjectField> fields) {}

    public record SubjectPage(List<Subject> subjects, int total) {}

    public record ExportedField(String field, String dataType, String value, String token, String decision) {}

    public record Entity(String type, int start, int end, double score, boolean custom, int entityVersion, boolean shadow) {}

    public record Detection(List<Entity> entities, String text, int rulesetVersion) {}

    public record FlowReport(int identifiers, int tokens, boolean clean, Map<String, Integer> byType) {}

    /** A single-use token for a secure component. */
    public record ClientToken(String clientToken, String expiresAt) {}

    /** Fields left null are not sent. {@code ttlSeconds} of 0 means the default (120). */
    public record ClientTokenRequest(String kind, String origin, List<String> fields, List<String> tokens, String purpose,
                                     String onBehalfOf, String subjectRef, String bindIp, int ttlSeconds) {
        public static ClientTokenRequest collect(String origin, List<String> fields, String subjectRef) {
            return new ClientTokenRequest("collect", origin, fields, null, null, null, subjectRef, null, 0);
        }

        public static ClientTokenRequest reveal(String origin, List<String> tokens, String purpose, String onBehalfOf) {
            return new ClientTokenRequest("reveal", origin, null, tokens, purpose, onBehalfOf, null, null, 0);
        }

        public ClientTokenRequest withBindIp(String ip) {
            return new ClientTokenRequest(kind, origin, fields, tokens, purpose, onBehalfOf, subjectRef, ip, ttlSeconds);
        }

        public ClientTokenRequest withTtlSeconds(int ttl) {
            return new ClientTokenRequest(kind, origin, fields, tokens, purpose, onBehalfOf, subjectRef, bindIp, ttl);
        }
    }

    public record Cloaked(String text, Map<String, Integer> changed, String id) {}

    public record Uncloaked(String text, Map<String, String> decisions) {}

    private static final int BATCH = 500;
    private final String baseUrl, serviceAccountId, keyId;
    private final PrivateKey key;
    private final HttpClient http;
    private final int maxAttempts;
    private final Duration timeout;
    private String token;
    private long expiry;

    /** Four attempts, 10-second timeout. Pass null for {@code http} to use a default client. */
    public VaultClient(String baseUrl, String serviceAccountId, String keyId, String seedB64, HttpClient http) throws Exception {
        this(baseUrl, serviceAccountId, keyId, seedB64, http, 4, Duration.ofSeconds(10));
    }

    public VaultClient(String baseUrl, String serviceAccountId, String keyId, String seedB64, HttpClient http, int maxAttempts, Duration timeout) throws Exception {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.serviceAccountId = serviceAccountId;
        this.keyId = keyId;
        byte[] seed = Base64.getDecoder().decode(seedB64);
        if (seed.length != 32) throw new IllegalArgumentException("the private key must be a base64 Ed25519 seed");
        byte[] prefix = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};
        byte[] der = new byte[prefix.length + seed.length];
        System.arraycopy(prefix, 0, der, 0, prefix.length);
        System.arraycopy(seed, 0, der, prefix.length, seed.length);
        this.key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        this.http = http != null ? http : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        this.maxAttempts = Math.max(1, maxAttempts);
        this.timeout = timeout;
    }

    // ---- plumbing ---------------------------------------------------------------

    private static String b64u(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String seg(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private String assertion() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        String head = b64u(Json.write(map("alg", "EdDSA", "typ", "JWT", "kid", keyId)).getBytes(StandardCharsets.UTF_8));
        String body = b64u(Json.write(map("iss", serviceAccountId, "sub", serviceAccountId, "aud", "onshore", "jti", UUID.randomUUID().toString(), "iat", now, "exp", now + 120)).getBytes(StandardCharsets.UTF_8));
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(key);
        sig.update((head + "." + body).getBytes(StandardCharsets.UTF_8));
        return head + "." + body + "." + b64u(sig.sign());
    }

    private synchronized String bearer() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        if (token != null && now < expiry - 60) return token;
        Map<String, Object> r = raw("POST", "/v1/auth/token", map("assertion", assertion()), null, null);
        token = str(r, "access_token");
        expiry = now + num(r, "expires_in");
        return token;
    }

    private synchronized void forget(String used) {
        if (used.equals(token)) token = null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> raw(String method, String path, Object body, String bearer, String purpose) throws Exception {
        VaultException last = null;
        for (int i = 0; i < maxAttempts; i++) {
            if (i > 0) {
                long wait = Math.min(2000, 100L << i);
                Thread.sleep(wait / 2 + ThreadLocalRandom.current().nextLong(wait / 2 + 1));
            }
            HttpRequest.BodyPublisher pub = body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(Json.write(body));
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(timeout).header("Content-Type", "application/json").method(method, pub);
            if (bearer != null) b.header("Authorization", "Bearer " + bearer);
            if (purpose != null) b.header("X-RV-Purpose", purpose);
            HttpResponse<String> resp;
            try {
                resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            } catch (java.io.IOException e) {
                last = new VaultException(0, "network_error", "the vault cannot be reached");
                continue;
            }
            int st = resp.statusCode();
            Object parsed;
            try {
                parsed = Json.parse(resp.body());
            } catch (RuntimeException e) {
                parsed = new LinkedHashMap<String, Object>();
            }
            Map<String, Object> data = parsed instanceof Map ? (Map<String, Object>) parsed : new LinkedHashMap<>();
            if (st < 300) return data;
            Map<String, Object> e = data.get("error") instanceof Map ? (Map<String, Object>) data.get("error") : Map.of();
            String code = str(e, "code");
            VaultException err = new VaultException(st, code != null ? code : "error", String.valueOf(e.getOrDefault("message", "status " + st)), str(e, "policy"), str(data, "request_id"));
            if (st == 401 && bearer != null) {
                forget(bearer);
                throw err;
            }
            if (st == 429 || st >= 500) {
                last = err;
                continue;
            }
            throw err;
        }
        throw last;
    }

    private Map<String, Object> call(String method, String path, Object body) throws Exception {
        return raw(method, path, body, bearer(), null);
    }

    private Map<String, Object> call(String method, String path, Object body, String purpose) throws Exception {
        return raw(method, path, body, bearer(), purpose);
    }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? null : String.valueOf(v);
    }

    private static int num(Map<String, Object> m, String k) {
        return m.get(k) instanceof Number n ? n.intValue() : 0;
    }

    private static boolean bool(Map<String, Object> m, String k) {
        return Boolean.TRUE.equals(m.get(k));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Map<String, Object> m, String k) {
        return m.get(k) instanceof List<?> l ? (List<Map<String, Object>>) l : List.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Map<String, Object> m, String k) {
        return m.get(k) instanceof Map<?, ?> o ? (Map<String, Object>) o : Map.of();
    }

    private static Map<String, Integer> counts(Map<String, Object> m) {
        Map<String, Integer> out = new LinkedHashMap<>();
        m.forEach((k, v) -> out.put(k, v instanceof Number n ? n.intValue() : 0));
        return out;
    }

    private static Reveal reveal(Map<String, Object> o, int offset) {
        Map<String, Object> e = obj(o, "error");
        return new Reveal(num(o, "index") + offset, str(o, "decision"), str(o, "value"), str(o, "policy"), str(e, "code"));
    }

    private static Subject subject(Map<String, Object> o) {
        return new Subject(str(o, "id"), str(o, "ref"), num(o, "field_count"), str(o, "created_at"), str(o, "last_accessed"), num(o, "reveals_30d"), bool(o, "restricted"));
    }

    // ---- tokens -----------------------------------------------------------------

    /** Stores values of one field and returns a token each, batching at 500. The first bad value fails its batch. */
    public List<String> tokenize(String vault, String fieldName, List<String> values) throws Exception {
        List<Item> items = new ArrayList<>(values.size());
        for (String v : values) items.add(new Item(fieldName, v));
        List<String> out = new ArrayList<>();
        for (TokenResult r : tokenize(vault, items, false, false)) out.add(r.token());
        return out;
    }

    /**
     * Stores values, batching at 500. With {@code continueOnError} good items are stored and each bad
     * one gets an error. With {@code dryRun} nothing is stored.
     */
    public List<TokenResult> tokenize(String vault, List<Item> items, boolean continueOnError, boolean dryRun) throws Exception {
        List<TokenResult> out = new ArrayList<>();
        for (int i = 0; i < items.size(); i += BATCH) {
            List<Object> chunk = new ArrayList<>();
            for (Item it : items.subList(i, Math.min(i + BATCH, items.size()))) chunk.add(map("field", it.field(), "value", it.value(), "subject_ref", it.subjectRef()));
            Map<String, Object> r = call("POST", "/v1/vaults/" + vault + "/tokenize", map("items", chunk, "continue_on_error", continueOnError, "dry_run", dryRun));
            for (Map<String, Object> o : list(r, "results")) {
                Map<String, Object> e = obj(o, "error");
                out.add(new TokenResult(num(o, "index") + i, str(o, "token"), bool(o, "existing"), e.isEmpty() ? null : new ItemError(str(e, "code"), str(e, "message"), str(e, "policy"))));
            }
        }
        return out;
    }

    /** Returns values as policy allows. A bad token gets an errorCode instead of failing the call. */
    public List<Reveal> detokenize(String vault, List<String> tokens, String purpose) throws Exception {
        List<RevealItem> items = new ArrayList<>(tokens.size());
        for (String t : tokens) items.add(new RevealItem(t));
        return detokenize(vault, items, purpose, true);
    }

    /** Returns values as policy allows, with per-item redaction. */
    public List<Reveal> detokenize(String vault, List<RevealItem> items, String purpose, boolean continueOnError) throws Exception {
        List<Reveal> out = new ArrayList<>();
        for (int i = 0; i < items.size(); i += BATCH) {
            List<Object> chunk = new ArrayList<>();
            for (RevealItem it : items.subList(i, Math.min(i + BATCH, items.size()))) chunk.add(map("token", it.token(), "redaction", it.redaction()));
            Map<String, Object> r = call("POST", "/v1/vaults/" + vault + "/detokenize", map("items", chunk, "purpose", purpose, "continue_on_error", continueOnError));
            for (Map<String, Object> o : list(r, "results")) out.add(reveal(o, i));
        }
        return out;
    }

    // ---- records ----------------------------------------------------------------

    /** Stores several fields for one person. All are stored or none. {@code subjectRef} may be null. */
    public StoredRecord insertRecord(String vault, Map<String, String> fields, String subjectRef) throws Exception {
        Map<String, Object> r = call("POST", "/v1/vaults/" + vault + "/records", map("fields", fields, "subject_ref", subjectRef));
        Map<String, String> tokens = new LinkedHashMap<>();
        obj(r, "tokens").forEach((k, v) -> tokens.put(k, String.valueOf(v)));
        return new StoredRecord(str(r, "id"), tokens);
    }

    /** Reads every field of a record, each as the access rules allow. */
    @SuppressWarnings("unchecked")
    public Map<String, Reveal> getRecord(String vault, String id, String purpose) throws Exception {
        Map<String, Object> r = call("GET", "/v1/vaults/" + vault + "/records/" + seg(id), null, purpose);
        Map<String, Reveal> out = new LinkedHashMap<>();
        obj(r, "fields").forEach((k, v) -> out.put(k, reveal((Map<String, Object>) v, 0)));
        return out;
    }

    /** Changes the value behind a new-token-each-time (cell) token. The token stays the same. */
    public void updateValue(String vault, String token, String value) throws Exception {
        call("PUT", "/v1/vaults/" + vault + "/tokens/" + seg(token), map("value", value));
    }

    /** Finds a token without revealing a value. Throws token_not_found when there's no match. */
    public String lookup(String vault, String fieldName, String value) throws Exception {
        return str(call("POST", "/v1/vaults/" + vault + "/lookup", map("field", fieldName, "value", value)), "token");
    }

    // ---- people -----------------------------------------------------------------

    /**
     * Lists the people in a vault. Query keys: query, field_type, has_reveals, flagged, created_after,
     * created_before, sort, dir, limit (1 to 200, default 50), offset.
     */
    public SubjectPage searchSubjects(String vault, Map<String, Object> query) throws Exception {
        Map<String, Object> r = call("POST", "/v1/vaults/" + vault + "/subjects/search", query == null ? Map.of() : query);
        List<Subject> out = new ArrayList<>();
        for (Map<String, Object> o : list(r, "subjects")) out.add(subject(o));
        return new SubjectPage(out, num(r, "total"));
    }

    /** One person and their fields, each masked at most. Never returns real values. */
    public SubjectDetail getSubject(String vault, String subjectId) throws Exception {
        Map<String, Object> r = call("GET", "/v1/vaults/" + vault + "/subjects/" + seg(subjectId), null);
        List<SubjectField> fields = new ArrayList<>();
        for (Map<String, Object> f : list(r, "fields")) fields.add(new SubjectField(str(f, "field"), str(f, "data_type"), str(f, "token"), str(f, "masked"), str(f, "decision"), str(f, "record_id")));
        return new SubjectDetail(subject(r), fields);
    }

    /** Exports a person's fields for an access request, as the access rules allow. */
    public List<ExportedField> exportSubject(String vault, String subjectId, String purpose) throws Exception {
        Map<String, Object> r = call("GET", "/v1/vaults/" + vault + "/subjects/" + seg(subjectId) + "/export", null, purpose);
        List<ExportedField> out = new ArrayList<>();
        for (Map<String, Object> f : list(r, "fields")) out.add(new ExportedField(str(f, "field"), str(f, "data_type"), str(f, "value"), str(f, "token"), str(f, "decision")));
        return out;
    }

    /** While restricted, nothing about the person reveals. Returns the new state. */
    public boolean restrictSubject(String vault, String subjectId, boolean restricted, String purpose) throws Exception {
        return bool(call("POST", "/v1/vaults/" + vault + "/subjects/" + seg(subjectId) + "/restrict", map("restricted", restricted, "purpose", purpose)), "restricted");
    }

    /** Erases everything held on a person. Returns how many records went. */
    public int eraseSubject(String vault, String subjectId, String purpose) throws Exception {
        return num(call("DELETE", "/v1/vaults/" + vault + "/subjects/" + seg(subjectId), null, purpose), "erased_records");
    }

    // ---- checks and detection ---------------------------------------------------

    /** Runs a check in the country and returns only true or false. */
    public boolean residentCheck(String vault, String tok, String check, String arg, String purpose) throws Exception {
        return bool(call("POST", "/v1/vaults/" + vault + "/resident/check", map("token", tok, "check", check, "arg", arg, "purpose", purpose)), "result");
    }

    /**
     * Finds identifiers in text. {@code vault} (may be null) applies its packs and your own data types and is
     * required with {@code tokenize}. {@code entities} (may be null) limits the types. Offsets are UTF-8 bytes.
     */
    public Detection detect(String text, String vault, boolean tokenize, List<String> entities, boolean includeShadow) throws Exception {
        Map<String, Object> r = call("POST", "/v1/detect", map("text", text, "vault", vault, "tokenize", tokenize, "entities", entities, "include_shadow", includeShadow));
        List<Entity> out = new ArrayList<>();
        for (Map<String, Object> e : list(r, "entities")) {
            double score = e.get("score") instanceof Number n ? n.doubleValue() : 0;
            out.add(new Entity(str(e, "type"), num(e, "start"), num(e, "end"), score, bool(e, "custom"), num(e, "entity_version"), bool(e, "shadow")));
        }
        return new Detection(out, str(r, "text"), num(r, "ruleset_version"));
    }

    /** Reports what a batch holds before a job sends it on. Only counts are kept. */
    public FlowReport checkFlow(String vault, String flow, String text) throws Exception {
        Map<String, Object> r = call("POST", "/v1/vaults/" + vault + "/flows/" + seg(flow) + "/check", map("text", text));
        return new FlowReport(num(r, "identifiers"), num(r, "tokens"), bool(r, "clean"), counts(obj(r, "by_type")));
    }

    // ---- secure components ------------------------------------------------------

    /** Mints a single-use token for a collect or reveal component. Call from your server only. */
    public ClientToken createClientToken(String vault, ClientTokenRequest req) throws Exception {
        Map<String, Object> r = call("POST", "/v1/vaults/" + vault + "/client-tokens", map(
                "kind", req.kind(), "origin", req.origin(), "fields", req.fields(), "tokens", req.tokens(), "purpose", req.purpose(),
                "on_behalf_of", req.onBehalfOf(), "subject_ref", req.subjectRef(), "bind_ip", req.bindIp(),
                "ttl_seconds", req.ttlSeconds() > 0 ? req.ttlSeconds() : null));
        return new ClientToken(str(r, "client_token"), str(r, "expires_at"));
    }

    // ---- cloaking ---------------------------------------------------------------

    /**
     * Cloaks text before it goes to an AI model or outside service. Send {@code profileId} or
     * {@code options}, not both (either may be null). {@code keepDays} above 0 keeps a digital twin.
     */
    public Cloaked cloak(String vault, String text, String profileId, Map<String, String> options, int keepDays) throws Exception {
        Map<String, Object> r = call("POST", "/v1/vaults/" + vault + "/cloak", map("text", text, "profile_id", profileId, "options", options, "keep_days", keepDays > 0 ? keepDays : null));
        return new Cloaked(str(r, "text"), counts(obj(r, "changed")), str(r, "id"));
    }

    /** Restores placeholders in text, as far as the access rules allow. */
    public Uncloaked uncloak(String vault, String twinId, String text, String purpose) throws Exception {
        Map<String, Object> r = call("POST", "/v1/vaults/" + vault + "/uncloak", map("id", twinId, "text", text, "purpose", purpose));
        Map<String, String> d = new LinkedHashMap<>();
        obj(r, "decisions").forEach((k, v) -> d.put(k, String.valueOf(v)));
        return new Uncloaked(str(r, "text"), d);
    }

    /** Deletes a digital twin before it expires. */
    public void deleteTwin(String vault, String twinId) throws Exception {
        call("DELETE", "/v1/vaults/" + vault + "/twins/" + seg(twinId), null);
    }

    // ---- webhooks ---------------------------------------------------------------

    /**
     * Checks a webhook from Onshore. Pass the body bytes exactly as received and the X-Rv-Signature
     * header. During a secret rotation either of two signatures is enough. {@code tolerance} null means 5 minutes.
     */
    public static boolean verifyWebhook(String secret, byte[] rawBody, String signatureHeader, Duration tolerance) {
        return verifyWebhook(secret, rawBody, signatureHeader, tolerance, System.currentTimeMillis() / 1000);
    }

    static boolean verifyWebhook(String secret, byte[] rawBody, String header, Duration tolerance, long now) {
        if (header == null) return false;
        long at = -1;
        List<String> sigs = new ArrayList<>();
        for (String part : header.split(",")) {
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            String k = part.substring(0, eq).trim(), v = part.substring(eq + 1).trim();
            if (k.equals("t")) {
                try { at = Long.parseLong(v); } catch (NumberFormatException e) { return false; }
            } else if (k.equals("v1")) sigs.add(v);
        }
        long tol = tolerance == null ? 300 : tolerance.toSeconds();
        if (at < 0 || Math.abs(now - at) > tol) return false;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update((at + ".").getBytes(StandardCharsets.UTF_8));
            byte[] want = mac.doFinal(rawBody);
            boolean ok = false;
            for (String s : sigs) {
                try {
                    ok |= MessageDigest.isEqual(HexFormat.of().parseHex(s), want);
                } catch (IllegalArgumentException ignored) {
                    // not hex
                }
            }
            return ok;
        } catch (Exception e) {
            return false;
        }
    }
}
