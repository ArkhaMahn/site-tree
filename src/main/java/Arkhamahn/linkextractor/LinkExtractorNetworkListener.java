package Arkhamahn.linkextractor;

import java.awt.EventQueue;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteMapEventPublisher;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.network.HttpSenderListener;

/**
 * Network-layer Burp-style link extraction for the Site tree.
 *
 * <p>Hooks the network layer via {@link HttpSenderListener} so that every response ZAP receives
 * (proxied browsing, spider, AJAX spider, active scan, manual requests) is inspected the moment it
 * arrives - on the request/proxy thread, before the message is saved to history - with no dependency
 * on the passive scan queue or any scan rule priority. If the source URL is in the session scope,
 * the add-on fires immediately and populates the Site tree.
 *
 * <p>Ported from {@code burp_style_passive_link_extraction.js} (a ZAP Scripts "Passive Rules" script)
 * into a compiled add-on that runs at the network level. Link discovery (patterns, candidate
 * normalisation, encoded-character decoding, chunking and domain/extension filtering) is ported and
 * adapted from xnLinkFinder ({@code https://github.com/xnl-h4ck3r/xnLinkFinder}).
 *
 * <p>Behaviour:
 * <ul>
 *   <li>The source response itself must belong to an in-scope URL, otherwise nothing is parsed.
 *   <li>Every candidate URL is resolved against the request's base URL and written to the Sites
 *       tree as a predicted entry - no request is ever sent to it. Cross-host candidates are flagged
 *       with a {@code "[NEW SUBDOMAIN]"} prefix on the note.
 *   <li>Every candidate URL needs a {@link HistoryReference} (that is how a Site tree node is
 *       backed), so the entries are written with a Note flagging them as not-yet-requested. The
 *       history <em>type</em> of that reference is what decides whether the entry can ever be listed
 *       in the history tab - see {@link #historyTypeFor(boolean)}.
 *   <li>With the "record in the history tab" option enabled (Tools &gt; Options &gt; Site tree) the
 *       entries use {@link HistoryReference#TYPE_ZAP_USER}, so they are listed in the history tab as
 *       soon as they are discovered. With the option disabled they use
 *       {@link HistoryReference#TYPE_HIDDEN} instead, which ZAP never lists in the history tab -
 *       neither when the entry is added nor when the history view is rebuilt (in-scope toggle, the
 *       history filter, or a session reload). They still show up in the Site tree and are still
 *       saved with the session.
 *   <li>Scope is delegated entirely to ZAP's own session/context scope engine.
 * </ul>
 *
 * <p>Safety (a network-layer hook must never disturb the request/response flow):
 * <ul>
 *   <li>Only cheap gate checks run on the network thread - body size, empty body, content type,
 *       source scope, and the parse-queue depth - plus a body-byte snapshot of a body that has
 *       already passed the size gate. The (potentially expensive) body decoding, parsing and
 *       insertion happen on a small pool of daemon worker threads; a response that arrives while the
 *       pool or its queue is saturated is dropped rather than queued or run inline.
 *   <li>Responses larger than the configured scan limit (default 5 MB, see {@link
 *       LinkExtractorOptionsParam#getMaxBodySizeMb()}) are not scanned at all, so neither the
 *       snapshot on the network thread nor the decode on the worker can be made arbitrarily large.
 *   <li>Every extraction pattern has bounded quantifiers, so a crafted page cannot turn a pattern
 *       into quadratic scanning work on a worker thread.
 *   <li>Insertions are rate limited by a token bucket that is checked <em>before</em> anything is
 *       persisted, each response is capped, and per-response work is bounded (one short host-node
 *       wait, a capped number of EDT tasks per flush), so a single response can neither flood the
 *       session database nor pin a worker thread.
 *   <li>A per-session dedup set avoids re-processing URLs that have already been inserted, so
 *       repeated traffic (e.g. an active scan hitting the same endpoints) does not spam the tree.
 *       The set is reset whenever site-tree nodes are removed (e.g. the user deletes nodes or
 *       refreshes the tree), so a deleted node is re-discovered on the next visit.
 *   <li>All threads, the pool and the pending task queue are released in {@link #shutdown()}.
 *   <li>Every code path is wrapped in {@code try/catch(Throwable)}.
 * </ul>
 */
public class LinkExtractorNetworkListener implements HttpSenderListener, EventConsumer {

    private static final Logger LOGGER = LogManager.getLogger(LinkExtractorNetworkListener.class);

    // Run early on the network layer; the value only defines ordering relative to other
    // HttpSenderListeners, not the proxy/history flow.
    private static final int LISTENER_ORDER = 100000;

    private static final String NOTE_BODY = "Discovered via passive link extraction - NOT requested";
    private static final String NOTE_NEW_SUBDOMAIN_PREFIX = "[NEW SUBDOMAIN] ";

    /**
     * History type for a discovered entry when it is to be listed in the history tab.
     *
     * <p>{@link HistoryReference#TYPE_ZAP_USER} is one of the three types ZAP's history tab queries
     * ({@code {TYPE_MANUAL/TYPE_PROXIED, TYPE_ZAP_USER, TYPE_PROXY_CONNECT}} in
     * {@code ExtensionHistory.getHistoryIds()}), so an entry of this type is listed both when it is
     * added and whenever the history view is rebuilt.
     */
    static final int HISTORY_TYPE_RECORDED = HistoryReference.TYPE_ZAP_USER;

    /**
     * History type for a discovered entry when it must not be listed in the history tab.
     *
     * <p>{@link HistoryReference#TYPE_HIDDEN} is not in the set the history tab queries and is not a
     * "temporary" type (so the reference is still written to the session database and the node still
     * survives a session reload). It is the only reliable way to keep an entry out of that tab: the
     * tab is not just fed by {@code ExtensionHistory.addHistory}, it is also rebuilt from the
     * session history by {@code ExtensionHistory.getHistoryIds()}, which the in-scope toggle, the
     * history filter and opening a session all trigger.
     */
    static final int HISTORY_TYPE_NOT_RECORDED = HistoryReference.TYPE_HIDDEN;

    private static final int MAX_SEEN = 50000;

    // Upper bound on placeholder nodes created from a single response, so one crafted page cannot
    // flood the session database with history rows.
    private static final int MAX_INSERTS_PER_RESPONSE = 200;

    private static final Pattern TEMPLATE_LITERAL = Pattern.compile("`([^`]*\\$\\{[^`]*\\}[^`]*)`");

    // Compiled once: this runs for every template-literal candidate, and String.replaceAll would
    // re-compile the pattern on each of them.
    private static final Pattern INTERPOLATION = Pattern.compile("\\$\\{[^}]*\\}");

    // Longest candidate accepted into the candidate set (a longer one is dropped in addCandidate).
    private static final int MAX_CANDIDATE_LENGTH = 2000;

    // Ported from xnLinkFinder (https://github.com/xnl-h4ck3r/xnLinkFinder) - file extensions that
    // indicate a real resource/endpoint (as opposed to a generic [a-zA-Z]{1,4} extension). Used by
    // the "filename with extension" extraction groups. 'map' is deliberately included so source map
    // files surface as findings.
    private static final String LINK_REGEX_FILES =
            "php|php3|php5|asp|aspx|ashx|cfm|cgi|pl|jsp|jspx|json|js|action|html|xhtml|htm|bak|do|txt"
                    + "|wsdl|wadl|xml|xls|xlsx|bin|conf|config|bz2|bzip2|gzip|tar\\.gz|tgz|log|src|zip|js\\.map";

    // Extensions from LINK_REGEX_FILES that are longer than 4 characters or contain a digit; these
    // would otherwise be missed by the "path with extension" group which only matches [a-zA-Z]{1,4}.
    private static final String LINK_REGEX_NONSTANDARD_FILES =
            "php3|php5|action|xhtml|config|bzip2|tar\\.gz|js\\.map";

    // Match boundaries around a candidate link: it must start at the beginning of the body or after
    // a quote/whitespace, and end at end-of-body or before a quote/newline/whitespace. Java does not
    // allow an unescaped `(?:(?<=^)|(?<="|'|\\n|\\r|\\s))` alternation of different-width
    // lookbehinds, so the `^` case is expressed as an alternative branch instead.
    private static final String LINK_PREFIX = "(?:^|(?<=[\"'\s]))";
    private static final String LINK_SUFFIX = "(?=$|[\"'\n\r\s])";

    // Domain candidates must end in a plausible TLD (xnLinkFinder's default common-TLD list plus a
    // set of internal/dev TLDs commonly seen in corporate or lab environments).
    private static final Set<String> ALLOWED_TLDS = buildAllowedTlds();

    private static Set<String> buildAllowedTlds() {
        Set<String> tlds = new HashSet<>();
        tlds.addAll(
                Arrays.asList(
                        "com", "de", "net", "org", "uk", "cn", "ga", "nl", "cf", "ml", "tk", "ru", "br",
                        "gq", "xyz", "fr", "eu", "info", "co", "au", "ca", "it", "in", "ch", "pl", "es",
                        "online", "us", "top", "jp", "biz", "se", "at", "dk", "cz", "za", "me", "ir",
                        "icu", "shop", "kr", "site", "mx", "hu", "io", "cc", "club", "no", "cyou",
                        "store"));
        tlds.addAll(
                Arrays.asList(
                        "local", "internal", "lan", "corp", "home", "test", "localhost", "localdomain",
                        "intranet"));
        return tlds;
    }

    // Known compound public suffixes (last-two-label TLDs) used when computing a host's
    // registrable domain so subdomain discovery stays within the in-scope domain: e.g.
    // "www.example.co.uk" and "api.example.co.uk" share "example.co.uk" while the unrelated
    // "evil.co.uk" does not. Curated from the most common multi-label public suffixes.
    private static final Set<String> COMPOUND_PUBLIC_SUFFIXES =
            new HashSet<>(
                    Arrays.asList(
                            "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk",
                            "org.uk", "plc.uk",
                            "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
                            "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz",
                            "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp",
                            "com.br", "net.br", "org.br", "gov.br", "edu.br",
                            "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
                            "co.in", "net.in", "org.in", "gov.in", "edu.in", "ac.in", "res.in",
                            "com.sg", "org.sg", "net.sg", "edu.sg", "gov.sg",
                            "co.za", "org.za", "net.za", "gov.za", "edu.za", "ac.za",
                            "com.mx", "org.mx", "net.mx", "gov.mx", "edu.mx", "gob.mx",
                            "com.ar", "org.ar", "net.ar", "gov.ar", "edu.ar", "gob.ar",
                            "com.co", "org.co", "net.co", "gov.co", "edu.co",
                            "com.tw", "org.tw", "net.tw", "gov.tw", "edu.tw", "idv.tw",
                            "com.hk", "org.hk", "net.hk", "gov.hk", "edu.hk",
                            "com.ng", "org.ng", "net.ng", "gov.ng", "edu.ng",
                            "com.pk", "org.pk", "net.pk", "gov.pk", "edu.pk",
                            "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr",
                            "co.ke", "org.ke", "net.ke", "gov.ke", "edu.ke", "ac.ke",
                            "com.ua", "org.ua", "net.ua", "gov.ua", "edu.ua",
                            "com.ph", "org.ph", "net.ph", "gov.ph", "edu.ph",
                            "com.my", "org.my", "net.my", "gov.my", "edu.my", "sch.my",
                            "com.vn", "org.vn", "net.vn", "gov.vn", "edu.vn", "ac.vn",
                            "com.sa", "org.sa", "net.sa", "gov.sa", "edu.sa",
                            "com.ae", "org.ae", "net.ae", "gov.ae", "edu.ae",
                            "co.il", "org.il", "net.il", "gov.il", "edu.il", "ac.il",
                            "com.pl", "org.pl", "net.pl", "gov.pl", "edu.pl",
                            "co.th", "org.th", "net.th", "gov.th", "edu.th", "ac.th",
                            "com.ru", "org.ru", "net.ru", "edu.ru",
                            "com.kr", "org.kr", "net.kr", "gov.kr", "edu.kr", "ac.kr", "go.kr",
                            "co.id", "or.id", "web.id", "gov.id", "edu.id", "ac.id", "sch.id",
                            "com.eg", "org.eg", "net.eg", "gov.eg", "edu.eg"));

    // Second-level labels that are almost always false positives (from xnLinkFinder).
    private static final Set<String> EXCLUDED_SUFFIXES =
            new HashSet<>(Arrays.asList("call", "skin", "menu", "style", "rest", "next", "top"));

    private static final Set<String> EXCLUDED_DOMAINS =
            new HashSet<>(
                    Arrays.asList(
                            "this", "self", "target", "value", "values", "prop", "properties",
                            "proparray", "useragent", "rect", "paddiing", "style", "rule", "bound",
                            "child", "global", "element", "div", "prototype", "event", "feature",
                            "path"));

    // Well-known third-party / framework hosts and paths that add no value to the Site tree
    // (curated from xnLinkFinder's DEFAULT_LINK_EXCLUSIONS; asset-path tokens are omitted so
    // genuine same-site resources like /css/ and /img/ still become tree nodes).
    private static final List<String> JUNK_TOKENS =
            Arrays.asList(
                    "w3.org", "schema.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
                    "doubleclick.net", "facebook", "twitter", "instagram", "linkedin", "youtube.com",
                    "youtu.be", "google", "mozilla.org", "wordpress.org", "wix.com", "parastorage.com",
                    "whatwg.org", "polyfill", "typekit.net", "openweathermap.org", "reactjs.org",
                    "angularjs.org", "jsdelivr.net", "newrelic.com", "optimizely.com", "cloudflare",
                    "googleapis", "gstatic", "bootstrap", "jquery", "node_modules", "cdnjs.cloudflare",
                    "/wp-json", "/wp-content", "/wp-includes");

    // Small blocklist to cut obvious noise/false-positive extensions that are never useful
    // site-tree nodes. Note 'map' is NOT here: source maps are valuable findings and are already
    // pulled out by the dedicated sourceMappingURL / SourceMap handling.
    private static final Pattern JUNK_EXTENSION =
            Pattern.compile("\\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot)(?:[?#]|$)", Pattern.CASE_INSENSITIVE);

    private static final Pattern WHITESPACE = Pattern.compile("\\s");
    private static final Pattern HAS_ALNUM = Pattern.compile("[0-9a-zA-Z]");
    private static final Pattern BACKSLASH_S = Pattern.compile("\\\\[sS]");
    private static final Pattern MIMETYPE_PREFIX =
            Pattern.compile("^(?:application|image|model|video|audio|text)/", Pattern.CASE_INSENSITIVE);

    // Batch EDT updates to prevent UI freezing. The queue is drained in bounded slices so one EDT
    // callback can never run an unbounded number of Site tree mutations.
    private static final Queue<Runnable> EDT_BATCH = new ConcurrentLinkedQueue<>();
    private static final AtomicBoolean EDT_FLUSH_SCHEDULED = new AtomicBoolean(false);
    private static final int MAX_EDT_TASKS_PER_FLUSH = 50;

    // Rate limiting for tree insertions (token bucket, per session). Refilled by an executor owned
    // by this listener so it is released in shutdown() rather than pinning the add-on class loader.
    private static final int MAX_INSERT_TOKENS = 50;
    private static final int INSERT_TOKEN_REFILL_PER_TICK = 10;
    private static final long INSERT_TOKEN_REFILL_MS = 100L;

    // Waiting for the base host node (see HostWait): bounded total wait and poll interval. The node
    // is created by the EDT almost immediately, so this is only a short race-window wait; keeping it
    // short matters because a worker thread is occupied for its whole duration and the default pool
    // is only 2 threads wide.
    private static final long HOST_WAIT_TIMEOUT_MS = 500L;
    private static final long HOST_WAIT_POLL_MS = 50L;

    // Load shedding on the network thread: a task that is queued but has not started yet has already
    // cost a full body copy, so responses are dropped while the parse queue is this deep rather than
    // queueing work that may only be picked up long after the response is irrelevant.
    private static final int MAX_QUEUED_RESPONSES = 16;

    // Large responses are searched in overlapping chunks to keep regex work bounded (xnLinkFinder
    // uses the same threshold/sizes).
    private static final int CHUNK_THRESHOLD = 50000;
    private static final int CHUNK_SIZE = 40000;
    private static final int CHUNK_OVERLAP = 5000;

    // Encoded representations of '/', ':', '&', '=', '"' and non-breaking space that xnLinkFinder
    // normalises before searching, so links hidden behind HTML entities / percent / unicode escapes
    // are still found.
    private static final String[][] ENCODED_CHAR_MAPPINGS = {
        {"&#x2f;|&#0?2f|%2f|\\\\u002f|\\\\/", "/"},
        {"&#x3a;|&#0?3a|%3a|\\\\u003a", ":"},
        {"%26|&amp;|&#0?38;|\\\\u0026", "&"},
        {"%3d|&equals;|&#0?61;|\\\\u003d", "="},
        {"&quot;|&#34;|&#034;|&#x22;|%22|\\\\u0022", "\""},
        {"&nbsp;", " "},
    };

    // The mappings are compiled once (String.replaceAll would re-parse and re-compile them on every
    // response) and applied in order, because a decoded value can itself be encodable.
    private static final Pattern[] ENCODED_CHAR_PATTERNS = buildEncodedCharPatterns();

    private static Pattern[] buildEncodedCharPatterns() {
        Pattern[] patterns = new Pattern[ENCODED_CHAR_MAPPINGS.length];
        for (int i = 0; i < ENCODED_CHAR_MAPPINGS.length; i++) {
            patterns[i] = Pattern.compile("(?i)" + ENCODED_CHAR_MAPPINGS[i][0]);
        }
        return patterns;
    }

    // A single hostname label: starts and ends with an alphanumeric (or non-ASCII letter/digit) and
    // may only contain hyphens/underscores inside. This rejects labels that begin or end with '-'
    // (e.g. "-api" or "api-"), which are not valid DNS hostnames.
    private static final String HOST_LABEL =
            "[a-zA-Z0-9\\u0080-\\uFFFF](?:[a-zA-Z0-9\\u0080-\\uFFFF_-]*[a-zA-Z0-9\\u0080-\\uFFFF])?";

    // Matches bare "host.label.tld" strings (any number of subdomain labels + optional path). The
    // negative lookbehind avoids re-matching inside "scheme://host" or after a path separator where
    // the bare-http/protocol-relative patterns already own the find. Candidates are validated
    // against ALLOWED_TLDS by validateDomainCandidate(); per-label hostname syntax is enforced by
    // isValidHostname(). Label repetitions are bounded: an unbounded quantifier here lets deeply
    // chained labels (about a thousand, only a few KB of body) recurse the regex engine until its
    // stack overflows, so the depth is capped at a level well beyond real-world subdomains.
    private static final int MAX_DOMAIN_LABELS = 24;

    private static final Pattern DOMAIN_URL =
            Pattern.compile(
                    "(?<![\\w.:/])(?:"
                            + HOST_LABEL
                            + "\\.){0,"
                            + MAX_DOMAIN_LABELS
                            + "}"
                            + HOST_LABEL
                            + "\\.[a-zA-Z]{2,24}(?:/[^\\s\"'<>()\\[\\]{}]{0,500})?");

    private static final List<Pattern> HTML_PATTERNS = buildHtmlPatterns();

    // JS-specific patterns; gated behind the "Parse JavaScript" option in Tools > Options >
    // Site tree.
    private static final List<Pattern> JS_PATTERNS = buildJsPatterns();

    // Matches a host token inside a response-header value, allowing an optional wildcard prefix
    // ("cdn.example.com", "*.example.com") and an optional leading dot (Set-Cookie "Domain=.example.com").
    // The wildcard/leading dot is consumed before group 2, which holds the base host directly
    // ("*.example.com" and ".example.com" both yield "example.com"). Label repetition is bounded the
    // same way as DOMAIN_URL to keep the matcher bounded.
    private static final Pattern HEADER_HOST_PATTERN =
            Pattern.compile(
                    "(?<![a-zA-Z0-9_.-])"
                            + "(?:(\\*)?\\.)?"
                            + "((?:(?:"
                            + HOST_LABEL
                            + "\\.){0,"
                            + MAX_DOMAIN_LABELS
                            + "})"
                            + HOST_LABEL
                            + "\\.[a-zA-Z]{2,24})"
                            + "(?![a-zA-Z0-9_.-])");

    // Response headers whose values are structurally never useful subdomains (lengths, dates,
    // encodings, transport directives, ...). Everything else - CSP, Link, Location,
    // Set-Cookie, Access-Control-*, Server, Vendor "X-*" headers, ... - is scanned for hosts.
    private static final Set<String> SKIP_HOST_HEADERS =
            new HashSet<>(
                    Arrays.asList(
                            "connection",
                            "keep-alive",
                            "transfer-encoding",
                            "content-length",
                            "content-type",
                            "content-encoding",
                            "content-language",
                            "content-disposition",
                            "cache-control",
                            "pragma",
                            "expires",
                            "date",
                            "age",
                            "last-modified",
                            "etag",
                            "vary",
                            "accept-ranges",
                            "retry-after",
                            "www-authenticate",
                            "proxy-authenticate",
                            "allow",
                            "strict-transport-security",
                            "x-xss-protection",
                            "x-content-type-options",
                            "x-frame-options",
                            "x-request-id",
                            "x-zap-scan-id"));

    // URLs already inserted for the current session (dedup across network threads). A bounded
    // FIFO set: when the cap is reached the OLDEST entries are evicted, so an attacker cannot
    // force a wholesale reset (and re-injection of previously seen URLs) by flooding new URLs.
    private static final Set<String> SEEN =
            Collections.synchronizedSet(
                    Collections.newSetFromMap(
                            new LinkedHashMap<String, Boolean>(1024, 0.75f, false) {

                                private static final long serialVersionUID = 1L;

                                @Override
                                protected boolean removeEldestEntry(
                                        Map.Entry<String, Boolean> eldest) {
                                    return size() > MAX_SEEN;
                                }
                            }));
    private static long currentSessionId = -1L;

    // ZAP's History extension (the History tab). Resolved lazily on first use and only cached when
    // it was found, so headless runs - where Control is not initialised - simply never cache it.
    private static volatile ExtensionHistory historyExtension;

    private final LinkExtractorOptionsParam options;
    // ThreadPoolExecutor (not the ExecutorService interface) so the network-thread saturation
    // gate below can inspect the queue depth before it pays for the body snapshot.
    private final ThreadPoolExecutor pool;
    private final AtomicInteger insertTokens = new AtomicInteger(MAX_INSERT_TOKENS);
    private final ScheduledExecutorService tokenRefill;

    public LinkExtractorNetworkListener(LinkExtractorOptionsParam options) {
        this.options = options;
        this.pool = createPool(options.getThreads());
        this.tokenRefill = createTokenRefillExecutor();
    }

    /**
     * Releases everything this listener owns: the worker pool, the token-refill executor and any
     * queued EDT work. Called when the ZAP session that created the listener ends (or the add-on is
     * unloaded), so neither the pool threads nor the scheduler outlive it.
     */
    public void shutdown() {
        pool.shutdownNow();
        tokenRefill.shutdownNow();
        // Queued tasks target this session's site tree, which is going away.
        EDT_BATCH.clear();
        resetSeen();
    }

    // Daemon worker pool (the add-on is passive); default AbortPolicy on purpose - a saturated
    // queue DROPS the parse rather than running it inline on the network/proxy thread.
    private ThreadPoolExecutor createPool(int threads) {
        AtomicInteger counter = new AtomicInteger();
        ThreadFactory threadFactory =
                r -> {
                    Thread t = new Thread(r, "ZAP-LinkExtractor-" + counter.incrementAndGet());
                    t.setDaemon(true);
                    return t;
                };
        ThreadPoolExecutor pool =
                new ThreadPoolExecutor(
                        threads,
                        threads,
                        30,
                        TimeUnit.SECONDS,
                        new LinkedBlockingQueue<>(100),
                        threadFactory);
        pool.allowCoreThreadTimeOut(true);
        return pool;
    }

    private ScheduledExecutorService createTokenRefillExecutor() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ZAP-LinkExtractor-TokenRefill");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleAtFixedRate(
                () ->
                        insertTokens.updateAndGet(
                                v -> Math.min(MAX_INSERT_TOKENS, v + INSERT_TOKEN_REFILL_PER_TICK)),
                0,
                INSERT_TOKEN_REFILL_MS,
                TimeUnit.MILLISECONDS);
        return executor;
    }

    private boolean tryAcquireInsertToken() {
        // The bucket must actually deny when empty. A "clamp to zero" update (v > 0 ? v - 1 : 0)
        // would leave the result at 0, which satisfies a ">= 0" test and hand out a token every
        // single time - i.e. no rate limiting at all.
        int remaining = insertTokens.get();
        while (remaining > 0) {
            if (insertTokens.compareAndSet(remaining, remaining - 1)) {
                return true;
            }
            remaining = insertTokens.get();
        }
        return false;
    }

    private static void scheduleEdtFlush() {
        if (EDT_FLUSH_SCHEDULED.compareAndSet(false, true)) {
            EventQueue.invokeLater(
                    () -> {
                        EDT_FLUSH_SCHEDULED.set(false);
                        int ran = 0;
                        Runnable task;
                        while (ran < MAX_EDT_TASKS_PER_FLUSH && (task = EDT_BATCH.poll()) != null) {
                            task.run();
                            ran++;
                        }
                        // More than one slice worth of work: keep the EDT responsive and continue.
                        if (!EDT_BATCH.isEmpty()) {
                            scheduleEdtFlush();
                        }
                    });
        }
    }

    private static List<Pattern> buildHtmlPatterns() {
        List<Pattern> patterns = new ArrayList<>();

        // Classic HTML/CSS attribute & style patterns; always applied. The attribute pattern uses a
        // negative lookbehind so it matches genuine HTML attributes (e.g. "<a href="), not JS DOM
        // property assignments such as "location.href = '...'" or "img.src = '...'" - those belong
        // to the JS-specific patterns and are gated behind the "Parse JavaScript" option.
        patterns.add(
                Pattern.compile(
                        "(?<![\\w:.])[\\w:-]*?(?:href|src|action|poster|cite|formaction|background|longdesc|usemap|manifest|codebase|profile)\\s*=\\s*[\"']([^\"'#\\s>]+)[\"']",
                        Pattern.CASE_INSENSITIVE));
        // The lazy runs below are bounded: "[^>]*?" and "[^}]*?" with an absent terminator (an
        // unclosed "<meta" or "$.ajax({") make the matcher re-scan to the end of the body for every
        // start offset, i.e. quadratic work on a crafted page. The cap is far beyond any real
        // attribute/option run while keeping the scan linear.
        patterns.add(Pattern.compile("(?i)<meta[^>]{0,2000}?url\\s*=\\s*([^\"'#\\s>]+)"));
        patterns.add(Pattern.compile("url\\(\\s*[\"']?([^\"')\\s]+)[\"']?\\s*\\)", Pattern.CASE_INSENSITIVE)); // CSS url(...)

        // Bare absolute http(s) URLs and protocol-relative URLs appearing anywhere in the body
        // (not just inside an attribute).
        patterns.add(Pattern.compile("\\bhttps?://[^\\s\"'<>)]+", Pattern.CASE_INSENSITIVE));
        patterns.add(
                Pattern.compile(
                        "(?:[\"'(]|^|\\s)(//"
                                + HOST_LABEL
                                + "(?:\\."
                                + HOST_LABEL
                                + "){0,"
                                + MAX_DOMAIN_LABELS
                                + "}\\.[a-zA-Z]{2,}[^\\s\"'<>)]*)"));

        // Source map references in the body ("//# sourceMappingURL=app.js.map"); the response
        // header form is handled separately in onHttpResponseReceive.
        patterns.add(Pattern.compile("(?i)sourceMappingURL\\s*=\\s*([^\\s\"'<>]+)"));

        // Bare domain mentions ("api.example.com", "config.js" style strings). Always applied; each
        // candidate is validated against a TLD allow-list before being used.
        patterns.add(DOMAIN_URL);

        return patterns;
    }

    private static List<Pattern> buildJsPatterns() {
        List<Pattern> patterns = new ArrayList<>();

        // Dynamic / JS-driven navigation & network calls
        patterns.add(Pattern.compile("fetch\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // fetch("...")
        patterns.add(Pattern.compile("\\.open\\(\\s*[\"'][A-Za-z]+[\"']\\s*,\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // XHR .open(method, url)
        patterns.add(Pattern.compile("(?:import|from)\\s+[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // ES module import
        patterns.add(Pattern.compile("\\bimport\\s*\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // dynamic import("...")
        patterns.add(Pattern.compile("\\brequire(?:\\.resolve)?\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // require("...")
        patterns.add(Pattern.compile("(?:window\\.)?location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // location / location.href / window.location(.href) =
        patterns.add(Pattern.compile("window\\.open\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // window.open("...")
        patterns.add(Pattern.compile("\\$\\.ajax\\(\\s*\\{[^}]{0,2000}?url\\s*:\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // $.ajax({ url: "..." }) - bounded run, see above
        patterns.add(Pattern.compile("\\$\\.(?:get|post|getJSON)\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // $.get/$.post/$.getJSON("...")
        patterns.add(Pattern.compile("axios(?:\\.(?:get|post|put|patch|delete|head|request))?\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // axios(...) / axios.get(...)
        patterns.add(Pattern.compile("new\\s+WebSocket\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // new WebSocket("wss://...")
        patterns.add(Pattern.compile("new\\s+EventSource\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // new EventSource("...")
        patterns.add(Pattern.compile("navigator\\.sendBeacon\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // navigator.sendBeacon("...")

        // Template-literal URLs - capture the whole literal, interpolations are replaced with a
        // placeholder segment when the candidate is normalised below.
        patterns.add(TEMPLATE_LITERAL);

        // Ported from xnLinkFinder's main link regex (capturing groups 2-4), gated behind the
        // "Parse JavaScript" option so inline <script> blocks in HTML pages do not leak API
        // endpoints when the option is off. The groups are wrapped in quote/whitespace boundaries:
        //   - JS_PATH      "/api/v1/users", "./rel/path", "../up", "#/route"
        //   - JS_PATH_EXT  "api/v1/users.json" (path ending in an extension)
        //   - JS_FILE_EXT  "users.json" (bare filename with a recognised extension)
        patterns.add(
                Pattern.compile(
                        LINK_PREFIX
                                + "(?:(?:#?/|\\.\\./|\\./)[^\"'><,;| *()%$^/\\\\\\[\\]][^\"'><,;|()\\s]{1,255})"
                                + LINK_SUFFIX));
        patterns.add(
                Pattern.compile(
                        LINK_PREFIX
                                + "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/\\.]{1,255}\\.(?:[a-zA-Z]{1,4}|"
                                + LINK_REGEX_NONSTANDARD_FILES
                                + ")(?:[?/][^\"']{0,1000}|))"
                                + LINK_SUFFIX));
        patterns.add(
                Pattern.compile(
                        LINK_PREFIX
                                + "([a-zA-Z0-9_\\-\\.]{1,255}\\.(?:"
                                + LINK_REGEX_FILES
                                + ")(?:\\?[^\"']{0,255}|))"
                                + LINK_SUFFIX));

        return patterns;
    }

    @Override
    public int getListenerOrder() {
        return LISTENER_ORDER;
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        // Nothing to do on the request side.
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        try {
            if (msg == null || msg.getResponseHeader() == null) {
                return;
            }
            final int bodyLength = msg.getResponseBody().length();
            if (bodyLength == 0) {
                return;
            }

            // Body-size gate, the cheapest rejection there is and the last unbounded input left: the
            // body is snapshotted on the network thread below and decoded to a String on the worker,
            // and the decoders can hold several further copies of it, so without this a single huge
            // response is enough to stall the request/response path and to spike memory. The limit is
            // configurable (Tools > Options > Site tree); responses above it are not scanned at all.
            final long maxBodyBytes = options.getMaxBodyBytes();
            if (!isBodyWithinScanLimit(bodyLength, maxBodyBytes)) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "LinkExtractor: body of {} bytes is over the {} byte scan limit, skipping {}",
                            bodyLength,
                            maxBodyBytes,
                            msg.getRequestHeader().getURI());
                }
                return;
            }

            // Only bother parsing response types that could plausibly contain links.
            String contentType = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
            if (contentType == null) {
                return;
            }
            contentType = contentType.toLowerCase(Locale.ROOT);
            if (contentType.indexOf("html") == -1
                    && contentType.indexOf("javascript") == -1
                    && contentType.indexOf("json") == -1
                    && contentType.indexOf("xml") == -1
                    && contentType.indexOf("css") == -1) {
                return;
            }

            String baseUrlStr;
            try {
                baseUrlStr = msg.getRequestHeader().getURI().toString();
            } catch (Exception e) {
                return;
            }

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                        "LinkExtractor: response type={} url={} bodyLen={}",
                        contentType,
                        baseUrlStr,
                        msg.getResponseBody().length());
            }

            // Scope gate: only in-scope sources are parsed. Cheap enough to run on the network
            // thread.
            if (!Model.getSingleton().getSession().isInScope(baseUrlStr)) {
                return;
            }

            // Saturation gate, before the copy below: a task that waits in the queue has still cost a
            // full body copy on the proxy thread, and it may only be picked up long after the
            // response stopped being relevant. Drop the response instead of queueing it.
            if (isParseQueueFull(pool.getQueue().size())) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("LinkExtractor: parse queue is full, dropping {}", baseUrlStr);
                }
                return;
            }

            // Snapshot the body bytes and its charset on the network thread (getBytes() returns a
            // reference to the message's internal array, which the proxy may mutate afterwards) and
            // decode/parse on the worker so a large body never stalls the request/response flow.
            final byte[] bodyBytes = msg.getResponseBody().getBytes();
            if (bodyBytes == null) {
                return;
            }
            final byte[] bodySnapshot = Arrays.copyOf(bodyBytes, bodyLength);
            final String charset = msg.getResponseBody().getCharset();

            // SourceMap / X-SourceMap response headers point at the source map for the served
            // resource; treat them like body-discovered candidates (resolved against the request
            // URL so relative header values work too).
            final List<String> extraCandidates = new ArrayList<>();
            for (String headerName : new String[] {"SourceMap", "X-SourceMap"}) {
                String value = msg.getResponseHeader().getHeader(headerName);
                if (value != null && !value.trim().isEmpty()) {
                    try {
                        extraCandidates.add(new URL(new URL(baseUrlStr), value.trim()).toString());
                    } catch (Exception e) {
                        extraCandidates.add(value.trim());
                    }
                }
            }

            // Subdomain discovery from response headers (Tools > Options > Site tree): scan every
            // header value for host tokens (honouring wildcards like "*.example.com") and treat
            // them like cross-host candidates so they become new subdomain folder nodes.
            if (options.isDiscoverSubdomainsFromHeaders()) {
                List<HttpHeaderField> headerFields = msg.getResponseHeader().getHeaders();
                if (headerFields != null) {
                    extraCandidates.addAll(extractHeaderHosts(headerFields));
                }
            }

            submit(() -> processResponse(baseUrlStr, bodySnapshot, charset, extraCandidates));
        } catch (Throwable t) {
            // A network-layer hook must never disturb the request/response flow.
            LOGGER.warn("LinkExtractor: onHttpResponseReceive error", t);
        }
    }

    private void submit(Runnable task) {
        try {
            pool.execute(task);
        } catch (RejectedExecutionException e) {
            // Pool saturated: drop the parse. Never run it inline on the network thread.
        }
    }

    /**
     * Invoked (synchronously) when a site-tree node or whole site is removed - e.g. the user
     * deletes nodes from the Site tree or the tree is refreshed. The per-session dedup set is
     * reset so a later visit to the same domain re-discovers the deleted URLs; the {@code findNode}
     * guard in {@link #processResponse} keeps nodes that are still present from being duplicated.
     *
     * @param event the site-tree change event.
     */
    @Override
    public void eventReceived(Event event) {
        if (event == null) {
            return;
        }
        String eventType = event.getEventType();
        if (!SiteMapEventPublisher.SITE_NODE_REMOVED_EVENT.equals(eventType)
                && !SiteMapEventPublisher.SITE_REMOVED_EVENT.equals(eventType)) {
            return;
        }
        resetSeen();
    }

    /**
     * Clears the per-session dedup set so already-processed URLs can be re-discovered.
     *
     * <p>Only ever invoked when the user removes nodes from the Site tree (or the tree is
     * refreshed); normal traffic never clears the set, so the fast-path dedup stays effective.
     */
    static void resetSeen() {
        SEEN.clear();
    }

    /** Package-private test hook: records {@code url} as already processed. */
    static void markSeen(String url) {
        SEEN.add(url);
    }

    /** Package-private test hook: whether {@code url} is currently in the dedup set. */
    static boolean isSeen(String url) {
        return SEEN.contains(url);
    }

    /** Package-private test hook: number of insertion tokens currently available. */
    int availableInsertTokens() {
        return insertTokens.get();
    }

    /** Package-private test hook: forces the insertion token bucket to {@code tokens}. */
    void setInsertTokens(int tokens) {
        insertTokens.set(tokens);
    }

    /** Package-private test hook: attempts to consume one insertion token. */
    boolean acquireInsertToken() {
        return tryAcquireInsertToken();
    }

    /**
     * The history type to create a discovered entry with, driven by the "record in the history tab"
     * option.
     *
     * <p>A Site tree node is always backed by a {@link HistoryReference} row, so the entry exists in
     * the session history either way; the type is what decides whether ZAP's history tab can list
     * it. Listing it is not something the tab only learns from
     * {@code ExtensionHistory.addHistory(...)}: the tab is rebuilt from the session history by
     * {@code ExtensionHistory.getHistoryIds()}, which only selects the proxied, ZAP-user and
     * proxy-connect types and is re-run by the in-scope toggle, the history filter and session loads.
     * Picking the type is therefore the only way to make the option hold.
     *
     * @param recordInHistoryTab whether the entry should be listed in the history tab.
     * @return {@link #HISTORY_TYPE_RECORDED} or {@link #HISTORY_TYPE_NOT_RECORDED}.
     */
    static int historyTypeFor(boolean recordInHistoryTab) {
        return recordInHistoryTab ? HISTORY_TYPE_RECORDED : HISTORY_TYPE_NOT_RECORDED;
    }

    /**
     * The body-size gate's decision, as a pure function of the response length and the configured
     * limit, so the boundary (a body of exactly the limit is still scanned) can be pinned by a test
     * without standing up a message.
     *
     * @param bodyLength the response body length in bytes.
     * @param maxBodyBytes the configured limit in bytes.
     * @return whether the body is small enough to be scanned at all.
     */
    static boolean isBodyWithinScanLimit(int bodyLength, long maxBodyBytes) {
        return bodyLength <= maxBodyBytes;
    }

    /**
     * The saturation gate's decision, as a pure function of the current queue depth.
     *
     * @param queuedResponses the number of tasks waiting in the parse queue.
     * @return whether the response should be dropped instead of snapshotted and queued.
     */
    static boolean isParseQueueFull(int queuedResponses) {
        return queuedResponses >= MAX_QUEUED_RESPONSES;
    }

    private void processResponse(
            String baseUrlStr, byte[] bodyBytes, String charset, List<String> extraCandidates) {
        try {
            Model model = Model.getSingleton();
            Session session = model.getSession();
            dedupe(session);

            URL baseUrl = new URL(baseUrlStr);
            String baseHost = baseUrl.getHost();
            if (baseHost != null) {
                baseHost = baseHost.toLowerCase(Locale.ROOT);
            }
            // Constant for the whole response: the registrable domain of the (in-scope) source host,
            // needed by every cross-host candidate. Hoisted out of the candidate loop.
            String baseRegistrable = registrableDomain(baseHost);

            String body = new String(bodyBytes, Charset.forName(charset));
            Set<String> found = extractCandidates(body, options.isParseJavascript());
            if (extraCandidates != null) {
                for (String extra : extraCandidates) {
                    if (extra == null) {
                        continue;
                    }
                    String normalised = normaliseCandidate(extra);
                    if (normalised != null && !JUNK_EXTENSION.matcher(normalised).find()) {
                        addCandidate(found, normalised);
                    }
                }
            }
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                        "LinkExtractor: parsed {} bytes, found {} candidates from {}",
                        bodyBytes.length,
                        found.size(),
                        baseUrlStr);
            }
            if (found.isEmpty()) {
                return;
            }

            SiteMap siteTree = session.getSiteTree();
            // Tracks the base host node for the whole response (see HostWait), so the wait is paid
            // at most once no matter how many candidates the response yields.
            HostWait hostWait = new HostWait(siteTree, baseHost);

            int inserted = 0;
            for (String raw : found) {
                if (inserted >= MAX_INSERTS_PER_RESPONSE) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug(
                                "LinkExtractor: per-response insert cap ({}) reached for {}",
                                MAX_INSERTS_PER_RESPONSE,
                                baseUrlStr);
                    }
                    break;
                }
                // Bare "//host/path" protocol-relative URLs need the scheme from the base page
                // prefixed before java.net.URL will accept them.
                String resolved;
                URL parsedResolved;
                try {
                    resolved = new URL(baseUrl, raw).toString();
                    parsedResolved = new URL(resolved);
                } catch (Exception e) {
                    continue;
                }

                // Drop candidates that resolve to a URL with a non-empty fragment (#/... Angular
                // routes and similar) - fragments are never sent to the server so they cannot be
                // site-tree nodes.
                if (parsedResolved.getRef() != null && !parsedResolved.getRef().isEmpty()) {
                    continue;
                }

                URI targetUri;
                try {
                    targetUri = new URI(resolved, false);
                } catch (Exception e) {
                    continue;
                }

                String discoveredHost;
                try {
                    discoveredHost = parsedResolved.getHost();
                    if (discoveredHost != null) {
                        discoveredHost = discoveredHost.toLowerCase(Locale.ROOT);
                    }
                } catch (Exception e) {
                    discoveredHost = null;
                }

                // Reject candidates whose resolved host is not a valid hostname (e.g. labels that
                // start or end with '-'), so invalid "subdomains" never reach the Site tree.
                if (discoveredHost != null && !isValidHostname(discoveredHost)) {
                    continue;
                }

                // Filter well-known third-party/framework noise by resolved host + path (relative
                // candidates that passed the raw-candidate check may still resolve onto a junk host
                // or a WordPress/asset path).
                if (isJunk((discoveredHost == null ? "" : discoveredHost) + parsedResolved.getPath())) {
                    continue;
                }

                boolean isNewSubdomain =
                        discoveredHost != null
                                && !discoveredHost.isEmpty()
                                && baseHost != null
                                && !discoveredHost.equals(baseHost);

                // In-scope enforcement: subdomain discovery must only add hosts on in-scope
                // domains. A cross-host candidate is kept only when its host belongs to the same
                // domain family as the (in-scope) source host - a subdomain of that registrable
                // domain - or when the resolved URL is itself explicitly within the session scope
                // (multi-domain contexts). Unrelated third-party hosts never reach the Site tree.
                if (isNewSubdomain
                        && !isSameDomainFamily(baseHost, baseRegistrable, discoveredHost)
                        && !session.isInScope(resolved)) {
                    continue;
                }

                // Subdomain discovery toggle (Tools > Options > Site tree): with it off, only
                // same-host candidates are added.
                if (!options.isDiscoverSubdomains() && isNewSubdomain) {
                    continue;
                }

                // A cross-host root URL with no path would make the subdomain host a leaf/page
                // node. Append "/" so the host renders as a folder node, with the discovered root
                // as a "/" page underneath - matching how ZAP displays a normally-browsed site.
                if (isNewSubdomain) {
                    String path = targetUri.getPath();
                    if (path == null || path.isEmpty()) {
                        int queryIdx = resolved.indexOf('?');
                        resolved =
                                queryIdx == -1
                                        ? resolved + "/"
                                        : resolved.substring(0, queryIdx)
                                                + "/"
                                                + resolved.substring(queryIdx);
                        try {
                            targetUri = new URI(resolved, false);
                        } catch (Exception e) {
                            continue;
                        }
                    }
                }

                // Skip URLs already inserted for this session.
                if (!SEEN.add(resolved)) {
                    continue;
                }

                // Skip anything already in the tree (real or previously-predicted).
                try {
                    if (siteTree.findNode(targetUri) != null) {
                        continue;
                    }
                } catch (Exception e) {
                    // The lookup itself failed, so nothing is known about this URL: forget the dedup
                    // entry again, otherwise the node could never be re-added on a later visit.
                    SEEN.remove(resolved);
                    continue;
                }

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "LinkExtractor: adding placeholder node for {} {}",
                            resolved,
                            isNewSubdomain ? "(new subdomain)" : "");
                }
                if (!addPlaceholderNode(
                        session,
                        siteTree,
                        hostWait,
                        targetUri,
                        isNewSubdomain,
                        options.isRecordInProxyHistory())) {
                    // Not inserted (rate limited, or the history reference could not be created):
                    // nothing was persisted, so release the dedup entry for a later retry.
                    SEEN.remove(resolved);
                    continue;
                }
                inserted++;
            }
        } catch (Throwable t) {
            LOGGER.warn("LinkExtractor: processResponse error for {}", baseUrlStr, t);
        }
    }

    /**
     * Resets the dedup set when a new session is loaded. Size-based eviction is handled by the
     * bounded FIFO set itself (oldest entries are dropped first), so a flood of new URLs can never
     * force a wholesale reset.
     *
     * @param session the current session.
     */
    private static void dedupe(Session session) {
        long sessionId = session.getSessionId();
        if (currentSessionId != sessionId) {
            currentSessionId = sessionId;
            SEEN.clear();
        }
    }

    /**
     * Runs all extraction patterns (HTML/CSS + JS) over the response body.
     *
     * @param body the response body.
     * @return the extracted candidates, never {@code null}.
     */
    static Set<String> extractCandidates(String body) {
        return extractCandidates(body, true);
    }

    /**
     * Runs the extraction patterns over the response body and returns the deduplicated raw
     * candidates (before resolution and scope filtering).
     *
     * @param body the response body.
     * @param parseJavascript whether the JS-specific patterns are run (Tools &gt; Options &gt; Sites
     *     tree).
     * @return the extracted candidates, never {@code null}.
     */
    static Set<String> extractCandidates(String body, boolean parseJavascript) {
        Set<String> found = new LinkedHashSet<>();
        // Normalise encoded slashes/colons/ampersands/equals/quotes once, up front (xnLinkFinder
        // preprocessing), so links obfuscated with HTML entities, percent-encoding or unicode
        // escapes are found by every pattern.
        String decoded = decodeEncodedChars(body);
        applyPatterns(decoded, HTML_PATTERNS, found);
        if (parseJavascript) {
            applyPatterns(decoded, JS_PATTERNS, found);
        }
        return found;
    }

    private static void applyPatterns(String body, List<Pattern> patterns, Set<String> found) {
        // Large bodies are searched in overlapping chunks to keep regex work bounded.
        if (body.length() <= CHUNK_THRESHOLD) {
            for (Pattern re : patterns) {
                runPattern(re, body, found);
            }
            return;
        }
        for (int start = 0; start < body.length(); start += CHUNK_SIZE - CHUNK_OVERLAP) {
            int end = Math.min(start + CHUNK_SIZE, body.length());
            String chunk = body.substring(start, end);
            for (Pattern re : patterns) {
                runPattern(re, chunk, found);
            }
        }
    }

    private static void runPattern(Pattern re, String body, Set<String> found) {
        Matcher m = re.matcher(body);
        while (m.find()) {
            String candidate = m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group(0);
            if (candidate == null) {
                continue;
            }

            // Template-literal group: normalise interpolations first.
            if (re == TEMPLATE_LITERAL) {
                candidate = INTERPOLATION.matcher(candidate).replaceAll("__DYNAMIC__");
            }

            // Bare-domain group: only accept strings that look like a real host with a plausible
            // TLD (xnLinkFinder's domain filtering), prefixed with "//" so they resolve like
            // protocol-relative URLs.
            if (re == DOMAIN_URL) {
                candidate = validateDomainCandidate(candidate);
                if (candidate == null) {
                    continue;
                }
            }

            String normalised = normaliseCandidate(candidate);
            if (normalised == null) {
                continue;
            }
            if (JUNK_EXTENSION.matcher(normalised).find()) {
                continue;
            }
            addCandidate(found, normalised);
        }
    }

    /**
     * Applies xnLinkFinder's candidate normalisation: strips surrounding quotes/parens, collapses
     * literal backslash escapes, trims trailing garbage, cuts at backticks/unbalanced brackets/"{@code </}".
     *
     * @param link the raw candidate.
     * @return the normalised candidate, or {@code null} if nothing useful remains.
     */
    private static String normaliseCandidate(String link) {
        if (link == null) {
            return null;
        }
        link = link.trim();
        link = stripChars(link, "\"'\n\r( ");
        if (link.indexOf('\\') != -1) {
            // Only candidates that actually contain a backslash can match any of these; the
            // String.replace calls return the same instance otherwise, but still scan.
            link = link.replace("\\n", "").replace("\\r", "").replace("\\.", ".");
        }
        if (link.isEmpty()) {
            return null;
        }

        // If the candidate is quoted (or wraps a literal \n/\r) on both ends, strip those too.
        String first = link.substring(0, 1);
        String last = link.substring(link.length() - 1);
        String firstTwo = link.length() >= 2 ? link.substring(0, 2) : first;
        String lastTwo = link.length() >= 2 ? link.substring(link.length() - 2) : last;
        boolean leadingNewline = "\\n".equals(firstTwo) || "\\r".equals(firstTwo);
        boolean trailingNewline = "\\n".equals(lastTwo) || "\\r".equals(lastTwo);
        boolean quotedLeading =
                leadingNewline
                        || "\"".equals(first)
                        || "'".equals(first)
                        || "\n".equals(first)
                        || "\r".equals(first);
        boolean quotedTrailing =
                trailingNewline
                        || "\"".equals(last)
                        || "'".equals(last)
                        || "\n".equals(last)
                        || "\r".equals(last);
        if (quotedLeading && quotedTrailing) {
            link = link.substring(leadingNewline ? 2 : 1, link.length() - (trailingNewline ? 2 : 1));
        }

        // Trailing backslashes, then '>', ';', ','. Equivalent to the previous
        // replaceAll("\\\\+$", "") / replaceAll("[>;,]+$", "") without compiling two patterns per
        // candidate.
        int end = link.length();
        while (end > 0 && link.charAt(end - 1) == '\\') {
            end--;
        }
        while (end > 0) {
            char c = link.charAt(end - 1);
            if (c == '>' || c == ';' || c == ',') {
                end--;
            } else {
                break;
            }
        }
        if (end != link.length()) {
            link = link.substring(0, end);
        }

        // Everything from the first backtick onwards is junk (template literal remainder).
        int backtick = link.indexOf('`');
        if (backtick != -1) {
            link = link.substring(0, backtick);
        }

        link = stripUnbalancedBrackets(link);

        // Everything from an unescaped "</" onwards is HTML, not a URL.
        int tagClose = link.indexOf("</");
        if (tagClose != -1) {
            link = link.substring(0, tagClose);
        }

        // A leading single dot is usually a JS/regex leftover.
        if (link.startsWith(".") && link.length() > 1 && link.charAt(1) != '.' && link.charAt(1) != '/') {
            link = link.substring(1);
        }

        return link.isEmpty() ? null : link;
    }

    private static String stripChars(String s, String chars) {
        int start = 0;
        int end = s.length();
        while (start < end && chars.indexOf(s.charAt(start)) != -1) {
            start++;
        }
        while (end > start && chars.indexOf(s.charAt(end - 1)) != -1) {
            end--;
        }
        return s.substring(start, end);
    }

    /**
     * Port of xnLinkFinder's stripLinkFromUnbalancedBrackets: cuts the link at the first truly
     * unbalanced closing bracket, and removes trailing opening brackets left unmatched at the end.
     */
    private static String stripUnbalancedBrackets(String link) {
        if (link.indexOf('(') == -1
                && link.indexOf('[') == -1
                && link.indexOf('{') == -1
                && link.indexOf(')') == -1
                && link.indexOf(']') == -1
                && link.indexOf('}') == -1) {
            // No brackets at all: nothing to strip, and nothing to allocate a stack for.
            return link;
        }
        int lastValidIndex = link.length();
        Deque<Integer> stack = new ArrayDeque<>();
        for (int i = 0; i < link.length(); i++) {
            char c = link.charAt(i);
            char opening = 0;
            switch (c) {
                case '(':
                case '[':
                case '{':
                    stack.push(i);
                    break;
                case ')':
                    opening = '(';
                    break;
                case ']':
                    opening = '[';
                    break;
                case '}':
                    opening = '{';
                    break;
                default:
                    break;
            }
            if (opening == 0) {
                continue;
            }
            if (!stack.isEmpty() && link.charAt(stack.peek()) == opening) {
                stack.pop();
            } else {
                lastValidIndex = i;
                break;
            }
        }
        if (!stack.isEmpty()) {
            // Bottom of the stack = first unmatched opening bracket.
            lastValidIndex = Math.min(lastValidIndex, stack.getLast());
        }
        return link.substring(0, Math.max(0, lastValidIndex));
    }

    /**
     * Validates a bare-domain candidate against the TLD allow-list and xnLinkFinder's excluded
     * suffix/domain lists, returning it prefixed with {@code //} (so it resolves like a
     * protocol-relative URL) or {@code null} when it is not a plausible host.
     */
    private static String validateDomainCandidate(String key) {
        String hostPart = key;
        int slash = key.indexOf('/');
        if (slash != -1) {
            hostPart = key.substring(0, slash);
        }
        // Every label must be a syntactically valid hostname label (no leading/trailing '-',
        // no empty/oversized labels), otherwise candidates like "-api.example.com" are rejected.
        if (!isValidHostname(hostPart)) {
            return null;
        }
        String[] labels = hostPart.split("\\.");
        if (labels.length < 2) {
            return null;
        }
        String last = labels[labels.length - 1].toLowerCase(Locale.ROOT);
        String lastTwo =
                labels.length >= 3
                        ? (labels[labels.length - 2] + "." + labels[labels.length - 1])
                                .toLowerCase(Locale.ROOT)
                        : "";
        String tld;
        int domainIdx;
        if (ALLOWED_TLDS.contains(last) && labels[labels.length - 2].length() > 2) {
            tld = last;
            domainIdx = labels.length - 2;
        } else if (ALLOWED_TLDS.contains(lastTwo) && labels.length >= 3) {
            tld = lastTwo;
            domainIdx = labels.length - 3;
        } else {
            return null;
        }
        String domainLabel = labels[domainIdx].toLowerCase(Locale.ROOT);
        if (domainLabel.length() <= 2 || domainLabel.startsWith("_")) {
            return null;
        }
        if (EXCLUDED_SUFFIXES.contains(tld) || EXCLUDED_DOMAINS.contains(domainLabel)) {
            return null;
        }
        if ("map".equals(tld) && !"js".equals(domainLabel)) {
            return null;
        }
        return "//" + key;
    }

    /**
     * The registrable (apex) domain of {@code host}: its last two labels, unless it ends in a known
     * compound public suffix (e.g. {@code co.uk}), in which case the last three. Single-label hosts
     * ({@code localhost}) return themselves. Case is normalised to lower-case.
     *
     * @param host the host to reduce, may be {@code null}.
     * @return the registrable domain, or {@code null} if the host is invalid or {@code null}.
     */
    static String registrableDomain(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }
        String h = host.toLowerCase(Locale.ROOT);
        String[] labels = h.split("\\.");
        if (labels.length <= 2) {
            return h;
        }
        String lastTwo = labels[labels.length - 2] + "." + labels[labels.length - 1];
        if (COMPOUND_PUBLIC_SUFFIXES.contains(lastTwo)) {
            return labels[labels.length - 3] + "." + lastTwo;
        }
        return lastTwo;
    }

    /**
     * Whether {@code discoveredHost} belongs to the same domain family as {@code baseHost}: it is
     * the same host, a subdomain of it, or shares its registrable domain (e.g. {@code api.example
     * .com} and {@code www.example.com} both belong to {@code example.com}). Used to keep subdomain
     * discovery within the in-scope domain.
     *
     * @param baseHost the (in-scope) source host, may be {@code null}.
     * @param discoveredHost the candidate host, may be {@code null}.
     * @return {@code true} if the candidate belongs to the base host's domain family.
     */
    static boolean isSameDomainFamily(String baseHost, String discoveredHost) {
        return isSameDomainFamily(baseHost, registrableDomain(baseHost), discoveredHost);
    }

    /**
     * As {@link #isSameDomainFamily(String, String)}, with the registrable domain of the base host
     * supplied by the caller: it is the same for every candidate of a response, so it is computed
     * once per response instead of once per candidate.
     *
     * @param baseHost the (in-scope) source host, may be {@code null}.
     * @param baseRegistrableDomain the registrable domain of {@code baseHost}, may be {@code null}.
     * @param discoveredHost the candidate host, may be {@code null}.
     * @return {@code true} if the candidate belongs to the base host's domain family.
     */
    static boolean isSameDomainFamily(
            String baseHost, String baseRegistrableDomain, String discoveredHost) {
        if (baseHost == null || discoveredHost == null) {
            return false;
        }
        String b = baseHost.toLowerCase(Locale.ROOT);
        String d = discoveredHost.toLowerCase(Locale.ROOT);
        if (b.equals(d) || d.endsWith("." + b)) {
            return true;
        }
        String dDomain = registrableDomain(d);
        return dDomain != null && dDomain.equals(baseRegistrableDomain);
    }

    /**
     * Whether {@code host} is a syntactically valid hostname: every dot-separated label must be
     * 1-63 chars, composed of letters/digits/inner hyphens, and must not start or end with a hyphen
     * or underscore. Accepts single-label hosts ({@code localhost}) and dotted-quad IPs.
     *
     * @param host the host to validate, may be {@code null}.
     * @return {@code true} if the host is well-formed.
     */
    static boolean isValidHostname(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        String h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        if (h.length() > 253) {
            return false;
        }
        String[] labels = h.split("\\.", -1);
        if (labels.length == 0) {
            return false;
        }
        for (String label : labels) {
            if (!isValidHostLabel(label)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether {@code label} is a valid hostname label: 1-63 chars of letters/digits/inner hyphens
     * (inner underscores tolerated), not starting or ending with a hyphen or underscore.
     *
     * @param label the label to validate, never {@code null}.
     * @return {@code true} if the label is well-formed.
     */
    private static boolean isValidHostLabel(String label) {
        if (label.isEmpty() || label.length() > 63) {
            return false;
        }
        char first = label.charAt(0);
        char last = label.charAt(label.length() - 1);
        if (first == '-' || last == '-' || first == '_' || last == '_') {
            return false;
        }
        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            if (!((c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '-'
                    || c == '_')) {
                return false;
            }
        }
        return true;
    }

    /**
     * Decodes the encoded forms of '/' ':' '&' '=' '"' and non-breaking space that xnLinkFinder
     * normalises before searching.
     *
     * <p>Every alternative of every mapping contains '%', '&amp;' or a backslash, so a body that
     * contains none of those three characters cannot contain anything to decode and is returned
     * unchanged without running the mappings.
     */
    static String decodeEncodedChars(String body) {
        if (body == null) {
            return "";
        }
        if (body.indexOf('%') == -1 && body.indexOf('&') == -1 && body.indexOf('\\') == -1) {
            return body;
        }
        String decoded = body;
        for (int i = 0; i < ENCODED_CHAR_PATTERNS.length; i++) {
            decoded = ENCODED_CHAR_PATTERNS[i].matcher(decoded).replaceAll(ENCODED_CHAR_MAPPINGS[i][1]);
        }
        return decoded;
    }

    /**
     * Scans HTTP response-header fields for host tokens and returns them prefixed with {@code //}
     * (so they resolve like protocol-relative URLs against the base URL).
     *
     * <p>A wildcard-prefixed entry ({@code *.example.com}) resolves to its base domain
     * ({@code example.com}), which is what a wildcard denotes: that domain and every host under it.
     *
     * <p>Headers whose values are structurally never useful (lengths, dates, encodings, transport
     * directives - see {@link #SKIP_HOST_HEADERS}) are not scanned. Candidates are validated with
     * {@link #isValidHostname} before being returned.
     *
     * @param headers the response-header fields, may be {@code null}.
     * @return the discovered hosts as {@code //host} strings, never {@code null}.
     */
    static Set<String> extractHeaderHosts(List<HttpHeaderField> headers) {
        Set<String> hosts = new LinkedHashSet<>();
        if (headers == null) {
            return hosts;
        }
        for (HttpHeaderField field : headers) {
            if (field == null) {
                continue;
            }
            String name = field.getName();
            String value = field.getValue();
            if (name == null || value == null) {
                continue;
            }
            if (SKIP_HOST_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                continue;
            }
            Matcher m = HEADER_HOST_PATTERN.matcher(value);
            while (m.find()) {
                String host = m.group(2);
                if (host == null || !isValidHostname(host)) {
                    continue;
                }
                hosts.add("//" + host);
            }
        }
        return hosts;
    }

    private static void addCandidate(Set<String> found, String raw) {
        if (raw == null) {
            return;
        }
        String link = raw.trim();
        if (link.isEmpty() || link.length() > MAX_CANDIDATE_LENGTH) {
            return;
        }
        String lower = link.toLowerCase(Locale.ROOT);
        if (lower.startsWith("javascript:")
                || lower.startsWith("data:")
                || lower.startsWith("mailto:")
                || lower.startsWith("tel:")) {
            return;
        }
        if (countNewlines(link) > 1) {
            return;
        }
        if (lower.startsWith("#") && !lower.startsWith("#/")) {
            return;
        }
        if (link.startsWith("$")
                || link.startsWith("\\")
                || link.startsWith("/=")
                || link.startsWith("-")
                || link.startsWith("...")) {
            return;
        }
        if (!isPrintable(link)) {
            return;
        }
        if (WHITESPACE.matcher(link).find()) {
            return;
        }
        if (!HAS_ALNUM.matcher(link).find()) {
            return;
        }
        if (BACKSLASH_S.matcher(link).find()) {
            return;
        }
        if (MIMETYPE_PREFIX.matcher(lower).find()) {
            return;
        }
        if (isJunk(link)) {
            return;
        }
        found.add(link);
    }

    private static int countNewlines(String s) {
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                count++;
            }
        }
        return count;
    }

    private static boolean isPrintable(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isISOControl(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /** True when the candidate (lower-cased, query stripped) contains a known junk token. */
    private static boolean isJunk(String link) {
        String target = link.split("\\?", 2)[0].toLowerCase(Locale.ROOT);
        for (String token : JUNK_TOKENS) {
            if (target.contains(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Creates the placeholder node backing one discovered URL: a history reference (which persists
     * the synthetic request-only message) plus a batched Site tree insertion.
     *
     * @return {@code true} if the entry was created and handed to the Site tree, {@code false} if
     *     nothing was persisted (rate limited, or the history reference could not be created).
     */
    private boolean addPlaceholderNode(
            Session session,
            SiteMap siteTree,
            HostWait hostWait,
            URI uri,
            boolean isNewSubdomain,
            boolean recordInProxyHistory) {
        // Rate limit tree insertions BEFORE anything is persisted: creating the HistoryReference
        // writes a row to the session database, so without this gate a crafted page full of unique
        // URLs could flood the database regardless of how fast the UI can keep up.
        if (!tryAcquireInsertToken()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("LinkExtractor: rate limited, skipping {}", uri);
            }
            return false;
        }

        // Build the synthetic message + HistoryReference on the worker thread (the HistoryReference
        // constructor persists the message to the DB), then mutate the Site tree on the Swing EDT
        // as required by SiteMap.
        final HttpMessage newMsg = new HttpMessage();
        final HistoryReference hr;
        final int historyType = historyTypeFor(recordInProxyHistory);
        try {
            HttpRequestHeader reqHeader = new HttpRequestHeader("GET", uri, "HTTP/1.1");
            newMsg.setRequestHeader(reqHeader);

            // The entry is left with NO response at all: the URL was never requested, so nothing
            // should be shown in the response panel. ZAP persists request-only messages cleanly
            // (the empty response header round-trips through the database without re-parsing), so
            // no placeholder status line is needed - a synthetic "HTTP/1.1 999 ..." header was
            // removed precisely because a fabricated status line cannot survive the DB round-trip.
            //
            // The history type is the option switch: a node always needs a history reference, and
            // that type is what decides whether ZAP's history tab may list this entry (live and on
            // any rebuild of the tab). See historyTypeFor(boolean).
            hr = new HistoryReference(session, historyType, newMsg);
        } catch (Exception e) {
            LOGGER.warn("LinkExtractor: failed to create HistoryReference for {}", uri, e);
            return false;
        }

        String note = NOTE_BODY;
        if (isNewSubdomain) {
            note = NOTE_NEW_SUBDOMAIN_PREFIX + note;
        }
        hr.setNote(note);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "LinkExtractor: HistoryReference {} created for {} note={} type={} ({} history tab)",
                    hr.getHistoryId(),
                    uri,
                    note,
                    historyType,
                    recordInProxyHistory ? "in" : "not in");
        }

        // Close the addPath race window for same-host candidates (see HostWait): the base host node
        // is waited for at most once per response, never per insertion.
        if (!isNewSubdomain) {
            hostWait.ensureHostPresent();
        }
        insertNodeBatched(siteTree, hr, newMsg, recordInProxyHistory);
        return true;
    }

    /**
     * Waits at most once per response for the base host node to be present in the tree.
     *
     * <p>{@code SiteMap.addPath(HistoryReference, HttpMessage)} is not synchronized (only
     * {@code addPath(ref)} is), so a caller inserting at the same moment as the proxy's own
     * {@code addToSiteMap} can race its host creation and end up with two sibling host nodes. The
     * proxy always adds the real (in-scope) message, so for same-host candidates this waits for
     * that host node to appear before we add ours; our own inserts are serialised by
     * {@link #insertNodeBatched}, so we never race each other either.
     *
     * <p>The wait is per response rather than per candidate: the base host is the same for every
     * candidate of a response and its presence is monotonic, so one bounded poll is enough, and a
     * timeout is not retried (otherwise a page whose host node never appears would pay the full
     * timeout once per candidate). The poll runs inline on the worker thread, so no extra thread is
     * created per insertion.
     */
    private static final class HostWait {

        private final SiteMap siteTree;
        private final String baseHost;
        private boolean attempted;

        HostWait(SiteMap siteTree, String baseHost) {
            this.siteTree = siteTree;
            this.baseHost = baseHost;
        }

        void ensureHostPresent() {
            if (attempted || siteTree == null || baseHost == null || baseHost.isEmpty()) {
                return;
            }
            attempted = true;
            URI hostUri;
            try {
                hostUri = new URI(baseHost, false);
            } catch (Exception e) {
                return;
            }
            long deadline = System.currentTimeMillis() + HOST_WAIT_TIMEOUT_MS;
            try {
                while (siteTree.findNode(hostUri) == null) {
                    if (System.currentTimeMillis() >= deadline) {
                        return;
                    }
                    Thread.sleep(HOST_WAIT_POLL_MS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("LinkExtractor: host wait failed for {}", baseHost, e);
                }
            }
        }
    }

    /**
     * Serialises all our tree insertions (SiteMap.addPath(HistoryReference, HttpMessage) is not
     * synchronized, so our own concurrent worker threads could otherwise race each other), then runs
     * the mutation on the Swing EDT using batched updates to prevent UI freezing.
     *
     * @param siteTree the site tree.
     * @param hr the history reference created for the discovered URL.
     * @param msg the (request-only) message the reference was created from.
     * @param recordInProxyHistory whether the entry is also to be recorded in the history tab.
     */
    private static synchronized void insertNodeBatched(
            SiteMap siteTree, HistoryReference hr, HttpMessage msg, boolean recordInProxyHistory) {
        EDT_BATCH.offer(() -> addPath(siteTree, hr, msg, recordInProxyHistory));
        scheduleEdtFlush();
    }

    private static void addPath(
            SiteMap siteTree, HistoryReference hr, HttpMessage msg, boolean recordInProxyHistory) {
        try {
            SiteNode node = siteTree.addPath(hr, msg);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                        "LinkExtractor: addPath result {} for {}",
                        node == null ? "null" : node.getNodeName(),
                        msg.getRequestHeader().getURI());
            }
        } catch (Exception e) {
            LOGGER.warn("LinkExtractor: addPath failed for {}", msg.getRequestHeader().getURI(), e);
            // The reference was already written to the session database; without the node it is an
            // orphan row nothing in the UI can reach, so remove it again.
            try {
                hr.delete();
            } catch (Exception deleteError) {
                LOGGER.warn("LinkExtractor: failed to remove orphaned history entry", deleteError);
            }
            return;
        }

        // The node is in the Site tree; the same entry can now be recorded in the history tab too,
        // so a discovered link or subdomain shows up in both places.
        if (recordInProxyHistory) {
            addToProxyHistory(hr);
        }
    }

    /**
     * Registers an already-created entry with ZAP's history (the <em>history tab</em>).
     *
     * <p>Uses {@link ExtensionHistory#addHistory(HistoryReference)} - the same entry point ZAP's own
     * Requester uses - so the History view owns the update: it marshals the change onto the EDT and
     * applies its own filters. Nothing is sent to the discovered URL, and the entry keeps the
     * "not requested" note. Only called when the option is enabled, i.e. when the reference was
     * created with {@link #HISTORY_TYPE_RECORDED} - the type itself is what keeps the entry in the
     * history tab across rebuilds of that view.
     *
     * @param hr the history reference created for the discovered URL.
     */
    private static void addToProxyHistory(HistoryReference hr) {
        try {
            ExtensionHistory history = getHistoryExtension();
            if (history == null) {
                return;
            }
            history.addHistory(hr);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                        "LinkExtractor: added HistoryReference {} to the history tab",
                        hr.getHistoryId());
            }
        } catch (Throwable t) {
            LOGGER.warn("LinkExtractor: failed to add {} to the history tab", hr.getURI(), t);
        }
    }

    /**
     * The ZAP History extension, resolved on first use (it is a core extension, but it is not
     * guaranteed to be present in headless/test runs).
     *
     * @return the History extension, or {@code null} if it is not available.
     */
    private static ExtensionHistory getHistoryExtension() {
        ExtensionHistory ext = historyExtension;
        if (ext != null) {
            return ext;
        }
        try {
            Control control = Control.getSingleton();
            if (control == null) {
                return null;
            }
            ext = control.getExtensionLoader().getExtension(ExtensionHistory.class);
        } catch (Throwable t) {
            LOGGER.debug("LinkExtractor: History extension not available", t);
            return null;
        }
        if (ext != null) {
            historyExtension = ext;
        }
        return ext;
    }
}
