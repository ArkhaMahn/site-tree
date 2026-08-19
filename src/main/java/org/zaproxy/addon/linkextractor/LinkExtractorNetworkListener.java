package org.zaproxy.addon.linkextractor;

import java.awt.EventQueue;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteMapEventPublisher;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.network.HttpSenderListener;

/**
 * Network-layer Burp-style link extraction for the Sites tree.
 *
 * <p>Hooks the network layer via {@link HttpSenderListener} so that every response ZAP receives
 * (proxied browsing, spider, AJAX spider, active scan, manual requests) is inspected the moment it
 * arrives - on the request/proxy thread, before the message is saved to history - with no dependency
 * on the passive scan queue or any scan rule priority. If the source URL is in the session scope,
 * the add-on fires immediately and populates the Sites tree.
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
 *   <li>Entries are written with {@link HistoryReference#TYPE_ZAP_USER} (distinct icon) and a Note
 *       flagging them as not-yet-requested.
 *   <li>Scope is delegated entirely to ZAP's own session/context scope engine.
 * </ul>
 *
 * <p>Safety (a network-layer hook must never disturb the request/response flow):
 * <ul>
 *   <li>Only cheap gate checks (empty body, content type, source scope) and a body-byte snapshot
 *       run on the network thread; the (potentially expensive) body decoding, parsing and insertion
 *       happen on a single daemon worker thread. If the pool is saturated the parse is dropped
 *       rather than run inline.
 *   <li>A per-session dedup set avoids re-processing URLs that have already been inserted, so
 *       repeated traffic (e.g. an active scan hitting the same endpoints) does not spam the tree.
 *       The set is reset whenever site-tree nodes are removed (e.g. the user deletes nodes or
 *       refreshes the tree), so a deleted node is re-discovered on the next visit.
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

    private static final int MAX_SEEN = 50000;

    private static final Pattern TEMPLATE_LITERAL = Pattern.compile("`([^`]*\\$\\{[^`]*\\}[^`]*)`");

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

    // Well-known third-party / framework hosts and paths that add no value to the Sites tree
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

    // A single hostname label: starts and ends with an alphanumeric (or non-ASCII letter/digit) and
    // may only contain hyphens/underscores inside. This rejects labels that begin or end with '-'
    // (e.g. "-api" or "api-"), which are not valid DNS hostnames.
    private static final String HOST_LABEL =
            "[a-zA-Z0-9\\u0080-\\uFFFF](?:[a-zA-Z0-9\\u0080-\\uFFFF_-]*[a-zA-Z0-9\\u0080-\\uFFFF])?";

    // Matches bare "host.label.tld" strings (any number of subdomain labels + optional path). The
    // negative lookbehind avoids re-matching inside "scheme://host" or after a path separator where
    // the bare-http/protocol-relative patterns already own the find. Candidates are validated
    // against ALLOWED_TLDS by validateDomainCandidate(); per-label hostname syntax is enforced by
    // isValidHostname(). Depth is unbounded so deeply nested subdomains are never truncated away.
    private static final Pattern DOMAIN_URL =
            Pattern.compile(
                    "(?<![\\w.:/])(?:"
                            + HOST_LABEL
                            + "\\.)*"
                            + HOST_LABEL
                            + "\\.[a-zA-Z]{2,24}(?:/[^\\s\"'<>()\\[\\]{}]{0,500})?");

    private static final List<Pattern> HTML_PATTERNS = buildHtmlPatterns();

    // JS-specific patterns; gated behind the "Parse JavaScript" option in Tools > Options >
    // Sites tree.
    private static final List<Pattern> JS_PATTERNS = buildJsPatterns();

    // URLs already inserted for the current session (dedup across network threads).
    private static final Set<String> SEEN = ConcurrentHashMap.newKeySet();
    private static long currentSessionId = -1L;

    private final LinkExtractorOptionsParam options;
    private final ExecutorService pool;

    public LinkExtractorNetworkListener(LinkExtractorOptionsParam options) {
        this.options = options;
        this.pool = createPool(options.getThreads());
    }

    // Daemon worker pool (the add-on is passive); default AbortPolicy on purpose - a saturated
    // queue DROPS the parse rather than running it inline on the network/proxy thread.
    private ExecutorService createPool(int threads) {
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
        patterns.add(Pattern.compile("(?is)<meta[^>]*?url\\s*=\\s*([^\"'#\\s>]+)"));
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
                                + ")*\\.[a-zA-Z]{2,}[^\\s\"'<>)]*)"));

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
        patterns.add(Pattern.compile("\\$\\.ajax\\(\\s*\\{[^}]*?url\\s*:\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)); // $.ajax({ url: "..." })
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
            if (msg.getResponseBody().length() == 0) {
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

            // Snapshot the body bytes and its charset on the network thread (getBytes() returns a
            // reference to the message's internal array, which the proxy may mutate afterwards) and
            // decode/parse on the worker so a large body never stalls the request/response flow.
            final byte[] bodyBytes = msg.getResponseBody().getBytes();
            if (bodyBytes == null) {
                return;
            }
            final byte[] bodySnapshot = Arrays.copyOf(bodyBytes, msg.getResponseBody().length());
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
     * deletes nodes from the Sites tree or the tree is refreshed. The per-session dedup set is
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
     * <p>Only ever invoked when the user removes nodes from the Sites tree (or the tree is
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
            LOGGER.info(
                    "LinkExtractor: parsed {} bytes, found {} candidates from {}",
                    bodyBytes.length,
                    found.size(),
                    baseUrlStr);
            if (found.isEmpty()) {
                return;
            }

            SiteMap siteTree = session.getSiteTree();

            for (String raw : found) {
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
                // start or end with '-'), so invalid "subdomains" never reach the Sites tree.
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

                // Subdomain discovery toggle (Tools > Options > Sites tree): with it off, only
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
                    continue;
                }

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "LinkExtractor: adding placeholder node for {} {}",
                            resolved,
                            isNewSubdomain ? "(new subdomain)" : "");
                }
                addPlaceholderNode(session, siteTree, targetUri, isNewSubdomain, baseUrlStr);
            }
        } catch (Throwable t) {
            LOGGER.warn("LinkExtractor: processResponse error for {}", baseUrlStr, t);
        }
    }

    /**
     * Resets the dedup set when a new session is loaded or when it grows beyond the cap.
     *
     * @param session the current session.
     */
    private static void dedupe(Session session) {
        long sessionId = session.getSessionId();
        synchronized (SEEN) {
            if (currentSessionId != sessionId) {
                currentSessionId = sessionId;
                SEEN.clear();
            } else if (SEEN.size() > MAX_SEEN) {
                SEEN.clear();
            }
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
                candidate = candidate.replaceAll("\\$\\{[^}]*\\}", "__DYNAMIC__");
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
        link = link.replace("\\n", "").replace("\\r", "").replace("\\.", ".");
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

        // Trailing backslashes, then '>', ';', ','.
        link = link.replaceAll("\\\\+$", "");
        link = link.replaceAll("[>;,]+$", "");

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
     */
    static String decodeEncodedChars(String body) {
        if (body == null) {
            return "";
        }
        String decoded = body;
        for (String[] mapping : ENCODED_CHAR_MAPPINGS) {
            decoded = decoded.replaceAll("(?i)" + mapping[0], mapping[1]);
        }
        return decoded;
    }

    private static void addCandidate(Set<String> found, String raw) {
        if (raw == null) {
            return;
        }
        String link = raw.trim();
        if (link.isEmpty() || link.length() > 2000) {
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

    private static void addPlaceholderNode(
            Session session, SiteMap siteTree, URI uri, boolean isNewSubdomain, String baseUrlStr) {
        // Build the synthetic message + HistoryReference on the worker thread (the HistoryReference
        // constructor persists the message to the DB), then mutate the Sites tree on the Swing EDT
        // as required by SiteMap.
        final HttpMessage newMsg = new HttpMessage();
        final HistoryReference hr;
        try {
            HttpRequestHeader reqHeader = new HttpRequestHeader("GET", uri, "HTTP/1.1");
            newMsg.setRequestHeader(reqHeader);

            // The entry is left with NO response at all: the URL was never requested, so nothing
            // should be shown in the response panel. ZAP persists request-only messages cleanly
            // (the empty response header round-trips through the database without re-parsing), so
            // no placeholder status line is needed - a synthetic "HTTP/1.1 999 ..." header was
            // removed precisely because a fabricated status line cannot survive the DB round-trip.
            hr = new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, newMsg);
        } catch (Exception e) {
            LOGGER.warn("LinkExtractor: failed to create HistoryReference for {}", uri, e);
            return;
        }

        String note = NOTE_BODY;
        if (isNewSubdomain) {
            note = NOTE_NEW_SUBDOMAIN_PREFIX + note;
        }
        hr.setNote(note);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "LinkExtractor: HistoryReference {} created for {} note={}",
                    hr.getHistoryId(),
                    uri,
                    note);
        }

        // SiteMap.addPath(HistoryReference, HttpMessage) is NOT synchronized (only addPath(ref) is),
        // so a caller inserting at the same moment as the proxy's own addToSiteMap can race its host
        // creation and end up with two sibling host nodes. The proxy always adds the real message,
        // so for same-host candidates we first wait for that host node to appear before inserting;
        // insertNode then serialises all our own inserts so we never race ourselves either.
        if (!isNewSubdomain) {
            waitForHost(siteTree, baseUrlStr);
        }
        insertNode(siteTree, hr, newMsg);
    }

    /**
     * Blocks the current thread until the base host of {@code hostUrl} is present in the tree, or a
     * bounded timeout elapses. The proxy inserts the real (in-scope) message right after the
     * response, so for same-host candidates this guarantees ZAP's host node exists before we add
     * ours, closing the addPath race window.
     *
     * @param siteTree the site tree.
     * @param hostUrl the base URL whose host node should appear.
     * @return {@code true} if the host appeared in time, {@code false} if the timeout elapsed.
     */
    private static boolean waitForHost(SiteMap siteTree, String hostUrl) {
        try {
            URI hostUri = new URI(hostUrl, false);
            long deadline = System.currentTimeMillis() + 1500L;
            while (System.currentTimeMillis() < deadline) {
                if (siteTree.findNode(hostUri) != null) {
                    return true;
                }
                try {
                    Thread.sleep(20);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Serialises all our tree insertions (SiteMap.addPath(HistoryReference, HttpMessage) is not
     * synchronized, so our own concurrent worker threads could otherwise race each other), then runs
     * the mutation on the Swing EDT when a view is present.
     */
    private static synchronized void insertNode(SiteMap siteTree, HistoryReference hr, HttpMessage msg) {
        if (!View.isInitialised() || EventQueue.isDispatchThread()) {
            addPath(siteTree, hr, msg);
        } else {
            EventQueue.invokeLater(() -> addPath(siteTree, hr, msg));
        }
    }

    private static void addPath(SiteMap siteTree, HistoryReference hr, HttpMessage msg) {
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
        }
    }
}