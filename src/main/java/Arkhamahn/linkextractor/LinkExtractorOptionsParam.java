package Arkhamahn.linkextractor;

import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

/**
 * Options for the {@link LinkExtractorNetworkListener}.
 *
 * <p>Four toggles are exposed under <em>Tools &gt; Options &gt; Site tree</em>:
 *
 * <ul>
 *   <li>{@link #isParseJavascript()} - whether JS-specific extraction patterns (fetch/axios/XHR/
 *       template literals, bare API path literals, ...) are run against response bodies.
 *   <li>{@link #isDiscoverSubdomains()} - whether cross-host links discovered on an in-scope page
 *       are added to the Site tree as new (folder) subdomain nodes.
 *   <li>{@link #isDiscoverSubdomainsFromHeaders()} - whether hostnames found in HTTP response
 *       headers (e.g. CSP, Link, Set-Cookie, Content-Location) are added as new subdomain nodes,
 *       honouring wildcard entries such as {@code *.example.com}.
 *   <li>{@link #isRecordInProxyHistory()} - whether the discovered links and subdomains are also
 *       recorded in the history tab, not only in the Site tree.
 * </ul>
 *
 * <p>Two numeric options bound the work instead: {@link #getThreads()} (worker concurrency) and
 * {@link #getMaxBodySizeMb()} (the largest response body that is scanned at all).
 *
 * <p>The fields are {@code volatile} because they are written on the Swing EDT (options panel) and
 * read concurrently from the network/worker threads of the listener.
 */
public class LinkExtractorOptionsParam extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(LinkExtractorOptionsParam.class);

    private static final String BASE_KEY = "linkextractor";

    private static final String PARSE_JAVASCRIPT_KEY = BASE_KEY + ".parseJavascript";
    private static final String DISCOVER_SUBDOMAINS_KEY = BASE_KEY + ".discoverSubdomains";
    private static final String DISCOVER_SUBDOMAINS_HEADERS_KEY =
            BASE_KEY + ".discoverSubdomainsFromHeaders";
    private static final String RECORD_IN_PROXY_HISTORY_KEY = BASE_KEY + ".recordInProxyHistory";
    private static final String THREADS_KEY = BASE_KEY + ".threads";
    private static final String MAX_BODY_SIZE_MB_KEY = BASE_KEY + ".maxBodySizeMb";

    private static final int CURRENT_VERSION = 3;
    private static final int DEFAULT_THREADS = 2;
    public static final int MIN_THREADS = 2;
    public static final int MAX_THREADS = 8;

    /**
     * Default upper bound, in megabytes, on the size of a response body that is scanned at all.
     *
     * <p>The body is copied on the network thread and decoded to a String on a worker, and the
     * decoders can hold several more copies of it, so an unbounded body is the one remaining input
     * that a hostile page can use to turn this hook into memory and stall pressure. 5 MB covers
     * realistic HTML, JSON, CSS and JS bundles; anything larger is usually a download, a media file
     * or a source map, none of which are link sources.
     */
    public static final int DEFAULT_MAX_BODY_SIZE_MB = 5;

    /** Smallest selectable limit: 1 MB. */
    public static final int MIN_MAX_BODY_SIZE_MB = 1;

    /**
     * Largest selectable limit: 100 MB. Bounded so the option cannot be used to switch the gate off
     * and make the copy unbounded again.
     */
    public static final int MAX_MAX_BODY_SIZE_MB = 100;

    private static final long BYTES_PER_MB = 1024L * 1024L;

    // Off by default: the history tab is a shared log of what ZAP actually handled, and every
    // discovered entry would show up there as a request that was never sent.
    private static final boolean DEFAULT_RECORD_IN_PROXY_HISTORY = false;

    private volatile boolean parseJavascript = true;
    private volatile boolean discoverSubdomains = true;
    private volatile boolean discoverSubdomainsFromHeaders = true;
    private volatile boolean recordInProxyHistory = DEFAULT_RECORD_IN_PROXY_HISTORY;
    private volatile int threads = DEFAULT_THREADS;
    private volatile int maxBodySizeMb = DEFAULT_MAX_BODY_SIZE_MB;

    public boolean isParseJavascript() {
        return parseJavascript;
    }

    public void setParseJavascript(boolean parseJavascript) {
        this.parseJavascript = parseJavascript;
        getConfig().setProperty(PARSE_JAVASCRIPT_KEY, parseJavascript);
    }

    public boolean isDiscoverSubdomains() {
        return discoverSubdomains;
    }

    public void setDiscoverSubdomains(boolean discoverSubdomains) {
        this.discoverSubdomains = discoverSubdomains;
        getConfig().setProperty(DISCOVER_SUBDOMAINS_KEY, discoverSubdomains);
    }

    public boolean isDiscoverSubdomainsFromHeaders() {
        return discoverSubdomainsFromHeaders;
    }

    public void setDiscoverSubdomainsFromHeaders(boolean discoverSubdomainsFromHeaders) {
        this.discoverSubdomainsFromHeaders = discoverSubdomainsFromHeaders;
        getConfig().setProperty(DISCOVER_SUBDOMAINS_HEADERS_KEY, discoverSubdomainsFromHeaders);
    }

    public boolean isRecordInProxyHistory() {
        return recordInProxyHistory;
    }

    public void setRecordInProxyHistory(boolean recordInProxyHistory) {
        this.recordInProxyHistory = recordInProxyHistory;
        getConfig().setProperty(RECORD_IN_PROXY_HISTORY_KEY, recordInProxyHistory);
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = Math.max(MIN_THREADS, Math.min(MAX_THREADS, threads));
        getConfig().setProperty(THREADS_KEY, this.threads);
    }

    /**
     * The largest response body that is scanned, in megabytes.
     *
     * @return the configured limit, always within {@link #MIN_MAX_BODY_SIZE_MB} and {@link
     *     #MAX_MAX_BODY_SIZE_MB}.
     */
    public int getMaxBodySizeMb() {
        return maxBodySizeMb;
    }

    public void setMaxBodySizeMb(int maxBodySizeMb) {
        this.maxBodySizeMb =
                Math.max(MIN_MAX_BODY_SIZE_MB, Math.min(MAX_MAX_BODY_SIZE_MB, maxBodySizeMb));
        getConfig().setProperty(MAX_BODY_SIZE_MB_KEY, this.maxBodySizeMb);
    }

    /**
     * {@link #getMaxBodySizeMb()} in bytes, i.e. the form the network-thread gate compares against.
     *
     * @return the scan limit in bytes.
     */
    public long getMaxBodyBytes() {
        return maxBodySizeMb * BYTES_PER_MB;
    }

    @Override
    protected void parseImpl() {
        try {
            parseJavascript = getBoolean(PARSE_JAVASCRIPT_KEY, true);
        } catch (ConversionException e) {
            LOGGER.error("Failed to read option {}", PARSE_JAVASCRIPT_KEY, e);
        }

        try {
            discoverSubdomains = getBoolean(DISCOVER_SUBDOMAINS_KEY, true);
        } catch (ConversionException e) {
            LOGGER.error("Failed to read option {}", DISCOVER_SUBDOMAINS_KEY, e);
        }

        try {
            discoverSubdomainsFromHeaders = getBoolean(DISCOVER_SUBDOMAINS_HEADERS_KEY, true);
        } catch (ConversionException e) {
            LOGGER.error("Failed to read option {}", DISCOVER_SUBDOMAINS_HEADERS_KEY, e);
        }

        try {
            recordInProxyHistory =
                    getBoolean(RECORD_IN_PROXY_HISTORY_KEY, DEFAULT_RECORD_IN_PROXY_HISTORY);
        } catch (ConversionException e) {
            LOGGER.error("Failed to read option {}", RECORD_IN_PROXY_HISTORY_KEY, e);
        }

        try {
            int t = getInt(THREADS_KEY, DEFAULT_THREADS);
            threads = Math.max(MIN_THREADS, t);
        } catch (ConversionException e) {
            LOGGER.error("Failed to read option {}", THREADS_KEY, e);
        }

        try {
            int mb = getInt(MAX_BODY_SIZE_MB_KEY, DEFAULT_MAX_BODY_SIZE_MB);
            maxBodySizeMb = Math.max(MIN_MAX_BODY_SIZE_MB, Math.min(MAX_MAX_BODY_SIZE_MB, mb));
        } catch (ConversionException e) {
            LOGGER.error("Failed to read option {}", MAX_BODY_SIZE_MB_KEY, e);
        }
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        if (fileVersion < 3) {
            // v3 added the maximum body size to scan. Configs from before it have no such key, so
            // the default is written out instead of being left to parseImpl()'s in-memory fallback.
            getConfig().setProperty(MAX_BODY_SIZE_MB_KEY, DEFAULT_MAX_BODY_SIZE_MB);
        }
    }
}