package org.zaproxy.addon.linkextractor;

import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

/**
 * Options for the {@link LinkExtractorNetworkListener}.
 *
 * <p>Two toggles are exposed under <em>Tools &gt; Options &gt; Sites tree</em>:
 *
 * <ul>
 *   <li>{@link #isParseJavascript()} - whether JS-specific extraction patterns (fetch/axios/XHR/
 *       template literals, bare API path literals, ...) are run against response bodies.
 *   <li>{@link #isDiscoverSubdomains()} - whether cross-host links discovered on an in-scope page
 *       are added to the Sites tree as new (folder) subdomain nodes.
 * </ul>
 *
 * <p>The fields are {@code volatile} because they are written on the Swing EDT (options panel) and
 * read concurrently from the network/worker threads of the listener.
 */
public class LinkExtractorOptionsParam extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(LinkExtractorOptionsParam.class);

    private static final String BASE_KEY = "linkextractor";

    private static final String PARSE_JAVASCRIPT_KEY = BASE_KEY + ".parseJavascript";
    private static final String DISCOVER_SUBDOMAINS_KEY = BASE_KEY + ".discoverSubdomains";

    private static final int CURRENT_VERSION = 1;

    private volatile boolean parseJavascript = true;
    private volatile boolean discoverSubdomains = true;

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
        // No versioned updates needed yet.
    }
}