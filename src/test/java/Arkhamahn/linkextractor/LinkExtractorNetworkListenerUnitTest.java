package Arkhamahn.linkextractor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteMapEventPublisher;
import org.parosproxy.paros.network.HttpHeaderField;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class LinkExtractorNetworkListenerUnitTest {

    private static LinkExtractorOptionsParam createOptions() {
        LinkExtractorOptionsParam options = new LinkExtractorOptionsParam();
        // Don't call parseImpl() as it reads from config; just use defaults
        return options;
    }

    @Test
    void shouldNotRecordInProxyHistoryByDefault() {
        LinkExtractorOptionsParam options = createOptions();
        options.load(new ZapXmlConfiguration());

        assertFalse(options.isRecordInProxyHistory());
    }

    @Test
    void shouldPersistRecordInProxyHistoryOption() {
        LinkExtractorOptionsParam options = createOptions();
        options.load(new ZapXmlConfiguration());
        options.setRecordInProxyHistory(true);
        assertTrue(options.isRecordInProxyHistory());

        LinkExtractorOptionsParam reloaded = createOptions();
        reloaded.load(options.getConfig());

        assertTrue(reloaded.isRecordInProxyHistory());
    }

    @Test
    void shouldUseZapUserHistoryTypeWhenRecordingInHistoryTab() {
        assertEquals(
                HistoryReference.TYPE_ZAP_USER, LinkExtractorNetworkListener.historyTypeFor(true));
    }

    /**
     * The body of a response is snapshotted on the network thread and decoded on a worker, so the
     * size of that body is the one input that could still be made arbitrarily large. The limit is an
     * option, so it must round-trip through the configuration and stay inside its documented range.
     */
    @Test
    void shouldDefaultTheMaxBodyScanLimitToFiveMegabytes() {
        LinkExtractorOptionsParam options = createOptions();
        options.load(new ZapXmlConfiguration());

        assertEquals(5, options.getMaxBodySizeMb());
        assertEquals(5L * 1024 * 1024, options.getMaxBodyBytes());
    }

    @Test
    void shouldPersistMaxBodySizeOption() {
        LinkExtractorOptionsParam options = createOptions();
        options.load(new ZapXmlConfiguration());
        options.setMaxBodySizeMb(12);
        assertEquals(12, options.getMaxBodySizeMb());
        assertEquals(12L * 1024 * 1024, options.getMaxBodyBytes());

        LinkExtractorOptionsParam reloaded = createOptions();
        reloaded.load(options.getConfig());

        assertEquals(12, reloaded.getMaxBodySizeMb());
    }

    @Test
    void shouldClampMaxBodySizeToItsRange() {
        LinkExtractorOptionsParam options = createOptions();
        options.load(new ZapXmlConfiguration());

        options.setMaxBodySizeMb(0);
        assertEquals(LinkExtractorOptionsParam.MIN_MAX_BODY_SIZE_MB, options.getMaxBodySizeMb());

        options.setMaxBodySizeMb(9999);
        assertEquals(LinkExtractorOptionsParam.MAX_MAX_BODY_SIZE_MB, options.getMaxBodySizeMb());

        // A limit out of range in the configuration is clamped on load, not just on set.
        options.getConfig().setProperty("linkextractor.maxBodySizeMb", 0);
        options.load(options.getConfig());
        assertEquals(LinkExtractorOptionsParam.MIN_MAX_BODY_SIZE_MB, options.getMaxBodySizeMb());
    }

    @Test
    void shouldUseHiddenHistoryTypeWhenNotRecordingInHistoryTab() {
        assertEquals(
                HistoryReference.TYPE_HIDDEN, LinkExtractorNetworkListener.historyTypeFor(false));
    }

    /**
     * The body-size gate decides, on the network thread, whether a body is ever copied and decoded.
     * A body of exactly the configured limit must still be scanned, and the limit has to be usable
     * for the whole option range rather than only the default.
     */
    @Test
    void shouldOnlySkipBodiesOverTheConfiguredLimit() {
        long limit = LinkExtractorOptionsParam.DEFAULT_MAX_BODY_SIZE_MB * 1024L * 1024L;

        assertTrue(LinkExtractorNetworkListener.isBodyWithinScanLimit(1, limit));
        assertTrue(LinkExtractorNetworkListener.isBodyWithinScanLimit((int) limit - 1, limit));
        assertTrue(LinkExtractorNetworkListener.isBodyWithinScanLimit((int) limit, limit));
        assertFalse(LinkExtractorNetworkListener.isBodyWithinScanLimit((int) limit + 1, limit));

        // The gate honours the whole option range, not just the default: exactly the largest
        // supported limit is still scanned, one byte more is not.
        long maxLimit = LinkExtractorOptionsParam.MAX_MAX_BODY_SIZE_MB * 1024L * 1024L;
        assertTrue(LinkExtractorNetworkListener.isBodyWithinScanLimit((int) maxLimit, maxLimit));
        assertFalse(LinkExtractorNetworkListener.isBodyWithinScanLimit((int) maxLimit + 1, maxLimit));
    }

    /**
     * The saturation gate drops a response before the body snapshot when the parse queue is already
     * this deep, so the depth at which it starts dropping is part of the add-on's behaviour.
     */
    @Test
    void shouldDropResponsesOnceTheParseQueueIsFull() {
        assertFalse(LinkExtractorNetworkListener.isParseQueueFull(0));
        assertFalse(LinkExtractorNetworkListener.isParseQueueFull(15));
        assertTrue(LinkExtractorNetworkListener.isParseQueueFull(16));
        assertTrue(LinkExtractorNetworkListener.isParseQueueFull(17));
        assertTrue(LinkExtractorNetworkListener.isParseQueueFull(10_000));
    }

    /**
     * The configuration carries a version so a later release can tell which keys a config predates.
     * A config written before the body limit existed must therefore be recognised as older and get
     * the default limit written into it, rather than relying on a value that is only in memory.
     */
    @Test
    void shouldWriteTheDefaultBodyLimitWhenMigratingAnOlderConfig() {
        LinkExtractorOptionsParam options = createOptions();
        options.load(new ZapXmlConfiguration());

        assertEquals(3, options.getCurrentVersion());

        options.updateConfigsImpl(2);
        assertEquals(
                LinkExtractorOptionsParam.DEFAULT_MAX_BODY_SIZE_MB,
                options.getConfig().getInt("linkextractor.maxBodySizeMb", -1));
    }

    /**
     * The insertion token bucket is checked before anything is persisted, so it has to actually deny
     * once it is empty. It previously clamped an empty bucket to 0 and then tested the result
     * against 0, so every single request was granted a token and nothing was ever rate limited.
     */
    @Test
    void shouldDenyInsertionsOnceTheTokenBucketIsEmpty() {
        LinkExtractorNetworkListener listener =
                new LinkExtractorNetworkListener(createOptions());
        // Shut the listener down first: the token refill scheduler would otherwise top the bucket
        // back up (correctly) while the test is looping.
        listener.shutdown();
        listener.setInsertTokens(0);

        for (int i = 0; i < 1000; i++) {
            assertFalse(listener.acquireInsertToken(), "empty bucket must deny insertion " + i);
        }
        assertEquals(0, listener.availableInsertTokens());
    }

    @Test
    void shouldGrantExactlyTheAvailableInsertTokens() {
        LinkExtractorNetworkListener listener =
                new LinkExtractorNetworkListener(createOptions());
        listener.shutdown();
        listener.setInsertTokens(3);

        assertTrue(listener.acquireInsertToken());
        assertTrue(listener.acquireInsertToken());
        assertTrue(listener.acquireInsertToken());
        assertFalse(listener.acquireInsertToken());
        assertEquals(0, listener.availableInsertTokens());
    }

    /**
     * The "&lt;meta ... url=" and "$.ajax({... url:" patterns used unbounded lazy runs whose
     * terminator may be absent (an unclosed tag/brace), which makes every start offset re-scan to
     * the end of the body: quadratic work a crafted page can trigger at will. The runs are bounded
     * now, so such a body must be processed quickly, while the real-world forms still extract.
     */
    @Test
    void shouldStayFastOnCraftedUnclosedMetaAndAjaxBodies() {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 24000; i++) {
            body.append("<meta name=x ");
            body.append("$.ajax({xxxxxxxx");
        }

        long start = System.nanoTime();
        Set<String> found = LinkExtractorNetworkListener.extractCandidates(body.toString());
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        // The unbounded patterns need ~50s for a body of this size (measured), so the 10s budget
        // below fails loudly if the bound is ever dropped again, while passing comfortably on a
        // slow machine with the bound in place.
        assertTrue(elapsedMs < 10_000, "crafted body took " + elapsedMs + "ms");
        assertTrue(found.isEmpty(), "no real candidate in the crafted body, got: " + found);
    }

    @Test
    void shouldStillExtractMetaRefreshAndAjaxUrls() {
        Set<String> meta =
                LinkExtractorNetworkListener.extractCandidates(
                        "<meta http-equiv=\"refresh\" content=\"0;url=/login\">");
        assertTrue(meta.contains("/login"), "meta refresh url not extracted, got: " + meta);

        Set<String> ajax =
                LinkExtractorNetworkListener.extractCandidates(
                        "$.ajax({ url: \"/api/items\", type: \"GET\" });");
        assertTrue(ajax.contains("/api/items"), "$.ajax url not extracted, got: " + ajax);
    }

    /**
     * Trailing backslashes and trailing {@code >;,} are stripped from every normalised candidate.
     * That used to be done with two {@code String.replaceAll} calls, which re-compiled both patterns
     * for every candidate; the character-loop version must behave identically.
     */
    @Test
    void shouldStripTrailingGarbageFromCandidates() {
        Set<String> found =
                LinkExtractorNetworkListener.extractCandidates(
                        "body{background:url(/static/app.css;)}"
                                + "body{background:url(/static/other.css>)}"
                                + "body{background:url(/static/third.css,)}"
                                + "body{background:url(/static/fourth.css\\)}");

        assertTrue(found.contains("/static/app.css"), "trailing ';' not stripped, got: " + found);
        assertTrue(found.contains("/static/other.css"), "trailing '>' not stripped, got: " + found);
        assertTrue(found.contains("/static/third.css"), "trailing ',' not stripped, got: " + found);
        assertTrue(found.contains("/static/fourth.css"), "trailing '\\' not stripped, got: " + found);
    }

    /**
     * The registrable domain of the source host is constant for a whole response and is now passed
     * into the family check pre-computed; the overload must agree with the two-argument version.
     */
    @Test
    void shouldAgreeOnDomainFamilyWhenBaseRegistrableDomainIsPrecomputed() {
        String[][] same = {
            {"www.example.com", "api.example.com"},
            {"example.com", "deep.sub.example.com"},
            {"www.example.co.uk", "shop.example.co.uk"},
            {"a.b.example.com", "example.com"},
        };
        for (String[] pair : same) {
            assertTrue(
                    LinkExtractorNetworkListener.isSameDomainFamily(pair[0], pair[1]),
                    pair[0] + " should share a family with " + pair[1]);
            assertTrue(
                    LinkExtractorNetworkListener.isSameDomainFamily(
                            pair[0], LinkExtractorNetworkListener.registrableDomain(pair[0]), pair[1]),
                    "pre-computed registrable domain changed the result for " + pair[0] + "/" + pair[1]);
        }

        String[][] different = {
            {"example.com", "example.org"},
            {"example.com", "notexample.com"},
            {"example.co.uk", "example.com"},
        };
        for (String[] pair : different) {
            assertFalse(
                    LinkExtractorNetworkListener.isSameDomainFamily(pair[0], pair[1]),
                    pair[0] + " should not share a family with " + pair[1]);
            assertFalse(
                    LinkExtractorNetworkListener.isSameDomainFamily(
                            pair[0], LinkExtractorNetworkListener.registrableDomain(pair[0]), pair[1]),
                    "pre-computed registrable domain changed the result for " + pair[0] + "/" + pair[1]);
        }
    }

    /**
     * The history tab is not only fed by {@code ExtensionHistory.addHistory(...)}: it is rebuilt from
     * the session history by {@code ExtensionHistory.getHistoryIds()}, which selects the proxied,
     * ZAP-user and proxy-connect types. An entry of any other type can therefore never be listed,
     * which is what makes the option hold - this test pins the type sets the add-on relies on.
     */
    @Test
    void shouldOnlyUseHistoryTypesTheHistoryTabCanList() {
        int[] historyTabTypes = {
            HistoryReference.TYPE_PROXIED,
            HistoryReference.TYPE_ZAP_USER,
            HistoryReference.TYPE_PROXY_CONNECT
        };

        assertTrue(contains(historyTabTypes, LinkExtractorNetworkListener.historyTypeFor(true)));
        assertFalse(contains(historyTabTypes, LinkExtractorNetworkListener.historyTypeFor(false)));
    }

    private static boolean contains(int[] values, int value) {
        for (int candidate : values) {
            if (candidate == value) {
                return true;
            }
        }
        return false;
    }

    @Test
    void shouldResetDeduplicationWhenSiteNodeRemoved() {
        LinkExtractorNetworkListener.markSeen("http://example.com/admin");
        assertTrue(LinkExtractorNetworkListener.isSeen("http://example.com/admin"));

        LinkExtractorNetworkListener listener = new LinkExtractorNetworkListener(createOptions());
        listener.eventReceived(
                new Event(
                        SiteMapEventPublisher.getPublisher(),
                        SiteMapEventPublisher.SITE_NODE_REMOVED_EVENT,
                        new Target()));

        assertFalse(LinkExtractorNetworkListener.isSeen("http://example.com/admin"));
    }

    @Test
    void shouldResetDeduplicationWhenWholeSiteRemoved() {
        LinkExtractorNetworkListener.markSeen("http://example.com/admin");
        assertTrue(LinkExtractorNetworkListener.isSeen("http://example.com/admin"));

        LinkExtractorNetworkListener listener = new LinkExtractorNetworkListener(createOptions());
        listener.eventReceived(
                new Event(
                        SiteMapEventPublisher.getPublisher(),
                        SiteMapEventPublisher.SITE_REMOVED_EVENT,
                        new Target()));

        assertFalse(LinkExtractorNetworkListener.isSeen("http://example.com/admin"));
    }

    @Test
    void shouldNotResetDeduplicationForUnrelatedEvents() {
        LinkExtractorNetworkListener.markSeen("http://example.com/admin");
        assertTrue(LinkExtractorNetworkListener.isSeen("http://example.com/admin"));

        LinkExtractorNetworkListener listener = new LinkExtractorNetworkListener(createOptions());
        listener.eventReceived(
                new Event(
                        SiteMapEventPublisher.getPublisher(),
                        SiteMapEventPublisher.SITE_NODE_ADDED_EVENT,
                        new Target()));

        assertTrue(LinkExtractorNetworkListener.isSeen("http://example.com/admin"));
    }

    @Test
    void shouldExtractLinksFromHtmlAttributes() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "<a href=\"/profile\">x</a><link rel=\"stylesheet\" href=\"/static/css/app.css\">"
                                + "<form action=\"/login\"></form><script src=\"https://cdn.example.com/lib.js\"></script>");

        assertTrue(candidates.contains("/profile"));
        assertTrue(candidates.contains("/static/css/app.css"));
        assertTrue(candidates.contains("/login"));
        assertTrue(candidates.contains("https://cdn.example.com/lib.js"));
    }

    @Test
    void shouldExtractJsEndpointLiteralsAndTemplateUrls() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "fetch('/api/v1/session'); axios.get(\"/api/v1/users\"); "
                                + "location.href = '/logout'; window.open('/admin'); "
                                + "const u = `/api/v1/items/${id}/edit`; "
                                + "const conf = { route: \"/api/v1/items/{id}\" };");

        assertTrue(candidates.contains("/api/v1/session"));
        assertTrue(candidates.contains("/api/v1/users"));
        assertTrue(candidates.contains("/logout"));
        assertTrue(candidates.contains("/admin"));
        assertTrue(candidates.contains("/api/v1/items/__DYNAMIC__/edit"));
        assertTrue(candidates.contains("/api/v1/items/{id}"));
    }

    @Test
    void shouldExtractBareAbsoluteAndProtocolRelativeUrls() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "see https://docs.example.com/guide or //rel.example.com/api/x now");

        assertTrue(candidates.contains("https://docs.example.com/guide"));
        assertTrue(candidates.contains("//rel.example.com/api/x"));
    }

    @Test
    void shouldSkipJunkAssetExtensionsAndUnwantedSchemes() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "href=\"/img/logo.png\" src=\"/style.css\" href=\"/font.woff2\" "
                                + "href=\"javascript:alert(1)\" href=\"data:text/html,x\" "
                                + "href=\"mailto:a@b.c\" href=\"/app.bundle.min.js\"");

        assertFalse(candidates.contains("/img/logo.png"));
        assertFalse(candidates.contains("/font.woff2"));
        assertFalse(candidates.contains("javascript:alert(1)"));
        assertFalse(candidates.contains("data:text/html,x"));
        assertFalse(candidates.contains("mailto:a@b.c"));
        assertTrue(candidates.contains("/style.css"));
        assertTrue(candidates.contains("/app.bundle.min.js"));
    }

    @Test
    void shouldDeduplicateCandidates() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "fetch('/api/v1/session'); axios.get('/api/v1/session'); fetch('/api/v1/session')");

        assertTrue(candidates.contains("/api/v1/session"));
        assertTrue(candidates.size() == 1);
    }

    @Test
    void shouldSkipJsPatternsWhenJsParsingDisabled() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "<a href=\"/profile\">x</a> fetch('/api/v1/session'); axios.get(\"/api/v1/users\"); "
                                + "location.href = '/logout'; const u = `/api/v1/items/${id}/edit`; "
                                + "const conf = { route: \"/api/v1/items/{id}\" };",
                        false);

        assertTrue(candidates.contains("/profile"));
        assertFalse(candidates.contains("/api/v1/session"));
        assertFalse(candidates.contains("/api/v1/users"));
        assertFalse(candidates.contains("/logout"));
        assertFalse(candidates.contains("/api/v1/items/__DYNAMIC__/edit"));
        assertFalse(candidates.contains("/api/v1/items/{id}"));
    }

    @Test
    void shouldDecodeEncodedSlashesAndUnicodeEscapes() {
        assertTrue(
                LinkExtractorNetworkListener.decodeEncodedChars("a%2fb&#x3a;c%3dd&amp;e%26f")
                        .equals("a/b:c=d&e&f"));

        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "fetch('/api%2fv1%2fsession'); window.open('http&#x3a;&#x2f;&#x2f;example.com&#x2f;admin'); "
                                + "const u = '/api\\u002fv1\\u002fusers';");

        assertTrue(candidates.contains("/api/v1/session"));
        assertTrue(candidates.contains("http://example.com/admin"));
        assertTrue(candidates.contains("/api/v1/users"));
    }

    @Test
    void shouldExtractSourceMappingUrlReferences() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "//# sourceMappingURL=/static/js/main.js.map (relative form)\n"
                                + "//# sourceMappingURL=app.bundle.min.js.map");

        assertTrue(candidates.contains("/static/js/main.js.map"));
        assertTrue(candidates.contains("app.bundle.min.js.map"));
    }

    @Test
    void shouldNormaliseBacktickUnbalancedBracketAndTagCloseGarbage() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "var u=\"/api/v1/x`evil\"; const a = '/api/v1/x{id'; "
                                + "const b = '/api/v1/x{id}'; url('/x</div');");

        assertTrue(candidates.contains("/api/v1/x"));
        assertFalse(candidates.contains("/api/v1/x`evil"));
        assertTrue(candidates.contains("/api/v1/x{id}"));
        assertFalse(candidates.contains("/api/v1/x{id"));
        assertTrue(candidates.contains("/x"));
    }

    @Test
    void shouldNotMatchSubdomainsWithLeadingOrTrailingHyphens() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "-api.example.com api-.example.com -cdn.example.com lib-.cdn.example.com",
                        false);

        assertFalse(candidates.contains("//-api.example.com"));
        assertFalse(candidates.contains("//api-.example.com"));
        assertFalse(candidates.contains("//-cdn.example.com"));
        assertFalse(candidates.contains("//lib-.cdn.example.com"));
    }

    @Test
    void shouldStillMatchHyphenatedButValidSubdomains() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "use api-test.example.com and staging-2.api.example.com", false);

        assertTrue(candidates.contains("//api-test.example.com"));
        assertTrue(candidates.contains("//staging-2.api.example.com"));
    }

    @Test
    void shouldMatchDeeplyNestedSubdomains() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "a.b.c.d.e.f.g.h.i.j.k.l.example.com and //one.two.three.four.five.six.example.com/api",
                        false);

        assertTrue(candidates.contains("//a.b.c.d.e.f.g.h.i.j.k.l.example.com"));
        assertTrue(candidates.contains("//one.two.three.four.five.six.example.com/api"));
    }

    @Test
    void shouldRejectInvalidHostnames() {
        assertFalse(LinkExtractorNetworkListener.isValidHostname("-api.example.com"));
        assertFalse(LinkExtractorNetworkListener.isValidHostname("api-.example.com"));
        assertFalse(LinkExtractorNetworkListener.isValidHostname("a..b.example.com"));
        assertFalse(LinkExtractorNetworkListener.isValidHostname("-foo.bar.example.com"));
        assertFalse(LinkExtractorNetworkListener.isValidHostname("foo-.bar.example.com"));
        assertFalse(LinkExtractorNetworkListener.isValidHostname(""));
        assertFalse(LinkExtractorNetworkListener.isValidHostname("exa mple.com"));

        assertTrue(LinkExtractorNetworkListener.isValidHostname("api.example.com"));
        assertTrue(LinkExtractorNetworkListener.isValidHostname("api-test.example.com"));
        assertTrue(LinkExtractorNetworkListener.isValidHostname("staging-2.api.example.com"));
        assertTrue(LinkExtractorNetworkListener.isValidHostname("localhost"));
        assertTrue(LinkExtractorNetworkListener.isValidHostname("1.2.3.4"));
    }

    @Test
    void shouldExtractBareDomainsAndFilterJunkDomains() {
        Set<String> candidates =
                LinkExtractorNetworkListener.extractCandidates(
                        "reach out at support.example.com or check api-test.local, ignore bootstrap.com "
                                + "and require(\"config.js\")",
                        false);

        assertTrue(candidates.contains("//support.example.com"));
        assertTrue(candidates.contains("//api-test.local"));
        assertFalse(candidates.contains("//bootstrap.com"));
        assertFalse(candidates.contains("//config.js"));
    }

    @Test
    void shouldExtractJsPathExtensionAndFilePatternsOnlyWhenJsParsingEnabled() {
        String input =
                "const a = '/api/v2/items'; const b = 'api/v2/export.json'; const c = 'config.json';";

        Set<String> enabled = LinkExtractorNetworkListener.extractCandidates(input);
        assertTrue(enabled.contains("/api/v2/items"));
        assertTrue(enabled.contains("api/v2/export.json"));
        assertTrue(enabled.contains("config.json"));

        Set<String> disabled = LinkExtractorNetworkListener.extractCandidates(input, false);
        assertFalse(disabled.contains("/api/v2/items"));
        assertFalse(disabled.contains("api/v2/export.json"));
        assertFalse(disabled.contains("config.json"));
    }

    @Test
    void shouldExtractHostsFromResponseHeaders() {
        List<HttpHeaderField> headers =
                Arrays.asList(
                        new HttpHeaderField("Link", "<https://cdn.example.com/lib.js>; rel=preload"),
                        new HttpHeaderField(
                                "Content-Security-Policy",
                                "default-src 'self' api.example.com *.assets.example.com"),
                        new HttpHeaderField("Set-Cookie", "session=abc; Domain=.example.com; Path=/"),
                        new HttpHeaderField("X-Backend-Server", "web01.internal.example.com"));

        Set<String> hosts = LinkExtractorNetworkListener.extractHeaderHosts(headers);

        assertTrue(hosts.contains("//cdn.example.com"));
        assertTrue(hosts.contains("//api.example.com"));
        assertTrue(hosts.contains("//assets.example.com"));
        assertTrue(hosts.contains("//example.com"));
        assertTrue(hosts.contains("//web01.internal.example.com"));
    }

    @Test
    void shouldResolveWildcardHeaderHostsToApexDomain() {
        List<HttpHeaderField> headers =
                Arrays.asList(
                        new HttpHeaderField(
                                "Content-Security-Policy",
                                "connect-src *.example.com *.sub.example.com realm.example.com"));

        Set<String> hosts = LinkExtractorNetworkListener.extractHeaderHosts(headers);

        assertTrue(hosts.contains("//example.com"));
        assertTrue(hosts.contains("//sub.example.com"));
        assertTrue(hosts.contains("//realm.example.com"));
    }

    @Test
    void shouldSkipHeadersThatCannotContainUsefulHosts() {
        List<HttpHeaderField> headers =
                Arrays.asList(
                        new HttpHeaderField("Content-Type", "text/html; charset=utf-8"),
                        new HttpHeaderField("Content-Length", "123"),
                        new HttpHeaderField("Content-Encoding", "gzip"),
                        new HttpHeaderField("Date", "Thu, 05 Sep 2026 06:00:00 GMT"),
                        new HttpHeaderField("Cache-Control", "no-store, max-age=0"),
                        new HttpHeaderField("Server", "nginx/1.18.0"),
                        new HttpHeaderField("X-Content-Type-Options", "nosniff"));

        Set<String> hosts = LinkExtractorNetworkListener.extractHeaderHosts(headers);

        assertTrue(hosts.isEmpty());
    }

    @Test
    void shouldSkipInvalidHeaderHostsButKeepValidOnes() {
        List<HttpHeaderField> headers =
                Arrays.asList(
                        new HttpHeaderField("X-Suspect", "bad-.example.com -evil.example.com"),
                        new HttpHeaderField("X-Good", "good.example.com"));

        Set<String> hosts = LinkExtractorNetworkListener.extractHeaderHosts(headers);

        assertTrue(hosts.contains("//good.example.com"));
        assertFalse(hosts.contains("//bad-.example.com"));
        assertFalse(hosts.contains("//-evil.example.com"));
    }

    @Test
    void shouldReturnEmptySetForNullOrEmptyHeaders() {
        assertTrue(LinkExtractorNetworkListener.extractHeaderHosts(null).isEmpty());
        assertTrue(LinkExtractorNetworkListener.extractHeaderHosts(Arrays.asList()).isEmpty());
        assertTrue(
                LinkExtractorNetworkListener.extractHeaderHosts(
                                Arrays.asList(new HttpHeaderField(null, null)))
                        .isEmpty());
    }

    @Test
    void shouldComputeRegistrableDomain() {
        assertEquals("example.com", LinkExtractorNetworkListener.registrableDomain("example.com"));
        assertEquals(
                "example.com", LinkExtractorNetworkListener.registrableDomain("www.example.com"));
        assertEquals(
                "example.com",
                LinkExtractorNetworkListener.registrableDomain("api.dev.example.com"));
        assertEquals(
                "example.co.uk",
                LinkExtractorNetworkListener.registrableDomain("www.example.co.uk"));
        assertEquals("localhost", LinkExtractorNetworkListener.registrableDomain("localhost"));
        assertNull(LinkExtractorNetworkListener.registrableDomain(null));
    }

    @Test
    void shouldConsiderSubdomainsOfSameRegistrableDomainInScope() {
        assertTrue(
                LinkExtractorNetworkListener.isSameDomainFamily(
                        "www.example.com", "api.example.com"));
        assertTrue(
                LinkExtractorNetworkListener.isSameDomainFamily(
                        "example.com", "www.example.com"));
        assertTrue(
                LinkExtractorNetworkListener.isSameDomainFamily(
                        "www.example.com", "example.com"));
        assertTrue(
                LinkExtractorNetworkListener.isSameDomainFamily(
                        "www.example.com", "deep.api.example.com"));
        assertTrue(
                LinkExtractorNetworkListener.isSameDomainFamily(
                        "www.example.co.uk", "api.example.co.uk"));
        assertTrue(LinkExtractorNetworkListener.isSameDomainFamily("localhost", "api.localhost"));
    }

    @Test
    void shouldRejectUnrelatedThirdPartyDomains() {
        assertFalse(
                LinkExtractorNetworkListener.isSameDomainFamily(
                        "example.com", "cdn.stripe.com"));
        assertFalse(
                LinkExtractorNetworkListener.isSameDomainFamily(
                        "www.example.com", "www.google.com"));
        assertFalse(
                LinkExtractorNetworkListener.isSameDomainFamily(
                        "example.co.uk", "evil.co.uk"));
        assertFalse(
                LinkExtractorNetworkListener.isSameDomainFamily("example.com", "example.com.evil.io"));
        assertFalse(LinkExtractorNetworkListener.isSameDomainFamily("example.com", null));
        assertFalse(LinkExtractorNetworkListener.isSameDomainFamily(null, "api.example.com"));
    }
}