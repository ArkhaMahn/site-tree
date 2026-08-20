package Arkhamahn.linkextractor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.SiteMapEventPublisher;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.model.Target;

class LinkExtractorNetworkListenerUnitTest {

    private static LinkExtractorOptionsParam createOptions() {
        LinkExtractorOptionsParam options = new LinkExtractorOptionsParam();
        // Don't call parseImpl() as it reads from config; just use defaults
        return options;
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
}