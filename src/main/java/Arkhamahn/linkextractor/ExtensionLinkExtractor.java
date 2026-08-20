package Arkhamahn.linkextractor;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.SiteMapEventPublisher;
import org.zaproxy.zap.ZAP;

/**
 * Registers the {@link LinkExtractorNetworkListener} with ZAP's network layer so that Burp-style
 * link extraction runs synchronously on every response ZAP receives - the moment an in-scope domain
 * is visited - instead of on the (lower-priority) passive scan queue. No UI is added; the add-on
 * only enhances the Sites tree.
 *
 * <p>Ported from the Burp-style passive link extraction script
 * {@code burp_style_passive_link_extraction.js}.
 */
public class ExtensionLinkExtractor extends ExtensionAdaptor {

    public static final String NAME = "ExtensionLinkExtractor";

    private static final String PREFIX = "linkextractor";

    private LinkExtractorOptionsParam optionsParam;
    private LinkExtractorOptionsPanel optionsPanel;
    private LinkExtractorNetworkListener networkListener;

    public ExtensionLinkExtractor() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // Options (Tools > Options > "Sites tree"): JavaScript parsing and subdomain discovery can
        // be switched off independently.
        optionsParam = new LinkExtractorOptionsParam();
        optionsPanel = new LinkExtractorOptionsPanel(optionsParam);
        extensionHook.addOptionsParamSet(optionsParam);
        extensionHook.getHookView().addOptionPanel(optionsPanel);

        // HttpSenderListener is the network-level hook: it fires inline on the request/proxy
        // thread for every response ZAP handles (proxied browsing, spider, AJAX spider, active
        // scan, manual requests), before the message is saved to history. This gives the tree
        // population the same priority as the visited message itself.
        networkListener = new LinkExtractorNetworkListener(optionsParam);
        extensionHook.addHttpSenderListener(networkListener);

        // React to site-tree deletions: when nodes are removed (including "delete all nodes" or the
        // "Refresh Sites tree" context action) the add-on's per-session dedup set must be reset, or
        // a later visit to the same domain would skip re-adding the deleted URLs.
        ZAP.getEventBus()
                .registerConsumer(
                        networkListener,
                        SiteMapEventPublisher.getPublisher().getPublisherName(),
                        SiteMapEventPublisher.SITE_NODE_REMOVED_EVENT,
                        SiteMapEventPublisher.SITE_REMOVED_EVENT);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (networkListener != null) {
            ZAP.getEventBus().unregisterConsumer(networkListener);
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}