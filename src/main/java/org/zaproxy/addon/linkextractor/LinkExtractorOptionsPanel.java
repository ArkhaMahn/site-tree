package org.zaproxy.addon.linkextractor;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JCheckBox;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapHtmlLabel;

/**
 * Options panel shown under <em>Tools &gt; Options &gt; Sites tree</em>.
 *
 * <p>Provides toggles for the two optional behaviours of the {@link LinkExtractorNetworkListener}:
 * JavaScript parsing and subdomain discovery.
 */
public class LinkExtractorOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final String PREFIX = "linkextractor.options";

    private LinkExtractorOptionsParam optionsParam;

    private JCheckBox parseJavascriptCheckBox;
    private JCheckBox discoverSubdomainsCheckBox;

    public LinkExtractorOptionsPanel(LinkExtractorOptionsParam optionsParam) {
        super();
        this.optionsParam = optionsParam;
        setName(Constant.messages.getString(PREFIX + ".title"));
        initialize();
    }

    private void initialize() {
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridwidth = 1;
        add(new ZapHtmlLabel(Constant.messages.getString(PREFIX + ".label.intro")), gbc);

        gbc.gridy = 1;
        add(getParseJavascriptCheckBox(), gbc);

        gbc.gridy = 2;
        add(getDiscoverSubdomainsCheckBox(), gbc);

        gbc.gridy = 3;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        add(new javax.swing.JPanel(), gbc);
    }

    private JCheckBox getParseJavascriptCheckBox() {
        if (parseJavascriptCheckBox == null) {
            parseJavascriptCheckBox = new JCheckBox(Constant.messages.getString(PREFIX + ".label.parseJavascript"));
        }
        return parseJavascriptCheckBox;
    }

    private JCheckBox getDiscoverSubdomainsCheckBox() {
        if (discoverSubdomainsCheckBox == null) {
            discoverSubdomainsCheckBox =
                    new JCheckBox(Constant.messages.getString(PREFIX + ".label.discoverSubdomains"));
        }
        return discoverSubdomainsCheckBox;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        LinkExtractorOptionsParam param = optionsParam.getParamSet(LinkExtractorOptionsParam.class);
        getParseJavascriptCheckBox().setSelected(param.isParseJavascript());
        getDiscoverSubdomainsCheckBox().setSelected(param.isDiscoverSubdomains());
    }

    @Override
    public void saveParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        LinkExtractorOptionsParam param = optionsParam.getParamSet(LinkExtractorOptionsParam.class);
        param.setParseJavascript(getParseJavascriptCheckBox().isSelected());
        param.setDiscoverSubdomains(getDiscoverSubdomainsCheckBox().isSelected());
    }
}