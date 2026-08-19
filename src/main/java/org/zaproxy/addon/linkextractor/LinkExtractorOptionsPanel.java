package org.zaproxy.addon.linkextractor;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapHtmlLabel;

/**
 * Options panel shown under <em>Tools > Options > Sites tree</em>.
 *
 * <p>Provides toggles for the optional behaviours of the {@link LinkExtractorNetworkListener}:
 * JavaScript parsing, subdomain discovery, and thread concurrency.
 */
public class LinkExtractorOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final String PREFIX = "linkextractor.options";

    private LinkExtractorOptionsParam optionsParam;

    private JCheckBox parseJavascriptCheckBox;
    private JCheckBox discoverSubdomainsCheckBox;
    private JSlider threadsSlider;

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
        gbc.insets = new Insets(8, 0, 0, 0);
        add(getThreadsPanel(), gbc);

        gbc.gridy = 4;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        add(new JPanel(), gbc);
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

    private JPanel getThreadsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.insets = new Insets(0, 20, 0, 0);
        panel.add(new JLabel(Constant.messages.getString(PREFIX + ".label.threads")), gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 20, 0, 0);
        panel.add(getThreadsSlider(), gbc);
        return panel;
    }

    private JSlider getThreadsSlider() {
        if (threadsSlider == null) {
            threadsSlider = new JSlider(
                    LinkExtractorOptionsParam.MIN_THREADS,
                    LinkExtractorOptionsParam.MAX_THREADS,
                    optionsParam.getThreads());
            threadsSlider.setMajorTickSpacing(1);
            threadsSlider.setMinorTickSpacing(1);
            threadsSlider.setPaintTicks(true);
            threadsSlider.setPaintLabels(true);
            threadsSlider.setSnapToTicks(true);
            threadsSlider.setToolTipText(Constant.messages.getString(PREFIX + ".label.threads.tooltip"));
        }
        return threadsSlider;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        LinkExtractorOptionsParam param = optionsParam.getParamSet(LinkExtractorOptionsParam.class);
        getParseJavascriptCheckBox().setSelected(param.isParseJavascript());
        getDiscoverSubdomainsCheckBox().setSelected(param.isDiscoverSubdomains());
        threadsSlider.setValue(param.getThreads());
    }

    @Override
    public void saveParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        LinkExtractorOptionsParam param = optionsParam.getParamSet(LinkExtractorOptionsParam.class);
        param.setParseJavascript(getParseJavascriptCheckBox().isSelected());
        param.setDiscoverSubdomains(getDiscoverSubdomainsCheckBox().isSelected());
        param.setThreads(threadsSlider.getValue());
    }
}