package Arkhamahn.linkextractor;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapHtmlLabel;

/**
 * Options panel shown under <em>Tools &gt; Options &gt; Site tree</em>.
 *
 * <p>Provides toggles for the optional behaviours of the {@link LinkExtractorNetworkListener}:
 * JavaScript parsing, subdomain discovery (body links and response headers), recording the
 * discovered links and subdomains in the history tab, and inputs for thread concurrency and the
 * maximum response body size that is scanned.
 */
public class LinkExtractorOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final String PREFIX = "linkextractor.options";

    private LinkExtractorOptionsParam optionsParam;

    private JCheckBox parseJavascriptCheckBox;
    private JCheckBox discoverSubdomainsCheckBox;
    private JCheckBox discoverSubdomainsFromHeadersCheckBox;
    private JCheckBox recordInProxyHistoryCheckBox;
    private JSlider threadsSlider;
    private JSpinner maxBodySizeSpinner;

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
        add(getDiscoverSubdomainsFromHeadersCheckBox(), gbc);

        gbc.gridy = 4;
        add(getRecordInProxyHistoryCheckBox(), gbc);

        gbc.gridy = 5;
        gbc.insets = new Insets(8, 0, 0, 0);
        add(getThreadsPanel(), gbc);

        gbc.gridy = 6;
        add(getMaxBodySizePanel(), gbc);

        gbc.gridy = 7;
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

    private JCheckBox getDiscoverSubdomainsFromHeadersCheckBox() {
        if (discoverSubdomainsFromHeadersCheckBox == null) {
            discoverSubdomainsFromHeadersCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    PREFIX + ".label.discoverSubdomainsFromHeaders"));
        }
        return discoverSubdomainsFromHeadersCheckBox;
    }

    private JCheckBox getRecordInProxyHistoryCheckBox() {
        if (recordInProxyHistoryCheckBox == null) {
            recordInProxyHistoryCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(PREFIX + ".label.recordInProxyHistory"));
        }
        return recordInProxyHistoryCheckBox;
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

    private JPanel getMaxBodySizePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.insets = new Insets(0, 20, 0, 0);
        panel.add(new JLabel(Constant.messages.getString(PREFIX + ".label.maxBodySizeMb")), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(getMaxBodySizeSpinner(), gbc);
        return panel;
    }

    private JSpinner getMaxBodySizeSpinner() {
        if (maxBodySizeSpinner == null) {
            maxBodySizeSpinner =
                    new JSpinner(
                            new SpinnerNumberModel(
                                    optionsParam.getMaxBodySizeMb(),
                                    LinkExtractorOptionsParam.MIN_MAX_BODY_SIZE_MB,
                                    LinkExtractorOptionsParam.MAX_MAX_BODY_SIZE_MB,
                                    1));
            maxBodySizeSpinner.setToolTipText(
                    Constant.messages.getString(PREFIX + ".label.maxBodySizeMb.tooltip"));
            maxBodySizeSpinner.setPreferredSize(new java.awt.Dimension(80, 24));
        }
        return maxBodySizeSpinner;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        LinkExtractorOptionsParam param = optionsParam.getParamSet(LinkExtractorOptionsParam.class);
        getParseJavascriptCheckBox().setSelected(param.isParseJavascript());
        getDiscoverSubdomainsCheckBox().setSelected(param.isDiscoverSubdomains());
        getDiscoverSubdomainsFromHeadersCheckBox()
                .setSelected(param.isDiscoverSubdomainsFromHeaders());
        getRecordInProxyHistoryCheckBox().setSelected(param.isRecordInProxyHistory());
        threadsSlider.setValue(param.getThreads());
        getMaxBodySizeSpinner()
                .setValue(
                        Math.max(
                                LinkExtractorOptionsParam.MIN_MAX_BODY_SIZE_MB,
                                Math.min(
                                        LinkExtractorOptionsParam.MAX_MAX_BODY_SIZE_MB,
                                        param.getMaxBodySizeMb())));
    }

    @Override
    public void saveParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        LinkExtractorOptionsParam param = optionsParam.getParamSet(LinkExtractorOptionsParam.class);
        param.setParseJavascript(getParseJavascriptCheckBox().isSelected());
        param.setDiscoverSubdomains(getDiscoverSubdomainsCheckBox().isSelected());
        param.setDiscoverSubdomainsFromHeaders(
                getDiscoverSubdomainsFromHeadersCheckBox().isSelected());
        param.setRecordInProxyHistory(getRecordInProxyHistoryCheckBox().isSelected());
        param.setThreads(threadsSlider.getValue());
        param.setMaxBodySizeMb(
                ((Number) getMaxBodySizeSpinner().getValue()).intValue());
    }
}
