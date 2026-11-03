package com.fortify.plugin.burp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Subset of a Burp {@code <dynamicAnalysis>} element (DOM-based issues found by Burp's
 * browser-powered scanning): where tainted data came from, where it ended up, and a proof of concept.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class BurpDynamicAnalysis {
    private String source;
    private String sink;
    private String sourceValue;
    private String sinkValue;
    private String sourceStackTrace;
    private String sinkStackTrace;
    private String poc;
    private String origin;

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getSink() {
        return sink;
    }

    public void setSink(String sink) {
        this.sink = sink;
    }

    public String getSourceValue() {
        return sourceValue;
    }

    public void setSourceValue(String sourceValue) {
        this.sourceValue = sourceValue;
    }

    public String getSinkValue() {
        return sinkValue;
    }

    public void setSinkValue(String sinkValue) {
        this.sinkValue = sinkValue;
    }

    public String getSourceStackTrace() {
        return sourceStackTrace;
    }

    public void setSourceStackTrace(String sourceStackTrace) {
        this.sourceStackTrace = sourceStackTrace;
    }

    public String getSinkStackTrace() {
        return sinkStackTrace;
    }

    public void setSinkStackTrace(String sinkStackTrace) {
        this.sinkStackTrace = sinkStackTrace;
    }

    public String getPoc() {
        return poc;
    }

    public void setPoc(String poc) {
        this.poc = poc;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }
}
