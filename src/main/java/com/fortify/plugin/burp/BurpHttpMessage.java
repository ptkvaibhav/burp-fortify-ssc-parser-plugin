package com.fortify.plugin.burp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText;

/**
 * A single HTTP request or response from a Burp {@code <requestresponse>} element, e.g.
 * {@code <request method="GET" base64="true">R0VUIC8...</request>}.
 * Burp only Base64-encodes messages when the corresponding report option is enabled, so the
 * {@code base64} attribute is honoured rather than assumed.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class BurpHttpMessage {
    @JacksonXmlProperty(isAttribute = true)
    private String method;

    @JacksonXmlProperty(isAttribute = true)
    private String base64;

    @JacksonXmlText
    private String content;

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getBase64() {
        return base64;
    }

    public void setBase64(String base64) {
        this.base64 = base64;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    /** @return true if Burp marked the message content as Base64-encoded. */
    public boolean isBase64Encoded() {
        return "true".equalsIgnoreCase(base64 == null ? null : base64.trim());
    }
}
