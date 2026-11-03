package com.fortify.plugin.burp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** A Burp {@code <requestresponse>} element: the evidence request/response pair for an issue. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class BurpRequestResponse {
    private BurpHttpMessage request;
    private BurpHttpMessage response;
    private String responseRedirected;

    public BurpHttpMessage getRequest() {
        return request;
    }

    public void setRequest(BurpHttpMessage request) {
        this.request = request;
    }

    public BurpHttpMessage getResponse() {
        return response;
    }

    public void setResponse(BurpHttpMessage response) {
        this.response = response;
    }

    public String getResponseRedirected() {
        return responseRedirected;
    }

    public void setResponseRedirected(String responseRedirected) {
        this.responseRedirected = responseRedirected;
    }
}
