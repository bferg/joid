//
// (C) Copyright 2007 VeriSign, Inc.  All Rights Reserved.
//
// VeriSign, Inc. shall have no responsibility, financial or
// otherwise, for any consequences arising out of the use of
// this material. The program material is provided on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.
//
// Distributed under an Apache License
// http://www.apache.org/licenses/LICENSE-2.0
//

package org.verisign.joid;

import java.io.UnsupportedEncodingException;
import java.util.Map;
import org.apache.log4j.Logger;
import org.verisign.joid.Crypto;

/**
 * The main OpenID implementation.
 *
 * The simplest way to implement OpenID is to let this class handle the
 * request and produce the response.
 *
 * <pre>
 * // Get a store implementation. You need this to store/retrieve associations,
 * // which is the way an OpenID provider and an OpenID relying party recognize
 * // each other.
 * Store store = ...
 *
 * // Get an OpenID implementation
 * OpenId openId = new OpenId(store);
 *
 * // Process the request into a response
 * String response = openId.handleRequest(query);
 *
 * // then send the response back to the sender.
 * </pre> 
 */
public class OpenId
{
    private final static Logger log = Logger.getLogger(OpenId.class);
    private Store store;
    private Crypto crypto;

    /**
     * Creates an OpenId instance. This instance will use the default crypto
     * implementation {@link Crypto}.
     *
     * @param store the datasource to use for associations.
     */
    public OpenId(Store store)
    {
	this.store = store;
	this.crypto = new Crypto();
    }

    /**
     * Returns whether the query is a valid OpenId message
     * that this implementation can handle.
     *
     * @param query the query top check.
     * @return true if this is a message that can be handled; false otherwise.
     */
    public boolean canHandle(String query)
    {
	try {
	    RequestFactory.parse(query);
	    return true;
	} catch (Exception e){
	    log.info(e);
	    return false;
	}
    }


    /**
     * Call this method if the data is posted by way of HTTP POST
     */
    public String handleRequest(Map map) throws OpenIdException
    {
	throw new RuntimeException("nyi");
    }

    /**
     * Returns whether the incoming request is an Association Request.
     *
     * @param query the request to check.
     * @return true if the incoming request is an Association Request; false
     * otherwise.
     */
    public boolean isAssociationRequest(String query)
    {
	try {
	    Request req = RequestFactory.parse(query);
	    return (req instanceof AssociationRequest);
	} catch (OpenIdException e) {
	    log.info(e);
	    return false;
	} catch (UnsupportedEncodingException e) {
	    log.info(e);
	    return false;
	}
    }

    /**
     * Returns whether the incoming request is an Authentication Request.
     *
     * @param query the request to check.
     * @return true if the incoming request is an Authentication Request; false
     * otherwise.
     */
    public boolean isAuthenticationRequest(String query) 
    {
	try {
	    Request req = RequestFactory.parse(query);
	    return (req instanceof AuthenticationRequest);
	} catch (OpenIdException e) {
	    log.info(e);
	    return false;
	} catch (UnsupportedEncodingException e) {
	    log.info(e);
	    return false;
	}
    }

    /**
     * Returns whether the incoming request is a Check Authentication Request.
     *
     * @param query the request to check.
     * @return true if the incoming request is a Check Authentication Request; false
     * otherwise.
     */
    public boolean isCheckAuthenticationRequest(String query) 
    {
	try {
	    Request req = RequestFactory.parse(query);
	    return (req instanceof CheckAuthenticationRequest);
	} catch (OpenIdException e) {
	    log.info(e);
	    return false;
	} catch (UnsupportedEncodingException e) {
	    log.info(e);
	    return false;
	}
    }

    /**
     * Call this method if the data is on the URL, i.e., GET
     */
    public String handleRequest(String query) throws OpenIdException
    {
	log.info("handleRequest()="+query);

	Request req = null;
	try {
	    req = RequestFactory.parse(query);
	} catch (UnsupportedEncodingException e){
	    log.warn("exception="+e);
	    throw new OpenIdException(e);
	}
	log.info("request="+req);
	Response resp = req.processUsing(store, crypto);
	log.info("response="+resp);
	return resp.toPostStringResponse();
    }

    /**
     * Returns whether the response is an error response.
     *
     * @param s the response.
     * @return true if the response is an error response, that is, whether 
     * processing the request yielded this response to contain an error; false
     * otherwise.
     */
    public boolean isAnErrorResponse(String s)
    {
	try {
	    Response resp = ResponseFactory.parse(s);
	    return (resp.getError() != null);
	} catch (UnsupportedEncodingException e){
	    return false;
	} catch (OpenIdException e){
	    return false;
	}
    }
}
