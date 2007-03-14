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

import java.util.Map;
import org.apache.log4j.Logger;

/**
 * Represents an OpenID request. Valid for OpenID 1.1 and 2.0 namespace.
 */
public abstract class Request
{
    String mode;
    String ns;

    private static String OPENID_20_NAMESPACE = "http://openid.net/signon/2.0";
    private static String OPENID_NS = "openid.ns";

    private final static Logger log = Logger.getLogger(Request.class);

    /**
     * Returns whether this request is an OpenID 2.0 request.
     *
     * @return true if this request is an OpenID 2.0 request.
     */
    public boolean isVersion2()
    {
	return Request.OPENID_20_NAMESPACE.equals(this.ns);
    }

    Request(Map map, String mode)
    {
	this.mode = mode;

	if (map != null) {
	    this.ns = (String) map.get(Request.OPENID_NS);
	}
    }

    String getNamespace(){return ns;}

    /**
     * Processes this request using the given store and crypto implementations.
     * This processing step should produce a valid response that can be
     * sent back to the requestor. Associations may be read from, written to,
     * or deleted from the store by way of this processing step.
     *
     * @param store the store implementation.
     * @param crypto the crypto implementation to use.
     *
     * @return the response
     *
     * @throws OpenIdException unrecoverable errors happen.
     */
    public abstract Response processUsing(Store store, Crypto crypto)
	throws OpenIdException;

    /** 
     * Returns a string representation of this request.
     *
     * @return a string representation of this request.
     */
    public String toString()
    {
        return "is version 2="+isVersion2()
            +", namespace="+ns;
    }
}
