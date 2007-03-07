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
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Represents an OpenID response. Valid for OpenID 1.1 and 2.0 namespace.
 */
public abstract class Response
{
    private final static Logger log = Logger.getLogger(Response.class);
    static String OPENID_20_NAMESPACE = "http://openid.net/signon/2.0";
    static String OPENID_NS = "openid.ns";
    static String OPENID_ERROR = "error";

    String ns;
    String error;

    
    String getError(){return error;}

    /**
     * Returns the namespace of this response. For OpenID 2.0 responses,
     * this namespace will be <code>http://openid.net/signon/2.0</code>.
     *
     * TODO: Made public to be accessible from unit tests only. Need
     * to rework that to change access level during test time.
     *
     * @return the namespace, or null if none (OpenID 1.x).
     */
    public String getNamespace(){return ns;}

    /**
     * Returns whether this response is an OpenID 2.0 response.
     *
     * @return true if this response is an OpenID 2.0 response.
     */
    public boolean isVersion2()
    {
	return Response.OPENID_20_NAMESPACE.equals(this.ns);
    }

    Response(Map map)
    {
	if (map != null) {
	    this.ns = (String) map.get(Response.OPENID_NS);
	    this.error = (String) map.get(Response.OPENID_ERROR);
	}
    }

    Map toMap()
    {
	Map map = new HashMap();
	if (ns != null){
	    map.put(Response.OPENID_NS, ns);
	}
	return map;
    }

    static char newline = '\n'; 
    // cannot be System.getProperty("line.separator"); since spec
    // requires '\n'

    /**
     * Unrolls this response as a string. This string will use the
     * <code>name:value</code> format of the specification. See also
     * {@link #toUrlStringResponse()}.
     *
     * @return the response as a string.
     */
    public String toPostStringResponse() 
    {
        return toStringResponseDelimitedBy(":", newline);
    }

    /**
     * Unrolls this response as a string. This string will use encoding
     * suitable for URLs. See also {@link #toPostStringResponse()}.
     *
     * @return the response as a string.
     */
    public String toUrlStringResponse() 
    {
        return toStringResponseDelimitedBy("=", '&');
    }
 
    private String toStringResponseDelimitedBy(String kvDelim, char lineDelim) 
    {
	Map map = toMap();
	Set set = map.entrySet();
	StringBuffer sb = new StringBuffer();
	try {
	    for (Iterator iter=set.iterator(); iter.hasNext();){
		Map.Entry mapEntry = (Map.Entry) iter.next();
		String key = (String) mapEntry.getKey();
		String value = (String) mapEntry.getValue();

		if (lineDelim == newline){
		    sb.append(key+kvDelim+value);
		    sb.append(lineDelim);
		} else {
		    sb.append(URLEncoder.encode(key, "UTF-8")+kvDelim
			      +URLEncoder.encode(value, "UTF-8"));
		    if (iter.hasNext()) {
			sb.append(lineDelim);
		    }
		}

	    }
	    return sb.toString();
	} catch (UnsupportedEncodingException e){
	    // should not happen
	    throw new RuntimeException("Internal error");
	}
    }

    /** 
     * Returns a string representation of this response.
     *
     * @return a string representation of this response.
     */
    public String toString()
    {
        return "is version 2="+isVersion2()
            +", error="+error
            +", namespace="+ns;
    }

}
