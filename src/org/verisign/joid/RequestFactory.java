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
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import org.apache.log4j.Logger;

/**
 * Produces requests from incoming queries.
 */
public class RequestFactory
{
    private final static Logger log = Logger.getLogger(RequestFactory.class);

    private RequestFactory(){}

    private static String OPENID_MODE = "openid.mode";
    private static String ASSOCIATE_MODE = "associate";
    private static String CHECKID_IMMEDIATE_MODE = "checkid_immediate";
    private static String CHECKID_SETUP_MODE = "checkid_setup";
    private static String CHECK_AUTHENTICATION_MODE = "check_authentication";

    /**
     * Parses a query into a request.
     *
     * @param query the query to parse.
     * @return the parsed request.
     * @throws UnsupportedEncodingException if the string is not properly 
     *  UTF-8 encoded.
     * @throws OpenIdException if the query cannot be parsed into a known
     *  request.
     */
    public static Request parse(String query) 
	throws UnsupportedEncodingException, OpenIdException
    {
	Map map = parseQuery(query);

	String s = (String) map.get(OPENID_MODE);
	if (ASSOCIATE_MODE.equals(s)){
	    return new AssociationRequest(map, s);
	} else if (CHECKID_IMMEDIATE_MODE.equals(s) 
		   || CHECKID_SETUP_MODE.equals(s)){
	    return new AuthenticationRequest(map, s);
	} else if (CHECK_AUTHENTICATION_MODE.equals(s)){
	    return new CheckAuthenticationRequest(map, s);
	} else {
	    throw new OpenIdException("Unknown "+OPENID_MODE+": "+s);
	}
    }

    /**
     * Parses a query into a map. 
     *
     * @param query the query to parse.
     * @return the parsed request.
     * @throws UnsupportedEncodingException if the string is not properly 
     *  UTF-8 encoded.
     */
    public static Map parseQuery(String query) 
	throws UnsupportedEncodingException
    {
	Map map = new HashMap();
	if (query == null) {
	    return map;
	}
	StringTokenizer st = new StringTokenizer(query, "?&=", true);
	String previous = null;
	while (st.hasMoreTokens()) {
	    String current = st.nextToken();
	    if ("?".equals(current) || "&".equals(current)) {
		//ignore
	    } else if ("=".equals(current)) {
		String name = URLDecoder.decode(previous, "UTF-8");
		if (st.hasMoreTokens()){
		    String value = URLDecoder.decode(st.nextToken(), "UTF-8");
		    if (checkValue(value)){
			map.put(name, value);
		    }
		}
	    } else {
		previous = current;
	    }
	}
	return map;
    }

    private static boolean checkValue(String value)
    {
	if ("&".equals(value)){
	    return false;
	}
	// more tests here perchance
	return true;
    }
}
