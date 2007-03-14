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
import java.util.Set;
import java.util.StringTokenizer;
import org.apache.log4j.Logger;

/**
 * Produces requests from incoming queries.
 */
public class ResponseFactory
{
    private final static Logger log = Logger.getLogger(ResponseFactory.class);

    private ResponseFactory(){}

    private static String OPENID_MODE = "openid.mode";
    private static String ASSOCIATE_MODE = "associate";

    /**
     * Parses a query into a response.
     *
     * @param query the query to parse.
     * @return the parsed response.
     * @throws UnsupportedEncodingException if the string is not properly 
     *  UTF-8 encoded.
     * @throws OpenIdException if the query cannot be parsed into a known
     *  response.
     */
    public static Response parse(String query) 
	throws UnsupportedEncodingException, OpenIdException
    {
	Map map = parseQuery(query);
	Set set = map.keySet();
	if (set.contains(AssociationResponse.OPENID_ENC_MAC_KEY)){
	    return new AssociationResponse(map);
	} else if (set.contains(AuthenticationResponse.OPENID_SIG)){
	    return new AuthenticationResponse(map);
 	} else {
 	    throw new OpenIdException("Cannot parse type of response from "+
				      query);
 	}
    }

    private static Map parseQuery(String query) 
	throws UnsupportedEncodingException
    {
	//log.debug("About to parse '"+query+"'");
	StringTokenizer st = new StringTokenizer(query, "?&=", true);
	Map map = new HashMap();
	String previous = null;
	while (st.hasMoreTokens()) {
	    String current = st.nextToken();
	    if ("?".equals(current) || "&".equals(current)) {
		//ignore
	    } else if ("=".equals(current)) {
		String name = URLDecoder.decode(previous, "UTF-8");
		String value = URLDecoder.decode(st.nextToken(), "UTF-8");
		// TODO, get rid of Cactus test inserted values
		if (!name.startsWith("Cactus")){
		    map.put(name, value);
		}
	    } else {
		previous = current;
	    }
	}
	//log.debug("Parsed into map: "+map);
	return map;
    }

}
