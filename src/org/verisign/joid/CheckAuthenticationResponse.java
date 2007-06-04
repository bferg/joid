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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import org.apache.log4j.Logger;
import org.apache.tsik.datatypes.DateTime;

/**
 * Represents an OpenID check authentication request.
 */
public class CheckAuthenticationResponse extends Response
{
    private final static Logger log 
	= Logger.getLogger(CheckAuthenticationResponse.class);

    private boolean isValid;
    
    private static String OPENID_IS_VALID = "is_valid";
    private final static String OPENID_INVALIDATE_HANDLE = "invalidate_handle";

    private AuthenticationResponse ar;
    private Map map;

    /**
     * Returns whether this response contains notification that the request
     * signature was valid.
     *
     * @return true if the incoming </code>check_authentication</code> was
     * processed to be valid; false otherwise.
     */
    public boolean isValid() {return isValid;}

    /**
     * Returns the internal elements mapped to a map. The keys used
     * are those defined by the specification, for example <code>openid.mode</code>.
     *
     * TODO: Made public only for unit tests. Needs to package-scope
     * limit this method.
     *
     * @return a map with all internal values mapped to their specification
     * keys.
     */
    public Map toMap()
    {
	return map;
    }

    /**
     * throws at errors in signature creation
     */
    CheckAuthenticationResponse(AuthenticationResponse ar,
				       Association a, Crypto crypto,
				       String invalidateHandle)
	throws OpenIdException
    {
	super(Collections.EMPTY_MAP);
	this.ar = ar;
	this.ns = ar.getNamespace();

	if (a != null) {
	    String sig = ar.sign(a.getAssociationType(),
				 a.getMacKey(), ar.getSignedList());
	    isValid = sig.equals(ar.getSignature());
	} else {
	    isValid = false;
	}
	map = new HashMap();
	map.put("mode", "id_res");
	map.put(CheckAuthenticationResponse.OPENID_IS_VALID, 
		isValid ? "true":"false");
	if (invalidateHandle != null) {
	    map.put(CheckAuthenticationResponse.OPENID_INVALIDATE_HANDLE, 
		    invalidateHandle);
	}
    }

    public String toString()
    {
        return "[CheckAuthenticationResponse "
            + super.toString()
            +", is valid="+isValid
	    +", authentication response="+ar
	    +"]";
    }
}