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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import org.apache.log4j.Logger;
import org.apache.tsik.datatypes.DateTime;

/**
 * Represents an OpenID authentication response.
 */
public class AuthenticationResponse extends Response
{
    private static Logger log = Logger.getLogger(AuthenticationResponse.class);

    private static String OPENID_RETURN_TO = "openid.return_to";
    private static String OPENID_IDENTITY = "openid.identity";
    private static String OPENID_ERROR = "openid.error";
    private static String OPENID_NONCE = "openid.nonce";
    private static String OPENID_MODE = "openid.mode";
    private static String 
	OPENID_INVALIDATE_HANDLE = "openid.invalidate_handle";
    private static String 
	OPENID_ASSOCIATION_HANDLE = "openid.assoc_handle";
    private static String OPENID_SIGNED = "openid.signed";
    // package scope so that ResponseFactory can trigger on this key
    static String OPENID_SIG = "openid.sig";

    String mode;
    String identity;
    String returnTo;
    String nonce;
    String invalidateHandle;
    String associationHandle;
    String signed;
    private String signature;
    private SimpleRegistration sreg;

    /** 
     * Returns the signature in this response.
     * @return the signature in this response.
     */
    public String getSignature(){return signature;}

    /** 
     * Returns the list of signed elements in this response.
     * @return the comma-separated list of signed elements in this response.
     */
    public String getSignedList(){return signed;}

    /** 
     * Returns the association handle in this response.
     * @return the association handle in this response.
     */
    public String getAssociationHandle(){return associationHandle;}

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
	Map map = super.toMap();
	
	map.put(AuthenticationResponse.OPENID_MODE, mode);
	map.put(AuthenticationResponse.OPENID_IDENTITY, identity);
	map.put(AuthenticationResponse.OPENID_RETURN_TO, returnTo);
	map.put(AuthenticationResponse.OPENID_NONCE, nonce);
	if (invalidateHandle != null){
	    map.put(AuthenticationResponse.OPENID_INVALIDATE_HANDLE, 
		    invalidateHandle);
	} 
	map.put(AuthenticationResponse.OPENID_ASSOCIATION_HANDLE, 
		associationHandle);
	if (signed != null){
	    map.put(AuthenticationResponse.OPENID_SIGNED, signed);
	}
	map.put(AuthenticationResponse.OPENID_SIG, signature);

	Map sregMap = sreg.getSuppliedValues();
	log.debug("sreg in authnresp = "+sreg);
	Set set = sregMap.entrySet();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();
	    map.put(SimpleRegistration.OPENID_SREG +"."+ key, value);
	}

	return map;
    }

    private String generateNonce()
    {
	String crumb = Crypto.generateCrumb();
	return DateTime.formatISODateTime(new Date()) + crumb;
    }

    /**
     * Unrolls this response as a string. This string will use encoding
     * suitable for URLs. The string will use the same namespace as the
     * incoming request.
     *
     * @param req the original request.
     * @param e any exception that occured while processing <code>req</code>,
     * may be null.
     *
     * @return the response as a string.
     */
    public static String toUrlStringResponse(Request req, OpenIdException e)
    {
	Map map = new HashMap();
	map.put(AuthenticationResponse.OPENID_MODE, "error");
	if (req != null) {
	    if (req.isVersion2()) {
		map.put(AuthenticationResponse.OPENID_NS, req.getNamespace());
	    }
	    map.put(AuthenticationResponse.OPENID_ERROR, e.getMessage());
	} else {
	    map.put(AuthenticationResponse.OPENID_ERROR, "OpenID request error");
	}
	try {
	    return new AuthenticationResponse(map).toUrlStringResponse();
	} catch (OpenIdException ex){
	    // this should never happen
	    log.error(ex);
	    return "internal error";
	}
    }

    /**
     * Signs the elements designated by the signed list with the given key and
     * returns the result encoded to a string.
     *
     * @param key the key to sign with (HMAC-SHA1)
     * @param signed the comma-separated list of elements to sign. The elements
     * must be mapped internally.
     * @return the Base 64 encoded result.
     * @throws OpenIdException at signature errors, or if the signed list points
     * to elements that are not mapped.
     */ 
    public String sign(byte[] key, String signed)
	throws OpenIdException
    {
	Map map = toMap();
	log.debug("in sign() map="+map);
	log.debug("in sign() signed="+signed);
	StringTokenizer st = new StringTokenizer(signed, ",");
	StringBuffer sb = new StringBuffer();
	while (st.hasMoreTokens()) {
	    String s = st.nextToken();
	    String name = "openid."+s;
	    String value = (String) map.get(name);
	    if (value == null){
		throw new OpenIdException("Cannot sign non-existent mapping: "
					  +s);
	    }
	    sb.append(s);
	    sb.append(':');
	    sb.append(value);
	    sb.append('\n');
	}
	try {
	    byte[] b = Crypto.hmacSha1(key, sb.toString().getBytes("UTF-8"));
 	    return Crypto.convertToString(b);
	} catch (UnsupportedEncodingException e){
	    throw new OpenIdException(e);
	} catch (InvalidKeyException e){
	    throw new OpenIdException(e);
	} catch (NoSuchAlgorithmException e){
	    throw new OpenIdException(e);
	}
    }


    /**
     * throws at errors in signature creation
     */
    AuthenticationResponse(AuthenticationRequest ar,
			   Association a, Crypto crypto,
			   String invalidateHandle)
	throws OpenIdException
    {
	super(null);
	mode = "id_res";
	identity = ar.getIdentity();
	returnTo = ar.getReturnTo();
	ns = ar.getNamespace();
	nonce = generateNonce();
	this.invalidateHandle = invalidateHandle; //may be null
	associationHandle = a.getHandle();
	signed = "identity,nonce,return_to";
	sreg = ar.getSimpleRegistration();
	log.debug("sreg="+sreg);
	if (sreg != null){
	    Map map = sreg.getSuppliedValues();
	    log.debug("sreg supplied values="+map);
	    Set set = map.entrySet();
	    for (Iterator iter = set.iterator(); iter.hasNext();){
		Map.Entry mapEntry = (Map.Entry) iter.next();
		String key = (String) mapEntry.getKey();
		signed += ",sreg." + key;
	    }
	}
	byte[] key = a.getMacKey();
	signature = sign(key, signed);
    }


    AuthenticationResponse(Map map) throws OpenIdException
    {
	super(map);
	Set set = map.entrySet();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();

	    if (AuthenticationResponse.OPENID_MODE.equals(key)) {
		mode = value;
	    } else if (AuthenticationResponse.OPENID_IDENTITY.equals(key)) {
		identity = value;
	    } else if (AuthenticationResponse.OPENID_RETURN_TO.equals(key)) {
		returnTo = value;
	    } else if (OPENID_NONCE.equals(key)) {
		nonce = value;
	    } else if (OPENID_INVALIDATE_HANDLE.equals(key)) {
		invalidateHandle = value;
	    } else if (OPENID_ASSOCIATION_HANDLE.equals(key)) {
		associationHandle = value;
	    } else if (OPENID_SIGNED.equals(key)) {
		signed = value;
	    } else if (OPENID_SIG.equals(key)) {
		signature = value;
	    }
	}
	this.sreg = SimpleRegistration.parseFromResponse(map);
	log.debug("authn resp constr sreg="+sreg);
    }

    public String toString()
    {
        return "[AuthenticationResponse "
            + super.toString()
	    +", sreg="+sreg
            +", mode="+mode
            +", nonce="+nonce
            +", association handle="+associationHandle
            +", invalidation handle="+invalidateHandle
            +", signed="+signed
            +", signature="+signature
            +", identity="+identity
	    +", return to="+returnTo
	    +"]";
    }

}