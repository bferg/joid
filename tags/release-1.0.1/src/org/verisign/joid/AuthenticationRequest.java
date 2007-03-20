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

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Represents an OpenID authentication request.
 */
public class AuthenticationRequest extends Request
{
    private final static Logger log 
	= Logger.getLogger(AuthenticationRequest.class);

    private String identity;
    private String handle;
    private String returnTo;
    private String trustRoot;
    private SimpleRegistration sreg;

    private final static String OPENID_IDENTITY = "openid.identity";
    private final static String OPENID_ASSOC_HANDLE = "openid.assoc_handle";
    private final static String 
	PICK_ONE = "http://openid.net/identifier_select/2.0";
    private final static String CHECKID_IMMEDIATE = "checkid_immediate";
    private final static String CHECKID_SETUP = "checkid_setup";

    private final static String OPENID_RETURN_TO = "openid.return_to";
    private final static String OPENID_TRUST_ROOT = "openid.trust_root";

    private static String OPENID_DH_CONSUMER_PUBLIC 
	= "openid.dh_consumer_public";

    private static String OPENID_SESSION_TYPE = "openid.session_type";
    private final static String DH_SHA1 = "DH-SHA1";
    private static Map statelessMap = new HashMap();
    private static AssociationRequest statelessAr;
    static {
	statelessMap.put(AuthenticationRequest.OPENID_SESSION_TYPE, 
			 AuthenticationRequest.DH_SHA1);
	// this value is not used for stateless, but it's not a valid
	// association request unless it's there
	//
	statelessMap.put(AuthenticationRequest.OPENID_DH_CONSUMER_PUBLIC, 
			 Crypto.convertToString(BigInteger.valueOf(1)));
	try {
	    // the request mode is irrelevant
	    //
	    statelessAr = new AssociationRequest(statelessMap, "");
	} catch (OpenIdException e){
	    // should not happen
	    //
	    throw new RuntimeException(e);
	}
    }

    /**
     * Creates a standard authentication request.
     *
     * @param identity the openid identity.
     * @param returnTo the return_to value.
     * @param trustRoot the openid trust_root.
     * @param assocHandle the openid association handle.
     * @return an AuthenticationRequest.
     * @throws OpenIdException if the request cannot be created.
     */
    public static 
	AuthenticationRequest create(String identity, String returnTo, 
				     String trustRoot, String assocHandle) 
	throws OpenIdException
    {
	Map map = new HashMap();
	map.put("openid.mode",CHECKID_SETUP);
	map.put(OPENID_IDENTITY, identity);
	map.put(OPENID_RETURN_TO, returnTo);
	map.put(OPENID_TRUST_ROOT, trustRoot);
	map.put(OPENID_ASSOC_HANDLE, assocHandle);
	return new AuthenticationRequest(map, CHECKID_SETUP);
    }


    AuthenticationRequest(Map map, String mode) throws OpenIdException
    {
	super(map, mode);
	Set set = map.entrySet();
	for (Iterator iter=set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();

	    if (OPENID_NS.equals(key)){
		this.ns = value;
	    } 
	    else if (OPENID_IDENTITY.equals(key)){
		this.identity = value;
	    } 
	    else if (OPENID_ASSOC_HANDLE.equals(key)){
		this.handle = value;
	    } 
	    else if (OPENID_RETURN_TO.equals(key)){
		this.returnTo = value; 
	    } 
	    else if (OPENID_TRUST_ROOT.equals(key)){
		this.trustRoot = value; 
	    }
	}
	this.sreg = new SimpleRegistration(map);
	checkInvariants();
    }

    Map toMap()
    {
	Map map = super.toMap();
       
	map.put(AuthenticationRequest.OPENID_IDENTITY, identity);
	map.put(AuthenticationRequest.OPENID_ASSOC_HANDLE, handle);
	map.put(AuthenticationRequest.OPENID_RETURN_TO, returnTo);
	map.put(AuthenticationRequest.OPENID_TRUST_ROOT, trustRoot);

	return map;
    }

    /**
     * Returns whether this request is immediate, that is, whether the
     * authentication mode is "CHECKID_IMMEDIATE".
     *
     * @return trut if this request is immediate; false otherwise.
     */
    public boolean isImmediate() 
    {
	return AuthenticationRequest.CHECKID_IMMEDIATE
	    .equals(this.mode);
    }

    private void checkInvariants() throws OpenIdException
    {
	if (mode == null){
	    throw new OpenIdException("Missing mode");
	}
	if (identity == null){
	    throw new OpenIdException("Missing identity");
	}
	if (trustRoot == null){
	    throw new OpenIdException("Missing trust root");
	}
	// actually optional per spec!
	/* if (returnTo == null){
	    throw new OpenIdException("Missing return to");
	    }*/
	checkTrustRoot();
    }

    private void checkTrustRoot() throws OpenIdException
    {
	if (trustRoot == null){
	    throw new OpenIdException("No "+OPENID_TRUST_ROOT+" given");
	}

	// URI fragments are not allowed in trustroot
	//
	if (trustRoot.indexOf('#') > 0) {
	    throw new OpenIdException("URI fragments are not allowed");
	}


	// Matched if:
	// 1. trustroot and returnto are identical
	// 2. trustroot contains wild-card characters "*.", and the 
	// trailing part of the returnto's domain is identical to the 
	// part of the trustroot following the "*." wildcard
	//
	// Trust root           Return to
	// ----------           ---------
	// example.com      =>  example.com      ==> ok
	// *.example.com    =>  example.com      ==> ok
	// *.example.com    =>  a.example.com    ==> ok
	// www.example.com  =>  a.example.com    ==> not ok
	//
	URL r, t;
	try {
	    r = new URL(returnTo);
	    t = new URL(trustRoot);
	} catch (MalformedURLException e) {
	    throw new OpenIdException("Malformed URL");
	}

	String tHost = new StringBuffer(t.getHost()).reverse().toString();
	String rHost = new StringBuffer(r.getHost()).reverse().toString();

	String[] tNames = tHost.split("\\.");
	String[] rNames = rHost.split("\\.");
	int len = (tNames.length > rNames.length) 
	    ? rNames.length : tNames.length;
	
	int i;
	for (i = 0; i < len; i += 1){
	    if (!(tNames[i].equals(rNames[i]))
		&& (!tNames[i].equals("*"))){
		throw new OpenIdException("returnTo not in trustroot set: "+
					  tNames[i]+", "+rNames[i]);
	    }
	}
	if ((i < tNames.length) && (!tNames[i].equals("*"))){
	    throw new OpenIdException("returnTo not in trustroot set: "+
				      tNames[1]);
	}


	// The return to path is equal to or a sub-directory of the 
	// realm's (trustroot's) path.
	//
	// Trust root     Return to
	// ----------     ---------
	// /a/b/c     =>  /a/b/c/d    ==> ok
	// /a/b/c     =>  /a/b        ==> not ok
	// /a/b/c     =>  /a/b/b      ==> not ok
	//

	String tPath = t.getPath();
	String rPath = r.getPath();

	int n = rPath.indexOf(tPath);
	if (n != 0) {
	    throw new OpenIdException("return to & trust root paths mismatch");
	}

	// if we're here, we're good to go!
    }


    public Response processUsing(Store store, Crypto crypto)
	throws OpenIdException
    {
	Association assoc = null;
	String invalidate = null;
	if (handle != null){
	    assoc = store.findAssociation(handle);
	    if (assoc != null && assoc.hasExpired()){
		log.info("Association handle has expired: "+handle);
		assoc = null;
	    }
	}
	if (handle == null || assoc == null){
	    log.info("Invalidating association handle: "+handle);
	    invalidate = handle;
	    assoc = store.generateAssociation(statelessAr, crypto);
	    store.saveAssociation(assoc);
	}
	return new AuthenticationResponse(this, assoc, crypto, invalidate);
    }

    /**
     * Returns the identity used in this authentication request.
     * 
     * @return the identity.
     */
    public String getIdentity(){return identity;}

    /**
     * Returns the 'return to' address in this authentication request.
     * 
     * @return the address.
     */
    public String getReturnTo(){return returnTo;}

    /**
     * Returns the handle used in this authentication request.
     * 
     * @return the handle
     */
    public String getHandle(){return handle;}

    /**
     * Returns the trust root address in this authentication request.
     * 
     * @return the address.
     */
    public String getTrustRoot(){return trustRoot;}

    /**
     * Returns the simple registration fields in this authentication request.
     * 
     * @return the sreg fields; or null if none present.
     */
    public SimpleRegistration getSimpleRegistration(){return sreg;}

    /**
     * Sets the simple registration fields in this authentication request.
     * 
     * @param sreg the registration fields.
     */
    public void setSimpleRegistration(SimpleRegistration sreg)
    {
	this.sreg = sreg;
    }

    public String toString()
    {
        return "[AuthenticationRequest "
	    + super.toString()
	    +", sreg="+sreg
            +", identity="+identity
            +", handle="+handle+", return to="+returnTo
            +", trust root="+trustRoot+"]";
    }

}
