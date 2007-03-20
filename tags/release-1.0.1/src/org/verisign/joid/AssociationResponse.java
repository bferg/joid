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
import java.math.BigInteger;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Represents an OpenID association response.
 */
public class AssociationResponse extends Response
{
    private final static Logger log 
	= Logger.getLogger(AssociationResponse.class);
    private static String OPENID_SESSION_TYPE = "session_type";
    private static String OPENID_ASSOCIATION_TYPE = "assoc_type";

    private static String OPENID_ERROR_CODE = "error_code";
    private static String OPENID_ASSOCIATION_HANDLE = "assoc_handle";
    private static String OPENID_MAC_KEY = "mac_key";
    // package scope so that ResponseFactory can trigger on this key
    static String OPENID_ENC_MAC_KEY = "enc_mac_key";
    private static String OPENID_DH_SERVER_PUBLIC = "dh_server_public";
    private static String OPENID_EXPIRES_IN = "expires_in";

    private String sessionType;
    private String associationType;
    private String associationHandle;
    private int expiresIn;
    private byte[] macKey;
    private BigInteger dhServerPublic;
    private byte[] encryptedMacKey;
    private String errorCode;

    /** 
     * Returns the error code (if any) occured while processing this response.
     * @return the error code; null if none.
     */
    public String getErrorCode(){return errorCode;}

    /** 
     * Returns the association handle in this response.
     * @return the association handle in this response.
     */
    public String getAssociationHandle(){return associationHandle;}

    /** 
     * Returns the Diffie-Hellman public server key in this response.
     * @return the Diffie-Hellman public server key in this response.
     */
    public BigInteger getDhServerPublic(){return dhServerPublic;}

    /** 
     * Returns the MAC key in this response. See also 
     * {@link #getEncryptedMacKey()}
     * @return the MAC key in this response; null if none.
     */
    public byte[] getMacKey(){return macKey;}

    /** 
     * Returns the encrypted MAC key in this response. See also
     * {@link #getMacKey()}
     * @return the encrypted MAC key in this response; null if none.
     */
    public byte[] getEncryptedMacKey(){return encryptedMacKey;}

    /** 
     * Returns the static number of seconds this association expires in.
     * @return the number of seconds until expiration.
     */
    public int getExpiresIn(){return expiresIn;}

    /** 
     * Returns the association type in this response.
     * @return the association type in this response.
     */
    public String getAssociationType(){return associationType;}

    /** 
     * Returns the session type in this response.
     * @return the session type in this response.
     */
    public String getSessionType(){return sessionType;}

    Map toMap()
    {
	Map map = super.toMap();
       
	if (errorCode != null){
	    map.put(AssociationResponse.OPENID_ERROR_CODE, errorCode);
	} else {
	    map.put(AssociationResponse.OPENID_SESSION_TYPE, sessionType);
	    map.put(AssociationResponse.OPENID_ASSOCIATION_HANDLE, 
		    associationHandle);
	    map.put(AssociationResponse.OPENID_ASSOCIATION_TYPE, 
		    associationType);
	    map.put(AssociationResponse.OPENID_EXPIRES_IN, ""+expiresIn);
	    if (macKey != null){
		map.put(AssociationResponse.OPENID_MAC_KEY, 
			Crypto.convertToString(macKey));
	    } else if (encryptedMacKey != null){
		map.put(AssociationResponse.OPENID_DH_SERVER_PUBLIC, 
			Crypto.convertToString(dhServerPublic));
		map.put(AssociationResponse.OPENID_ENC_MAC_KEY, 
			Crypto.convertToString(encryptedMacKey));
	    }
	}
	return map;
    }

    AssociationResponse(AssociationRequest ar, Association a, Crypto crypto)
    {
	super(null);
	this.ns = ar.getNamespace();
	if (a.isSuccessful()){
	    this.sessionType = a.getSessionType();
	    this.associationHandle = a.getHandle();
	    this.associationType = a.getAssociationType();
	    this.expiresIn = a.getLifetime().intValue();
	    this.dhServerPublic = a.getPublicDhKey();
	    if (a.isEncrypted()) {
		this.encryptedMacKey = a.getEncryptedMacKey();
	    } else {
		this.macKey = a.getMacKey();
	    }
	} else {
	    this.errorCode = a.getErrorCode();
	    this.error = a.getError();
	}
    }


    AssociationResponse(Map map) throws OpenIdException
    {
	super(map);
	Set set = map.entrySet();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();

	    if (AssociationResponse.OPENID_SESSION_TYPE.equals(key)){
		sessionType = AssociationRequest.parseSessionType(value);
	    } 
	    else if (AssociationResponse
		       .OPENID_ASSOCIATION_TYPE.equals(key)){
		associationType
		    = AssociationRequest.parseAssociationType(value);
	    } 
	    else if (OPENID_DH_SERVER_PUBLIC.equals(key)){
		dhServerPublic = Crypto.convertToBigIntegerFromString(value);
	    } 
	    else if (OPENID_ASSOCIATION_HANDLE.equals(key)){
		associationHandle = value;
	    } 
	    else if (OPENID_EXPIRES_IN.equals(key)){
		expiresIn = Integer.parseInt(value);
	    } 
	    else if (OPENID_MAC_KEY.equals(key)){
		macKey = Crypto.convertToBytes(value);	
	    } 
	    else if (OPENID_ENC_MAC_KEY.equals(key)){
		encryptedMacKey = Crypto.convertToBytes(value);	
	    } 
	    else if (OPENID_ERROR_CODE.equals(key)){
		errorCode = value;	
	    }
	}
    }

    public String toString()
    {
	String s = "[AssociationResponse "
            + super.toString()
            +", session type="+sessionType
            +", association type="+associationType
            +", association handle="+associationHandle
	    +", expires in="+expiresIn;
	if (dhServerPublic != null) {
            s += ", server public key="+Crypto.convertToString(dhServerPublic);
	}
	if (macKey != null) {
            s += ", MAC key="+Crypto.convertToString(macKey);
	}
	if (encryptedMacKey != null) {
            s += ", encrypted MAC key="
		+Crypto.convertToString(encryptedMacKey);
	}
	if (errorCode != null) {
            s += ", error code="+errorCode;
	}
	s+="]";
	return s;
    }

}