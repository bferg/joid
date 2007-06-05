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

package org.verisign.joid.db;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import org.apache.log4j.Logger;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;

/**
 * An association in the database.
 */
public class Association implements org.verisign.joid.Association
{
    private final static Logger log = Logger.getLogger(Association.class);
    private Long id;
    private String mode;
    private String handle;
    private String secret;
    private Date issuedDate;
    private Long lifetime;
    private String associationType;

    // Not in db
    private String error;
    private String sessionType;
    private byte[] encryptedMacKey;
    private BigInteger publicKey;

    public boolean isSuccessful()
    {
	return (error == null);
    }

    public boolean isEncrypted()
    {
	return ((AssociationRequest.DH_SHA1.equals(sessionType))
		|| (AssociationRequest.DH_SHA256.equals(sessionType)));
    }
    
    /**
     * Hibernate mapping.
     */
    public Long getId() {return id;}

    /** Hibernate mapping. */
    public String getSecret() {return secret;}

    /** Hibernate mapping. */
    public void setSecret(String secret) {this.secret = secret;}

    /** Hibernate mapping. */
    public void setId(Long id) {this.id = id;}

    /** Hibernate mapping. */
    public String getMode() {return mode;}

    /** Hibernate mapping. */
    public void setMode(String s) {mode = s;}

    /** Hibernate mapping. */
    public String getHandle() {return handle;}

    /** Hibernate mapping. */
    public void setHandle(String s) {this.handle = s;}

    /** Hibernate mapping. */
    public Date getIssuedDate() {return issuedDate;}

    /** Hibernate mapping. */
    public void setIssuedDate(Date issuedDate) 
    {
 	SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
 	Date tmp = issuedDate;
	sdf.format(tmp);
	this.issuedDate = tmp;
    }

    public Long getLifetime() {return lifetime;}
    public void setLifetime(Long lifetime) {this.lifetime = lifetime;}

    public String getAssociationType() {return associationType;}
    public void setAssociationType(String s) {this.associationType = s;}

    /**
     * Returns a string representation of this assocation.
     *
     * @return a string representation of this assocation.
     */
    public String toString() 
    {
	String s = "[Association secret="+secret;
	if (encryptedMacKey != null) {
	    s += ", encrypted secret="+Crypto.convertToString(encryptedMacKey);
	} 
	if (publicKey != null) {
	    s += ", public key="+Crypto.convertToString(publicKey);
	}
	s+=", type="+associationType+", issuedDate="+issuedDate+"]";
	return s;
    }

    public String getError() {return error;}

    public String getErrorCode(){throw new RuntimeException("nyi");}

    public void setSessionType(String sessionType)
    {
	this.sessionType = sessionType;
    }
    public String getSessionType()
    {
	return sessionType;
    }

    /** Hibernate mapping. */
    public void setMacKey(byte[] macKey)
    {
	this.secret = Crypto.convertToString(macKey);
    }

    /** Hibernate mapping. */
    public byte[] getMacKey()
    {
	return Crypto.convertToBytes(secret);
    }

    public void setEncryptedMacKey(byte[] b)
    {
	encryptedMacKey = b;
    }

    public byte[] getEncryptedMacKey()
    {
	return encryptedMacKey;
    }

    public void setPublicDhKey(BigInteger pk){publicKey = pk;}
    public BigInteger getPublicDhKey(){return publicKey;}

    public boolean hasExpired()
    {
	Calendar now = Calendar.getInstance();
	log.debug("now: "+now.toString());
	Calendar expired = Calendar.getInstance();
	log.debug("issuedDate: "+issuedDate.toString());
	expired.setTime(issuedDate);
	expired.add(Calendar.SECOND, lifetime.intValue());
	log.debug("expired: "+expired.toString());
	log.debug("now.after(expired): "+now.after(expired));
	return now.after(expired);
    }
}