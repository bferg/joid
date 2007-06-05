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

// import java.math.BigInteger;
// import java.util.Calendar;
// import org.verisign.joid.AssociationRequest;
// import org.verisign.joid.Crypto;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.apache.log4j.Logger;

/**
 * A nonce in the database.
 */
public class Nonce implements org.verisign.joid.Nonce
{
    private final static Logger log = Logger.getLogger(Nonce.class);
    private Long id;
    private String nonce;
    private Date checkedDate;
    
    /** Hibernate mapping. */
    public Long getId() {return id;}

    /** Hibernate mapping. */
    public void setId(Long id) {this.id = id;}

    /** Hibernate mapping. */
    public String getNonce() {return nonce;}
    /** Hibernate mapping. */
    public void setNonce(String s) {nonce = s;}

    /** Hibernate mapping. */
    public Date getCheckedDate() {return checkedDate;}

    /** Hibernate mapping. */
    public void setCheckedDate(Date date) 
    {
 	SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
 	Date tmp = date;
	sdf.format(tmp);
	this.checkedDate = tmp;
    }

    /**
     * Returns a string representation of this nonce.
     *
     * @return a string representation of this nonce.
     */
    public String toString() 
    {
	return "[Nonce nonce="+nonce+", checked="+checkedDate+"]";
    }
}
