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

import java.util.Date;
import java.util.List;
import org.apache.log4j.Logger;
import org.apache.tsik.datatypes.Base64;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.Store;

/**
 * A database backed store.
 */
public class DbStore extends Store
{
    private final static Logger log = Logger.getLogger(DbStore.class);
    private DbStore() {}
    private static DbStore dbStore;

    /**
     * Returns the one database store.
     *
     * @return the database store.
     */
    public static DbStore getInstance()
    {
	if (dbStore == null){
	    dbStore = new DbStore();
	}
	return dbStore;
    }

    public org.verisign.joid.Association 
	generateAssociation(AssociationRequest req, Crypto crypto) 
	throws OpenIdException
    {
	Association a = new Association();
	a.setMode("unused");
	a.setHandle(Crypto.generateHandle());
	a.setSessionType(req.getSessionType());

	byte[] secret = null;
	if (req.isNotEncrypted()){
	    secret = crypto.generateSecret(req.getAssociationType());
	} else {
	    secret = crypto.generateSecret(req.getSessionType());
	    crypto.setDiffieHellman(req.getDhModulus(), req.getDhGenerator());
	    byte[] encryptedSecret 
		= crypto.encryptSecret(req.getDhConsumerPublic(), secret);
	    a.setEncryptedMacKey(encryptedSecret);
	    a.setPublicDhKey(crypto.getPublicKey());
	}
	a.setMacKey(secret);
	a.setIssuedDate(new Date());
	// lifetime in seconds
	a.setLifetime(new Long(60*10));

	a.setAssociationType(req.getAssociationType());
	return a;
    }

    public void saveAssociation(org.verisign.joid.Association a)
    {
        Session session = HibernateUtil.currentSession();
	Transaction tx = session.beginTransaction();
	session.save(a);
	tx.commit();
        HibernateUtil.closeSession();
    }

    public void deleteAssociation(org.verisign.joid.Association a)
    {
        Session session = HibernateUtil.currentSession();
	session.delete(a);
    }

    public org.verisign.joid.Association findAssociation(String handle)
	throws OpenIdException
    {
        Session session = HibernateUtil.currentSession();
	Transaction tx = session.beginTransaction();

	String s = "from Association as a where a.handle=:handle";
	Query q = session.createQuery(s);
	q.setParameter("handle",handle);
	List l = q.list();
	if (l.size() > 1) {
	    throw new OpenIdException("Non-unique association handle: "+handle);
	}
	tx.commit();
        HibernateUtil.closeSession();

	if (l.size() == 0) {
	    log.info("Found no such association: "+handle);
	    return null;
	} else {
	    return (Association) l.get(0);
	}
    }
    
}
