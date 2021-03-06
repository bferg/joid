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
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.verisign.joid.IAssociation;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.INonce;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.IStore;
import org.verisign.joid.server.Association;
import org.verisign.joid.server.Nonce;


/**
 * A database backed store.
 */
public class DbStore implements IStore
{
    private final static Log log = LogFactory.getLog( DbStore.class );

    private long associationLifetime = 600;


    /**
     * {@inheritDoc}
     */
    public IAssociation generateAssociation( AssociationRequest req, Crypto crypto )
        throws OpenIdException
    {
        Association a = new Association();
        a.setHandle( Crypto.generateHandle() );
        a.setSessionType( req.getSessionType() );

        byte[] secret = null;
        if ( req.isNotEncrypted() )
        {
            secret = crypto.generateSecret( req.getAssociationType().toString() );
        }
        else
        {
            secret = crypto.generateSecret( req.getSessionType().toString() );
            crypto.setDiffieHellman( req.getDhModulus(), req.getDhGenerator() );
            byte[] encryptedSecret = crypto.encryptSecret( req.getDhConsumerPublic(), secret );
            a.setEncryptedMacKey( encryptedSecret );
            a.setPublicDhKey( crypto.getPublicKey() );
        }
        a.setMacKey( secret );
        a.setIssuedDate( new Date() );
        // lifetime in seconds
        a.setLifetime( new Long( associationLifetime ) );

        a.setAssociationType( req.getAssociationType() );
        return a;
    }


    /**
     * {@inheritDoc}
     */
    public INonce generateNonce( String nonce ) throws OpenIdException
    {
        Nonce n = new Nonce();
        n.setNonce( nonce );
        n.setCheckedDate( new Date() );
        return n;
    }


    /**
     * {@inheritDoc}
     */
    public void saveNonce( INonce n )
    {
        Session session = HibernateUtil.currentSession();
        Transaction tx = session.beginTransaction();
        session.save( n );
        tx.commit();
        HibernateUtil.closeSession();
    }


    /**
     * {@inheritDoc}
     */
    public void saveAssociation( IAssociation a )
    {
        Session session = HibernateUtil.currentSession();
        Transaction tx = session.beginTransaction();
        session.save( a );
        tx.commit();
        HibernateUtil.closeSession();
    }


    /**
     * {@inheritDoc}
     */
    public void deleteAssociation( IAssociation a )
    {
        Session session = HibernateUtil.currentSession();
        session.delete( a );
    }


    /**
     * {@inheritDoc}
     */
    public IAssociation findAssociation( String handle ) throws OpenIdException
    {
        Session session = HibernateUtil.currentSession();
        Transaction tx = session.beginTransaction();

        String s = "from Association as a where a.handle=:handle";
        Query q = session.createQuery( s );
        q.setParameter( "handle", handle );
        List<?> l = q.list();
        if ( l.size() > 1 )
        {
            throw new OpenIdException( "Non-unique association handle: " + handle );
        }
        tx.commit();
        HibernateUtil.closeSession();

        if ( l.size() == 0 )
        {
            log.debug( "Found no such association: " + handle );
            return null;
        }
        else
        {
            return ( IAssociation ) l.get( 0 );
        }
    }


    /**
     * {@inheritDoc}
     */
    public INonce findNonce( String nonce ) throws OpenIdException
    {
        Session session = HibernateUtil.currentSession();
        Transaction tx = session.beginTransaction();

        String s = "from Nonce as n where n.nonce=:nonce";
        Query q = session.createQuery( s );
        q.setParameter( "nonce", nonce );
        List<?> l = q.list();
        if ( l.size() > 1 )
        {
            throw new OpenIdException( "Non-unique nonce: " + nonce );
        }
        tx.commit();
        HibernateUtil.closeSession();

        if ( l.size() == 0 )
        {
            log.debug( "Found no such nonce: " + nonce );
            return null;
        }
        else
        {
            return ( INonce ) l.get( 0 );
        }
    }
}
