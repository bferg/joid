/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.verisign.joid.stores.ldap;


import java.awt.dnd.InvalidDnDOperationException;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.shared.ldap.model.cursor.SearchCursor;
import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.shared.ldap.model.filter.SearchScope;
import org.apache.directory.shared.ldap.model.message.Response;
import org.apache.directory.shared.ldap.model.message.SearchResultEntry;
import org.apache.directory.shared.ldap.model.name.Dn;
import org.apache.directory.shared.util.GeneralizedTime;

import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.IAssociation;
import org.verisign.joid.INonce;
import org.verisign.joid.IStore;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.OpenIdRuntimeException;
import org.verisign.joid.server.Association;
import org.verisign.joid.server.Nonce;


/**
 * An LDAP based IStore implementation.
 *
 * @author <a href="mailto:akarasulu@gmail.com">Alex Karasulu</a>
 */
public class LdapStore implements IStore, JoidLdapConstants
{
    private final static Log LOG = LogFactory.getLog( LdapStore.class );
    
    
    /** The association life time */
    private long associationLifetime = 600;

    
    private Dn nonceBaseDn;
    private Dn associationBaseDn;
    
    

    /**
     * @param nonceBaseDn the nonceBaseDn to set
     */
    public void setNonceBaseDn( Dn nonceBaseDn )
    {
        this.nonceBaseDn = nonceBaseDn;
    }


    /**
     * @return the nonceBaseDn
     */
    public Dn getNonceBaseDn()
    {
        return nonceBaseDn;
    }


    /**
     * @param associationBaseDn the associationBaseDn to set
     */
    public void setAssociationBaseDn( Dn associationBaseDn )
    {
        this.associationBaseDn = associationBaseDn;
    }


    /**
     * @return the associationBaseDn
     */
    public Dn getAssociationBaseDn()
    {
        return associationBaseDn;
    }


    /**
     * @param associationLifetime the associationLifetime to set
     */
    public void setAssociationLifetime( long associationLifetime )
    {
        this.associationLifetime = associationLifetime;
    }


    /**
     * @return the associationLifetime
     */
    public long getAssociationLifetime()
    {
        return associationLifetime;
    }
    
    
    private LdapConnection acquireConnection()
    {
        return null;
    }
    
    
    private void releaseConnection( LdapConnection conn )
    {
        
    }


    /**
     * {@inheritDoc}
     */
    public IAssociation generateAssociation( AssociationRequest req, Crypto crypto ) throws OpenIdException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( "Generating association from request:" + req );
        }
        
        Association a = new Association();
        a.setMode( "unused" );
        a.setHandle( Crypto.generateHandle() );
        a.setSessionType( req.getSessionType() );
        
        byte[] secret = null;
        if ( req.isNotEncrypted() )
        {
            secret = crypto.generateSecret( req.getAssociationType() );
        }
        else
        {
            secret = crypto.generateSecret( req.getSessionType() );
            crypto.setDiffieHellman( req.getDhModulus(), req.getDhGenerator() );
            byte[] encryptedSecret = crypto.encryptSecret( req.getDhConsumerPublic(), secret );
            a.setEncryptedMacKey( encryptedSecret );
            a.setPublicDhKey( crypto.getPublicKey() );
        }
        a.setMacKey( secret );
        a.setIssuedDate( new Date() );
        // lifetime in seconds
        a.setLifetime( new Long( getAssociationLifetime() ) );

        a.setAssociationType( req.getAssociationType() );
        return a;
    }


    /**
     * {@inheritDoc}
     */
    public void deleteAssociation( IAssociation a )
    {
        LdapConnection conn = acquireConnection();
        StringBuilder sb = new StringBuilder( HANDLE_AT );
        sb.append( '=' ).append( a.getHandle() );
        
        Dn deleteDn = null; 

        try
        {
            deleteDn = associationBaseDn.add( sb.toString() );
            conn.delete( deleteDn );
        }
        catch ( LdapInvalidDnException e )
        {
            String msg = "Failed to create dn for association entry to delete";
            LOG.error( msg, e );
            throw new OpenIdRuntimeException( msg + ':' + e.toString() );
        }
        catch ( LdapException e )
        {
            String msg = "Failed to delete association entry: " + deleteDn.toString();
            LOG.error( msg, e );
        }
        finally
        {
            releaseConnection( conn );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void saveAssociation( IAssociation a )
    {
    }


    /**
     * {@inheritDoc}
     */
    public IAssociation findAssociation( String handle ) throws OpenIdException
    {
        LdapConnection conn = acquireConnection();
        StringBuilder sb = new StringBuilder( '(' );
        sb.append( HANDLE_AT );
        sb.append( '=' ).append( handle ).append( ')' );
        
        try
        {
            SearchCursor cursor = conn.search( associationBaseDn, sb.toString(), SearchScope.ONELEVEL, "*" );
            SearchResultEntry response = ( SearchResultEntry ) cursor.get();
            
            if ( cursor.next() == true )
            {
                throw new OpenIdException( "Did not expect to get more than one association back." );
            }
            
            Entry entry = response.getEntry();
            Association a = new Association();
            a.setAssociationType( entry.get( ASSOCIATION_TYPE_AT ).get().toString() );
            a.setHandle( entry.get( HANDLE_AT ).get().toString() );
            
            GeneralizedTime gt = new GeneralizedTime( entry.get( ISSUED_DATE_AT ).get().toString() );
            a.setIssuedDate( gt.getCalendar().getTime() );
            a.setLifetime( Long.parseLong( entry.get( LIFETIME_AT ).get().toString() ) );
            a.setMode( entry.get( MODE_AT ).get().toString() );
            a.setSecret( entry.get( SECRET_AT ).get().toString() );
            a.setAssociationType( entry.get( ASSOCIATION_TYPE_AT ).get().toString() );
            
            return a;
        }
        catch ( Exception e )
        {
            LOG.error( "Failed to find association with handle: " + handle, e );
            throw new OpenIdException( e );
        }
        finally
        {
            releaseConnection( conn );
        }
    }


    /**
     * {@inheritDoc}
     */
    public INonce findNonce( String nonce ) throws OpenIdException
    {
        return null;
    }


    /**
     * {@inheritDoc}
     */
    public void saveNonce( INonce n )
    {
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
}
