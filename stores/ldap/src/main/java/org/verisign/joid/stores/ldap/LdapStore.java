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


import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.PoolableLdapConnectionFactory;
import org.apache.directory.shared.ldap.model.entry.DefaultModification;
import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.directory.shared.ldap.model.entry.EntryAttribute;
import org.apache.directory.shared.ldap.model.entry.Modification;
import org.apache.directory.shared.ldap.model.entry.ModificationOperation;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.name.Dn;
import org.apache.directory.shared.ldap.model.schema.AttributeType;

import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.IAssociation;
import org.verisign.joid.INonce;
import org.verisign.joid.IStore;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.server.Association;
import org.verisign.joid.server.Nonce;


/**
 * An LDAP based IStore implementation.
 *
 * @author <a href="mailto:akarasulu@gmail.com">Alex Karasulu</a>
 */
public class LdapStore implements IStore
{
    private final static Log LOG = LogFactory.getLog( LdapStore.class );

    private static final Modification[] EMPTY_MODS = new Modification[0];
    
    /** The association life time */
    private long associationLifetime = 600;

    private Dn nonceBaseDn;
    private Dn associationBaseDn;

    private AssociationDao associationDao;
    private NonceDao nonceDao;
    
    private LdapConnectionConfig connConfig;
    private LdapConnectionPool connPool;
    
    
    public void initialize()
    {
        connPool = new LdapConnectionPool( new PoolableLdapConnectionFactory( getConnConfig() ) );
        
        associationDao = new AssociationDao( new LdapNetworkConnectionManager( connPool ), associationBaseDn );
        nonceDao = new NonceDao( new LdapNetworkConnectionManager( connPool ), associationBaseDn );
    }
    

    /**
     * @param connConfig the connConfig to set
     */
    public void setConnConfig( LdapConnectionConfig connConfig )
    {
        this.connConfig = connConfig;
    }


    /**
     * @return the connConfig
     */
    public LdapConnectionConfig getConnConfig()
    {
        return connConfig;
    }


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
    public void deleteAssociation( IAssociation association ) throws OpenIdException
    {
        associationDao.deleteEntry( association );
    }
    

    /**
     * {@inheritDoc}
     */
    public void saveAssociation( IAssociation association ) throws OpenIdException
    {
        Entry entry = associationDao.getEntry( association.getHandle() );
        
        if ( entry == null )
        {
            associationDao.create( association );
        }
        else
        {
            associationDao.update( association, entry );
        }
    }
    

    /**
     * {@inheritDoc}
     */
    public IAssociation findAssociation( String handle ) throws OpenIdException
    {
        return associationDao.read( handle );
    }


    /**
     * {@inheritDoc}
     */
    public INonce findNonce( String nonce ) throws OpenIdException
    {
        return nonceDao.read( nonce );
    }


    /**
     * {@inheritDoc}
     */
    public void saveNonce( INonce nonce ) throws OpenIdException
    {
        Entry entry = nonceDao.getEntry( nonce.getNonce() );
        
        if ( entry == null )
        {
            nonceDao.create( nonce );
        }
        else
        {
            nonceDao.update( nonce, entry );
        }
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


    // -----------------------------------------------------------------------
    // Utility methods
    // -----------------------------------------------------------------------
    
    
    static Modification[] calculateModifications( Entry before, Entry after ) throws LdapException 
    {
        List<Modification> modList = new ArrayList<Modification>();

        for ( EntryAttribute attribute : before )
        {
            AttributeType type = attribute.getAttributeType();
            EntryAttribute afterAttribute = after.get( type );
            
            // if after change attribute is null then op is a remove
            if ( afterAttribute == null )
            {
                modList.add( new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attribute ) );
                continue;
            }
            
            // if both attributes are equal do nothing
            if ( afterAttribute.equals( attribute ) )
            {
                continue;
            }
                
            // if single valued attribute then perform a replace 
            if ( type.isSingleValued() )
            {
                modList.add( new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, afterAttribute ) );
                continue;
            }
            
            // if multi-valued attribute then we must determine what changed
            throw new NotImplementedException();
            
        }
        
        
        // calculate add attribute modifications to perform for attributes present in 
        // after entry but not present in before entry due to add changes 
        for ( EntryAttribute attribute : after )
        {
            AttributeType type = attribute.getAttributeType();
            EntryAttribute beforeAttribute = before.get( type );
            
            // if before change attribute is null then op is an add
            if ( beforeAttribute == null )
            {
                modList.add( new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attribute ) );
                continue;
            }
        }
        
        
        return modList.toArray( EMPTY_MODS );
    }
}
