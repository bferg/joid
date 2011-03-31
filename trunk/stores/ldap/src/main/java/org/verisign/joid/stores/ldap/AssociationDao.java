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


import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.shared.ldap.model.cursor.SearchCursor;
import org.apache.directory.shared.ldap.model.entry.DefaultEntry;
import org.apache.directory.shared.ldap.model.entry.DefaultModification;
import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.directory.shared.ldap.model.entry.EntryAttribute;
import org.apache.directory.shared.ldap.model.entry.Modification;
import org.apache.directory.shared.ldap.model.entry.ModificationOperation;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.shared.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.shared.ldap.model.filter.SearchScope;
import org.apache.directory.shared.ldap.model.message.SearchResultEntry;
import org.apache.directory.shared.ldap.model.name.Dn;
import org.apache.directory.shared.ldap.model.schema.AttributeType;
import org.apache.directory.shared.util.GeneralizedTime;
import org.verisign.joid.IAssociation;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.OpenIdRuntimeException;
import org.verisign.joid.server.Association;


/**
 * A data access object for managing {@link IAssociation} instance CRUD operations.
 *
 * @author <a href="mailto:akarasulu@gmail.com">Alex Karasulu</a>
 */
class AssociationDao implements LdapDao<IAssociation, String>
{
    private static final Log LOG = LogFactory.getLog( AssociationDao.class );
    
    private static final Modification[] EMPTY_MODS = new Modification[0];
    
    private LdapConnectionPool connPool;
    
    private Dn baseDn;

    static final String ASSOCIATION_TYPE_AT = "opAssociationTypeAt";

    static final String HANDLE_AT = "opHandleAt";

    static final String ISSUED_DATE_AT = "opIssuedDateAt";

    static final String LIFETIME_AT = "opLifetimeAt";
    
    static final String MODE_AT = "opModeAt";

    static final String SECRET_AT = "opSecretAt";

    static final String ASSOCIATION_OC = "opAssociationOc";
    
    
    /**
     * Creates a new instance of AssociationDao.
     *
     * @param connPool The LDAP Connection Pool to use.
     * @param baseDn The baseDn under which association entries are found.
     */
    AssociationDao( LdapConnectionPool connPool, Dn baseDn )
    {
        this.connPool = connPool;
        this.baseDn = baseDn;
    }

    
    // -----------------------------------------------------------------------
    // LdapDao implementation methods
    // -----------------------------------------------------------------------
    
    
    /**
     * {@inheritDoc}
     */
    public Dn getDn( String handle ) throws OpenIdException
    {
        StringBuilder sb = new StringBuilder( HANDLE_AT );
        sb.append( '=' ).append( handle );

        Dn associationDn = null;
    
        try
        {
            associationDn = baseDn.add( sb.toString() );
        }
        catch ( LdapInvalidDnException e )
        {
            String msg = "Failed to create dn for association entry to delete";
            LOG.error( msg, e );
            throw new OpenIdException( msg + ':' + e.toString() );
        }
    
        return associationDn;
    }
    
    
    /**
     * {@inheritDoc}
     */
    public Entry getEntry( String handle ) throws OpenIdException
    {
        LdapConnection conn = null;

        Dn dn = getDn( handle );
        Entry entry = null;
        
        try
        {
            conn = acquireConnection();
            entry = conn.lookup( dn );
        }
        catch ( LdapNoSuchObjectException e )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( "getEntry( Association ): entry " + dn + " not found in store. "
                    + "Returning a null entry." );
            }
        }
        catch ( LdapException e )
        {
            String msg = "getEntry( Association ): unexpected failure: " + e.getMessage();
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        finally
        {
            releaseConnection( conn );
        }
        
        return entry;
    }


    /**
     * {@inheritDoc}
     */
    public void create( IAssociation association ) throws OpenIdException
    {
        LdapConnection conn = acquireConnection();
        Entry entry = toEntry( association );

        try
        {
            conn.add( entry );
        }
        catch ( LdapException e )
        {
            String msg = "create( Association ): unexpected failure";
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        finally
        {
            releaseConnection( conn );
        }
    }

    
    /**
     * {@inheritDoc}
     */
    public void update( IAssociation entity, Entry before ) throws OpenIdException
    {
        Entry after = toEntry( entity );
        LdapConnection conn = acquireConnection();
        
        try
        {
            Modification[] mods = calculateModifications( before, after );
            conn.modify( before.getDn(), mods );
        }
        catch ( LdapException e )
        {
            String msg = "update( IAssociation, Entry ): unexpected failure";
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        finally
        {
            releaseConnection( conn );
        }
    }

    
    /**
     * {@inheritDoc}
     */
    public void update( IAssociation entity ) throws OpenIdException
    {
        update( entity, getEntry( entity.getHandle() ) );
    }


    /**
     * {@inheritDoc}
     */
    public IAssociation read( String handle ) throws OpenIdException
    {
        LdapConnection conn = acquireConnection();
        StringBuilder sb = new StringBuilder( '(' );
        sb.append( HANDLE_AT );
        sb.append( '=' ).append( handle ).append( ')' );

        try
        {
            SearchCursor cursor = conn.search( baseDn, sb.toString(), SearchScope.ONELEVEL, "*" );
            SearchResultEntry response = ( SearchResultEntry ) cursor.get();

            if ( cursor.next() == true )
            {
                throw new OpenIdException( "Did not expect to get more than one association back." );
            }

            return toObject( response.getEntry() );
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
    public IAssociation delete( String primaryKey ) throws OpenIdException
    {
        IAssociation association = read( primaryKey );

        if ( association == null )
        {
            LOG.warn( "No association to delte for pk" + primaryKey );
            return null;
        }
        
        LdapConnection conn = null;
        Dn associationDn = getDn( primaryKey );

        try
        {
            conn = acquireConnection();
            conn.delete( associationDn );
        }
        catch ( LdapException e )
        {
            String msg = "Failed to delete association entry: " + associationDn.toString();
            LOG.error( msg, e );
            throw new OpenIdRuntimeException( msg, e ); 
        }
        finally
        {
            releaseConnection( conn );
        }
        
        return association;
    }


    /**
     * {@inheritDoc}
     */
    public void deleteEntry( IAssociation entity ) throws OpenIdException
    {
        delete( entity.getHandle() );
    }


    /**
     * {@inheritDoc}
     */
    public IAssociation toObject( Entry entry ) throws OpenIdException
    {
        Association association = new Association();
        association.setAssociationType( entry.get( ASSOCIATION_TYPE_AT ).get().toString() );
        association.setHandle( entry.get( HANDLE_AT ).get().toString() );

        GeneralizedTime gt = null;
        
        try
        {
            gt = new GeneralizedTime( entry.get( ISSUED_DATE_AT ).get().toString() );
        }
        catch ( ParseException e )
        {
            String msg = "Parsing generalizedTime attribute failed";
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        
        association.setIssuedDate( gt.getCalendar().getTime() );
        association.setLifetime( Long.parseLong( entry.get( LIFETIME_AT ).get().toString() ) );
        association.setMode( entry.get( MODE_AT ).get().toString() );
        association.setSecret( entry.get( SECRET_AT ).get().toString() );

        return association;
    }


    /**
     * {@inheritDoc}
     */
    public Entry toEntry( IAssociation association ) throws OpenIdException
    {
        Entry entry = new DefaultEntry( getDn( association.getHandle() ) );
       
        try
        {
            entry.add( ASSOCIATION_TYPE_AT, association.getAssociationType() );
            entry.add( HANDLE_AT, association.getHandle() );
            entry.add( LIFETIME_AT, Long.toString( association.getLifetime() ) );
            entry.add( SECRET_AT, association.getMacKey() );
            
            Calendar calendar = Calendar.getInstance();
            calendar.setTime( new Date() );
            GeneralizedTime gt = new GeneralizedTime( calendar );
            entry.add( ISSUED_DATE_AT, gt.toGeneralizedTime() );
        }
        catch ( LdapException e )
        {
            String msg = "Failed to generate LDAP entry from association: " + association;
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        
        return entry;
    }

    
    // -----------------------------------------------------------------------
    // Private methods
    // -----------------------------------------------------------------------
    
    
    private Modification[] calculateModifications( Entry before, Entry after ) throws LdapException 
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

    
    private LdapConnection acquireConnection() 
    {
        try
        {
            return connPool.getConnection();
        }
        catch ( Exception e )
        {
            LOG.error( "Failed to acquire LDAP connection", e );
            throw new OpenIdRuntimeException( e.getMessage() );
        }
    }


    private void releaseConnection( LdapConnection conn )
    {
        try
        {
            connPool.releaseConnection( ( LdapNetworkConnection ) conn );
        }
        catch ( Exception e )
        {
            LOG.error( "Failed to release LDAP connection", e );
        }
    }
}
