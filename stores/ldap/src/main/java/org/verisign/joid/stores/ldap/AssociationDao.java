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
import java.util.Calendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.shared.ldap.model.constants.SchemaConstants;
import org.apache.directory.shared.ldap.model.cursor.SearchCursor;
import org.apache.directory.shared.ldap.model.entry.DefaultEntry;
import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.directory.shared.ldap.model.entry.Modification;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.shared.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.shared.ldap.model.message.SearchResultEntry;
import org.apache.directory.shared.ldap.model.message.SearchScope;
import org.apache.directory.shared.ldap.model.name.Dn;
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
    
    private LdapConnectionManager connMan;
    
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
     * @param connPool The LDAP connection manager to use.
     * @param baseDn The baseDn under which association entries are found.
     */
    AssociationDao( LdapConnectionManager connMan, Dn baseDn )
    {
        this.connMan = connMan;
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
            throw new OpenIdException( msg + ':' + e.toString(), e );
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
            conn = connMan.acquireConnection();
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
            connMan.releaseConnection( conn );
        }
        
        return entry;
    }


    /**
     * {@inheritDoc}
     */
    public void create( IAssociation association ) throws OpenIdException
    {
        LdapConnection conn = connMan.acquireConnection();
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
            connMan.releaseConnection( conn );
        }
    }

    
    /**
     * {@inheritDoc}
     */
    public void update( IAssociation entity, Entry before ) throws OpenIdException
    {
        Entry after = toEntry( entity );
        LdapConnection conn = connMan.acquireConnection();
        
        try
        {
            Modification[] mods = LdapStore.calculateModifications( before, after );
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
            connMan.releaseConnection( conn );
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
        LdapConnection conn = connMan.acquireConnection();
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
            String msg = "Failed to find association with handle: " + handle;
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        finally
        {
            connMan.releaseConnection( conn );
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
            LOG.warn( "No association to delte for pk: " + primaryKey );
            return null;
        }
        
        LdapConnection conn = null;
        Dn dn = getDn( primaryKey );

        try
        {
            conn = connMan.acquireConnection();
            conn.delete( dn );
        }
        catch ( LdapException e )
        {
            String msg = "Failed to delete association entry: " + dn.toString();
            LOG.error( msg, e );
            throw new OpenIdRuntimeException( msg, e ); 
        }
        finally
        {
            connMan.releaseConnection( conn );
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
            entry.add( SchemaConstants.OBJECT_CLASS_AT, ASSOCIATION_OC );
            entry.add( ASSOCIATION_TYPE_AT, association.getAssociationType() );
            entry.add( HANDLE_AT, association.getHandle() );
            entry.add( LIFETIME_AT, Long.toString( association.getLifetime() ) );
            entry.add( SECRET_AT, association.getMacKey() );
            
            Calendar calendar = Calendar.getInstance();
            calendar.setTime( association.getIssuedDate() );
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
}
