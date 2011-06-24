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
import org.apache.directory.shared.ldap.model.cursor.EntryCursor;
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
import org.verisign.joid.INonce;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.OpenIdRuntimeException;
import org.verisign.joid.server.Nonce;


/**
 * An LDAP data access object for Nonce objects.
 *
 * @author <a href="mailto:akarasulu@gmail.com">Alex Karasulu</a>
 */
public class NonceDao implements LdapDao<INonce, String>
{
    static final String CHECKED_DATE_AT = "opCheckedDateAt";
    static final String NONCE_AT = "opNonceAt";
    static final String NONCE_OC = "opNonceOc";

    private static final Log LOG = LogFactory.getLog( NonceDao.class );
    
    private LdapConnectionManager connMan;
    
    private Dn baseDn;


    /**
     * Creates a new instance of NonceDao.
     *
     * @param connPool The LDAP Connection manager to use.
     * @param baseDn The baseDn under which nonce entries are found.
     */
    NonceDao( LdapConnectionManager connMan, Dn baseDn )
    {
        this.connMan = connMan;
        this.baseDn = baseDn;
    }

    
    /**
     * Creates a new instance of NonceDao.
     *
     * @param connPool The LDAP Connection manager to use.
     * @param baseDn The baseDn under which nonce entries are found.
     */
    NonceDao( LdapConnectionManager connMan, String baseDn ) throws OpenIdException
    {
        this.connMan = connMan;
        
        try
        {
            this.baseDn = new Dn( baseDn );
        }
        catch ( LdapInvalidDnException e )
        {
            String msg = "Invalid dn base argument: " + baseDn;
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
    }

    
    // -----------------------------------------------------------------------
    // LdapDao implementation methods
    // -----------------------------------------------------------------------
    
    
    /**
     * {@inheritDoc}
     */
    public void create( INonce entity ) throws OpenIdException
    {
        LdapConnection conn = connMan.acquireConnection();
        Entry entry = toEntry( entity );

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
    public INonce read( String nonce ) throws OpenIdException
    {
        LdapConnection conn = connMan.acquireConnection();
        StringBuilder sb = new StringBuilder( "(" );
        sb.append( NONCE_AT );
        sb.append( '=' ).append( nonce ).append( ')' );

        EntryCursor cursor = null;
        try
        {
            cursor = conn.search( baseDn, sb.toString(), SearchScope.ONELEVEL, "*" );

            if ( cursor.next() )
            {
                SearchResultEntry response = ( SearchResultEntry ) cursor.get();

                if ( cursor.next() == true )
                {
                    throw new OpenIdException( "Did not expect to get more than one nonce back." );
                }

                return toObject( response.getEntry() );
            }
            else
            {
                return null;
            }
        }
        catch ( Exception e )
        {
            String msg = "Failed to find nonce with handle: " + nonce;
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        finally
        {
            if ( cursor != null )
            {
                try
                {
                    cursor.close();
                }
                catch ( Exception e )
                {
                    LOG.warn( "Failed to properly close a cursor.", e );
                }
            }
            connMan.releaseConnection( conn );
        }
    }

    
    /**
     * {@inheritDoc}
     */
    public void update( INonce entity ) throws OpenIdException
    {
        update( entity, getEntry( entity.getNonce() ) );
    }


    /**
     * {@inheritDoc}
     */
    public void update( INonce entity, Entry entry ) throws OpenIdException
    {
        Entry after = toEntry( entity );
        LdapConnection conn = connMan.acquireConnection();
        
        try
        {
            Modification[] mods = LdapStore.calculateModifications( entry, after );
            conn.modify( entry.getDn(), mods );
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
    public INonce delete( String primaryKey ) throws OpenIdException
    {
        INonce nonce = read( primaryKey );
        
        if ( nonce == null )
        {
            LOG.warn( "No nonce for pk: " + primaryKey );
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
            String msg = "Failed to delete nonce entry: " + dn.toString();
            LOG.error( msg, e );
            throw new OpenIdRuntimeException( msg, e ); 
        }
        finally
        {
            connMan.releaseConnection( conn );
        }
        
        return nonce;
    }

    
    /**
     * {@inheritDoc}
     */
    public void deleteEntry( INonce entity ) throws OpenIdException
    {
        delete( entity.getNonce() );
    }

    
    /**
     * {@inheritDoc}
     */
    public INonce toObject( Entry entry ) throws OpenIdException
    {
        if ( ! entry.contains( SchemaConstants.OBJECT_CLASS_AT, NONCE_OC ) )
        {
            throw new OpenIdException( "Entry's objectClass does not contain " + NONCE_OC );
        }
        
        Nonce nonce = new Nonce();
        nonce.setNonce( entry.get( NONCE_AT ).get().toString() );
        
        GeneralizedTime gt = null;
        
        try
        {
            String gtString = entry.get( CHECKED_DATE_AT ).get().toString();
            gt = new GeneralizedTime( gtString );
        }
        catch ( ParseException e )
        {
            String msg = "Parsing generalizedTime attribute failed";
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        
        nonce.setCheckedDate( gt.getCalendar().getTime() );
        
        return nonce;
    }

    
    /**
     * {@inheritDoc}
     */
    public Entry toEntry( INonce nonce ) throws OpenIdException
    {
        Entry entry = new DefaultEntry( getDn( nonce.getNonce() ) );
        
        try
        {
            entry.add( SchemaConstants.OBJECT_CLASS_AT, NONCE_OC );
            entry.add( NONCE_AT, nonce.getNonce() );
            
            Calendar calendar = Calendar.getInstance();
            calendar.setTime( nonce.getCheckedDate() );
            GeneralizedTime gt = new GeneralizedTime( calendar );
            entry.add( CHECKED_DATE_AT, gt.toGeneralizedTime() );
        }
        catch ( LdapException e )
        {
            String msg = "Failed to generate LDAP entry from nonce: " + nonce;
            LOG.error( msg, e );
            throw new OpenIdException( msg, e );
        }
        
        return entry;
    }

    
    /**
     * {@inheritDoc}
     */
    public Entry getEntry( String nonce ) throws OpenIdException
    {
        LdapConnection conn = null;

        Dn dn = getDn( nonce );
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
    public Dn getDn( String nonce ) throws OpenIdException
    {
        StringBuilder sb = new StringBuilder( NONCE_AT );
        sb.append( '=' ).append( nonce );

        Dn dn = null;
    
        try
        {
            dn = baseDn.add( sb.toString() );
        }
        catch ( LdapInvalidDnException e )
        {
            String msg = "Failed to create dn for nonce entry to delete";
            LOG.error( msg, e );
            throw new OpenIdException( msg + ':' + e.toString(), e );
        }
    
        return dn;
    }
}
