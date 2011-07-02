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


import static org.junit.Assert.*;

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.PoolableLdapConnectionFactory;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.shared.ldap.model.constants.SchemaConstants;
import org.apache.directory.shared.ldap.model.entry.DefaultEntry;
import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.directory.shared.ldap.model.name.Dn;
import org.apache.directory.shared.util.GeneralizedTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.verisign.joid.INonce;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.server.Nonce;


/**
 * Integration test cases for the NonceDao implementation.
 *
 * @author <a href="mailto:akarasulu@apache.org">Alex Karasulu</a>
 */
@RunWith( FrameworkRunner.class )
@CreateDS( allowAnonAccess = true, name = "NonceDaoITest-class", partitions =
    {
        @CreatePartition(
            name = "joid",
            suffix = "dc=joid,dc=org",
            contextEntry = @ContextEntry(
                entryLdif = "dn: dc=joid,dc=org\n" +
                    "dc: joid\n" +
                    "objectClass: top\n" +
                    "objectClass: domain\n\n" ),
            indexes =
            {
                @CreateIndex( attribute = "objectClass" ),
                @CreateIndex( attribute = "dc" ),
                @CreateIndex( attribute = "ou" )
            })
    } )
@CreateLdapServer( transports =
    { @CreateTransport(protocol = "LDAP") })

@ApplyLdifFiles( "openid.ldif" )   
@ApplyLdifs(
    {
        // Entry # 0
        "dn: ou=nonces,dc=joid,dc=org",
        "objectClass: organizationalUnit",
        "objectClass: top",
        "ou: nonces",
        "description: openid nonces reside under this search base",

        // Entry # 1
        "dn: ou=associations,dc=joid,dc=org",
        "objectClass: organizationalUnit",
        "objectClass: top",
        "ou: associations",
        "description: openid nonces reside under this search base"
    }
)
public class NonceDaoITest extends AbstractLdapTestUnit
{
    private static final Logger LOG = LoggerFactory.getLogger( NonceDaoITest.class );
    
    private static final String BASE_DN = "ou=nonces,dc=joid,dc=org";
    
    private INonce nonce;

    private NonceDao dao;
    
    
    @Before
    public void before() throws Exception
    {
        assertTrue( getLdapServer().isEnabled() );
        
        LdapConnectionConfig config = new LdapConnectionConfig();
        
        config.setName( "uid=admin,ou=system" );
        config.setCredentials( "secret" );
        config.setLdapHost( "localhost" );
        config.setLdapPort( getLdapServer().getPort() );
        
        LOG.info( "Connection config = {}", config );
        
        // Test to see if we can bind to the LDAP server
        LdapNetworkConnection conn = new LdapNetworkConnection( config );
        conn.connect();
        conn.bind();
        assertTrue( conn.exists( "dc=joid,dc=org" ) );
        conn.close();

        LdapConnectionPool connPool = new LdapConnectionPool( new PoolableLdapConnectionFactory( config ) );
        LdapNetworkConnectionManager connMan = new LdapNetworkConnectionManager( connPool );
        dao = new NonceDao( connMan, BASE_DN );
        nonce = generateNonce();
    }
    
    
    @After
    public void after() throws Exception
    {
        dao = null;
        nonce = null;
    }
    
    
    /**
     * Utility method to generate and reuse a Nonce.
     *
     * @return the generated random nonce.
     * @throws OpenIdException
     */
    private static INonce generateNonce() throws OpenIdException
    {
        String nonce = RandomStringUtils.randomAlphanumeric( 16 );
        Nonce n = new Nonce();
        n.setNonce( nonce );
        n.setCheckedDate( new Date() );
        return n;
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#create(org.verisign.joid.INonce)}.
     */
    @Test
    public void testCreate() throws Exception
    {
        assertNotNull( ldapServer );
        dao.create( nonce );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#create(org.verisign.joid.INonce)}.
     */
    @Test( expected = OpenIdException.class )
    public void testDoubleCreate() throws Exception
    {
        assertNotNull( ldapServer );
        dao.create( nonce );
        dao.create( nonce );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#read(java.lang.String)}.
     */
    @Test
    public void testRead() throws Exception
    {
        testCreate();
        INonce reloaded = dao.read( nonce.getNonce() );
        assertEquals( reloaded.getNonce(), nonce.getNonce() );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#read(java.lang.String)}.
     */
    @Test
    public void testReadNonexistant() throws Exception
    {
        testCreate();
        INonce reloaded = dao.read( "nonexistant-nonce" );
        assertNull( "Should return null to show non-existance", reloaded );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#update(org.verisign.joid.INonce)}.
     */
    @Test
    public void testUpdateINonce() throws Exception
    {
        testCreate();
        INonce reloaded = dao.read( nonce.getNonce() );
        assertEquals( reloaded.getNonce(), nonce.getNonce() );

        // now set the reloaded instance's date to UNIX start 
        Date newDate = new Date( 0 );
        reloaded.setCheckedDate( newDate );

        // the reloaded no longer has the same checked date as the original nonce instance
        assertFalse( reloaded.getCheckedDate().equals( nonce.getCheckedDate() ) );
        
        // now update the store with the new date
        dao.update( reloaded );
        
        // keep a handle on the lastReloaded instance and reload the reloaded again
        INonce lastReloaded = reloaded;
        reloaded = dao.read( nonce.getNonce() );

        // the lastReloaded and freshly reloaded instances should be the 
        // same yet different from the original nonce we started out with
        assertFalse( reloaded.equals( lastReloaded ) );
        assertTrue( reloaded.getCheckedDate().equals( lastReloaded.getCheckedDate() ) );
        assertFalse( reloaded.getCheckedDate().equals( nonce.getCheckedDate() ) );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#update(org.verisign.joid.INonce, org.apache.directory.shared.ldap.model.entry.Entry)}.
     */
    @Test
    public void testUpdateINonceEntry() throws Exception
    {
        testCreate();
        INonce reloaded = dao.read( nonce.getNonce() );
        assertEquals( reloaded.getNonce(), nonce.getNonce() );

        // now set the reloaded instance's date to UNIX start 
        Date newDate = new Date( 0 );
        reloaded.setCheckedDate( newDate );

        // the reloaded no longer has the same checked date as the original nonce instance
        assertFalse( reloaded.getCheckedDate().equals( nonce.getCheckedDate() ) );
        
        // now update the store with the new date
        dao.update( reloaded, dao.toEntry( nonce ) );
        
        // keep a handle on the lastReloaded instance and reload the reloaded again
        INonce lastReloaded = reloaded;
        reloaded = dao.read( nonce.getNonce() );

        // the lastReloaded and freshly reloaded instances should be the 
        // same yet different from the original nonce we started out with
        assertFalse( reloaded.equals( lastReloaded ) );
        assertTrue( reloaded.getCheckedDate().equals( lastReloaded.getCheckedDate() ) );
        assertFalse( reloaded.getCheckedDate().equals( nonce.getCheckedDate() ) );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#delete(java.lang.String)}.
     */
    @Test
    public void testDelete() throws Exception
    {
        testCreate();
        
        INonce deleted = dao.delete( nonce.getNonce() );
        assertEquals( deleted.getNonce(), nonce.getNonce() );
        assertNull( dao.read( nonce.getNonce() ) );
    }

    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#delete(java.lang.String)}.
     */
    @Test
    public void testNonexistantDelete() throws Exception
    {
        testCreate();
        
        INonce deleted = dao.delete( nonce.getNonce() );
        assertEquals( deleted.getNonce(), nonce.getNonce() );
        assertNull( dao.read( nonce.getNonce() ) );

        // second attempt to delete should produce an error.
        assertNull( "Should be null since nothing got deleted", dao.delete( nonce.getNonce() ) );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#deleteEntry(org.verisign.joid.INonce)}.
     */
    @Test
    public void testDeleteEntry() throws Exception
    {
        testCreate();
        
        dao.deleteEntry( nonce );
        assertNull( dao.read( nonce.getNonce() ) );
    }
    
    
    /**
     * Tests the NonceDao's ability to generate a {@link INonce} object from 
     * an LDAP entry for the nonce.
     */
    @Test
    public void testToObject() throws Exception
    {
        Entry entry = new DefaultEntry( new Dn( NonceDao.NONCE_AT + "=" + nonce.getNonce() ) );
        entry.add( SchemaConstants.OBJECT_CLASS_AT, NonceDao.NONCE_OC );
        entry.add( NonceDao.NONCE_AT, nonce.getNonce() );
        
        Calendar calendar = Calendar.getInstance();
        calendar.setTime( nonce.getCheckedDate() );
        GeneralizedTime gt = new GeneralizedTime( calendar );
        entry.add( NonceDao.CHECKED_DATE_AT, gt.toGeneralizedTime() );
        
        INonce generated = dao.toObject( entry );
        assertEquals( generated.getNonce(), nonce.getNonce() );
        assertEquals( generated.getCheckedDate().getTime(), nonce.getCheckedDate().getTime() );
    }


    /**
     * Tests the NonceDao's ability to convert a Nonce into an entry.
     */
    @Test
    public void testToEntry() throws Exception
    {
        Entry entry = dao.toEntry( nonce );
        assertEquals( entry.get( NonceDao.NONCE_AT ).getString(), nonce.getNonce() );
        
        String checkedDate = entry.get( NonceDao.CHECKED_DATE_AT ).getString();
        GeneralizedTime gt = new GeneralizedTime( checkedDate );
        assertEquals( gt.getCalendar().getTime(), nonce.getCheckedDate() );
    }


    /**
     * Tests the NonceDao's ability to get an LDAP entry from the store
     * as a simple LDAP entry before using it to build an object.
     */
    @Test
    public void testGetEntry() throws Exception
    {
        testCreate();
        Entry entry = dao.getEntry( nonce.getNonce() );
        assertEquals( entry.get( NonceDao.NONCE_AT ).getString(), nonce.getNonce() );
        
        String checkedDate = entry.get( NonceDao.CHECKED_DATE_AT ).getString();
        GeneralizedTime gt = new GeneralizedTime( checkedDate );
        assertEquals( gt.getCalendar().getTime(), nonce.getCheckedDate() );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#getDn(java.lang.String)}.
     */
    @Test
    public void testGetDn() throws Exception
    {
        Dn dn = new Dn( NonceDao.NONCE_AT + "=" + nonce.getNonce() + ",ou=nonces, dc=joid, dc=org" );
        assertEquals( dn, dao.getDn( nonce.getNonce() ) );
    }
    
    
    /**
     * Test with a bad DN to the constructor
     */
    @Test( expected=OpenIdException.class )
    public void testBadDn() throws Exception
    {
        new NonceDao( null, "a bad dn" );
    }
    
    
    /**
     * Test with a Dn object in alternative constructor
     */
    @Test
    public void testWithDn() throws Exception
    {
        new NonceDao( null, new Dn( "dc=joid,dc=com" ) );
    }
}
