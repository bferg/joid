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

import java.math.BigInteger;
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
import org.verisign.joid.AssociationType;
import org.verisign.joid.IAssociation;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.server.Association;


/**
 * Integration test cases for the AssociatinDao implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith( FrameworkRunner.class )
@CreateDS( allowAnonAccess = true, name = "AssociationDaoITest-class", partitions =
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
public class AssociationDaoITest extends AbstractLdapTestUnit
{
    private static final Logger LOG = LoggerFactory.getLogger( AssociationDaoITest.class );
    
    private static final String BASE_DN = "ou=associations,dc=joid,dc=org";
    
    private IAssociation association;

    private AssociationDao dao;
    
    
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
        dao = new AssociationDao( connMan, BASE_DN );
        association = generateAssociation();
    }
    
    
    @After
    public void after() throws Exception
    {
        dao = null;
        association = null;
    }
    
    
    /**
     * Utility method to generate and reuse an Association.
     *
     * @return the generated random association.
     * @throws OpenIdException
     */
    private static IAssociation generateAssociation() throws OpenIdException
    {
        Association association = new Association();
        association.setAssociationType( AssociationType.HMAC_SHA1 );
        association.setEncryptedMacKey( RandomStringUtils.randomAlphanumeric( 16 ).getBytes() );
        association.setIssuedDate( new Date() );
        association.setLifetime( 600L );
        association.setMacKey( RandomStringUtils.randomAlphanumeric( 16 ).getBytes() );
        association.setSecret( "secret" );
        association.setPublicDhKey( new BigInteger( "1895327263942918" ) );
        association.setSessionType( "DH-SHA1" );
        association.setHandle( RandomStringUtils.randomAlphanumeric( 16 ) );
        
        return association;
    }


    /**
     * Test's the Dao's create functionality.
     */
    @Test
    public void testCreate() throws Exception
    {
        assertNotNull( ldapServer );
        dao.create( association );
    }


    /**
     * Tests the Dao's create functionality attempting to fail by recreating the 
     * same association.
     */
    @Test( expected = OpenIdException.class )
    public void testDoubleCreate() throws Exception
    {
        assertNotNull( ldapServer );
        dao.create( association );
        dao.create( association );
    }


    /**
     * Simple test for the Dao's read functionality.
     */
    @Test
    public void testRead() throws Exception
    {
        testCreate();
        IAssociation reloaded = dao.read( association.getHandle() );
        
        assertEquals( reloaded.getHandle(), association.getHandle() );
        assertEquals( reloaded.getAssociationType(), association.getAssociationType() );
        assertEquals( reloaded.getIssuedDate(), association.getIssuedDate() );
        assertEquals( reloaded.getLifetime(), association.getLifetime() );
    }


    /**
     * Tests the return of null on read of non-existent association.
     */
    @Test
    public void testReadNonexistant() throws Exception
    {
        testCreate();
        IAssociation reloaded = dao.read( "nonexistant-nonce" );
        assertNull( "Should return null to show non-existance", reloaded );
    }


    /**
     * Tests the Dao object's ability to update an Association.
     */
    @Test
    public void testUpdateIAssociation() throws Exception
    {
        testCreate();
        IAssociation reloaded = dao.read( association.getHandle() );
        assertEquals( reloaded.getHandle(), association.getHandle() );

        // now set the reloaded instance's date to UNIX start 
        Date newDate = new Date( 0 );
        reloaded.setIssuedDate( newDate );

        // the reloaded no longer has the same issued date as the original association instance
        assertFalse( reloaded.getIssuedDate().equals( association.getIssuedDate() ) );
        
        // now update the store with the new date
        dao.update( reloaded );
        
        // keep a handle on the lastReloaded instance and reload the reloaded again
        IAssociation lastReloaded = reloaded;
        reloaded = dao.read( association.getHandle() );

        // the lastReloaded and freshly reloaded instances should be the 
        // same yet different from the original association we started out with
        assertFalse( reloaded.equals( lastReloaded ) );
        assertTrue( reloaded.getIssuedDate().equals( lastReloaded.getIssuedDate() ) );
        assertFalse( reloaded.getIssuedDate().equals( association.getIssuedDate() ) );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#update(org.verisign.joid.INonce, org.apache.directory.shared.ldap.model.entry.Entry)}.
     */
    @Test
    public void testUpdateIAssociationEntry() throws Exception
    {
        testCreate();
        IAssociation reloaded = dao.read( association.getHandle() );
        assertEquals( reloaded.getHandle(), association.getHandle() );

        // now set the reloaded instance's date to UNIX start 
        Date newDate = new Date( 0 );
        reloaded.setIssuedDate( newDate );

        // the reloaded no longer has the same issued date as the original association
        assertFalse( reloaded.getIssuedDate().equals( association.getIssuedDate() ) );
        
        // now update the store with the new date
        dao.update( reloaded, dao.toEntry( association ) );
        
        // keep a handle on the lastReloaded instance and reload the reloaded again
        IAssociation lastReloaded = reloaded;
        reloaded = dao.read( association.getHandle() );

        // the lastReloaded and freshly reloaded instances should be the 
        // same yet different from the original association we started out with
        assertFalse( reloaded.equals( lastReloaded ) );
        assertTrue( reloaded.getIssuedDate().equals( lastReloaded.getIssuedDate() ) );
        assertFalse( reloaded.getIssuedDate().equals( association.getIssuedDate() ) );
    }


    /**
     * Tests the AssociationDao's ability to delete an Association.
     */
    @Test
    public void testDelete() throws Exception
    {
        testCreate();
        
        IAssociation deleted = dao.delete( association.getHandle() );
        assertEquals( deleted.getHandle(), association.getHandle() );
        assertNull( dao.read( association.getHandle() ) );
    }

    
    /**
     * Checks the Dao's behavior (returns null) when attempting to delete a 
     * non-existent association.
     */
    @Test
    public void testNonexistentDelete() throws Exception
    {
        testCreate();
        
        IAssociation deleted = dao.delete( association.getHandle() );
        assertEquals( deleted.getHandle(), association.getHandle() );
        assertNull( dao.read( association.getHandle() ) );

        // second attempt to delete should produce an error.
        assertNull( "Should be null since nothing got deleted", dao.delete( association.getHandle() ) );
    }


    /**
     * Tests the Dao's deleteEntry method.
     */
    @Test
    public void testDeleteEntry() throws Exception
    {
        testCreate();
        
        dao.deleteEntry( association );
        assertNull( dao.read( association.getHandle() ) );
    }
    

    /**
     * Tests the Dao's ability to generate an Association object instance from 
     * the association entry.
     */
    @Test
    public void testToObject() throws Exception
    {
        Entry entry = new DefaultEntry( new Dn( AssociationDao.HANDLE_AT + "=" + association.getHandle() ) );
        entry.add( SchemaConstants.OBJECT_CLASS_AT, AssociationDao.ASSOCIATION_OC );
        entry.add( AssociationDao.HANDLE_AT, association.getHandle() );
        entry.add( AssociationDao.SECRET_AT, association.getSecret() );
        entry.add( AssociationDao.ASSOCIATION_TYPE_AT, association.getAssociationType().toString() );
        entry.add( AssociationDao.LIFETIME_AT, association.getLifetime().toString() );
        entry.add( AssociationDao.MODE_AT, association.getMode().toString() );
        
        Calendar calendar = Calendar.getInstance();
        calendar.setTime( association.getIssuedDate() );
        GeneralizedTime gt = new GeneralizedTime( calendar );
        entry.add( AssociationDao.ISSUED_DATE_AT, gt.toGeneralizedTime() );
        
        IAssociation generated = dao.toObject( entry );
        assertEquals( generated.getHandle(), association.getHandle() );
        assertEquals( generated.getIssuedDate().getTime(), association.getIssuedDate().getTime() );
        assertEquals( generated.getSecret(), association.getSecret() );
        assertEquals( generated.getAssociationType(), association.getAssociationType() );
        assertEquals( generated.getLifetime(), association.getLifetime() );
        assertEquals( generated.getMode(), association.getMode() );
    }


    /**
     * Tests the AssociationDao's ability to convert an Association into an 
     * LDAP entry.
     */
    @Test
    public void testToEntry() throws Exception
    {
        Entry entry = dao.toEntry( association );
        assertEquals( entry.get( AssociationDao.ASSOCIATION_TYPE_AT ).getString(),
            association.getAssociationType().toString() );
        assertEquals( entry.get( AssociationDao.HANDLE_AT ).getString(), 
            association.getHandle() );
        assertEquals( entry.get( AssociationDao.LIFETIME_AT).getString(), 
            association.getLifetime().toString() );
        assertEquals( entry.get( AssociationDao.MODE_AT ).getString(), 
            association.getMode() );
        assertEquals( entry.get( AssociationDao.SECRET_AT ).getString(), 
            association.getSecret() );
        
        String issuedDate = entry.get( AssociationDao.ISSUED_DATE_AT ).getString();
        GeneralizedTime gt = new GeneralizedTime( issuedDate );
        assertEquals( gt.getCalendar().getTime(), association.getIssuedDate() );
    }


    /**
     * Tests the AssociationDao's ability to get an LDAP entry from the store
     * corresponding to an Association without using the entry to build the 
     * object.
     */
    @Test
    public void testGetEntry() throws Exception
    {
        testCreate();
        Entry entry = dao.getEntry( association.getHandle() );
        assertEquals( entry.get( AssociationDao.ASSOCIATION_TYPE_AT ).getString(),
            association.getAssociationType().toString() );
        assertEquals( entry.get( AssociationDao.HANDLE_AT ).getString(), 
            association.getHandle() );
        assertEquals( entry.get( AssociationDao.LIFETIME_AT).getString(), 
            association.getLifetime().toString() );
        assertEquals( entry.get( AssociationDao.MODE_AT ).getString(), 
            association.getMode() );
        assertEquals( entry.get( AssociationDao.SECRET_AT ).getString(), 
            association.getSecret() );
        
        String issuedDate = entry.get( AssociationDao.ISSUED_DATE_AT ).getString();
        GeneralizedTime gt = new GeneralizedTime( issuedDate );
        assertEquals( gt.getCalendar().getTime(), association.getIssuedDate() );
    }


    /**
     * Tests the Dao's ability to generate the DN for an association.
     */
    @Test
    public void testGetDn() throws Exception
    {
        Dn dn = new Dn( AssociationDao.HANDLE_AT + "=" + association.getHandle() + ",ou=associations, dc=joid, dc=org" );
        assertEquals( dn, dao.getDn( association.getHandle() ) );
    }
    
    
    /**
     * Test with a bad DN to the constructor
     */
    @Test( expected=OpenIdException.class )
    public void testBadDn() throws Exception
    {
        new AssociationDao( null, "a bad dn" );
    }
    
    
    /**
     * Test with a Dn object in alternative constructor
     */
    @Test
    public void testWithDn() throws Exception
    {
        new AssociationDao( null, new Dn( "dc=joid,dc=com" ) );
    }
}
