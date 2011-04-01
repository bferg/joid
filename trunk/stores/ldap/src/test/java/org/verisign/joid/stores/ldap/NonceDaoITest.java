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

import java.util.Date;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.PoolableLdapConnectionFactory;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.verisign.joid.INonce;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.server.Nonce;


/**
 * Integration test cases for the NonceDao implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
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
    private static final String BASE_DN = "ou=nonces,dc=joid,dc=org";
    
    private INonce nonce;

    private NonceDao dao;
    
    
    @Before
    public void before() throws Exception
    {
        LdapConnectionConfig config = new LdapConnectionConfig();
        
        config.setCredentials( "secret" );
        config.setLdapHost( "localhost" );
        config.setLdapPort( getLdapServer().getPort() );

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
    
    
    static INonce generateNonce() throws OpenIdException
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
    @Ignore
    public void testCreate() throws Exception
    {
        assertNotNull( ldapServer );
        dao.create( nonce );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#read(java.lang.String)}.
     */
    @Test
    @Ignore
    public void testRead() throws Exception
    {
        testCreate();
        INonce reloaded = dao.read( nonce.getNonce() );
        assertEquals( reloaded.getNonce(), nonce.getNonce() );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#update(org.verisign.joid.INonce)}.
     */
    @Test
    @Ignore ( "Not yet implemented" )
    public void testUpdateINonce()
    {
        fail( "Not yet implemented" );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#update(org.verisign.joid.INonce, org.apache.directory.shared.ldap.model.entry.Entry)}.
     */
    @Test
    @Ignore ( "Not yet implemented" )
    public void testUpdateINonceEntry()
    {
        fail( "Not yet implemented" );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#delete(java.lang.String)}.
     */
    @Test
    @Ignore ( "Not yet implemented" )
    public void testDelete()
    {
        fail( "Not yet implemented" );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#deleteEntry(org.verisign.joid.INonce)}.
     */
    @Test
    @Ignore ( "Not yet implemented" )
    public void testDeleteEntry()
    {
        fail( "Not yet implemented" );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#toObject(org.apache.directory.shared.ldap.model.entry.Entry)}.
     */
    @Test
    @Ignore ( "Not yet implemented" )
    public void testToObject()
    {
        fail( "Not yet implemented" );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#toEntry(org.verisign.joid.INonce)}.
     */
    @Test
    @Ignore ( "Not yet implemented" )
    public void testToEntry()
    {
        fail( "Not yet implemented" );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#getEntry(java.lang.String)}.
     */
    @Test
    @Ignore ( "Not yet implemented" )
    public void testGetEntry()
    {
        fail( "Not yet implemented" );
    }


    /**
     * Test method for {@link org.verisign.joid.stores.ldap.NonceDao#getDn(java.lang.String)}.
     */
    @Test
    @Ignore ( "Not yet implemented" )
    public void testGetDn()
    {
        fail( "Not yet implemented" );
    }
}
