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
package org.verisign.joid.db;

import static org.junit.Assert.*;


import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.DiffieHellman;
import org.verisign.joid.OpenIdException;


/**
 * Tests for {@link DbStore}
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TestDbStore
{

    private static DbStore dbStore;
    private static Association association;
    private static Nonce nonce;
    private final static String serverUrl =  "http://simple.example.org";
    
    
    /**
     * Initialization
     *
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void setUpClass() throws Exception
    {
        dbStore = new DbStore();
    }


    /**
     * Destruction
     *
     * @throws java.lang.Exception
     */
    @AfterClass
    public static void tearDownClass() throws Exception
    {
        dbStore = null;
    }


    /**
     * Test method for {@link org.verisign.joid.db.DbStore#generateAssociation(org.verisign.joid.AssociationRequest, org.verisign.joid.Crypto)}.
     * @throws OpenIdException 
     */
    @Test
    public void testGenerateAssociation() throws OpenIdException
    {
        DiffieHellman dh = DiffieHellman.getDefault();
        Crypto crypto = new Crypto();
        crypto.setDiffieHellman(dh);

        AssociationRequest associationRequest = AssociationRequest.create(crypto);
        
        association = ( Association ) dbStore.generateAssociation(associationRequest,  crypto );
    }
    
    




    /**
     * Test method for {@link org.verisign.joid.db.DbStore#saveAssociation(org.verisign.joid.Association)}.
     */
    @Test
    public void testSaveAssociation()
    {
        dbStore.saveAssociation( association );
        
        assertNotNull( association );
        assertNotNull( association.getId() ); 
    }
    
    /**
     * Test method for {@link org.verisign.joid.db.DbStore#findAssociation(java.lang.String)}.
     * @throws OpenIdException 
     */
    @Test
    public void testFindAssociation() throws OpenIdException
    {
        association = ( Association ) dbStore.findAssociation( association.getHandle() );
        
        assertNotNull( association );
        
    }


    /**
     * Test method for {@link org.verisign.joid.db.DbStore#deleteAssociation(org.verisign.joid.Association)}.
     * @throws OpenIdException 
     */
    @Test
    public void testDeleteAssociation() throws OpenIdException
    {
        dbStore.deleteAssociation( association );
        
        assertNull( dbStore.findAssociation( association.getHandle() ) );
    }

    

    /**
     * Test method for {@link org.verisign.joid.db.DbStore#generateNonce(java.lang.String)}.
     * @throws OpenIdException 
     */
    @Test
    public void testGenerateNonce() throws OpenIdException
    {
         nonce = ( Nonce ) dbStore.generateNonce( serverUrl );
    }
    
    

    /**
     * Test method for {@link org.verisign.joid.db.DbStore#saveNonce(org.verisign.joid.Nonce)}.
     */
    @Test
    public void testSaveNonce()
    {
        dbStore.saveNonce( nonce );
        
        assertNotNull ( nonce.getId() );
    }
    
    /**
     * Test method for {@link org.verisign.joid.db.DbStore#findNonce(java.lang.String)}.
     * @throws OpenIdException 
     */
    @Test
    public void testFindNonce() throws OpenIdException
    {
        Nonce n =  ( Nonce ) dbStore.findNonce( serverUrl ); 
        
        assertNotNull( n );
        assertEquals( n.getNonce(), nonce.getNonce() );
    }
    
}
