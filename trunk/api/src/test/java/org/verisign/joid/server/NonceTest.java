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
package org.verisign.joid.server;


import static org.junit.Assert.*;

import java.util.Calendar;
import java.util.Date;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;


/**
 * Tests the Nonce class.
 *
 * @author <a href="mailto:akarasulu@apache.org">Alex Karasulu</a>
 */
public class NonceTest
{
    Nonce nonce;
    Calendar cal;
    Date date;
    
    
    @Before
    public void setUp()
    {
        nonce = new Nonce();
        Calendar cal = Calendar.getInstance();
        cal.set( 2011, 2, 2, 2, 2, 2 );
        cal.set( Calendar.MILLISECOND, 222 );
        date = cal.getTime();
    }
    
    
    @After
    public void tearDown()
    {
        nonce = null;
        cal = null;
        date = null;
    }
    
    
    /**
     * Checks to see that the checkedDate property is working.
     */
    @Test
    public void testCheckedDate()
    {
        long original = date.getTime();
        nonce.setCheckedDate( date );
        long recalculated = nonce.getCheckedDate().getTime();
        assertEquals( "Nonce.checkedDate property does not hold.", original, recalculated );
    }
    
    
    /**
     * Old checkDate property setter implementation fails to preserve 
     * milliseconds in dates causing issues throughout the code.
     */
    @SuppressWarnings("deprecation")
    @Test
    public void testOldCheckDate()
    {
        long original = date.getTime();
        nonce._setCheckedDate( date );
        long recalculated = nonce.getCheckedDate().getTime();
        System.out.println( "original = " + original + ", recalculated = " + recalculated );
        
        assertEquals( "Nonce.checkedDate property should not hold.", original, recalculated );
    }
}
