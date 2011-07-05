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
package org.verisign.joid.handlers;


import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.verisign.joid.Message;
import org.verisign.joid.Mode;
import org.verisign.joid.handlers.EncodingMode;
import org.verisign.joid.handlers.MessageEncoder;


/**
 * Tests the MessageEncoder class.
 *
 * @author <a href="mailto:akarasulu@apache.org">Alex Karasulu</a>
 */
public class MessageEncoderTest
{
    private Message message;
    private MessageEncoder encoder;
    
    
    private class MyMessage extends Message
    {
        public MyMessage()
        {
            setMode( Mode.ASSOCIATE );
            setNamespace( Message.OPENID_20_NAMESPACE );
        }
    }


    /**
     * Setup.
     *
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception
    {
        message = new MyMessage();
        encoder = new MessageEncoder();
    }


    /**
     * tearDown.
     *
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception
    {
        message = null;
        encoder = null;
    }


    /**
     * Test method for {@link MessageEncoder#encode(Message, EncodingMode, StringBuilder)}.
     */
    @Test
    public void testEncodePost() throws Exception
    {
        String POST_CORRECT = "openid.mode:associate\n"
            + "openid.ns:http://specs.openid.net/auth/2.0";
        StringBuilder sb = encoder.encode( message, EncodingMode.POST_STRING, null );
        assertEquals( POST_CORRECT, sb.toString() );
    }

    
    /**
     * Test method for {@link MessageEncoder#encode(Message, EncodingMode, StringBuilder)}.
     */
    @Test
    public void testEncodeUrl() throws Exception
    {
        String URL_CORRECT =  "openid.mode=associate&"
            + "openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0";
        StringBuilder sb = encoder.encode( message, EncodingMode.URL_STRING, null );
        assertEquals( URL_CORRECT, sb.toString() );
    }
}
