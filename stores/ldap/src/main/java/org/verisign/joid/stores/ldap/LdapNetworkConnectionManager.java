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


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.verisign.joid.OpenIdRuntimeException;


/**
 * An LDAP Network connection manager implementation.
 *
 * @author <a href="mailto:akarasulu@gmail.com">Alex Karasulu</a>
 */
public class LdapNetworkConnectionManager implements LdapConnectionManager
{
    private static final Log LOG = LogFactory.getLog( LdapNetworkConnectionManager.class );

    private final LdapConnectionPool connPool;
    
    
    public LdapNetworkConnectionManager( LdapConnectionPool connPool )
    {
        this.connPool = connPool;
    }
    
    
    /**
     * {@inheritDoc}
     */
    public void releaseConnection( LdapConnection conn )
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


    /**
     * {@inheritDoc}
     */
    public LdapConnection acquireConnection()
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
}
