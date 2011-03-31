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


import org.apache.directory.ldap.client.api.LdapConnection;


/**
 * Interface for LDAP connection management to abstract away different kinds of
 * connection management mechanisms: i.e. pooled network connections verses 
 * internal non-pooled ldap session connections. 
 *
 * @author <a href="mailto:akarasulu@gmail.com">Alex Karasulu</a>
 */
public interface LdapConnectionManager
{
    /**
     * Releases an {@link LdapConnection} after use. Depending on the 
     * implementation and the connection type, the connection might actually 
     * be destroyed.
     *
     * @param conn The connection to be released.
     */
    void releaseConnection( LdapConnection conn );
    
    
    /**
     * Acquires an {@link LdapConnection} either by creating one or accessing
     * one that is free from within a connection pool.
     *
     * @return An {@link LdapConnection} object ready to be used.
     */
    LdapConnection acquireConnection();
}
