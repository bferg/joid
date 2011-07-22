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
import org.apache.directory.server.HttpDirectoryService;
import org.apache.directory.server.core.LdapCoreSessionConnection;
import org.apache.directory.shared.ldap.model.exception.LdapException;

/**
 * TODO LdapSessionConnectionManager.
 *
 * @author <a href="mailto:birkan.duman@gmail.com">Birkan Duman</a>
 */
public class LdapSessionConnectionManager implements LdapConnectionManager
{
    
    private HttpDirectoryService service;
    
    public LdapSessionConnectionManager( HttpDirectoryService directoryService )
    {
        this.service = directoryService;
    }

    /* (non-Javadoc)
     * @see org.verisign.joid.stores.ldap.LdapConnectionManager#releaseConnection(org.apache.directory.ldap.client.api.LdapConnection)
     */
    public void releaseConnection( LdapConnection conn )
    {
        try
        {
            conn.unBind();
        }
        catch ( LdapException e )
        {
            e.printStackTrace();
        }
    }


    /* (non-Javadoc)
     * @see org.verisign.joid.stores.ldap.LdapConnectionManager#acquireConnection()
     */
    public LdapConnection acquireConnection()
    {
        LdapConnection conn = new LdapCoreSessionConnection( service.getDirService().getAdminSession() );
        return conn;
    }

}
