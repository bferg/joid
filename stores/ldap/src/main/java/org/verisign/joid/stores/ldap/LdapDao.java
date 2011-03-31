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


import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.directory.shared.ldap.model.name.Dn;
import org.verisign.joid.OpenIdException;


/**
 * An LDAP data access object for OpenID entities.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface LdapDao<E, P>
{
    void create( E entity ) throws OpenIdException;
    
    E read( P primaryKey ) throws OpenIdException;
    
    void update( E entity ) throws OpenIdException;
    
    void update( E entity, Entry entry ) throws OpenIdException;
    
    E delete( P primaryKey ) throws OpenIdException;
    
    void deleteEntry( E entity ) throws OpenIdException;
    
    E toObject( Entry entry ) throws OpenIdException;
    
    Entry toEntry( E object ) throws OpenIdException;
    
    Entry getEntry( P primaryKey ) throws OpenIdException;
    
    Dn getDn( P primaryKey ) throws OpenIdException;
}
