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
 * @author <a href="mailto:akarasulu@gmail.com">Alex Karasulu</a>
 */
public interface LdapDao<E, P>
{
    /**
     * Creates a new entity within the backing store.
     * 
     * @param entity The new entity to be created.
     * @throws OpenIdException On failures to create the entity.
     */
    void create( E entity ) throws OpenIdException;
    
    
    /**
     * Reads an existing entity from the backing store.
     * 
     * @param primaryKey The primary key for the entity.
     * @return The entity or null if the entity with primaryKey does not exist
     * in the backing store.
     * @throws OpenIdException On failures to read the entity from the backing
     * store: missing entities return null instead of raising an exception.
     */
    E read( P primaryKey ) throws OpenIdException;
    
    
    /**
     * Updates the entity within the backing store of something has changed.
     *
     * @param entity The latest version of the entity to update.
     * @throws OpenIdException On failures to update the entity in the backing 
     * store: missing entities raise an exception.
     */
    void update( E entity ) throws OpenIdException;
    
    
    /**
     * Updates the entity within the backing store of something has changed.
     *
     * @param entity The latest version of the entity to update.
     * @param entry The old LDAP {@link Entry} for the entity in the backing store.
     * @throws OpenIdException On failures to update the entity in the backing 
     * store: missing entities raise an exception.
     */
    void update( E entity, Entry entry ) throws OpenIdException;
    
    
    /**
     * Deletes the entity with the supplied primary key from the backing store.
     * 
     * @param primaryKey The primary key of the entity to delete.
     * @return The state of the entity before deletion.
     * @throws OpenIdException On failures to delete the entity, including when
     * the entity is missing in the backing store.
     */
    E delete( P primaryKey ) throws OpenIdException;
    
    
    /**
     * Deletes the supplied entity from the backing store.
     * 
     * @param entity The entity to delete.
     * @throws OpenIdException On failures to delete the entity, including when
     * the entity is missing in the backing store.
     */
    void deleteEntry( E entity ) throws OpenIdException;
    
    
    /**
     * Converts the LDAP {@link Entry} for the entity into an object instance.
     * 
     * @param entry The LDAP entry for the entity.
     * @return The object instance of the entity.
     * @throws OpenIdException On failures to transform the entry into an object instance.
     */
    E toObject( Entry entry ) throws OpenIdException;
    
    
    /**
     * Converts the entity object instance into an LDAP {@link Entry}.
     * 
     * @param object The object instance of the entity.
     * @return The LDAP entry for the entity's object instance.
     * @throws OpenIdException On failures to transform the object instance into an Entry.
     */
    Entry toEntry( E object ) throws OpenIdException;
    
    
    /**
     * Gets the LDAP {@link Entry} from the backing store using the supplied 
     * primary key.
     * 
     * @param primaryKey The primary key of the entity in the LDAP backing store.
     * @return The LDAP entry of the entity in the LDAP backing store or null 
     * if the entity does not exist.
     * @throws OpenIdException On failures to retrieve the LDAP entry for the 
     * entity: non-existence does not raise an exception since null is returned 
     * instead.
     */
    Entry getEntry( P primaryKey ) throws OpenIdException;
    
    
    /**
     * Constructs the distinguished name of the entity leveraging the base Dn
     * containing all subordinate entities.
     * 
     * @param primaryKey The primary key used to construct the Dn of the entity.
     * @return The distinguished name of the entity.
     * @throws OpenIdException When invalid LDAP {@link Dn} names are generated.
     */
    Dn getDn( P primaryKey ) throws OpenIdException;
}
