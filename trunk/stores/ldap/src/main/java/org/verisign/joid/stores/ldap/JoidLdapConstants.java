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


/**
 * JOID specific OpenID LDAP Schema Entity Constants
 *
 * @author <a href="mailto:akarasulu@gmail.com">Alex Karasulu</a>
 */
public interface JoidLdapConstants
{
    // Nonce related schema entity constants 
    
    String NONCE_OC = "opNonceOc";
    String NONCE_AT = "opNonceAt";
    String CHECKED_DATE_AT = "opCheckedDateAt";
    
    // Association related schema entity constants 
    
    String ASSOCIATION_OC = "opAssociationOc";
    String MODE_AT = "opModeAt";
    String HANDLE_AT = "opHandleAt";
    String SECRET_AT = "opSecretAt";
    String ISSUED_DATE_AT = "opIssuedDateAt";
    String LIFETIME_AT = "opLifetimeAt";
    String ASSOCIATION_TYPE_AT = "opAssociationTypeAt";
}
