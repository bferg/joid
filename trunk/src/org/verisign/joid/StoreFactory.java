//
// (C) Copyright 2007 VeriSign, Inc.  All Rights Reserved.
//
// VeriSign, Inc. shall have no responsibility, financial or
// otherwise, for any consequences arising out of the use of
// this material. The program material is provided on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.
//
// Distributed under an Apache License
// http://www.apache.org/licenses/LICENSE-2.0
//

package org.verisign.joid;

import org.verisign.joid.db.DbStore;

/**
 * Creates stores. Currently the {@link org.verisign.joid.db.DbStore} is
 * supported.
 */
public class StoreFactory
{
    private StoreFactory(){}

    /**
     * Returns whether the store type is implemented. 
     *
     * @param storeType the type to check.
     * @return true if the store type is implemented; false otherwise.
     */
    public static boolean hasType(String storeType)
    {
	return "db".equals(storeType);
    }

    /**
     * Gets a store implementation. Use store type "db" to retrieve a
     * {@link org.verisign.joid.db.DbStore}.
     *
     * @param storeType the type to cget.
     * @return the store.
     * @throws IllegalArgumentException if the store type is not supported.
     */
    public static Store getInstance(String storeType)
    {
	if ("db".equals(storeType)){
	    return DbStore.getInstance();
	} else {
	    throw new IllegalArgumentException("No such type: "+storeType);
	}
    }
}
