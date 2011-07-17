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
package org.verisign.joid.examples.relying.party;


import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.verisign.joid.consumer.OpenIdFilter;
import org.verisign.joid.util.UrlUtils;


/**
 * A servlet to handle relying party requests.
 *
 * @author <a href="mailto:birkan.duman@gmail.com">Birkan Duman</a>
 */
public class RelyingPartyServlet extends HttpServlet
{
    private final Log LOG = LogFactory.getLog( RelyingPartyServlet.class );

    @Override
    public void init( ServletConfig config ) throws ServletException
    {
        LOG.debug( "initializing" );
        super.init( config );
    }


    @Override
    protected void doPost( HttpServletRequest req, HttpServletResponse resp ) throws ServletException, IOException
    {
        LOG.debug( "doPost()" );

        String returnTo = UrlUtils.getBaseUrl( req );

        try
        {
            String id = req.getParameter( "openid_url" );
            if ( !id.startsWith( "http" ) )
            {
                id = "http://" + id;
            }
            
            String trustRoot = req.getParameter( "trustRoot" );

            String s = OpenIdFilter.joid().getAuthUrl( id, returnTo, trustRoot );
            resp.sendRedirect( s );
        }
        catch ( Throwable e )
        {
            LOG.error( e.getMessage() );
        }

    }

    private static final long serialVersionUID = -3820978132823430725L;
}
