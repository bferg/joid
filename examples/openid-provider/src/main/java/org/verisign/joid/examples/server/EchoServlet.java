package org.verisign.joid.examples.server;


import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class EchoServlet extends HttpServlet
{
    private static final long serialVersionUID = 297364154782L;


    public void doGet( HttpServletRequest request, HttpServletResponse response )
        throws ServletException, IOException
    {
        doQuery( request, response );
    }


    public void doPost( HttpServletRequest request, HttpServletResponse response )
        throws ServletException, IOException
    {
        doQuery( request, response );
    }


    public void doQuery( HttpServletRequest request, HttpServletResponse response )
        throws ServletException, IOException
    {
        PrintWriter out = response.getWriter();
        out.println( request.getQueryString() );
        out.flush();
    }
}
