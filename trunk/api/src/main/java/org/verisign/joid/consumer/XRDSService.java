package org.verisign.joid.consumer;


/**
 * User: treeder
 * Date: Oct 3, 2008
 * Time: 12:08:11 AM
 */
public class XRDSService
{
    private String uri;
    private int priority = 0;

    public int getPriority() 
    {
        return priority;
    }

    public void setPriority( int priority ) 
    {
        this.priority = priority;
    }

    public void setUri( String uri )
    {
        this.uri = uri;
    }

    public String getUri()
    {
        return uri;
    }
}
