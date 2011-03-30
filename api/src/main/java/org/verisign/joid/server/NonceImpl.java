package org.verisign.joid.server;


import java.util.Date;
import java.text.SimpleDateFormat;

import org.verisign.joid.Nonce;


/**
 * A simple Nonce implementation.
 */
public class NonceImpl implements Nonce
{
    private Long id;
    private String nonce;
    private Date checkedDate;


    /** Hibernate mapping. */
    public Long getId()
    {
        return id;
    }


    /** Hibernate mapping. */
    public void setId( Long id )
    {
        this.id = id;
    }


    /** Hibernate mapping. */
    public String getNonce()
    {
        return nonce;
    }


    /** Hibernate mapping. */
    public void setNonce( String s )
    {
        nonce = s;
    }


    /** Hibernate mapping. */
    public Date getCheckedDate()
    {
        return checkedDate;
    }


    /** Hibernate mapping. */
    public void setCheckedDate( Date date )
    {
        SimpleDateFormat sdf = new SimpleDateFormat( "yyyy-MM-dd HH:mm:ss" );
        Date tmp = date;
        sdf.format( tmp );
        this.checkedDate = tmp;
    }


    /**
     * Returns a string representation of this Nonce.
     *
     * @return a string representation of this Nonce.
     */
    public String toString()
    {
        return "[Nonce nonce=" + nonce + ", checked=" + checkedDate + "]";
    }
}
