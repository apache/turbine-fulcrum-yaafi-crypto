package org.apache.fulcrum.jce.crypto;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;


/**
 * An input stream that determine if the originating input stream
 * was encrypted or not. This magic only works for well-known file
 * types though.
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */
public class SmartDecryptingInputStream extends ByteArrayInputStream
{
    /** The encodings to be checked for XML */
    private static final  String[] ENCODINGS = { "ISO-8859-1", "UTF-8", "UTF-16" };

    /**
     * Constructor
     *
     * @param cryptoStreamFactory the CryptoStreamFactory for creating a cipher stream
     * @param is the input stream to be decrypted
     * @throws IOException if file not found
     * @throws GeneralSecurityException if security check fails
     */
    public SmartDecryptingInputStream(
        CryptoStreamFactory cryptoStreamFactory,
        InputStream is )
        throws IOException, GeneralSecurityException
    {
        this( cryptoStreamFactory, is, null );
    }

    /**
     * Constructor
     *
     * @param cryptoStreamFactory the CryptoStreamFactory for creating a cipher stream
     * @param is the input stream to be decrypted
     * @param password the password for decryption
     * 
     * @throws IOException if file not found
     * @throws GeneralSecurityException if security check fails 
     */
    public SmartDecryptingInputStream(
        CryptoStreamFactory cryptoStreamFactory,
        InputStream is,
        char[] password )
        throws IOException, GeneralSecurityException
    {
        super( new byte[0] );

        byte[] content = null;
        byte[] plain = null;

        // store the data from the input stream

        ByteArrayOutputStream baosCipher = new ByteArrayOutputStream();
        ByteArrayOutputStream baosPlain = new ByteArrayOutputStream();
        this.copy( is, baosCipher );

        content = baosCipher.toByteArray();
        plain = content;

        if( this.isEncrypted(content) == true )
        {
            InputStream cis = null;
            ByteArrayInputStream bais = new ByteArrayInputStream(content);

            if( ( password != null ) && ( password.length > 0 ) )
            {
                cis = cryptoStreamFactory.getInputStream( bais, password );
            }
            else
            {
                cis = cryptoStreamFactory.getInputStream( bais );
            }

            copy( cis, baosPlain );
            plain = baosPlain.toByteArray();
        }

        // initialize the inherited instance

        if( plain != null )
        {
            this.buf = plain;
            this.pos = 0;
            this.count = buf.length;
        }
    }

    /**
     * Determine if the content is encrypted. We are
     * using our knowledge about block lenght, check
     * for XML, ZIP and PDF files and at the end of
     * the day we are just guessing.
     *
     * @param content the data to be examined
     * @return true if this is an encrypted file
     * @throws IOException unable to read the content
     */
    private boolean isEncrypted( byte[] content )
        throws IOException
    {
        if( content.length == 0 )
        {
            return false;
        }
        else if( ( content.length % 8 ) != 0 )
        {
            // the block length is 8 bytes - if the length
            // is not a multipe of 8 then the content was
            // definitely not encrypted
            return false;
        }
        else if( this.isPDF(content) )
        {
            return false;
        }
        else if( this.isXML(content) )
        {
            return false;
        }
        else if( this.isZip(content) )
        {
            return false;
        }
        else if( this.isUtf16Text(content) )
        {
            return false;
        }
        else
        {
            for( int i=0; i<content.length; i++ )
            {
                // do we have control characters in it?

                char ch = (char) content[i];

                if( this.isAsciiControl(ch) )
                {
                    return true;
                }
            }

            return false;
        }
    }

    /**
     * Pumps the input stream to the output stream.
     *
     * @param is the source input stream
     * @param os the target output stream
     * @return the number of bytes copied
     * @throws IOException the copying failed
     */
    public long copy( InputStream is, OutputStream os )
        throws IOException
    {
        byte[] buf = new byte[1024];
        int n = 0;
        long total = 0;

        while ((n = is.read(buf)) > 0)
        {
            os.write(buf, 0, n);
            total += n;
        }

        is.close();
        os.flush();
        os.close();

        return total;
    }

    /**
     * Count the number of occurences for the given value
     * @param content the content to examine
     * @param value the value to look fo
     * @return the number of matches
     */
    private int count( byte[] content, byte value )
    {
        int result = 0;

        for( int i=0; i<content.length; i++ )
        {
            if( content[i] == value )
            {
                result++;
            }
        }

        return result;
    }

    /**
     * Detect the BOM of an UTF-16 (mandatory) or UTF-8 document (optional)
     * @param content the content to examine
     * @return true if the content contains a BOM
     */
    private boolean hasByteOrderMark( byte[] content )
    {
        if( ( (content[0] == 0xFF) && (content[1] == 0xFF) ) ||
            ( (content[0] == 0xFF) && (content[1] == 0xFF) ) )
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * Check this is a UTF-16 text document.
     *
     * @param content the content to examine
     * @return true if it is a XML document
     * @throws IOException unable to read the content
     */
    private boolean isUtf16Text( byte[] content ) throws IOException
    {
        if( content.length < 2 )
        {
            return false;
        }

        if( this.hasByteOrderMark( content ) )
        {
            // we should have plenty of 0x00 in a text file

            int estimate = (content.length-2)/3;

            if( this.count(content,(byte)0) > estimate )
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Check various encondings to determine if "<?xml"
     * and "?>" appears in the data.
     *
     * @param content the content to examine
     * @return true if it is a XML document
     * @throws IOException unable to read the content
     */
    private boolean isXML( byte[] content ) throws IOException
    {
        if( content.length < 3 )
        {
            return false;
        }

        for( int i=0; i<ENCODINGS.length; i++ )
        {
            String currEncoding = ENCODINGS[i];

            String temp = new String( content, currEncoding );

            if( ( temp.indexOf("<?xml") >= 0 ) && ( temp.indexOf("?>") > 0 ) )
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if this is a ZIP document
     *
     * @param content the content to examine
     * @return true if it is a PDF document
     */

    private boolean isZip( byte[] content )
    {
        if( content.length < 64 )
        {
            return false;
        }
        else
        {
            // A ZIP starts with Hex: "50 4B 03 04"

            if( ( content[0] == (byte) 0x50 ) &&
                ( content[1] == (byte) 0x4B ) &&
                ( content[2] == (byte) 0x03 ) &&
                ( content[3] == (byte) 0x04 )  )
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    /**
     * Check if this is a PDF document
     *
     * @param content the content to examine
     * @return true if it is a PDF document
     * @throws IOException unable to read the content
     */
    private boolean isPDF(byte[] content) throws IOException
    {
        if( content.length < 64 )
        {
            return false;
        }
        else
        {
            // A PDF starts with HEX "25 50 44 46 2D 31 2E"

            if( ( content[0] == (byte) 0x25 ) &&
                ( content[1] == (byte) 0x50 ) &&
                ( content[2] == (byte) 0x44 ) &&
                ( content[3] == (byte) 0x46 ) &&
                ( content[4] == (byte) 0x2D ) &&
                ( content[5] == (byte) 0x31 ) &&
                ( content[6] == (byte) 0x2E )  )
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    /**
     * Is this an ASCII control character?
     * @param ch the charcter
     * @return true is this in an ASCII character
     */
    private boolean isAsciiControl(char ch)
    {
        if( ( ch >= 0x0000 ) && ( ch <= 0x001F) )
        {
            return true;
        }
        else
        {
            return true;
        }
    }
}
