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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Helper class to provde generic stream functions.
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl </a>
 */

public final class StreamUtil
{
    /** the size of the internal buffer to copy streams */
    private static final int BUFFER_SIZE = 1024;

    /**
     * Create an input stream supporting the following types
     *
     * <ul>
     *  <li>String (using the UTF-8 encoded content)</li>
     *  <li>File</li>
     *  <li>byte[]</li>
     *  <li>char[]</li>
     *  <li>ByteArrayOutputStream</li>
     *  <li>InputStream</li>
     * </ul>
     *
     * @param source the source object
     * @return the created input stream
     * @throws java.io.IOException creating the input stream failed
     */
    public static InputStream createInputStream( Object source )
        throws IOException
    {
        InputStream is;

        // create an InputStream

        if( source instanceof String )
        {
            byte[] content = ((String) source).getBytes("utf-8");
            is = new ByteArrayInputStream( content );
        }
        else if( source instanceof File )
        {
            is = new FileInputStream( (File) source );
        }
        else if( source instanceof byte[] )
        {
            is = new ByteArrayInputStream( (byte[]) source );
        }
        else if( source instanceof char[] )
        {
            byte[] content = new String((char[])source).getBytes("utf-8");
            is = new ByteArrayInputStream( content );
        }
        else if( source instanceof ByteArrayOutputStream )
        {
            byte[] content = ((ByteArrayOutputStream) source).toByteArray();
            is = new ByteArrayInputStream( content );
        }
        else if( source instanceof InputStream )
        {
            is = (InputStream) source;
        }
        else
        {
            throw new IllegalArgumentException("Don't know hot to handle " + source.getClass().getName());
        }

        return is;
    }

    /**
     * Create an output stream supporting the following types
     *
     * <ul>
     *  <li>File</li>
     *  <li>String</li>
     *  <li>OutputStream</li>
     * </ul>
     *
     * @param target the target object
     * @return the output stream
     * @throws java.io.IOException creating the output stream failed
     */
    public static OutputStream createOutputStream( Object target )
        throws IOException
    {
        OutputStream os;

        if( target instanceof File )
        {
            File currFile = (File) target;
            createParentFile(currFile);
            os = new FileOutputStream(currFile);
        }
        else if( target instanceof String )
        {
            File currFile = new File((String) target);
            createParentFile(currFile);
            os = new FileOutputStream(currFile);
        }
        else if( target instanceof OutputStream )
        {
            os = (OutputStream) target;
        }
        else
        {
            throw new IllegalArgumentException("Don't know hot to handle " + target.getClass().getName());
        }

        return os;
    }

    /**
     * Pumps the input stream to the output stream.
     *
     * @param is the source input stream
     * @param os the target output stream
     * @return the number of bytes copied
     * @throws java.io.IOException the copying failed
     */
    public static long copy( InputStream is, OutputStream os )
        throws IOException
    {
        byte[] buf = new byte[BUFFER_SIZE];
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
     * Ensure that the parent directories exists before writing to
     * the file.
     * 
     * @param currFile the file to write to
     */
    private static void createParentFile(File currFile)
    {
        File parentFile = currFile.getParentFile();
        
        if((parentFile != null) && !parentFile.exists())
        {
            boolean success = parentFile.mkdirs();
            if ( !success )
            {
            	System.err.println("Error, could not create directory to write parent file");
            }
        }
    }
}