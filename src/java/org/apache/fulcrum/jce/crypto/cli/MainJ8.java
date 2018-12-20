package org.apache.fulcrum.jce.crypto.cli;

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

import org.apache.fulcrum.jce.crypto.CryptoParameters;
import org.apache.fulcrum.jce.crypto.CryptoUtilJ8;

/**
 * Command line tool for encrypting/decrypting a file or string
 *
 * file [enc|dec] passwd [file]*
 * string [enc|dec] passwd plaintext
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public class MainJ8
{
    /**
     * Allows usage on the command line.
     * 
     * @param args the command line parameters
     */
    public static void main( String[] args )
    {
        try
        {
            if( args.length < 3 )
            {
                printHelp();
                throw new IllegalArgumentException("Invalid command line");
            }

            String operationMode = args[0];


            if( operationMode.equals("file") )
            {
                processFiles(args);
            }
            else if( operationMode.equals("string") )
            {
                processString(args);
            }
        }
        catch (Exception e)
        {
            System.out.println("Error : " + e.getMessage());
        }
    }

    /**
     * Prints usage information.
     */
    public static void printHelp()
    {
        System.out.println("\r\n*** Command line tool for encrypting/decrypting strings/files ***\r\n*** algorithm based on "+ CryptoParameters.ALGORITHM_J8+ "***\r\n");
        System.out.println( "*** Usage: ***\r\n");
        System.out.println("java -cp target\\classes; "+ MainJ8.class.getName()+ " <operation mode:file:string> <coding mode:enc|dec> <password> <path|string> [target]\r\ne.g.\r\n");
        System.out.println( MainJ8.class.getSimpleName()+ " file [enc|dec] passwd source [target]");
        System.out.println(MainJ8.class.getSimpleName() + " string [enc|dec] passwd source");
    }

    /**
     * Decrypt/encrypt a list of files
     * @param args the command line
     * @throws Exception the operation failed
     */
    public static void processFiles(String[] args)
        throws Exception
    {
        String cipherMode = args[1];
        char[] password = args[2].toCharArray();
        File sourceFile = new File(args[3]);
        File targetFile = null;

        if( args.length == 4 )
        {
            targetFile = sourceFile;
        }
        else
        {
            targetFile = new File(args[4]);
            File parentFile = targetFile.getParentFile(); 

            if(parentFile != null)
            {
                parentFile.mkdirs();
            }
        }

        processFile(cipherMode,password,sourceFile,targetFile);
    }

    /**
     * Decrypt/encrypt a single file
     * @param cipherMode the mode
     * @param password the passwors
     * @param sourceFile the file to process
     * @param targetFile the targetf file
     * @throws Exception the operation failed
     */
    public static void processFile(String cipherMode, char[] password, File sourceFile, File targetFile)
        throws Exception
    {
        FileInputStream fis = new FileInputStream(sourceFile);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        CryptoUtilJ8 cryptoUtilJ8 = CryptoUtilJ8.getInstance();

        if( cipherMode.equals("dec") )
        {
            System.out.println("Decrypting " + sourceFile.getAbsolutePath() );
            cryptoUtilJ8.decrypt( fis, baos, password );
            fis.close();

            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            FileOutputStream fos = new FileOutputStream(targetFile);
            CryptoUtilJ8.copy(bais,fos);
            bais.close();
            fos.close();
        }
        else if( cipherMode.equals("enc") )
        {
            System.out.println("Enrypting " + sourceFile.getAbsolutePath() );
            cryptoUtilJ8.encrypt( fis, baos, password );
            fis.close();

            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            FileOutputStream fos = new FileOutputStream(targetFile);
            CryptoUtilJ8.copy(bais,fos);
            bais.close();
            fos.close();
        }
        else
        {
            String msg = "Don't know what to do with : " + cipherMode;
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Decrypt/encrypt a string.
     * 
     * @param args the command line
     * @throws Exception the operation failed
     */
    public static void processString(String[] args)
        throws Exception
    {
        String cipherMode = args[1];
        char[] password = args[2].toCharArray();
        String value = args[3];
        String result = null;
        
        CryptoUtilJ8 cryptoUtilJ8 = CryptoUtilJ8.getInstance();

        if( cipherMode.equals("dec") )
        {
            result = cryptoUtilJ8.decryptString(value,password);
        }
        else
        {
            result = cryptoUtilJ8.encryptString(value,password);
        }

        System.out.println( result );
    }
}