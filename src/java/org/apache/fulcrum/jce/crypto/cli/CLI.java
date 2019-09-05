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

import org.apache.fulcrum.jce.crypto.CryptoUtil;
import org.apache.fulcrum.jce.crypto.StreamUtil;

/**
 * Command line tool for encrypting/decrypting files
 *
 * file [enc|dec] passwd [file]*
 * string [enc|dec] passwd plaintext
 *
 * @author <a href="mailto:siegfried.goeschl@it20one.at">Siegfried Goeschl</a>
 */

public class CLI
{
    /**
     * Allows testing on the command line.
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
        System.out.println("Main file [enc|dec] passwd source [target]");
        System.out.println("Main string [enc|dec] passwd source");
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

            if (parentFile != null)
            {
                boolean success = parentFile.mkdirs();
                if ( !success )
                {
                	System.err.println("Failed to create directory");
                }
            }
        }

        processFile(cipherMode,password,sourceFile,targetFile);
    }

    /**
     * Decrypt and encrypt a single file
     * @param cipherMode the mode
     * @param password the password
     * @param sourceFile the file to process
     * @param targetFile the target file
     * @throws Exception the operation failed
     */
    public static void processFile(String cipherMode, char[] password, File sourceFile, File targetFile)
        throws Exception
    {
        try (FileInputStream fis = new FileInputStream(sourceFile)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
            if( cipherMode.equals("dec") )
            {
                System.out.println("Decrypting " + sourceFile.getAbsolutePath() );
                CryptoUtil.getInstance().decrypt( fis, baos, password );
                fis.close();
    
                ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
                FileOutputStream fos = new FileOutputStream(targetFile);
                StreamUtil.copy(bais,fos);
                bais.close();
                fos.close();
            }
            else if( cipherMode.equals("enc") )
            {
                System.out.println("Encrypting " + sourceFile.getAbsolutePath() );
                CryptoUtil.getInstance().encrypt( fis, baos, password );
                fis.close();
    
                ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
                FileOutputStream fos = new FileOutputStream(targetFile);
                StreamUtil.copy(bais,fos);
                bais.close();
                fos.close();
            }
            else
            {
                String msg = "Don't know what to do with : " + cipherMode;
                throw new IllegalArgumentException(msg);
            }
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

        if( cipherMode.equals("dec") )
        {
            result = CryptoUtil.getInstance().decryptString(value,password);
        }
        else
        {
            result = CryptoUtil.getInstance().encryptString(value,password);
        }

        System.out.println( result );
    }
}