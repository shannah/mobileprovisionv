/*
 * Copyright (c) 2012, Codename One and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Codename One designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *  
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 * 
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Please contact Codename One through http://www.codenameone.com/ if you 
 * need additional information or have any questions.
 */
package provisioningprofilevalidator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author shannah
 */
public class ProvisioningProfileValidator {
    
    private static final String keyFilePassword = "password";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        if (args.length < 2) {
            String prefix = "java -jar ProvisioningProfileValidator.jar";
            if (System.getProperties().keySet().contains("jdeploy.base")) {
                prefix = "mobileprovisionv";
            }
            System.out.println("Mobile Provision Validator v1.0\n");
            System.out.println("Description:");
            System.out.println("  A CLI tool to validate that an iOS provisioning profile matches a given .p12 or .key file\n");
            System.out.println("Usage:\n  "+prefix+" /path/to/development.mobileprovision /path/to/develpment.p12 mypassword");
            System.out.println("  or");
            System.out.println("  "+prefix + " /path/to/development.mobileprovision /path/to/development.key mypassword");
            System.out.println("Output:");
            System.out.println("  1  or 0.  1 if they match.  0 if they don't");
            System.exit(1);
        }
        
        String ppPath = args[0];
        String keyOrP12Path = args[1];
        String password = args.length > 2 ? args[2] : "";
        boolean result;
        if (keyOrP12Path.endsWith(".p12")) {
            result = new ProvisioningProfileValidator().validateProvisioningProfileAgainstP12(new File(ppPath), new File(keyOrP12Path), password);
        } else {
            result = new ProvisioningProfileValidator().validateProvisioningProfileAgainstKey(new File(ppPath), new File(keyOrP12Path), password);
        }
        System.out.println(result?1:0);
        System.exit(0);

    }
    
    public boolean validateProvisioningProfileAgainstKey(File provisioningProfile, File keyFile, String keyPassword) throws IOException {
        return getProvisioningProfileModulus(provisioningProfile).equals(getKeyModulus(keyFile, keyPassword));
    }
    
    public boolean validateProvisioningProfileAgainstP12(File provisioningProfile, File p12, String p12Password) throws IOException {
        return getProvisioningProfileModulus(provisioningProfile).equals(getP12Modulus(p12, p12Password));
    }
    
    private String getKeyModulus(File keyFile, String keyFilePassword) throws IOException {
        
        ProcessBuilder pb = new ProcessBuilder();
        pb.command("openssl", "rsa", "-noout", "-text", "-in", keyFile.getPath(), "-modulus", "-passin", "pass:"+keyFilePassword);
        Process p = pb.start();
        String modulusStr = null;
        try (InputStream is = p.getInputStream()) {
            modulusStr = scanForModulus(is);
        }
        if (modulusStr == null) {
            throw new IOException("Failed to find modulus in key file "+keyFile.getPath());
        }
        return modulusStr;
        
    }
    
    private String getP12Modulus(File p12, String p12Password) throws IOException {
        File keyFile = File.createTempFile(p12.getName(), ".key");
        keyFile.deleteOnExit();
        try {
            extractKeyFromP12(p12, p12Password, keyFile, keyFilePassword);
            return getKeyModulus(keyFile, keyFilePassword);
        } finally {
            keyFile.delete();
        }
    }
    
    private File extractKeyFromP12(File p12, String p12Password, File keyFileDest, String keyFilePassword) throws IOException {
        try {
            ProcessBuilder pb = new ProcessBuilder();
            pb.command("openssl", "pkcs12", "-in", p12.getPath(), "-nocerts", "-out", keyFileDest.getPath(), "-password", "pass:"+p12Password, "-passout", "pass:"+keyFilePassword);
            Process p = pb.start();
            p.waitFor();
            return keyFileDest;
        } catch (InterruptedException ex) {
            Logger.getLogger(ProvisioningProfileValidator.class.getName()).log(Level.SEVERE, null, ex);
            throw new IOException(ex);
        }
        
    }
    
    private String getProvisioningProfileModulus(File provisioningProfile) throws IOException {
        try {
            ProcessBuilder pb = new ProcessBuilder();
            pb.command("security", "cms", "-D", "-i", provisioningProfile.getPath());
            Process p = pb.start();
            Document doc;
            try (InputStream is = p.getInputStream()) {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                DocumentBuilder db = dbf.newDocumentBuilder();
                doc = db.parse(is);
            }

            NodeList keys = doc.getDocumentElement().getElementsByTagName("key");
            int len = keys.getLength();
            String developerCertificatesStr = null;
            for (int i=0; i<len; i++) {
                Element key = (Element)keys.item(i);
                if ("DeveloperCertificates".equals(key.getTextContent())) {
                    Node n = key;
                    while (n != null && !((n = n.getNextSibling()) instanceof Element)) {
                        
                    }
                    if (n == null) {
                        throw new IOException("Did not find <array> after <key>");
                    }
                    Element array = (Element)n;
                    Element data = (Element)array.getElementsByTagName("data").item(0);
                    developerCertificatesStr = data.getTextContent();
                    break;
                }
            }
            if (developerCertificatesStr == null) {
                throw new IOException("Provisioning profile has no DeveloperCertificates listed");
            }
            
            
            byte[] decodedDeveloperCertificate = Base64.getDecoder().decode(developerCertificatesStr);
            File tmpDer = File.createTempFile(provisioningProfile.getName(), ".der");
            try {
                tmpDer.deleteOnExit();
                try (FileOutputStream fos = new FileOutputStream(tmpDer)) {
                    fos.write(decodedDeveloperCertificate);
                }

                pb = new ProcessBuilder();
                pb.command("openssl", "x509", "-noout", "-text", "-in", tmpDer.getPath(), "-inform", "DER", "-modulus");
                p = pb.start();
                String modulusStr = null;

                try (InputStream is = p.getInputStream()) {
                    modulusStr = scanForModulus(is);
                }


                if (modulusStr == null) {
                    throw new IOException("Failed to find modulus for provisioning profile");
                }

                return modulusStr;
            } finally {
                tmpDer.delete();
            }
            
            
        } catch (ParserConfigurationException ex) {
            Logger.getLogger(ProvisioningProfileValidator.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SAXException ex) {
            Logger.getLogger(ProvisioningProfileValidator.class.getName()).log(Level.SEVERE, null, ex);
        }   
        
        throw new IOException("Failed to find modulus string");
    }
    
    private static String read(final InputStream is, final int bufferSize) {
        final char[] buffer = new char[bufferSize];
        final StringBuilder out = new StringBuilder();
        try (Reader in = new InputStreamReader(is, "UTF-8")) {
            for (;;) {
                int rsz = in.read(buffer, 0, buffer.length);
                if (rsz < 0)
                    break;
                out.append(buffer, 0, rsz);
            }
        }
        catch (UnsupportedEncodingException ex) {
            /* ... */
        }
        catch (IOException ex) {
            /* ... */
        }
        return out.toString();
    }
    
    private static String scanForModulus(InputStream is) throws IOException {
        String modulusStr=null;
        Scanner in = new Scanner(is);
        while (in.hasNextLine()) {
            String line = in.next();
            if (line.startsWith("Modulus=")) {
                modulusStr = line.substring(line.indexOf("=")+1).trim();
                break;
            }
        }
        return modulusStr;
    }

}
