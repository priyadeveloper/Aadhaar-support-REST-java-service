/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uidreceive;

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import sun.misc.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * REST Web Service
 *
 * @author vc
 */
@Path("MyPath")
public class MyPathResource {

    @Context
    private UriInfo context;

    /**
     * Creates a new instance of MyPathResource
     */
    public MyPathResource() {
    }

    

    /**
     * PUT method for updating or creating an instance of MyPathResource
     * @param content representation for the resource
     * @return an HTTP response with content of the updated or created resource.
     */
    @PUT
    @Consumes("text/plain")
    public void putText(String content) {
    }
     @POST
    @Produces("text/xml")
     @Consumes("text/xml")
    @Path("/{uidnum}")
     ///{reqtype}
    
    public String getText( @PathParam("uidnum") String s,String w) {
       // ,@PathParam("reqtype") String rt
        
        //@PathParam("url") String url,
        char c0=s.charAt(0);
		char c1=s.charAt(1);
                String url;
               // if("otp".equals(rt))
     //url="http://auth.uidai.gov.in/otp/1.6/public/"+c0+"/"+c1+"/MLTbKYcsgYMq1zgL3WMZYrnyvsarlljxpom2A-QTPc0Zud23shpnqPk";
	//else
                    
   
                url="http://auth.uidai.gov.in/1.6/public/"+c0+"/"+c1+"/MLTbKYcsgYMq1zgL3WMZYrnyvsarlljxpom2A-QTPc0Zud23shpnqPk";
        
        try {
             return sendReceive(w,url);
        } catch (Exception ex) {
           return ex.toString();
        }
      //return w;
        
      
    }
    private String sendReceive(String s,String url) throws Exception
    {
     
       
String charset = "UTF-8";
String signedDoc;

        signedDoc = new DigitalSigner("/home/priya/code/public-may2012.p12","public".toCharArray(),"public").signXML(s,true);
String query=signedDoc;
/*

URLConnection urlConnection = new URL(url).openConnection();
urlConnection.setUseCaches(false);
urlConnection.setDoOutput(true); // Triggers POST.
urlConnection.setRequestProperty("accept-charset", charset);
urlConnection.setRequestProperty("content-type", "text/xml");


OutputStreamWriter writer = null;
try {
    writer = new OutputStreamWriter(urlConnection.getOutputStream(), charset);
    writer.write(query); // Write POST query string (if any needed).
} finally {
    if (writer != null) try { writer.close(); } catch (IOException ex) {
    return "Output is incorrect";}
}

InputStream result = urlConnection.getInputStream();
InputStreamReader isr = new InputStreamReader(result);
StringBuilder sb=new StringBuilder("");
BufferedReader br = new BufferedReader(isr);
String read = br.readLine();

while(read != null) {
    //System.out.println(read);
    sb.append(read);
    read =br.readLine();

}

return sb.toString();


      */
        
        
    return query;
    
}
    class DigitalSigner {

	private static final String MEC_TYPE = "DOM";
	private static final String WHOLE_DOC_URI = "";
	private static final String KEY_STORE_TYPE = "PKCS12";
	
	private KeyStore.PrivateKeyEntry keyEntry;
	
	
	public DigitalSigner(String keyStoreFile, char[] keyStorePassword, String alias) {
		this.keyEntry = getKeyFromKeyStore(keyStoreFile, keyStorePassword, alias);
		
		
		if (keyEntry == null) {
			throw new RuntimeException("Key could not be read for digital signature. Please check value of signature "
					+ "alias and signature password, and restart the Auth Client");
		}
	}

	
	public String signXML(String xmlDocument, boolean includeKeyInfo) {
		Security.addProvider(new BouncyCastleProvider());
		try {
			
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document inputDocument = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xmlDocument)));

			
			Document signedDocument = sign(inputDocument, includeKeyInfo);
			
			
			StringWriter stringWriter = new StringWriter();
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(signedDocument), new StreamResult(stringWriter));

			return stringWriter.getBuffer().toString();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Error while digitally signing the XML document", e);
		}
	}

	private Document sign(Document xmlDoc, boolean includeKeyInfo) throws Exception {
		
		if (System.getenv("SKIP_DIGITAL_SIGNATURE") != null) {
			return xmlDoc;
		}

		
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance(MEC_TYPE);
		
		Reference ref = fac.newReference(WHOLE_DOC_URI, fac.newDigestMethod(DigestMethod.SHA1, null),
				Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null,
				null);

		
		SignedInfo sInfo = fac.newSignedInfo(
				fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
				fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

		if (keyEntry == null) {
			throw new RuntimeException(
					"Key could not be read for digital signature. Please check value of signature alias and signature password, and restart the Auth Client");
		}

		X509Certificate x509Cert = (X509Certificate) keyEntry.getCertificate();

		KeyInfo kInfo = getKeyInfo(x509Cert, fac);
		DOMSignContext dsc = new DOMSignContext(this.keyEntry.getPrivateKey(), xmlDoc.getDocumentElement());
		XMLSignature signature = fac.newXMLSignature(sInfo, includeKeyInfo ? kInfo : null);
		signature.sign(dsc);

		Node node = dsc.getParent();
		return node.getOwnerDocument();

	}
	
	@SuppressWarnings("unchecked")
	private KeyInfo getKeyInfo(X509Certificate cert, XMLSignatureFactory fac) {
		KeyInfoFactory kif = fac.getKeyInfoFactory();
		List x509Content = new ArrayList();
		x509Content.add(cert.getSubjectX500Principal().getName());
		x509Content.add(cert);
		X509Data xd = kif.newX509Data(x509Content);
		return kif.newKeyInfo(Collections.singletonList(xd));
	}

	private KeyStore.PrivateKeyEntry getKeyFromKeyStore(String keyStoreFile, char[] keyStorePassword, String alias) {
		
		FileInputStream keyFileStream = null;
		try {
			KeyStore ks = KeyStore.getInstance(KEY_STORE_TYPE);
			keyFileStream = new FileInputStream(keyStoreFile);
			ks.load(keyFileStream, keyStorePassword);

			KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
					new KeyStore.PasswordProtection(keyStorePassword));
			return entry;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} finally {
			if (keyFileStream != null) {
				try {
					keyFileStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

	}
    }
}
