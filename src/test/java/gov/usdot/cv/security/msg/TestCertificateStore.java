package gov.usdot.cv.security.msg;

import java.io.IOException;
import java.text.ParseException;

import gov.usdot.cv.security.cert.CertificateWrapper;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

public class TestCertificateStore {
	
    static final private boolean isDebugOutput = false;
    private static final Logger log = Logger.getLogger(TestCertificateStore.class);
    
    private static final String certsValidDate = "Thu May 11 02:00:00 EDT 2017";
    
    private static final String PcaCert = "80030080fabd443dbf8585fa5981197632787063617273652d746573742e6768736973732e636f6d5e6f5b0002190f14c186000a83010380007c8001e4800348010180012380038500010101008001060001260001800001818001828001050290010490ffff010490ffff020490ffff030490ffff04000183000187008083e7255472518727263f9d3d7f5f7f819baf10771bfadfdc75326778f7bd0c7a8a8080832e142f1875e9947357cc4062b2d0f63b293c935bb242aa0c2ca5470df8ac1be98080a20d86ab6c94a0deaa7353cb9eaabe5275613fcfc55e5d26648b1ce17ebdae2b5041ddb5bc4967b72909b127be83e9932f023532c7041d023fe92121cd310b01";

    private static final String SigningPrivateKey = "4cfb69ebfea42814116ca752416fb2bc5a8b20e7195ef96bff89ad4cd2567986";
    
    private static final String SelfCert  = "0003018097e3682da8de6431508300000000001917119083279c80118c736cc53a9426ffff0101000187818288719fb921a47d02e57e759afa1688d02c721e062bc6928cb638cc6b7256d043";
    private static final String SelfCertPrivateKeyReconstructionValue = "701b753e785e68a4b0976e4afb2af0471065efa1d6021334ffa790331d6bfdfe";
    
    private static final String ClientCert  = "0003018097e3682da8de64315083000000000019204c1083279c80118c736cc53a9426ffff0101000187818214e51669cc0995687b12276be16d4ba9efb56afe752354c27f7eb4c08f8ade0f";
    private static final String ClientCertPrivateKeyReconstructionValue = "4a98ebab657aad74f89b40eaee2e73ceccf3c1074897b6321db14dea19ff50f0";
    
	public static void load() throws ParseException, DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
		CryptoProvider.initialize();
        UnitTestHelper.initLog4j(isDebugOutput);
        
		ClockHelperTest.setNow(certsValidDate);
		
		CryptoProvider cryptoProvider = new CryptoProvider();
		
		String[] names = { "PCA", "Self", "Client" };
		for( String name : names )
			if ( !load(cryptoProvider, name) )
				throw new CertificateException("Couldn't load certificate named " + name);
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name) throws DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
		if ( name == null )
			return false;
		if ( name.equals("PCA") )
			return load(cryptoProvider, "PCA", PcaCert);
		if ( name.equals("Self") )
			return load(cryptoProvider, "Self", SelfCert, SelfCertPrivateKeyReconstructionValue, SigningPrivateKey);
		if ( name.equals("Client") )
			return load(cryptoProvider, "Client", ClientCert, ClientCertPrivateKeyReconstructionValue, SigningPrivateKey);
		return false;
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name, String hexCert) throws DecoderException, CertificateException, IOException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
    	return load(cryptoProvider, name, hexCert, null, null);
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name, String hexCert,
								String hexPrivateKeyReconstructionValue, String hexSigningPrivateKey)
										throws CertificateException, IOException, DecoderException, CryptoException, DecodeFailedException, DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
    	byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
    	CertificateWrapper cert;
    	if ( hexPrivateKeyReconstructionValue == null && hexSigningPrivateKey == null ) {
    		cert = CertificateWrapper.fromBytes(cryptoProvider, certBytes);
    	} else {
	    	byte[] privateKeyReconstructionValueBytes = Hex.decodeHex(hexPrivateKeyReconstructionValue.toCharArray());
	    	byte[] signingPrivateKeyBytes = Hex.decodeHex(hexSigningPrivateKey.toCharArray());
	    	cert = CertificateWrapper.fromBytes(cryptoProvider, certBytes, privateKeyReconstructionValueBytes, signingPrivateKeyBytes);
    	}
    	if ( cert != null ) {
    		boolean isValid = cert.isValid();
    		log.debug("Certificate is valid: " + isValid);
    		if ( isValid )
    			CertificateManager.put(name, cert);
    		return isValid;
    	}
    	return false;
	}
}
