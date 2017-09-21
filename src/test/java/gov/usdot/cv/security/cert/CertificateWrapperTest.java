package gov.usdot.cv.security.cert;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.BeforeClass;
import org.junit.Test;

import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EccP256CurvePoint;
import gov.usdot.asn1.generated.ieee1609dot2.ieee1609dot2basetypes.EciesP256EncryptedKey;
import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.crypto.ECIESProvider;
import gov.usdot.cv.security.crypto.EcdsaP256SignatureWrapper;
import gov.usdot.cv.security.util.UnitTestHelper;

public class CertificateWrapperTest {

    static final private boolean isDebugOutput = false;
    private static final Logger log = Logger.getLogger(CertificateWrapperTest.class);
    
    private static final String certsValidDate = "Thu May 11 02:00:00 EDT 2017";
    
    private static final String PcaCert = "80030080fabd443dbf8585fa5981197632787063617273652d746573742e6768736973732e636f6d5e6f5b0002190f14c186000a83010380007c8001e4800348010180012380038500010101008001060001260001800001818001828001050290010490ffff010490ffff020490ffff030490ffff04000183000187008083e7255472518727263f9d3d7f5f7f819baf10771bfadfdc75326778f7bd0c7a8a8080832e142f1875e9947357cc4062b2d0f63b293c935bb242aa0c2ca5470df8ac1be98080a20d86ab6c94a0deaa7353cb9eaabe5275613fcfc55e5d26648b1ce17ebdae2b5041ddb5bc4967b72909b127be83e9932f023532c7041d023fe92121cd310b01";

    private static final String SigningPrivateKey = "4cfb69ebfea42814116ca752416fb2bc5a8b20e7195ef96bff89ad4cd2567986";
    
    private static final String SelfCert  = "0003018097e3682da8de6431508300000000001917119083279c80118c736cc53a9426ffff0101000187818288719fb921a47d02e57e759afa1688d02c721e062bc6928cb638cc6b7256d043";
    private static final String SelfCertPrivateKeyReconstructionValue = "701b753e785e68a4b0976e4afb2af0471065efa1d6021334ffa790331d6bfdfe";
    
    private static final String ClientCert  = "0003018097e3682da8de64315083000000000019204c1083279c80118c736cc53a9426ffff0101000187818214e51669cc0995687b12276be16d4ba9efb56afe752354c27f7eb4c08f8ade0f";
    private static final String ClientCertPrivateKeyReconstructionValue = "4a98ebab657aad74f89b40eaee2e73ceccf3c1074897b6321db14dea19ff50f0";
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
		CryptoProvider.initialize();
        UnitTestHelper.initLog4j(isDebugOutput);
        
		ClockHelperTest.setNow(certsValidDate);
    }
    
    @Test
    public void test()  throws DecoderException, CertificateException, IOException,
    							CryptoException, InvalidCipherTextException, DecodeFailedException,
    							DecodeNotSupportedException, EncodeFailedException, EncodeNotSupportedException {
    	testExplicit();
    	testEncrypted("Self", SelfCert, SelfCertPrivateKeyReconstructionValue, SigningPrivateKey);
    	testEncrypted("Client", ClientCert, ClientCertPrivateKeyReconstructionValue, SigningPrivateKey);
    }
    
    public void testExplicit() throws DecoderException, CertificateException, IOException, CryptoException,
    									EncodeFailedException, EncodeNotSupportedException {
    	for(String[] cert : new String[][] {{ PcaCert, "PCA" }}) {
    		String hexCert = cert[0];
    		String name = cert[1];
    		
    		byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
        	CertificateWrapper certificate = CertificateWrapper.fromBytes(new CryptoProvider(), certBytes);
        	
        	if(certificate != null) {
        		boolean isValid = certificate.isValid();
        		log.debug("Certificate is valid: " + isValid);
        		if(isValid) {
        			CertificateManager.put(name, certificate);
        		}
        	}
    	}
    }
    
    public void testEncrypted(String name, String hexCert, String hexPrivateKeyReconstructionValue, String hexSeedPrivateKey) 
    																	throws DecoderException, CertificateException, IOException,
    																			CryptoException, InvalidCipherTextException,
    																			DecodeFailedException,DecodeNotSupportedException,
    																			EncodeFailedException, EncodeNotSupportedException {
    	CryptoProvider cryptoProvider = new CryptoProvider();
    	byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
    	byte[] privateKeyReconstructionValueBytes = Hex.decodeHex(hexPrivateKeyReconstructionValue.toCharArray());
    	byte[] seedPrivateKeyBytes = Hex.decodeHex(hexSeedPrivateKey.toCharArray());
    	CertificateWrapper certificate = CertificateWrapper.fromBytes(cryptoProvider, certBytes, privateKeyReconstructionValueBytes, seedPrivateKeyBytes);
    	if(certificate != null) {
    		boolean isValid = certificate.isValid();
    		log.debug("Certificate is valid: " + isValid);
    		if(isValid) {
    			CertificateManager.put(name + "-private", certificate);
    		}
    		
    		testSigningKeyPair(cryptoProvider, certificate);
    		testEncryptionKeyPair(cryptoProvider, certificate);

    		ECDSAProvider ecdsaProvider = cryptoProvider.getSigner();
    		
			byte[] publicCertBytes = certificate.getBytes();
			CertificateWrapper publicCert = CertificateWrapper.fromBytes(cryptoProvider, publicCertBytes);
			if ( publicCert != null ) {
				assertTrue(publicCert.isValid());
				CertificateManager.put(name + "-public", certificate);
				assertNotNull(certificate.getSigningPrivateKey());
				assertNotNull(certificate.getEncryptionPrivateKey());
				assertNull(publicCert.getSigningPrivateKey());
				assertNull(publicCert.getEncryptionPrivateKey());
				comparePublicKeys(ecdsaProvider, certificate.getSigningPublicKey(), publicCert.getSigningPublicKey());
				comparePublicKeys(ecdsaProvider, certificate.getEncryptionPublicKey(), publicCert.getEncryptionPublicKey());
			}
    	}
    }
    
    private void comparePublicKeys(ECDSAProvider ecdsaProvider, ECPublicKeyParameters publicKey1, ECPublicKeyParameters publicKey2) 
    																									throws CryptoException {
		EccP256CurvePoint encodedPublicKey1 = ecdsaProvider.encodePublicKey(publicKey1);
		EccP256CurvePoint encodedPublicKey2 = ecdsaProvider.encodePublicKey(publicKey2);
		assertTrue( "Public keys match", encodedPublicKey1.equalTo(encodedPublicKey2));
    }
    
    private void testSigningKeyPair(CryptoProvider cryptoProvider, CertificateWrapper certificate) {
    	assertNotNull(cryptoProvider);
    	assertNotNull(certificate);
    	ECDSAProvider ecdsaProvider = cryptoProvider.getSigner();
    	
		final byte[] textBytes = "Hello, World!".getBytes();

		EcdsaP256SignatureWrapper signature = ecdsaProvider.computeSignature(textBytes,  certificate.getBytes(), certificate.getSigningPrivateKey());
		boolean isSignatureValid = ecdsaProvider.verifySignature(textBytes, certificate.getBytes(), certificate.getSigningPublicKey(), signature);
		log.debug("Is Signarure Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
    }
    
    public void testEncryptionKeyPair(CryptoProvider cryptoProvider, CertificateWrapper certificate)
    											throws InvalidCipherTextException, CryptoException,
    													EncodeFailedException, EncodeNotSupportedException {
    	assertNotNull(cryptoProvider);
    	assertNotNull(certificate);
    	
		// generate key to encrypt
		KeyParameter symmetricKey = AESProvider.generateKey();
		assertNotNull(symmetricKey);
		log.debug(Hex.encodeHexString(symmetricKey.getKey()));
		
		
		ECIESProvider eciesProvider = cryptoProvider.getECIESProvider();
		
		// encrypt and encode the key
		EciesP256EncryptedKey eciesP256EncryptedKey = eciesProvider.encodeEciesP256EncryptedKey(symmetricKey, certificate.getEncryptionPublicKey());
		
		// decode and decrypt the key
		KeyParameter symmetricKey2 = eciesProvider.decodeEciesP256EncryptedKey(eciesP256EncryptedKey, certificate.getEncryptionPrivateKey());
		assertNotNull(symmetricKey2);
		log.debug(Hex.encodeHexString(symmetricKey2.getKey()));
		
		assertTrue(Arrays.equals(symmetricKey.getKey(), symmetricKey2.getKey()));
    }
}

