import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;


public class TestBCOpenPGP {
	
	private boolean isArmored = false;
	private String id = "damico";
	private String passwd = "******";
	private boolean integrityCheck = true;
	
	
	private String pubKeyFile = "/tmp/pub.bpg";
	private String privKeyFile = "/tmp/secret.bpg";
	
	private String plainTextFile = "/tmp/plain-text.txt";
	private String cypherTextFile = "/tmp/cypher-text.dat";
	private String decPlainTextFile = "/tmp/dec-plain-text.txt";

	//@Test
	public void genKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {
		
		RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");

		kpg.initialize(1024);

		KeyPair                    kp = kpg.generateKeyPair();

		

		if (isArmored)
		{
			

			FileOutputStream    out1 = new FileOutputStream("/tmp/secret.asc");
			FileOutputStream    out2 = new FileOutputStream("/tmp/pub.asc");

			rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), true);
		}
		else
		{
			FileOutputStream    out1 = new FileOutputStream("/tmp/secret.bpg");
			FileOutputStream    out2 = new FileOutputStream("/tmp/pub.bpg");

			rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), false);
		}

	}
	
	@Test
	public void encrypt() throws NoSuchProviderException, IOException, PGPException{
		FileInputStream keyIn = new FileInputStream(pubKeyFile);
        FileOutputStream out = new FileOutputStream(cypherTextFile);
        PGPUtil.encryptFile(out, plainTextFile, PGPUtil.readPublicKey(keyIn),
        		isArmored, integrityCheck);
        out.close();
        keyIn.close();
	}
	
	@Test
	public void decrypt() throws Exception{
		
		FileInputStream in = new FileInputStream(cypherTextFile);
        FileInputStream keyIn = new FileInputStream(privKeyFile);
        FileOutputStream out = new FileOutputStream(decPlainTextFile);
        PGPUtil.decryptFile(in, out, keyIn, passwd.toCharArray());
        in.close();
        out.close();
        keyIn.close();
	}

}
