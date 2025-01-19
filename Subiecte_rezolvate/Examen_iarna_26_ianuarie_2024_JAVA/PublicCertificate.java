package ism.ase.ro.sap.exam.Casuneanu.Lorena;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class PublicCertificate {
		public static PublicKey getCertificateKey(String certificateFile) throws CertificateException, IOException {

			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certFactory
					.generateCertificate(Files.newInputStream(Paths.get(certificateFile)));
			
			return certificate.getPublicKey();
					
				
			
		}
}
