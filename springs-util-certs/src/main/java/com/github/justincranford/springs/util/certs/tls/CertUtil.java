package com.github.justincranford.springs.util.certs.tls;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;

@SuppressWarnings("nls")
public class CertUtil {
    // uses opinionated values for root CA X509Certificate
	public static X509Certificate createSignedRootCaCert(final Provider caSigningProvider, final String caSigningAlgorithm, final KeyPair caKeyPair) throws Exception {
		X509Certificate rootCaCert = CertUtil.createCert(
            Date.from(ZonedDateTime.of(1970,  1,  1,  0,  0,  0,         0, ZoneOffset.UTC).toInstant()),
            Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
            new BigInteger(159, SecureRandomUtil.SECURE_RANDOM),
            caKeyPair.getPublic(),
            new X500Name(RFC4519Style.INSTANCE, "DC=Root CA"),
            caKeyPair.getPrivate(),
            new X500Name(RFC4519Style.INSTANCE, "DC=Root CA"),
            caSigningAlgorithm,
            caSigningProvider,
            new Extensions(new Extension[] {
                new Extension(Extension.basicConstraints, true, new BasicConstraints(0)           .toASN1Primitive().getEncoded()),
                new Extension(Extension.keyUsage,         true, new KeyUsage(KeyUsage.keyCertSign).toASN1Primitive().getEncoded())
            })
        );
		return rootCaCert;
	}

    // uses opinionated values for Web server X509Certificate
	public static X509Certificate createSignedServerCert(final Provider caSigningProvider, final String caSigningAlgorithm, final PrivateKey caPrivateKey, final PublicKey serverPublicKey, final Set<String> sanDnsNames, final Set<String> sanIpAddresses) throws Exception {
		final List<GeneralName> generalNameList = new ArrayList<>(sanDnsNames.size() + sanIpAddresses.size());
		generalNameList.addAll(   sanDnsNames.stream().map(sanDnsName   -> new GeneralName(GeneralName.dNSName,   sanDnsName)).toList());
		generalNameList.addAll(sanIpAddresses.stream().map(sanIpAddress -> new GeneralName(GeneralName.iPAddress, sanIpAddress)).toList());
		final GeneralName[] generalNames = generalNameList.toArray(new GeneralName[generalNameList.size()]);

		final X509Certificate serverCert = CertUtil.createCert(
            Date.from(ZonedDateTime.of(1970,  1,  1,  0,  0,  0,         0, ZoneOffset.UTC).toInstant()),
            Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
            new BigInteger(159, SecureRandomUtil.SECURE_RANDOM),
            serverPublicKey,
            new X500Name(RFC4519Style.INSTANCE, "CN=HTTPS Server,DC=Root CA"),
            caPrivateKey,
            new X500Name(RFC4519Style.INSTANCE, "DC=Root CA"),
            caSigningAlgorithm,
            caSigningProvider,
            new Extensions(new Extension[] {
                new Extension(Extension.keyUsage,               true,  new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
                new Extension(Extension.extendedKeyUsage,       false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).toASN1Primitive().getEncoded()),
                new Extension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames).toASN1Primitive().getEncoded())
            })
        );
		return serverCert;
	}

	// general purpose X509Certificate settings (e.g. root CA, sub CA, end entity, etc)
    public static X509Certificate createCert(
        final Date       notBefore,
        final Date       notAfter,
        final BigInteger serialNumber,
        final PublicKey  subjectPublicKey,
        final X500Name   subjectDN,
        final PrivateKey issuerPrivateKey,
        final X500Name   issuerDN,
        final String     issuerSigningAlgorithm,
        final Provider   issuerSigningProvider,
        final Extensions extensions
    ) throws Exception {
        final JcaX509v3CertificateBuilder jcaX509v3CertificateBuilder = new JcaX509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN, subjectPublicKey);
        for (final ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
            jcaX509v3CertificateBuilder.addExtension(extensions.getExtension(oid));
        }
        final JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(issuerSigningAlgorithm);
        if (issuerSigningProvider != null) {
            jcaContentSignerBuilder.setProvider(issuerSigningProvider);
        }
        final ContentSigner contentSigner = jcaContentSignerBuilder.build(issuerPrivateKey);
        X509CertificateHolder x509CertificateHolder = jcaX509v3CertificateBuilder.build(contentSigner);
        final JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        return jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
    }
}
