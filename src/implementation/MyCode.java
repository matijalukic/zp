package implementation;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.*;

import com.sun.istack.internal.NotNull;
import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import code.GuiException;
import gui.Constants;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.OIDName;
import x509.v3.CodeV3;

import static org.bouncycastle.asn1.x509.Extension.extendedKeyUsage;
import static org.bouncycastle.asn1.x509.Extension.privateKeyUsagePeriod;

public class MyCode extends CodeV3 {
    enum LoadStatus {
        ERROR(-1),
        UNSIGNED(0),
        SIGNED(1),
        TRUSTED(2);

        private int status;

        public int getStatus() {
            return status;
        }

        private LoadStatus(int status) {
            this.status = status;
        }
    }

    // Extended key usages set
    static class OID{
        static final String ANY = "2.5.29.37.0";
        static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
        static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
        static final String CODE_SIGN = "1.3.6.1.5.5.7.3.3";
        static final String EMAIL_PROT = "1.3.6.1.5.5.7.3.4";
        static final String TIME_STAMP = "1.3.6.1.5.5.7.3.8";
        static final String OCSP_SIGN = "1.3.6.1.5.5.7.3.9";
        static final String DATE_OF_BIRTH = "1.3.6.1.5.5.7.9.1";
        static final String GENDER = "1.3.6.1.5.5.7.9.3";
        static final String PLACE_OF_BIRTH = "1.3.6.1.5.5.7.9.2";
        static final String COUNTRY_OF_CITIZEN = "1.3.6.1.5.5.7.9.4";
    }

    private static final String keyStoreFileName = "STORE";

    private static KeyPair generateKeyPair(String ecCurve) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(ECGenParameterSpecial.getInstance(ecCurve));

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
        }
        return null;
    }


    private KeyStorage keyStorage;

    private Enumeration keys;
    private Map<String, CertificateKey> allKeypairs;


    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
        this.allKeypairs = new HashMap<>();
        // KeyStorage init
        try {
            keyStorage = new KeyStorage();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        // Only version V3
        access.setVersion(Constants.V3);
        // Bouncy castle Provider
        Security.addProvider(new BouncyCastleProvider());


    }

    @Override
    public boolean canSign(String arg0) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean exportCSR(String arg0, String arg1, String arg2) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean exportCertificate(String arg0, String arg1, int arg2, int arg3) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean exportKeypair(String arg0, String arg1, String arg2) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String arg0) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String arg0) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getSubjectInfo(String arg0) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean importCAReply(String arg0, String arg1) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String importCSR(String arg0) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean importCertificate(String arg0, String arg1) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean importKeypair(String keyPairName, String file, String password) {
        return keyStorage.importKeyPair(keyPairName, file, password);
    }

    private String getCurveName(@NotNull X509Certificate keyPair){
        ECPublicKey publicKey = (ECPublicKey)keyPair.getPublicKey();
        ECParameterSpec specs = publicKey.getParams();

        return specs.toString().split(" ")[0];
    }

    private void showVersionSerial(X509Certificate certificate){
        access.setVersion(Constants.V3); // always V3
        access.setSerialNumber(certificate.getSerialNumber().toString());
        access.setNotBefore(certificate.getNotBefore());
        access.setNotAfter(certificate.getNotAfter());

    }

    private void showKeyUsage(X509Certificate certificate){
        // key usage
        access.setKeyUsage(certificate.getKeyUsage());
    }

    private String parseSetName(String rawParamsString){
        String[] splitedByBrace = rawParamsString.split("\\[");
        String[] splitedBySpace = splitedByBrace[1].split(" ");
        return splitedBySpace[0];
    }

    private void showAlgorithm(X509Certificate certificate) {

        try {
            // always EC
            access.setPublicKeyAlgorithm("EC");
            access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
            // algorithm info
            access.setPublicKeyECCurve(getCurveName(certificate));

            // TODO get public parameter SET
            access.setPublicKeyParameter(parseSetName(((ECPublicKey) certificate.getPublicKey()).getParams().toString()));


        } catch (ClassCastException e) {
            e.printStackTrace();
        }

    }


    private void showSubject(X509Certificate certificate){

        // SET SUBJECT
        SubjectInfo parsedSubjectInfo = SubjectInfo.parse(certificate.getSubjectDN().toString());

        access.setSubjectCommonName(parsedSubjectInfo.getCommonName());
        access.setSubjectCountry(parsedSubjectInfo.getCountry());
        access.setSubjectState(parsedSubjectInfo.getState());
        access.setSubjectOrganization(parsedSubjectInfo.getOrganization());
        access.setSubjectOrganizationUnit(parsedSubjectInfo.getOrgUnit());
        access.setSubjectLocality(parsedSubjectInfo.getLocality());

    }

    private void showCritical(X509Certificate certificate){
        // extensions critical
        for (String criticalString : certificate.getCriticalExtensionOIDs()) {
            if (criticalString.equals(org.bouncycastle.asn1.x509.Extension.keyUsage.toString())) {
                access.setCritical(Constants.KU, true);
            }
            if (criticalString.equals(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString())) {
                access.setCritical(Constants.SDA, true);
            }
            if (criticalString.equals(extendedKeyUsage.toString())) {
                access.setCritical(Constants.EKU, true);
            }
        }
    }

    private void showSubjectDirectoryAttributes(X509Certificate certificate){
        // subject directory attributes
        String oidSubjectDirectoryAttrs = org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.getId();
        byte[] extensionValue = certificate.getExtensionValue(oidSubjectDirectoryAttrs);

        DLSequence sdaOc = null;
        try {
            sdaOc = (DLSequence) X509ExtensionUtil.fromExtensionValue(extensionValue);
            SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(sdaOc);

            for(Object attribute: subjectDirectoryAttributes.getAttributes()){
                Attribute attributeCasted = (Attribute)attribute;

                // every enumeration has one or zero elements
                Enumeration attributeItems = attributeCasted.getAttrValues().getObjects();
                if(attributeItems.hasMoreElements()){
                    DERPrintableString attributeString = (DERPrintableString)attributeItems.nextElement();

                    switch (attributeCasted.getAttrType().getId()){
                        case OID.DATE_OF_BIRTH:
                            // set date of birth
                            access.setDateOfBirth(attributeString.getString());
                            break;
                        case OID.COUNTRY_OF_CITIZEN:
                            access.setSubjectDirectoryAttribute(Constants.COC, attributeString.getString());
                            break;
                        case OID.PLACE_OF_BIRTH:
                            access.setSubjectDirectoryAttribute(Constants.POB, attributeString.getString());
                            break;
                        case OID.GENDER:
                            access.setGender(attributeString.getString());
                            break;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void showExtendedKeyUsage(X509Certificate certificate){
        // extended key usage
        try {
            if(certificate.getExtendedKeyUsage() != null) {
                boolean[] extendedKeyBooleans = new boolean[7];
                for (String ekuOid : certificate.getExtendedKeyUsage()) {
                    if (ekuOid.equals(OID.ANY)) extendedKeyBooleans[0] = true;
                    if (ekuOid.equals(OID.SERVER_AUTH)) extendedKeyBooleans[1] = true;
                    if (ekuOid.equals(OID.CLIENT_AUTH)) extendedKeyBooleans[2] = true;
                    if (ekuOid.equals(OID.CODE_SIGN)) extendedKeyBooleans[3] = true;
                    if (ekuOid.equals(OID.EMAIL_PROT)) extendedKeyBooleans[4] = true;
                    if (ekuOid.equals(OID.TIME_STAMP)) extendedKeyBooleans[5] = true;
                    if (ekuOid.equals(OID.OCSP_SIGN)) extendedKeyBooleans[6] = true;
                }

                access.setExtendedKeyUsage(extendedKeyBooleans);
            }
        } catch (CertificateParsingException e) {
            e.printStackTrace();
        }
    }

    private void certificateToGUI(X509Certificate certificate) {
        showVersionSerial(certificate);

        showAlgorithm(certificate);

        showKeyUsage(certificate);

        showSubject(certificate);

        showCritical(certificate);

        showSubjectDirectoryAttributes(certificate);

        showExtendedKeyUsage(certificate);
    }

    @Override
    public int loadKeypair(String keypairName) {
        LoadStatus loadStatus;
        try {
            X509Certificate cert = keyStorage.getCertificate(keypairName);
            if (cert == null) throw new Exception("There is no certificate founded under alias: " + keypairName);

            // show certificate on GUI
            certificateToGUI(cert);
            // set status unsigned
            loadStatus = LoadStatus.UNSIGNED;

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
            // status is error
            loadStatus = LoadStatus.ERROR;
        }
        return loadStatus.getStatus();
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            if (keyStorage == null) {
                keyStorage = new KeyStorage();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return keyStorage.load();
    }

    @Override
    public boolean removeKeypair(String keypairName) {
        return keyStorage.remove(keypairName);
    }

    @Override
    public void resetLocalKeystore() {
        keyStorage.reset();
    }

    private static X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

    private static X509Certificate generateCertificate(CertificateKey certificateKey, KeyPair keyPair) throws OperatorCreationException, IOException, CertificateException {
        x500NameBuilder.addRDN(BCStyle.CN, certificateKey.getSubject().getCommonName());
        x500NameBuilder.addRDN(BCStyle.O, certificateKey.getSubject().getOrganization());
        x500NameBuilder.addRDN(BCStyle.OU, certificateKey.getSubject().getOrgUnit());
        x500NameBuilder.addRDN(BCStyle.L, certificateKey.getSubject().getLocality());
        x500NameBuilder.addRDN(BCStyle.ST, certificateKey.getSubject().getState());
        x500NameBuilder.addRDN(BCStyle.C, certificateKey.getSubject().getCountry());

        // signature algorithm
        ContentSigner signer = new JcaContentSignerBuilder(certificateKey.getPublicKeyDigestAlgorithm()).build(keyPair.getPrivate());
        // v3 only
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(x500NameBuilder.build(), new BigInteger(certificateKey.getSerialNumber()),
                certificateKey.getNotBefore(), certificateKey.getNotAfter(), x500NameBuilder.build(), keyPair.getPublic());

        /**
         * Extensions
         */
        // Key usage
        int keyUsageMask = 0;
        boolean[] keyUsages = certificateKey.getExtension().getKeyUsage();
        /**
         * Key usage
         * 0. Digital Signature [0]
         * 1. Content Commitment [1]
         * 2. Key Encipherment [2]
         * 3. Data Encipherment [3]
         * 4. Key Agreement [4]
         * 5. Certificate Signing [5]
         * 6. CRL Signing [6]
         * 7. Encipher Only [7]
         * 8. Decipher Only [8]
         */
        keyUsageMask |= keyUsages[0] ? X509KeyUsage.digitalSignature : 0;
        keyUsageMask |= keyUsages[2] ? X509KeyUsage.keyEncipherment : 0;
        keyUsageMask |= keyUsages[3] ? X509KeyUsage.dataEncipherment : 0;
        keyUsageMask |= keyUsages[4] ? X509KeyUsage.keyAgreement : 0;
        keyUsageMask |= keyUsages[5] ? X509KeyUsage.keyCertSign : 0;
        keyUsageMask |= keyUsages[6] ? X509KeyUsage.cRLSign : 0;
        keyUsageMask |= keyUsages[7] ? X509KeyUsage.encipherOnly : 0;
        keyUsageMask |= keyUsages[8] ? X509KeyUsage.decipherOnly : 0;

        X509KeyUsage x509KeyUsage = new X509KeyUsage(keyUsageMask);
        certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, certificateKey.getExtension().isCritical(Constants.KU), x509KeyUsage.getEncoded());


        // subject directory attributes
        Vector<Attribute> attributes = new Vector<>(4);

        // gender saving
        ASN1Set genderSet = new DERSet(new DERPrintableString(certificateKey.getExtension().getGender()));
        attributes.add(new Attribute(new ASN1ObjectIdentifier(OID.GENDER), genderSet));

        // date of birth
        ASN1Set dateOfBirthSet = new DERSet(new DERPrintableString(certificateKey.getExtension().getDateOfBirth()));
        attributes.add(new Attribute(new ASN1ObjectIdentifier(OID.DATE_OF_BIRTH), dateOfBirthSet));
        // place of birth
        ASN1Set placeOfBithSet = new DERSet(new DERPrintableString(certificateKey.getExtension().getSubjectDirectoryAttribute()[Constants.POB]));
        attributes.add(new Attribute(new ASN1ObjectIdentifier(OID.PLACE_OF_BIRTH), placeOfBithSet));
        // country of citizenship
        ASN1Set citizenshipSet = new DERSet(new DERPrintableString(certificateKey.getExtension().getSubjectDirectoryAttribute()[Constants.COC]));
        attributes.add(new Attribute(new ASN1ObjectIdentifier(OID.COUNTRY_OF_CITIZEN), citizenshipSet));

        // init attributes
        SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes(attributes);

        certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes, certificateKey.getExtension().isCritical(Constants.SDA),subjectDirectoryAttributes.toASN1Primitive());

        // extended key usage
        Vector<KeyPurposeId> keyPurposeIds = new Vector<>();
        boolean[] extendedKeyBooleans = certificateKey.getExtension().getExtendedKeyUsage();
        int arraySize = 0;
        // Mapping from booleans to KeyPurposeID
        if(extendedKeyBooleans[0]){
            keyPurposeIds.add(KeyPurposeId.anyExtendedKeyUsage);
            arraySize++;
        }

        if(extendedKeyBooleans[1]) {
            keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);
            arraySize++;
        }
        if(extendedKeyBooleans[2]) {
            keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
            arraySize++;
        }
        if(extendedKeyBooleans[3]) {
            keyPurposeIds.add(KeyPurposeId.id_kp_codeSigning);
            arraySize++;
        }
        if(extendedKeyBooleans[4]) {
            keyPurposeIds.add(KeyPurposeId.id_kp_emailProtection);
            arraySize++;
        }
        if(extendedKeyBooleans[5]) {
            keyPurposeIds.add(KeyPurposeId.id_kp_timeStamping);
            arraySize++;
        }
        if(extendedKeyBooleans[6]){
            keyPurposeIds.add(KeyPurposeId.id_kp_OCSPSigning);
            arraySize++;
        }

        // to array converter
        KeyPurposeId[] keyPurposeIdsArr = new KeyPurposeId[arraySize];
        for(int i = 0; i < arraySize; i++){
            keyPurposeIdsArr[i] = keyPurposeIds.get(i);
        }
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(keyPurposeIdsArr);

        certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, certificateKey.getExtension().isCritical(Constants.EKU), extendedKeyUsage.toASN1Primitive());


        return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
    }


    @Override
    public boolean saveKeypair(String keypairName) {
        // if version one algorithm
        if (access.getVersion() == Constants.V1)
            return false;
        // check if already exists
        if (allKeypairs.containsKey(keypairName))
            return false;
        try {
            /**
             * Get Data from GUI
             */
            CertificateKey certificateKey = new CertificateKey();
            certificateKey.setAlias(keypairName);
            certificateKey.setSerialNumber(access.getSerialNumber());
            certificateKey.setNotAfter(access.getNotAfter());
            certificateKey.setNotBefore(access.getNotBefore());
            // algorithm info
            certificateKey.setPublicKeyAlgorithm("EC"); // always EC
            certificateKey.setPublicKeyParameter(access.getPublicKeyParameter());
            certificateKey.setPublicKeyDigestAlgorithm(access.getPublicKeyDigestAlgorithm());
            certificateKey.setPublicKeyECCurve(access.getPublicKeyECCurve());

            // initializing subject info
            SubjectInfo subject = certificateKey.getSubject();
            subject.setState(access.getSubjectState());
            subject.setCommonName(access.getSubjectCommonName());
            subject.setCountry(access.getSubjectCountry());
            subject.setLocality(access.getSubjectLocality());
            subject.setOrganization(access.getSubjectOrganization());
            subject.setOrgUnit(access.getSubjectOrganizationUnit());

            // setting extension
            Extension extension = certificateKey.getExtension();
            extension.setCritical(Constants.KU, access.isCritical(Constants.KU)); // setting critical key usage
            extension.setCritical(Constants.SDA, access.isCritical(Constants.SDA)); // setting critical subject directory attribute
            extension.setCritical(Constants.EKU, access.isCritical(Constants.EKU)); // setting critical extended key usage
            extension.setKeyUsage(access.getKeyUsage());
            extension.setDateOfBirth(access.getDateOfBirth());
            extension.setSubjectDirectoryAttribute(Constants.POB, access.getSubjectDirectoryAttribute(Constants.POB));
            extension.setSubjectDirectoryAttribute(Constants.COC, access.getSubjectDirectoryAttribute(Constants.COC));
            extension.setGender(access.getGender());
            extension.setExtendedKeyUsage(access.getExtendedKeyUsage());

            KeyPair keyPair;
            if ((keyPair = generateKeyPair(certificateKey.getPublicKeyECCurve())) == null)
                return false;
            // generate cert
            X509Certificate certificate = generateCertificate(certificateKey, keyPair);

            // certificate chain
            Certificate[] certificateChain = new Certificate[1];
            certificateChain[0] = certificate;


            // save to keyStore
            keyStorage.put(keypairName, keyPair, certificateChain);
            // save to file output
            keyStorage.save();

        } catch (OperatorCreationException | IOException | CertificateException | KeyStoreException e) {
            e.printStackTrace();

            return false;
        }


        return true;
    }

    @Override
    public boolean signCSR(String arg0, String arg1, String arg2) {
        // TODO Auto-generated method stub
        return false;
    }


}
