package implementation;

import gui.Constants;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import x509.v3.GuiV3;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

/**
 * Handles the saving loading and deleting storage of keys
 */
public class KeyStorage {
    private static final String fileName = "keystorage";
    private static final String instanceName = "PKCS12";
    private static final String password = "password123";
    private static final char[] PASSWORD = password.toCharArray();
    private static final String X509_INSTANCE = "X.509";
    private static CertificateFactory certificateFactory;
    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();


    static {
        try {
            certificateFactory = CertificateFactory.getInstance(X509_INSTANCE);
        } catch (CertificateException e) {
            e.printStackTrace();
            System.out.println("Failed to init CertificateFactory!");
            System.exit(1);
        }
    }


    private KeyStore keyStore;
    private FileOutputStream fileOutputStream;
    private FileInputStream fileInputStream;
    private PKCS10CertificationRequest certificationRequest;

    public FileOutputStream getFileOutputStream() throws FileNotFoundException {
        if (fileOutputStream == null)
            fileOutputStream = new FileOutputStream(fileName);
        return fileOutputStream;
    }

    public FileInputStream getFileInputStream() throws FileNotFoundException {
        if (fileInputStream == null)
            fileInputStream = new FileInputStream(fileName);
        return fileInputStream;
    }

    public KeyStorage() throws KeyStoreException {
        this.keyStore = KeyStore.getInstance(KeyStorage.instanceName);
        load();
    }

    public KeyStore getKeyStore() throws KeyStoreException {
        if (keyStore == null)
            this.keyStore = KeyStore.getInstance(KeyStorage.instanceName);
        return keyStore;
    }

    public void put(String keypairName, KeyPair keyPair, Certificate[] certificates) throws KeyStoreException {
        getKeyStore().setKeyEntry(keypairName, keyPair.getPrivate(), PASSWORD, certificates);
    }

    /**
     * Save keys to the file
     *
     * @return boolean
     */
    public boolean save() {
        try {
            keyStore.store(getFileOutputStream(), PASSWORD);
            return true;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();

            return false;
        }
    }

    public Enumeration<String> load() {
        try {
            File inputKeyStorageFile = new File(fileName);
            if (inputKeyStorageFile.exists() && !inputKeyStorageFile.isDirectory()) {
                fileInputStream = new FileInputStream(inputKeyStorageFile);
                keyStore.load(fileInputStream, PASSWORD);
            }
            // file doesnt exists
            else {
                keyStore.load(null, null);
            }
            return keyStore.aliases();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }

        return null;
    }

    public X509Certificate getCertificate(String alias) {
        try {
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Deletes the keyStore file
     */
    private void deleteFile() {
        File deletingFile = new File(fileName);
        if (deletingFile.exists() && !deletingFile.isDirectory())
            deletingFile.delete();
    }


    private void removeAliases() throws KeyStoreException {
        Enumeration<String> aliases = keyStore.aliases();
        List<String> aliasesList = new ArrayList<>();

        // push to String list
        while (aliases.hasMoreElements()) {
            aliasesList.add(aliases.nextElement());
        }
        for (String alias : aliasesList) {
            keyStore.deleteEntry(alias);
        }
    }

    public boolean remove(String keyPairAlias) {
        try {
            // delete key
            keyStore.deleteEntry(keyPairAlias);

            // save file
            save();
            return true;
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
    }

    public void reset() {
        try {
            removeAliases();

            deleteFile();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }


    // Importing .p12 into program
    public boolean importKeyPair(String keyPairName, String fileName, String importingPassword) {

        try (FileInputStream importingKeyPairStream = new FileInputStream(fileName)) {
            KeyStore importingKeyStore = KeyStore.getInstance(instanceName, BOUNCY_CASTLE_PROVIDER);
            // imports int keystore
            importingKeyStore.load(importingKeyPairStream, importingPassword.toCharArray());

            // chaining keypairss
            List<String> chainAliases = Collections.list(importingKeyStore.aliases());
            chainAliases.forEach(
                    importingAlias -> {
                        try {
                            Key key = importingKeyStore.getKey(importingAlias, importingPassword.toCharArray());
                            Certificate[] chain = importingKeyStore.getCertificateChain(importingAlias);

                            // put in local KeyStore
                            keyStore.setKeyEntry(keyPairName, key, null, chain);
                        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
                            e.printStackTrace();
                        }
                    }
            );
            // save to file
            if (!save())
                return false;
            load(); // load to program
            return true;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    // exporting
    public boolean exportKeyPair(String keypairName, String filePath, String exportingPassword) {

        try (FileOutputStream exportKeyPairStream = new FileOutputStream(filePath)) {
            KeyStore exportingKeyStoreInstance = KeyStore.getInstance(instanceName, BOUNCY_CASTLE_PROVIDER);
            // load empty keystore
            exportingKeyStoreInstance.load(null, exportingPassword.toCharArray());

            // chaining
            Key localKey = keyStore.getKey(keypairName, PASSWORD);
            Certificate[] localKeyChain = keyStore.getCertificateChain(keypairName);
            exportingKeyStoreInstance.setKeyEntry(keypairName, localKey, exportingPassword.toCharArray(), localKeyChain);

            // exporting
            exportingKeyStoreInstance.store(exportKeyPairStream, exportingPassword.toCharArray());

            return true;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException | CertificateException e) {
            e.printStackTrace();
            return false;
        }
    }


    public boolean importCertificate(String filePath, String alias) {
        try {
            File fileToImport = new File(filePath);
            FileInputStream fis = new FileInputStream(fileToImport.getAbsolutePath());

            X509Certificate certificateToImport = (X509Certificate) certificateFactory.generateCertificate(fis);
            keyStore.setCertificateEntry(alias, certificateToImport);

            return save();
        } catch (KeyStoreException | CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        }
        return false;
    }


    private boolean exportDer(String filePath, String keyPairName, int format) {
        if (format == Constants.HEAD) {
            try (FileOutputStream fos = new FileOutputStream(filePath)) {
                byte[] certificateBytes = keyStore.getCertificate(keyPairName).getEncoded();
                fos.write(certificateBytes);
                return true;
            } catch (CertificateEncodingException | KeyStoreException | IOException e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    private boolean exportPem(String filePath, String keyPairName, int format) {
        if (Constants.HEAD == format) {
            try (
                    FileWriter fw = new FileWriter(filePath);
                    PemWriter pemWriter = new PemWriter(fw)
            ) {
                byte[] certificate = keyStore.getCertificate(keyPairName).getEncoded();
                pemWriter.writeObject(new PemObject("CERTIFICATE", certificate));

                return true;
            } catch (CertificateEncodingException | KeyStoreException | IOException e) {
                e.printStackTrace();
            }
        } else if (Constants.CHAIN == format) {
            try
                    (
                            FileWriter fw = new FileWriter(filePath);
                            PemWriter pemWriter = new PemWriter(fw)
                    ) {
                Certificate[] chain = keyStore.getCertificateChain(keyPairName);
                for (Certificate certificate : chain) {
                    pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
                }
                return true;
            } catch (CertificateEncodingException | IOException | KeyStoreException e) {
                e.printStackTrace();
            }
        }

        return false;
    }

    public boolean exportCertificate(String filePath, String keyPairName, int encoding, int format) {
        if (Constants.DER == encoding) {
            return exportDer(filePath, keyPairName, format);
        } else if (Constants.PEM == encoding) {
            return exportPem(filePath, keyPairName, format);
        }
        return false;
    }

    public boolean canSign(String keyPairName) {
        try {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keyPairName);
            // check if it is certificate authority
//            if (certificate.getBasicConstraints() == -1) {
//                return false;
//            }
            boolean[] keyUsage = certificate.getKeyUsage();
            if (keyUsage == null) {
                return false; // key usage is not set
            }
            // return Key certificate sign usage
            return keyUsage[Constants.KEY_CERT_SIGN];
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return false;
    }


    public boolean exportCSR(String file, String keyPairName, String algorithm) {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keyPairName);

            X500Name name = SubjectInfo.getName(certificate.getSubjectDN().toString().replaceAll("\\s,\\s", ","));
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
            PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(name, info);
            AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder().find(signature);
            AsymmetricKeyParameter parameter = PrivateKeyFactory.createKey(keyStore.getKey(keyPairName, null).getEncoded());
            ContentSigner contentSigner = new BcRSAContentSignerBuilder(signature, digest).build(parameter);

            PKCS10CertificationRequest request = builder.build(contentSigner);

            fos.write(request.getEncoded());
            return true;
        } catch (OperatorCreationException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            e.printStackTrace();
        }
        return false;
    }

    private void setKeyUsage(JcaX509v3CertificateBuilder builder, boolean[] keyUsages, boolean keyUsageCritical) throws CertIOException {
        int keyUsageMask = 0;
        keyUsageMask |= keyUsages[0] ? X509KeyUsage.digitalSignature : 0;
        keyUsageMask |= keyUsages[2] ? X509KeyUsage.keyEncipherment : 0;
        keyUsageMask |= keyUsages[3] ? X509KeyUsage.dataEncipherment : 0;
        keyUsageMask |= keyUsages[4] ? X509KeyUsage.keyAgreement : 0;
        keyUsageMask |= keyUsages[5] ? X509KeyUsage.keyCertSign : 0;
        keyUsageMask |= keyUsages[6] ? X509KeyUsage.cRLSign : 0;
        keyUsageMask |= keyUsages[7] ? X509KeyUsage.encipherOnly : 0;
        keyUsageMask |= keyUsages[8] ? X509KeyUsage.decipherOnly : 0;

        KeyUsage keyUsageInstance = new KeyUsage(keyUsageMask);
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, keyUsageCritical, keyUsageInstance);
    }

    public boolean signCSR(GuiV3 access, String file, String keyPairName, String algorithm) {
        try {
            PKCS10CertificationRequest request = certificationRequest;
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keyPairName);

            X500Name name = new JcaX509CertificateHolder(certificate).getSubject();
            BigInteger serial = new BigInteger(access.getSerialNumber());
            Date notBefore = access.getNotBefore();
            Date notAfter = access.getNotAfter();

            X500Name subject = request.getSubject();
            PublicKey pubKey = new JcaPKCS10CertificationRequest(request).setProvider(BOUNCY_CASTLE_PROVIDER).getPublicKey();

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial, notBefore, notAfter, subject, pubKey);
            setKeyUsage(builder, access.getKeyUsage(), access.isCritical(Constants.KU));
            // TODO subject directory attributes
            // TODO extented key usages

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyPairName, PASSWORD); // TODO test password
            ContentSigner signer = new JcaContentSignerBuilder(algorithm).setProvider(BOUNCY_CASTLE_PROVIDER).build(privateKey);

            X509Certificate signed = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

            // get chain
            ArrayList<JcaX509CertificateHolder> chain = new ArrayList<>();
            // add certificate holder to chain
            chain.add(new JcaX509CertificateHolder(signed));

            for (Certificate c : keyStore.getCertificateChain(keyPairName)) {
                X509Certificate xc = (X509Certificate) c;
                chain.add(new JcaX509CertificateHolder(xc));
            }
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addCertificates(new CollectionStore<>(chain));

            CMSTypedData typedData = new CMSProcessableByteArray(signed.getEncoded());
            CMSSignedData signedData = generator.generate(typedData);

            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(signedData.getEncoded());
            }

            save();
            load();
            return true;
        } catch (CertificateException | OperatorCreationException | InvalidKeyException | NoSuchAlgorithmException | KeyStoreException | CMSException | IOException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        return false;
    }

    public String importCSR(String file) {
        try
            (
                    FileInputStream fis = new FileInputStream(file);
                    DataInputStream dis = new DataInputStream(fis)
            ) {
            byte[] fileContent = new byte[dis.available()];
            dis.readFully(fileContent);

            PKCS10CertificationRequest request = new PKCS10CertificationRequest(fileContent);
            certificationRequest = request;

            ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BOUNCY_CASTLE_PROVIDER).build(request.getSubjectPublicKeyInfo());
//            if (request.isSignatureValid(contentVerifierProvider))
                return request.getSubject().toString().replaceAll("\\s,\\s", ",");

        } catch (OperatorCreationException | IOException e) {
            e.printStackTrace();
        }

        GuiV3.reportError("CSR signing is failed");
        return null;
    }


    private boolean validCAReply(String fileName, String keyPairName){
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BOUNCY_CASTLE_PROVIDER);
        try(
            FileInputStream fis = new FileInputStream(fileName);
            DataInputStream dis = new DataInputStream(fis)
        ){
            byte[] fileContent = new byte[dis.available()];
            dis.readFully(fileContent);

            CMSSignedData signedData = new CMSSignedData(fileContent);
            Collection<SignerInformation> signerInformations = signedData.getSignerInfos().getSigners();

            // foreach signer
            for(SignerInformation signer: signerInformations){
                @SuppressWarnings({"uncheked"})
                Selector<X509CertificateHolder> certificateHolderSelector = (Selector<X509CertificateHolder>) signer.getSID();
                Collection<X509CertificateHolder> holders = signedData.getCertificates().getMatches(certificateHolderSelector);

                Optional<X509CertificateHolder> firstHolder = holders.stream().findFirst();
                if(firstHolder.isPresent()){
                    X509CertificateHolder holder = firstHolder.get();
                    X509Certificate certificate = converter.getCertificate(holder);

                    // if it is not verified
                    if(!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate))){
                        return false;
                    }
                }
            }

            Collection<X509CertificateHolder> holders = signedData.getCertificates().getMatches(null);
            Optional<X509CertificateHolder> firstHolder = holders.stream().findFirst();

            // if the first holder is not present
            if(!firstHolder.isPresent()) return false; // return false


            X509CertificateHolder certHolder = firstHolder.get();
            X509Certificate cert = converter.getCertificate(certHolder);
            X509Certificate toVerify = (X509Certificate) keyStore.getCertificate(keyPairName);

            // verify cert
            return toVerify.getSubjectX500Principal().equals(cert.getSubjectX500Principal());
        } catch (CMSException | IOException | CertificateException | KeyStoreException | OperatorCreationException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean importCAReply(String filePath, String keyPairName){
        // ca reply is valid
//        if(!validCAReply(filePath, keyPairName)){
//            System.out.println("CA reply is not valid!");
//            return false;
//        }

        try(FileInputStream fis = new FileInputStream(filePath)){
            Collection<? extends Certificate> certChain = CertificateFactory.getInstance(X509_INSTANCE).generateCertificates(fis);
            Key keystoreKey = keyStore.getKey(keyPairName, null); //PASSWORD);

            // import key entry
            keyStore.setKeyEntry(keyPairName, keystoreKey, /**PASSWORD**/ null, certChain.toArray(new Certificate[certChain.size()]));
            save();

            return true;
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        return false;
    }

    private boolean isChainSigned(X509Certificate certificate, String keyPairName){
        try {
            Certificate[] certificateChain = keyStore.getCertificateChain(keyPairName);

            // only one in chain verify only one
            if(1==certificateChain.length){
                certificate.verify(certificate.getPublicKey());
                return certificate.getBasicConstraints() != -1;
            }
            else{
                for(int i = 0;  i < certificateChain.length-1; i++){
                    // verify for the next one in the chain
                    certificateChain[i].verify(certificateChain[i+1].getPublicKey());
                    // if one certificate is not signed return false
                    if(((X509Certificate)certificateChain[i+1]).getBasicConstraints() == -1)
                        return false;
                }
                // all are verified
                return true;
            }

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();
        }
        return false;

    }

    public MyCode.LoadStatus getLoadStatus(X509Certificate certificate, String keyPairName){
        // if it is in the KeyStore
        try {
            if(keyStore.isCertificateEntry(keyPairName)){
                return MyCode.LoadStatus.TRUSTED;
            }
            // chain is signed
            if(isChainSigned(certificate, keyPairName))
                return MyCode.LoadStatus.SIGNED;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return MyCode.LoadStatus.UNSIGNED;
    }
}

