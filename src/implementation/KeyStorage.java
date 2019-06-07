package implementation;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Handles the saving loading and deleting storage of keys
 */
public class KeyStorage {
    private static final String fileName = "keystorage";
    private static final String instanceName = "PKCS12";
    private static final String password = "password123";
    private static final char[] PASSWORD = password.toCharArray();


    private KeyStore keyStore;
    private FileOutputStream fileOutputStream;
    private FileInputStream fileInputStream;


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
        if(keyStore==null)
            this.keyStore = KeyStore.getInstance(KeyStorage.instanceName);
        return keyStore;
    }

    public void put(String keypairName, KeyPair keyPair, Certificate[] certificates) throws KeyStoreException {
        getKeyStore().setKeyEntry(keypairName, keyPair.getPrivate(), password.toCharArray(), certificates);
    }

    /**
     * Save keys to the file
     *
     * @return boolean
     */
    public boolean save() {
        try {
            keyStore.store(getFileOutputStream(), password.toCharArray());
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
                keyStore.load(fileInputStream, password.toCharArray());
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

    public X509Certificate getCertificate(String alias){
        try {
            return (X509Certificate)keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Deletes the keyStore file
     */
    private void deleteFile(){
        File deletingFile = new File(fileName);
        if(deletingFile.exists() && !deletingFile.isDirectory())
            deletingFile.delete();
    }


    private void removeAliases() throws KeyStoreException {
        Enumeration<String> aliases = keyStore.aliases();
        List<String> aliasesList = new ArrayList<>();

        // push to String list
        while(aliases.hasMoreElements()){
            aliasesList.add(aliases.nextElement());
        }
        for(String alias: aliasesList) {
            keyStore.deleteEntry(alias);
        }
    }

    public boolean remove(String keyPairAlias) {
        try{
            // delete key
            keyStore.deleteEntry(keyPairAlias);

            // save file
            save();
            return true;
        }
        catch (KeyStoreException e){
            e.printStackTrace();
            return false;
        }
    }

    public void reset(){
        try {
            removeAliases();

            deleteFile();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public boolean importKeyPair(String keyPairName, String fileName, String password){

        try(FileInputStream importingKeyPairStream = new FileInputStream(fileName)) {
            KeyStore importingKeyStore = KeyStore.getInstance(instanceName, new BouncyCastleProvider());
            // imports int keystore
            importingKeyStore.load(importingKeyPairStream, password.toCharArray());

            // chaining keypairss
            List<String> chainAliases = Collections.list(importingKeyStore.aliases());
            chainAliases.forEach(
                    importingAlias -> {
                        try{
                            Key key = importingKeyStore.getKey(importingAlias, password.toCharArray());
                            Certificate[] chain = importingKeyStore.getCertificateChain(importingAlias);

                            // put in local KeyStore
                            keyStore.setKeyEntry(keyPairName, key, null, chain);
                        } catch (UnrecoverableKeyException|NoSuchAlgorithmException|KeyStoreException e) {
                            e.printStackTrace();
                        }
                    }
            );
            // save to file
            save();

            return true;
        } catch (KeyStoreException|CertificateException|NoSuchAlgorithmException|IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}

