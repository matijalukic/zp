package implementation;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

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

        while(aliases.hasMoreElements()){
            String alias = aliases.nextElement();
            keyStore.deleteEntry(alias);
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
}

