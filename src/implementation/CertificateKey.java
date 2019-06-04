package implementation;

import javax.security.auth.Subject;
import java.security.KeyPair;
import java.util.Date;

public class CertificateKey {
    // Our Classes
    private SubjectInfo subject;
    private Extension extension;

    private Date notBefore;
    private Date notAfter;
    private boolean trusted;
    private boolean signed;
    private String alias;
    private String serialNumber;
    private KeyPair keyPair;
    private String publicKeyAlgorithm;
    private String publicKeyParameter;
    private String publicKeyDigestAlgorithm;
    private String publicKeyECCurve;

    public CertificateKey() {
        super();

        this.subject = new SubjectInfo();
        this.extension = new Extension();
    }


    public Extension getExtension() {
        return extension;
    }

    public SubjectInfo getSubject() {
        return subject;
    }


    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    public boolean isSigned() {
        return signed;
    }

    public boolean isTrusted() {
        return trusted;
    }

    public void setTrusted(boolean trusted) {
        this.trusted = trusted;
    }

    public void setSigned(boolean signed) {
        this.signed = signed;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public String getPublicKeyParameter() {
        return publicKeyParameter;
    }

    public void setPublicKeyParameter(String publicKeyParameter) {
        this.publicKeyParameter = publicKeyParameter;
    }

    public String getPublicKeyDigestAlgorithm() {
        return publicKeyDigestAlgorithm;
    }

    public void setPublicKeyDigestAlgorithm(String publicKeyDigestAlgorithm) {
        this.publicKeyDigestAlgorithm = publicKeyDigestAlgorithm;
    }

    public String getPublicKeyECCurve() {
        return publicKeyECCurve;
    }

    public void setPublicKeyECCurve(String publicKeyECCurve) {
        this.publicKeyECCurve = publicKeyECCurve;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }
}
