package implementation;

public class Extension {

    private boolean[] critical; // 15 values constants
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
    private boolean[] keyUsage; // 9 values
    private String dateOfBirth;
    private String[] subjectDirectoryAttribute; // 2 values
    private String gender; // 0 male, 1 female
    private boolean[] extendedKeyUsage; // 7  values

    public Extension() {
        // init arrays
        critical = new boolean[15];
        keyUsage = new boolean[9];
        subjectDirectoryAttribute = new String[2];
        extendedKeyUsage = new boolean[7];
    }

    public boolean[] getCritical() {
        return critical;
    }
    public boolean isCritical(int index){
        return critical[index];
    }

    public void setCritical(int index, boolean critical) {
        this.critical[index] = critical;
    }


    public boolean[] getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(boolean[] keyUsage) {
        this.keyUsage = keyUsage;
    }

    public String getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(String dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public String[] getSubjectDirectoryAttribute() {
        return subjectDirectoryAttribute;
    }

    public void setSubjectDirectoryAttribute(int index, String subjectDirectoryAttribute) {
        this.subjectDirectoryAttribute[index] = subjectDirectoryAttribute;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public boolean[] getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    public void setExtendedKeyUsage(boolean[] extendedKeyUsage) {
        this.extendedKeyUsage = extendedKeyUsage;
    }
}
