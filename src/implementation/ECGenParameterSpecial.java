package implementation;

import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class ECGenParameterSpecial extends ECGenParameterSpec {
    /**
     * Changes some ec curve names with the one that are provided
     *
     * @param ecName
     * @return
     */
    private static String replaceEcName(String ecName){
        Map<String,String> changingNames = new HashMap<>();
        changingNames.put("prime256v1", "secp256r1"); // replace prime256v1 with secp256r1
        changingNames.put("P-256", "secp256r1"); // replace P-256 with secp256r1
        changingNames.put("P-384", "secp384r1"); // replace P-384 with secp384r1
        changingNames.put("P-521", "secp521r1"); // replace P-521 with secp521r1
        changingNames.put("B-283", "sect283r1"); // replace B-283 with sect283r1
        changingNames.put("B-409", "sect409r1"); // replace B-409 with sect409r1
        changingNames.put("B-571", "sect571r1"); // replace P-521 with secp521r1


        // if it should be replaced
        if(changingNames.get(ecName) != null)
            return changingNames.get(ecName);
        return ecName;
    }

    /**
     * Return instance with replaced name
     *
     *
     * @param ecName
     * @return
     */
    public static ECGenParameterSpec getInstance(String ecName){
        return new ECGenParameterSpec(replaceEcName(ecName));
    }


    public ECGenParameterSpecial(String stdName) {
        super(stdName);
    }


}
