package ma.amiharbi;

import ma.amiharbi.encryption.CryptoUtilImpl;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SymetricCrypto {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        String data = "le message a crypté";

        SecretKey secretKey = cryptoUtil.generateSecretKey();


        String encryptedData = cryptoUtil.encryptAES(data.getBytes(), secretKey);
        byte[] encodedSecretKey =  secretKey.getEncoded();

        System.out.println("secret key is: "+ cryptoUtil.encodetoBase64(encodedSecretKey));
        System.out.println("encrypted data is: "+ encryptedData);

        byte[] decryptedData = cryptoUtil.decryptAES(encryptedData.getBytes(), secretKey);

        System.out.print("decrypted data is: "+ cryptoUtil.convertByteInString(decryptedData));
    }
}
