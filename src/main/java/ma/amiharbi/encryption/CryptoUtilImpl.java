package ma.amiharbi.encryption;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

public class CryptoUtilImpl {

    public String encodetoBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public byte[] decodefromBase64(byte[] dataBase64) {
        return Base64.getDecoder().decode(dataBase64);
    }

    public String encodetoBase64Url(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data);
    }

    public byte[] decodefromBase64URL(String dataBase64) {
        return Base64.getUrlDecoder().decode(dataBase64.getBytes());
    }

    public String encodetoHex(byte[] data) {
        return DatatypeConverter.printHexBinary(data);
    }

    public String encodetoHexNative(byte[] data) {
        Formatter formatter = new Formatter();
        for (byte b : data) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public String convertByteInString(byte[] data) {
        return new String(data);
    }

    public String encryptAES(byte[] data, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
       // SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0, secret.length(), "AES");
        //SecretKey secretKey = this.generateSecretKey();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data);
        return this.encodetoBase64(encryptedData);
    }

    public byte[] decryptAES(byte[] encodedEncryptedData, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decodeEncryptedData = this.decodefromBase64(encodedEncryptedData);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = cipher.doFinal(decodeEncryptedData);
        return decryptedData;
    }

    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public PublicKey publicKeyFromBase64(String pkBase64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedPk = Base64.getDecoder().decode(pkBase64);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedPk));
        return  publicKey;
    }

    public PrivateKey privateKeyFromBase64(String pkBase64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedPk = Base64.getDecoder().decode(pkBase64);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedPk));
        return  privateKey;
    }

    public String encryptRSA(byte[] data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(data);
        return encodetoBase64(bytes);
    }

   /* public String decryptRSA(String dataBase64, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedEncryptedData = decodefromBase64(dataBase64);
    }*/
}
