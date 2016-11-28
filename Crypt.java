import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/*
 * Crypt class for java
 *
 * @author fangjinmin@gmail.com
 * @date 2016/11/28
 * @version 1.0
 */

public class Crypt {
    
    //sceret key
    private String key;
    //IV size
    private static final int IV_SIZE = 16;
    private static final String HASH_ALAGORITHM = "SHA-256";
    private static final String ENCODING = "UTF-8";
    private static final String ENCRYPT_ALAGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    /*
     * construct method
     *
     * @param key String secret key
     *
     */
    public Crypt(String key) {
        this.key = key;
    }

    /*
     * encrypt data
     *
     * @param data String the data to be encrypted
     * @return base64 endcoded encrypted data
     *
     */
 
    public String encrypt(String data) throws Exception {

        //create IV
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParam = new IvParameterSpec(iv);

        //create SecretKeySpec
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ENCRYPT_ALAGORITHM);

        //encrypt
        byte[] dataBytes = data.getBytes(ENCODING);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParam);
        byte[] encrypted = cipher.doFinal(dataBytes);

        //connect IV and encrypted text
        byte[] encryptedIVAndText = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, encryptedIVAndText, IV_SIZE, encrypted.length);

        //create hmac hash
        byte[] hmacBytes = hmac(encryptedIVAndText);
        byte[] finalData = new byte[encryptedIVAndText.length + hmacBytes.length];
        System.arraycopy(hmacBytes, 0, finalData, 0, hmacBytes.length);
        System.arraycopy(encryptedIVAndText, 0, finalData, hmacBytes.length, encryptedIVAndText.length);

        //base64 url safe encode
        Base64.Encoder encoder = Base64.getUrlEncoder();
        return encoder.encodeToString(finalData);
    }

    /*
     * decrypt data
     *
     * @param data String the data to be decrypted
     * @return decrypted data. if falied i will be thrown an exception.
     *
     */
    public String decrypt(String data) throws Exception {
        //base64 url safe encode
        Base64.Decoder decoder = Base64.getUrlDecoder();
        byte[] encryptedBytes = decoder.decode(data);

        //check hash 
        byte[] rowHmacBytes = new byte[64];
        System.arraycopy(encryptedBytes, 0, rowHmacBytes, 0, 64);
        byte[] encryptedIVAndText = new byte[encryptedBytes.length - 64];
        System.arraycopy(encryptedBytes, rowHmacBytes.length, encryptedIVAndText, 0, encryptedIVAndText.length);
        byte[] hmacBytes = hmac(encryptedIVAndText);
        //if not equal, it would be modified by someone else
        if(!MessageDigest.isEqual(rowHmacBytes,hmacBytes)) {
            throw new Exception("modified by someone else");
        }

        //get IV
        byte[] iv= new byte[IV_SIZE];
        System.arraycopy(encryptedIVAndText, 0, iv, 0, IV_SIZE);
        IvParameterSpec ivParam = new IvParameterSpec(iv);

        //get encryted text
        byte[] encryptedText = new byte[encryptedIVAndText.length - IV_SIZE];
        System.arraycopy(encryptedIVAndText, IV_SIZE, encryptedText, 0, encryptedText.length);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ENCRYPT_ALAGORITHM);

        // decrypt
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParam);
        byte[] decryptedBytes = cipher.doFinal(encryptedText);
        return new String(decryptedBytes, ENCODING);
    }

    /*
     * create hmac hash 
     *
     * @param data bytes[] the data to be decrypted
     * @return hash data. if falied i will be thrown an exception.
     *
     */
    private byte[] hmac(byte[] data) throws Exception {
        SecretKeySpec sk = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(sk);

        byte[] macBytes = mac.doFinal(data);
        
        StringBuilder sb = new StringBuilder(2 * macBytes.length);
        for(byte b: macBytes) {
            sb.append(String.format("%02x", b&0xff) );
        }
        
        return sb.toString().getBytes();
    }
}
