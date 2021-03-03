package com.audit.tempprojectbase64tobytearray;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    String key = "MyKey";
    String ogValue = "RajanTheGreat";
    String bs64 = "p0o7zBZl9JHJ60cxB5/+3w";
    static String characterEncoding = "UTF-8";
    static String cipherTransformation = "AES/CBC/PKCS5Padding";
    static String aesEncryptionAlgorithm = "AES";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            ogValue = decrypt(bs64, key);
            bs64 = encrypt(ogValue, key);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String plainText, String key) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{

        if(plainText==null)
            plainText="";
        byte[] plainTextbytes =  plainText.getBytes(characterEncoding);// Base64.decodeBase64(plainText.getBytes());;
        byte[] keyBytes = getKeyBytes(key);
        return new String(Base64.encode(encrypt(plainTextbytes,keyBytes, keyBytes), Base64.NO_CLOSE));

    }

    public static byte[] encrypt(byte[] plainText, byte[] key, byte [] initialVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance(cipherTransformation);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, aesEncryptionAlgorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        plainText = cipher.doFinal(plainText);
        return plainText;
    }

    private static byte[] getKeyBytes(String key) throws UnsupportedEncodingException{
        byte[] keyBytes= new byte[16];
        byte[] parameterKeyBytes= key.getBytes(characterEncoding);
        System.arraycopy(parameterKeyBytes, 0, keyBytes, 0, Math.min(parameterKeyBytes.length, keyBytes.length));
        return keyBytes;
    }

    public static String decrypt(String encryptedText, String key) throws KeyException, GeneralSecurityException, GeneralSecurityException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] cipheredBytes = Base64.decode(encryptedText.getBytes(), Base64.DEFAULT);
        byte[] keyBytes = getKeyBytes(key);
        return new String(decrypt(cipheredBytes, keyBytes, keyBytes), characterEncoding);
    }

    public static byte[] decrypt(byte[] cipherText, byte[] key, byte [] initialVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {

        Cipher cipher = Cipher.getInstance(cipherTransformation);
        SecretKeySpec secretKeySpecy = new SecretKeySpec(key, aesEncryptionAlgorithm);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpecy, ivParameterSpec);
        cipherText = cipher.doFinal(cipherText);
        return cipherText;
    }
}