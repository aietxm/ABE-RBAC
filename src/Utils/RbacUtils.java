package Utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import Rbac.FileCipher;
import Rbac.RoleCipher;
import Rbac.RoleUserSecret;
import Rbac.SourceFileCipher;
import Utils.AbeSettings;
import CipherStore.LocalCache;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import netscape.security.Privilege;

public class RbacUtils {


    static LocalCache cache = new LocalCache(32);


    //生成ID，用户ID，资源ID，角色ID 以及KR和VR
    public static Element GenerateID(Pairing pairing, String Group) {
        if (Group.equals("ZR"))
            return pairing.getZr().newRandomElement();
        else
            return pairing.getGT().newRandomElement();
    }

    public static FileCipher getFileCipherByIDf(Element IDf) {
        String key = AbeSettings.filecipher + IDf;
        //System.out.println("getFileCipherByIDf:" + key);

        FileCipher fileCipher = (FileCipher) cache.get(key);
        return fileCipher == null ? null : fileCipher;
    }

    public static void fileCipherSave(Element IDf, FileCipher fileCipher) {
        String key = AbeSettings.filecipher + IDf;
       // System.out.println("fileCipherSave:" + key);
        cache.put(key, fileCipher);
    }

    public static SourceFileCipher getSourceFileCipherByIDf(Element IDf) {
        String key = AbeSettings.sourceFileFlag + IDf;

        //System.out.println("getSourceFileCipherByIDf:" + key);

        SourceFileCipher cipher = (SourceFileCipher) cache.get(key);

        return cipher == null ? null : cipher;
    }

    public static void SourceFileCipherSave(Element IDf, SourceFileCipher sourceFileCipher) {
        String key = AbeSettings.sourceFileFlag + IDf;
        cache.put(key, sourceFileCipher);

    }

    public static RoleCipher getRoleCipherByIDr(Element IDr) {
        String key = AbeSettings.roleCipherFlag + IDr;
       // System.out.println("getRoleCipherByIDr:" + key);
        RoleCipher roleCipher = (RoleCipher) cache.get(key);

        return roleCipher == null ? null : roleCipher;
    }

    public static void RoleCipherSave(Element IDr, RoleCipher roleCipher) {
        String key = AbeSettings.roleCipherFlag + IDr;
       // System.out.println("RoleCipherSave:" + key);
        cache.put(key, roleCipher);
    }


    public static void RoleUserSecretSave(Element IDu, Element IDr, RoleUserSecret secret) {
        String key = AbeSettings.roleUserSecret + IDr.duplicate().add(IDu);
       // System.out.println("RoleUserSecretSave:" + key);
        cache.put(key, secret);
    }

    public static RoleUserSecret getRoleUserSecret(Element IDu,Element IDr){
        String key = AbeSettings.roleUserSecret + IDr.duplicate().add(IDu);
       // System.out.println("RoleUserSecretSave:" + key);
        RoleUserSecret roleUserSecret = (RoleUserSecret) cache.get(key);

        return roleUserSecret==null?null:roleUserSecret;
    }

    public static void PrivilegeSave(Element IDf, Element Kf){
        String key = AbeSettings.PrivilegeSet + IDf;
        // System.out.println("RoleUserSecretSave:" + key);

        cache.put(key, Kf);
    }

    public static Element getPrivilegeSet(Element IDf){
        String key = AbeSettings.PrivilegeSet + IDf;
        // System.out.println("RoleUserSecretSave:" + key);
        Element privilege = (Element) cache.get(key);

        return privilege==null?null:privilege;
    }


    public static InputStream getFile(Element IDf) {
        String testString = "this is test";
        return new ByteArrayInputStream(testString.getBytes());

    }

    public static Element elementG2FromString(byte[] s, Pairing pairing) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance(AbeSettings.ELEMENT_HASHING_ALGORITHM);
            byte[] digest = sha1.digest(s);
            return pairing.getG1().newElementFromHash(digest, 0, digest.length);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing Alogrithm not available: " + AbeSettings.ELEMENT_HASHING_ALGORITHM, e);
        }
    }

    public static Element elementZRFromString(byte[] s, Pairing pairing) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance(AbeSettings.ELEMENT_HASHING_ALGORITHM);
            byte[] digest = sha1.digest(s);
            return pairing.getZr().newElementFromHash(digest, 0, digest.length);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing Alogrithm not available: " + AbeSettings.ELEMENT_HASHING_ALGORITHM, e);
        }
    }

    //生成权限密钥集（未启用）
    public static Element getPriviligeSet(Element IDf, String pri) throws Exception{
        String key = AbeSettings.PrivilegeSet + IDf;
        if(cache.contains(key)){
            return (Element)cache.get(key);
        }
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPublic();

        if(pri.equals(AbeSettings.PRI_READ)){

        }

        if(pri.equals(AbeSettings.PRI_WRITE)){

        }

        if(pri.equals(AbeSettings.PRI_READ_WRITE)){

        }

        return null;

    }



}
