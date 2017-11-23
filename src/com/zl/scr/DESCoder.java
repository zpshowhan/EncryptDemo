package com.zl.scr;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/** 
 * DES加密解密
 * 
* @ClassName: DESCoder 
* @Description: TODO 对称加密算法 
* @Company:方正
* @author zhaolei 
* @version 1.0 2017年8月17日 上午11:15:19 
*/
public class DESCoder {

	private final static String DES = "DES";
    private final static String ENCODE = "UTF-8";
    private final static String defaultKey = "IOS6lOeslOWtlWeieUteWtkOiuoeeulacug";

    /**
     * 
    *
    * @Title: encrypt 
    * @Description: TODO 使用 默认key 加密 
    * @param @param data 加密数据
    * @param @return
    * @param @throws Exception    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String encrypt(String data) throws Exception {
        return encrypt(data, defaultKey);
    }

    /**
     * 
    *
    * @Title: decrypt 
    * @Description: TODO 使用 默认key 解密 
    * @param @param data 要解密的密文
    * @param @return
    * @param @throws Exception    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String decrypt(String data) throws Exception{
        return decrypt(data, defaultKey);
    }

    /**
     * 
    *
    * @Title: encrypt 
    * @Description: TODO 使用自定义的key加密数据 
    * @param @param data 要加密的数据
    * @param @param key 自定义秘钥
    * @param @return
    * @param @throws Exception    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String encrypt(String data, String key) throws Exception {
        return encrypt(data, key, ENCODE);
    }
    /**
     * 
    *
    * @Title: encrypt 
    * @Description: TODO 使用自定义的key加密数据 
    * @param @param data 明文
    * @param @param key 秘钥 秘钥长度必须为8的倍数
    * @param @param charset 编码
    * @param @return
    * @param @throws Exception    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String encrypt(String data, String key,String charset) throws Exception {
        byte[] bt = encrypt(data.getBytes(charset), key.getBytes(charset));
        String strs = new BASE64Encoder().encode(bt);
        return strs;
    }
    /**
     * 
    *
    * @Title: decrypt 
    * @Description: TODO 根据自定义的key进行解密
    * @param @param data 密文
    * @param @param key 秘钥 秘钥长度必须为8的倍数
    * @param @return
    * @param @throws Exception    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String decrypt(String data, String key) throws Exception {
        return decrypt(data, key, ENCODE);
    }
    /**
     * 
    *
    * @Title: decrypt 根据自定义的key进行解密
    * @Description: TODO  
    * @param @param data 密文
    * @param @param key 秘钥
    * @param @param charset 编码
    * @param @return
    * @param @throws Exception    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String decrypt(String data, String key,String charset) throws Exception {
        if (data == null)
            return null;
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] buf = decoder.decodeBuffer(data);
        byte[] bt = decrypt(buf, key.getBytes(charset));
        return new String(bt, charset);
    }
    
    private static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key);

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);

        // Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(DES);

        // 用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);

        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key);

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);

        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(DES);

        // 用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);

        return cipher.doFinal(data);
    }
    public static void main(String[] args) {
		String content="你好我的宝贝";
		try {
			String encrypt = DESCoder.encrypt(content, defaultKey,CharsetCom.UTF_8);
			System.out.println("encrypt: "+encrypt);
			String decrypt = DESCoder.decrypt(encrypt, defaultKey,CharsetCom.UTF_8);
			System.out.println("decrypt: "+decrypt);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
