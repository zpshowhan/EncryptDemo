package com.zl.scr;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/** 
 * 3DES 或Triple DES 三重数据加密算法
 * 
* @ClassName: DES3Coder 
* @Description: TODO 对称加密算法 
* @Company:方正
* @author zhaolei 
* @version 1.0 2017年8月17日 下午1:39:36 
*/
public class DES3Coder {

	private final static String ENCODE = "UTF-8";
	private static final String ALGORITHM = "DESede"; 
	private static final String PASSWORD_CRYPT_KEY = "2012PinganVitality075522628888ForShenZhenBelter075561869839";
	
	/**
	 * 
	*
	* @Title: encryptMode 
	* @Description: TODO 3DES 加密
	* @param @param content 明文字符串
	* @param @return    设定文件 
	* @return String    返回类型 
	* @throws
	 */
	public static String encryptMode(String  content){
		return encryptMode(PASSWORD_CRYPT_KEY, content);
	}
	/**
	 * 
	*
	* @Title: encryptMode 
	* @Description: TODO 3DES加密 
	* @param @param key 秘钥
	* @param @param content 明文字符串
	* @param @return    设定文件 
	* @return String    返回类型 
	* @throws
	 */
	public static String encryptMode(String key,String  content) {
		try {
			return encryptMode(build3DesKey(key), content);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * 
	*
	* @Title: encryptMode 
	* @Description: TODO 3DES加密 
	* @param @param key 秘钥数组
	* @param @param content 明文字符串
	* @param @return    设定文件 
	* @return String    返回类型 
	* @throws
	 */
	public static String encryptMode(byte[] key,String  content) {
		try {
			byte[] src= content.getBytes(ENCODE);
			SecretKey deskey = new SecretKeySpec(key, ALGORITHM);    //生成密钥
			Cipher c1 = Cipher.getInstance(ALGORITHM);    //实例化负责加密/解密的Cipher工具类
			c1.init(Cipher.ENCRYPT_MODE, deskey);    //初始化为加密模式
			byte[] cot=c1.doFinal(src);
			return new BASE64Encoder().encode(cot);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	public static byte[] encryptMode(String key,byte[]  content) {
		try {
			return encryptMode(build3DesKey(key), content);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
	public static byte[] encryptMode(byte[] key,byte[] content) {
		try {
			SecretKey deskey = new SecretKeySpec(key, ALGORITHM);    //生成密钥
			Cipher c1 = Cipher.getInstance(ALGORITHM);    //实例化负责加密/解密的Cipher工具类
			c1.init(Cipher.ENCRYPT_MODE, deskey);    //初始化为加密模式
			byte[] cot=c1.doFinal(content);
			return cot;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	public static String decryptMode(String content) {  
		
		try {
			byte[] bt = decryptMode(new BASE64Decoder().decodeBuffer(content));
			return new String(bt,ENCODE);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	public static String decryptMode(String key,String content) {  
		try {
			byte[] bt = decryptMode(build3DesKey(key), content);
			return new String(bt,ENCODE);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	public static byte[] decryptMode(byte[] Key, String content) {
		try {
			return decryptMode(Key, content);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	public static byte[] decryptMode(byte[] content) {      
		try {
			return decryptMode(build3DesKey(PASSWORD_CRYPT_KEY), content);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	public static byte[] decryptMode(byte[] d3key,byte[] content) {      
		try {
			SecretKey deskey = new SecretKeySpec(d3key, ALGORITHM);
			Cipher c1 = Cipher.getInstance(ALGORITHM);
			c1.init(Cipher.DECRYPT_MODE, deskey);    //初始化为解密模式
			byte[] cot=c1.doFinal(content);
			return cot;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	public static byte[] build3DesKey(String keyStr) throws UnsupportedEncodingException{
         byte[] key = new byte[24];    //声明一个24位的字节数组，默认里面都是0
         byte[] temp = keyStr.getBytes(ENCODE);    //将字符串转成字节数组
         /*
          * 执行数组拷贝
          * System.arraycopy(源数组，从源数组哪里开始拷贝，目标数组，拷贝多少位)
          */
         if(key.length > temp.length){
             //如果temp不够24位，则拷贝temp数组整个长度的内容到key数组中
             System.arraycopy(temp, 0, key, 0, temp.length);
         }else{
             //如果temp大于24位，则拷贝temp数组24个长度的内容到key数组中
             System.arraycopy(temp, 0, key, 0, key.length);
         }
         return key;
     } 
	
	public static byte[] create3DesKey() throws NoSuchAlgorithmException{
		KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);//密钥生成器
		keyGen.init(168);  //可指定密钥长度为112或168，默认为168   
		SecretKey secretKey = keyGen.generateKey();//生成密钥
		byte[] key = secretKey.getEncoded();//密钥字节数组
		return key;
	}

	public static void main(String[] args) throws Exception {
		String content="000000000000";
		byte[] key=create3DesKey();
		String encrypt = DES3Coder.encryptMode(content);
		
		System.out.println("密文："+(encrypt));
		String decrypt = DES3Coder.decryptMode(encrypt);
		System.out.println("解密后："+(decrypt));
	}
}
