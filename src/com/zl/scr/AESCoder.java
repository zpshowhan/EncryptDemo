package com.zl.scr;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/** 
 * AES 加密解密
* @ClassName: AESCoder 
* @Description: TODO 对称加密算法
* @Company:方正
* @author zhaolei 
* @version 1.0 2017年8月17日 下午12:32:26 
*/
public class AESCoder {

	private final static String AES = "AES";
    private final static String ENCODE = "UTF-8";
    public final static String defaultKey = "vsmIwEu2";
    /**
     * 
    *
    * @Title: AESEncode 
    * @Description: TODO AES加密  
    * @param @param charset 编码
    * @param @param content 明文
    * @param @return    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String AESEncode(String charset,String content){
    	return AESEncode(defaultKey, charset, content);
    }
    /**
     * 
    *
    * @Title: AESEncode 
    * @Description: TODO  AES加密  
    * @param @param content 明文
    * @param @return    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String AESEncode(String content){
    	return AESEncode(defaultKey, ENCODE, content);
    }
    /**
     * 
    *
    * @Title: AESEncode 
    * @Description: TODO AES加密 
    * @param @param encodeKey 秘钥 (如果秘钥为""或者null 会使用系统默认的秘钥)
    * @param @param charset 编码
    * @param @param content 要加密的内容
    * @param @return    设定文件 
    * @return String    返回类型 
    * @throws
     */
	public static String AESEncode(String encodeKey,String charset,String content){
        try {
        	if(encodeKey==null||encodeKey==""){
        		encodeKey=defaultKey;
        	}
            //1.构造密钥生成器，指定为AES算法,不区分大小写
            KeyGenerator keygen=KeyGenerator.getInstance(AES);
            //2.根据encodeKey规则初始化密钥生成器
            //生成一个128位的随机源,根据传入的字节数组
            //String.getBytes()默认使用的编码是ISO-8859-1
            keygen.init(128, new SecureRandom(encodeKey.getBytes(charset)));
              //3.产生原始对称密钥
            SecretKey original_key=keygen.generateKey();
              //4.获得原始对称密钥的字节数组
            byte [] raw=original_key.getEncoded();
            //5.根据字节数组生成AES密钥
            SecretKey key=new SecretKeySpec(raw, AES);
              //6.根据指定算法AES自成密码器
            Cipher cipher=Cipher.getInstance(AES);
              //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(Cipher.ENCRYPT_MODE, key);
            //8.获取加密内容的字节数组(这里要设置为utf-8)不然内容中如果有中文和英文混合中文就会解密为乱码
            byte [] byte_encode=content.getBytes(charset);
            //9.根据密码器的初始化方式--加密：将数据加密
            byte [] byte_AES=cipher.doFinal(byte_encode);
          //10.将加密后的数据转换为字符串
            //这里用Base64Encoder中会找不到包
            //解决办法：
            //在项目的Build path中先移除JRE System Library，再添加库JRE System Library，重新编译后就一切正常了。
            String AES_encode=new String(new BASE64Encoder().encode(byte_AES));
          //11.将字符串返回
            return AES_encode;
        } catch (Exception e) {
            e.printStackTrace();
        } 
        //如果有错就返加null
        return null;         
    }
	/**
	 * 
	*
	* @Title: AESDncode 
	* @Description: TODO AES解密
	* @param @param charset 编码
	* @param @param content 密文
	* @param @return    设定文件 
	* @return String    返回类型 
	* @throws
	 */
	public static String AESDncode(String charset,String content){
		return AESDncode(defaultKey, charset, content);
	}
	/**
	 * 
	*
	* @Title: AESDncode 
	* @Description: TODO  AES解密
	* @param @param content 密文
	* @param @return    设定文件 
	* @return String    返回类型 
	* @throws
	 */
	public static String AESDncode(String content){
		return AESDncode(defaultKey, ENCODE, content);
	}
	/**
	 * 
	*
	* @Title: AESDncode 
	* @Description: TODO AES解密 
	* @param @param encodeKey 秘钥 (如果秘钥为""或者null 会使用系统默认的秘钥)
	* @param @param charset 编码
	* @param @param content 加密过的内容
	* @param @return    设定文件 
	* @return String    返回类型 
	* @throws
	 */
    public static String AESDncode(String encodeKey,String charset,String content){
        try {
        	if(encodeKey==null||encodeKey==""){
        		encodeKey=defaultKey;
        	}
            //1.构造密钥生成器，指定为AES算法,不区分大小写
            KeyGenerator keygen=KeyGenerator.getInstance(AES);
            //2.根据encodeKey规则初始化密钥生成器
            //生成一个128位的随机源,根据传入的字节数组
            keygen.init(128, new SecureRandom(encodeKey.getBytes(charset)));
              //3.产生原始对称密钥
            SecretKey original_key=keygen.generateKey();
              //4.获得原始对称密钥的字节数组
            byte [] raw=original_key.getEncoded();
            //5.根据字节数组生成AES密钥
            SecretKey key=new SecretKeySpec(raw, AES);
              //6.根据指定算法AES自成密码器
            Cipher cipher=Cipher.getInstance(AES);
              //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(Cipher.DECRYPT_MODE, key);
            //8.将加密并编码后的内容解码成字节数组
            byte [] byte_content= new BASE64Decoder().decodeBuffer(content);
            /*
             * 解密
             */
            byte [] byte_decode=cipher.doFinal(byte_content);
            String AES_decode=new String(byte_decode,charset);
            return AES_decode;
        } catch (Exception e) {
            e.printStackTrace();
        }
        //如果有错就返加null
        return null;         
    }
    public static void main(String[] args) {
		String content="00000000000";
		String encode = AESCoder.AESEncode(content);
		System.out.println("encode: "+encode);
		String dncode = AESCoder.AESDncode(encode);
		System.out.println("dncode: "+dncode);
	}
}
