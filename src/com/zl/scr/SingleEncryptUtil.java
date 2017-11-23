package com.zl.scr;

import java.security.MessageDigest;
import java.util.Arrays;

/** 
 *  
 *  
* @ClassName: SingleEncryptUtil 
* @Description: TODO 单向加密算法（不可逆）集合 
* @Company:方正
* @author zhaolei 
* @version 1.0 2017年8月16日 下午1:45:47 
*/
public class SingleEncryptUtil {

	//加密类型MD5
	private static final String ALGORITHM_MD5 = "MD5";
    //加密类型SHA-1
    private static final String ALGORITHM_SHA1 = "SHA-1";
    //加密类型SHA-256
    private static final String ALGORITHM_SHA256 = "SHA-256";
    //加密类型SHA-384
    private static final String ALGORITHM_SHA384 = "SHA-384";
    private final static String ENCODE = "UTF-8";

    /**
     * 
    *
    * @Title: EncryptMD5 
    * @Description: TODO MD5加密 
    * @param @param args
    * @param @return    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String EncryptMD5(String... args){
    	
		return Encrypt(ALGORITHM_MD5, args);
    }
    /**
     * 
    *
    * @Title: EncryptSHA1 
    * @Description: TODO SHA-1加密
    * @param @param args
    * @param @return    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String EncryptSHA1(String... args){
    	
    	return Encrypt(ALGORITHM_SHA1, args);
    }
    /**
     * 
    *
    * @Title: EncryptSHA256 
    * @Description: TODO SHA-256加密 
    * @param @param args
    * @param @return    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String EncryptSHA256(String... args){
    	
    	return Encrypt(ALGORITHM_SHA256, args);
    }
    /**
     * 
    *
    * @Title: EncryptSHA384 
    * @Description: TODO SHA-384加密 
    * @param @param args
    * @param @return    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String EncryptSHA384(String... args){
    	
    	return Encrypt(ALGORITHM_SHA384, args);
    }
    /**
     * 
    *
    * @Title: Encrypt 
    * @Description: TODO 加密公共方法 
    * @param @param type
    * @param @param args
    * @param @return    设定文件 
    * @return String    返回类型 
    * @throws
     */
    public static String Encrypt(String type,String... args){
		try {
			Arrays.sort(args);
			StringBuffer sb = new StringBuffer();
			// 字符串排序
			Arrays.sort(args);
			for (String a : args) {
				sb.append(a);
			}
			String str = sb.toString();
			// 
			MessageDigest md = MessageDigest.getInstance(type);
			//String.getBytes()默认使用的编码是ISO-8859-1
			md.update(str.getBytes(ENCODE));
			byte[] digest = md.digest();

			StringBuffer hexstr = new StringBuffer();
			String shaHex = "";
			for (int i = 0; i < digest.length; i++) {
				shaHex = Integer.toHexString(digest[i] & 0xFF);
				if (shaHex.length() < 2) {
					hexstr.append(0);
				}
				hexstr.append(shaHex);
			}
			return hexstr.toString();
		} catch (Exception e) {
			e.getStackTrace();
		}
		return null;
    	
    }
    public static void main(String[] args) {
		String content="12313212";
		SingleEncryptUtil.EncryptMD5(content);
	}
}
