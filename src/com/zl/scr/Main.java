package com.zl.scr;

import java.net.URLEncoder;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/** 
* @ClassName: Main 
* @Description: TODO(这里用一句话描述这个类的作用) 
* @Company:方正
* @author zhaolei 
* @version 1.0 2017年8月16日 下午1:52:59 
*/
public class Main {

	public static void main(String[] args) throws Exception {
//        String a="12313asdasdasd+-";
//        String b="你好啊。";
//        System.out.println(URLEncoder.encode(a, "utf-8"));
        
        BASE64Encoder encode = new BASE64Encoder();

        String base64 = encode.encode(" 五笔字型电子计算机".getBytes());

        System.out.println(base64);

       

        BASE64Decoder decode = new BASE64Decoder();

        byte [] b = decode.decodeBuffer(base64);

        System.out.println( new String(b)); 
	}
}
