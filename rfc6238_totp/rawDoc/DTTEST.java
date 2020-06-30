import java.io.UnsupportedEncodingException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
// import java.nio.ByteBuffer;
// import java.util.*;
import java.math.BigInteger;
// import java.util.TimeZone;
import java.util.Base64;


public class DTTEST {
    private DTTEST(){
        System.out.println("Start:");
    }

    /**
     * This method uses the JCE to provide the crypto algorithm.
     * HMAC computes a Hashed Message Authentication Code with the
     * crypto hash algorithm as a parameter.
     *
     * @param crypto: the crypto algorithm (HmacSHA1, HmacSHA256,
     *                             HmacSHA512)
     * @param keyBytes: the bytes to use for the HMAC key
     * @param text: the message or text to be authenticated = time
     */

    private static byte[] hmac_sha(String crypto, byte[] key, byte[] text){
        try {
            // byte[] keyBytes = Base64.getDecoder().decode(key);
            // byte[] keyBytes = Base64.getDecoder().decode(key);
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey =
                new SecretKeySpec(key, crypto);
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }


    /**
    * This method converts a HEX string to Byte[]
    *
    * @param hex: the HEX string
    *
    * @return: a byte array
    */

    private static byte[] hexStr2Bytes(String hex){
    // Adding one byte to get the right conversion
    // Values starting with "0" can be converted
    byte[] bArray = new BigInteger("10" + hex,16).toByteArray();

    // Copy all the REAL bytes, not the "first"
    byte[] ret = new byte[bArray.length - 1];
    for (int i = 0; i < ret.length; i++)
        ret[i] = bArray[i+1];
    return ret;
    }

    private static final long [] DIGITS_POWER = 
    { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000L };
    // 0  1   2   3       4     5        6         7        8          9          10

     /**
      * This method generates a TOTP value for the given
      * set of parameters.
      *
      * @param key: the shared secret, HEX encoded
      * @param time: a value that reflects a time
      * @param returnDigits: number of digits to return
      *
      * @return: a numeric String in base 10 that includes
      *              {@link truncationDigits} digits
      */

    public static String generateTOTP(String key, String time, String returnDigits){
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }


    /**
    * This method generates a TOTP value for the given
    * set of parameters.
    *
    * @param key: the shared secret, HEX encoded
    * @param time: a value that reflects a time
    * @param returnDigits: number of digits to return
    *
    * @return: a numeric String in base 10 that includes
    *              {@link truncationDigits} digits
    */

    public static String generateTOTP256(String key,
        String time,
        String returnDigits){
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }

 /**
      * This method generates a TOTP value for the given
      * set of parameters.
      *
      * @param key: the shared secret, HEX encoded
      * @param time: a value that reflects a time
      * @param returnDigits: number of digits to return
      *
      * @return: a numeric String in base 10 that includes
      *              {@link truncationDigits} digits
      */

    public static String generateTOTP512(String key,
    String time,
    String returnDigits){
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }


/**
* This method generates a TOTP value for the given
* set of parameters.
*
* @param key: the shared secret, HEX encoded
* @param time: a value that reflects a time
* @param returnDigits: number of digits to return
* @param crypto: the crypto function to use
*
* @return: a numeric String in base 10 that includes
*              {@link truncationDigits} digits
*/

public static String generateTOTP(String key,
      String time,
      String returnDigits,
      String crypto){
  int codeDigits = Integer.decode(returnDigits).intValue();
  String result = null;

  // Using the counter
  // First 8 bytes are for the movingFactor
  // Compliant with base RFC 4226 (HOTP)
  while (time.length() < 16 )
      time = "0" + time;

  // Get the HEX in a Byte[]
//   byte[] msg = ByteBuffer.allocate(8).putLong(time).array();
  byte[] msg = hexStr2Bytes(time);
  byte[] k = hexStr2Bytes(key);

  byte[] hash = hmac_sha(crypto, k, msg);

  // put selected bytes into result int
  int offset = hash[hash.length - 1] & 0xf;

  int binary =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);

  long otp = binary % DIGITS_POWER[codeDigits];

  result = Long.toString(otp);
  while (result.length() < codeDigits) {
      result = "0" + result;
  }
  return result;
    }

    public static String stringToBase64(String str) {

        try{
            String reusult = Base64.getEncoder().encodeToString(str.getBytes("utf-8"));
            return reusult;
        }catch (UnsupportedEncodingException e){
            String msg = "error";
            return msg;
        }
        
        
    }
    

    public static String stringToHexAscii(String value)  
    {  
        StringBuffer sbu = new StringBuffer();  
        char[] chars = value.toCharArray();   
        for (int i = 0; i < chars.length; i++) {  
                sbu.append(Integer.toHexString(Integer.valueOf(chars[i]).intValue()));  

        }  
        return sbu.toString();  
    }  

    public static String asciiToString(String value) {
        StringBuffer sbu = new StringBuffer();  
        char[] chars = value.toCharArray();   
        for (int i = 0; i < chars.length; i++) {  
                try{
                    sbu.append( (char) Integer.parseInt(String.valueOf(chars[i])));
                }  catch(NumberFormatException ex){

                }

        }  
        return sbu.toString();  
    }

    /*
        整体思路：
        总结：TOTP算法对userid和passwd加密，然后post到指定host;
            1.原始字符串转换成ASCII码的数字表示；
            2.ASCII码的数字转换为16进制；
            3.取原子时的时钟戳，去掉时区。在转换时，考虑int和long int转换的小数舍弃情况；
            4.设置30S动态时间口令；
            5.HmacSHA512加密；
            6.返回结果标准化处理(userid:passwd-timebasedResult)；
            7.对标准化结果进行base64编码；
            8.Postman的headers增加内容——Authorization: Basic base64编码标准结果；
            9.Content-Type: application/json;
            10.Body->raw->content:
                {
                    "contact_email": "",
                    "github_url": ""
                }
    */
     public static void main(String[] args) {
        while(true){
        long T0 = 0;
        int X = 30;
        // String steps = "0";
        String seed = "q506169874@gmail.com";
        String postString = "HENNGECHALLENGE003";
        // 通常编码，要将字符串转换编码，然后换成16进制编码；
        // 一般编程里面，没有特殊要求，编码都是十六进制的
        String asciiResult = stringToHexAscii(seed + postString);
        // String asciiResult = "3530363136393837344071712e636f6d48454e4e47454348414c4c454e4745303033";
        // String asciiResult = stringToBase64(seed + postString);
        String stringResult = asciiToString(asciiResult);

        DateFormat df = new SimpleDateFormat("YYYY-MM-dd HH:mm:ss");
        // df.setTimeZone(TimeZone.getTimeZone("JST"));

        // 此处除以1000，是因为float和int转换会丢弃小数位
        // 多数编程语言都有一个缺点，两个整数相除。如果结果是小数，最后得出的结果就是一个整数。
        // 小数位会被丢弃，所以利用这一点，除以30之前，根本不需要做整除的处理。
        // 浮点的长度普遍比整型长。
        // 这个计算结果这样，其实是c语言导致的，有浮点数参与计算，结果才可以为浮点。
        // 数值计算你可以记一个经典例子。1/2=0，1/2.0=0.5，1.0/2=0.5
        int testTime = (int) (System.currentTimeMillis()/1000L);
        int reminderTime =X - (int) (System.currentTimeMillis() / 1000 % X);
        
        long T = (testTime - T0) / X ;
        
        String steps = Long.toHexString(T).toUpperCase();
        System.out.println("除以30后的时间:"+T);
        while (steps.length() < 16) steps = "0" + steps;


        System.out.println(df.format(new Date(System.currentTimeMillis())));
        System.out.println("unix time（正确）:"+testTime);
        System.out.println("unix time2（原始时间）:"+(System.currentTimeMillis()));
        System.out.println("unix time2（Int转型截取数据）:"+(int) (System.currentTimeMillis()));
        System.out.println("Ascii Result:" + asciiResult);
        System.out.println("stringResult:" + stringResult);
        System.out.println("HmacSHA512:"+generateTOTP(asciiResult, steps, "10", "HmacSHA512"));

        String str = seed + ":" +generateTOTP(asciiResult, steps, "10", "HmacSHA512");
        System.out.println("str:" + str);
        String result = stringToBase64(str);

        System.out.println("result:" + "Basic " + result);
        while(reminderTime > 0){
            try {
                
                System.out.print(reminderTime+",");
                Thread.sleep(1000);
                reminderTime--;
            }catch (Exception ex){
                System.out.println("catch a error");
            }

        }
        
    }
}


}