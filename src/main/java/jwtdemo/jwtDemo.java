package jwtdemo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/*
 * 使用 JWT框架生成token 和检验token是否有效
 */

/**
 *
 * @author yingying
 */
public class jwtDemo
{
  private final String CLEENT_ID = "12345678";//应用id
  private final String CLEENT_SECRET = "clientSecret12345678";
  
  /**
   * 生成token
   * @param outerUserID 系统管理员id
   * @param account 系统管理员账号
   * @return token
   */
  public String getToken ( Long outerUserID, String account )
  {
    String token = null;
    try
    {
      //生成token
      Algorithm algorithm = Algorithm.HMAC256( CLEENT_SECRET );

      Calendar calendar = Calendar.getInstance();
      calendar.add( Calendar.MINUTE, 30 ); //过期时间30分钟
      Date date = calendar.getTime();

      token = JWT.create()
          .withIssuer( CLEENT_ID )//请求方
          .withExpiresAt( date )//过期时间
          .withClaim("out_user_id", outerUserID )//系统管理员id
          .withClaim("account", account )
          .sign( algorithm );
      
    } 
    
    catch ( UnsupportedEncodingException | JWTCreationException exception ){
        //UTF-8 encoding not supported/Invalid Signing configuration / Couldn't convert Claims.
    }
    return token;
  }
  
  /**
   * 检查token是否可用
   * @param token 
   * @return  是否可用
   */
  public boolean validate ( String token )
  {
    boolean flag = false;
    try
    {
      //检查token
      Algorithm algorithm = Algorithm.HMAC256( String.valueOf( CLEENT_SECRET ) );
      JWTVerifier verifier = JWT.require( algorithm )
        .build(); 
      DecodedJWT jwt = verifier.verify( token );
      flag = true;
    } 
    catch ( UnsupportedEncodingException | JWTVerificationException exception){
      //UTF-8 encoding not supported
    }
    
    return flag;
  }
  
  /**
   * 获取token的信息
   * @param token
   * @return 
   */
  public Map<String, Object> getTokenInfo( String token )
  {
    Map<String, Object> tokenMap = new HashMap<>();
    try
    {
      DecodedJWT jwt = JWT.decode( token );
      
      String algorithm = jwt.getAlgorithm();
      String type = jwt.getType();
      Long clientId = Long.valueOf( jwt.getIssuer() ); //请求方
      Date expiresAt = jwt.getExpiresAt(); //过期时间
      Long outerUserID = jwt.getClaim( "out_user_id" ).asLong();//系统管理员id
      String account = jwt.getClaim( "account" ).asString();//管理员账号
      
      tokenMap.put( "algorithm", algorithm );
      tokenMap.put( "type", type );
      tokenMap.put( "clientId", clientId );
      tokenMap.put( "expiresAt", expiresAt );
      tokenMap.put( "outerUserID", outerUserID );
      tokenMap.put( "account", account );
    } 
    catch( JWTDecodeException e )
    {
      //Invalid token
    }
    return tokenMap;
  }
  
  
  public static void main( String[] args )
  {
    //创建token
    Long outerUserId = 123456789L;
    String account = "gsj";
    jwtDemo jetTest = new jwtDemo();
    String token = jetTest.getToken( outerUserId, account );
    //输出token的信息
    if( jetTest.validate( token ) )
    {
      Map<String, Object> tokenMap = jetTest.getTokenInfo( token );
      tokenMap.entrySet().forEach((Map.Entry<String, Object> entry) ->
      {
        String key = entry.getKey();
        Object value = entry.getValue();
        System.out.println( key + ": " + value );
      });
    }
  }
}
