package com.sigurdsoftware.jwt4scalatra

import org.scalatra.auth.{ ScentrySupport, ScentryStrategy }
import javax.servlet.http.{ HttpServletResponse, HttpServletRequest }
import org.scalatra.ScalatraBase
import org.scalatra.Unauthorized
import org.scalatra.Forbidden
import org.scalatra.BadRequest
import authentikat.jwt.JsonWebToken
import authentikat.jwt.JwtClaimsSetJValue



/**
 * Provides a hook for basic JWT support
 */
trait JWTAuthSupport[T <: AnyRef] { self: (ScalatraBase with ScentrySupport[T]) =>
  import JWTAuthStrategy._
  
  /**
   * If we don't have an Authorization header, send a challenge.
   * If we have an Authorization header, but it is the wrong scheme, send a challenge.
   * @return T The user claims
   */
  protected def jwtAuth()(implicit request: HttpServletRequest, response: HttpServletResponse):T = {
    if(!isAuthStrValid(request)) halt(status=401, headers=challengeheader)
    scentry.authenticate(scheme).getOrElse(halt(Forbidden()))
  }

}

/**
 * Companion object for parsing the Auth header
 */
object JWTAuthStrategy {

  val authorizationKey = "Authorization"
  val scheme = "Bearer"
  val challengeheader = Map("WWW-Authenticate" -> scheme)
  
  implicit def request2JWTAuthRequest(r: HttpServletRequest):JWTAuthRequest = new JWTAuthRequest(r)
  
  def isAuthStrValid(r:JWTAuthRequest) = r.hasAuth && r.isBearerAuth
  
  class JWTAuthRequest(r: HttpServletRequest) {
    private val jwtHeader = Option(r.getHeader(authorizationKey))
    private val jwtToken = jwtHeader.flatMap(_.split(" ") match {
      case Array(x, y, _*) => Some((x, y))
      case Array(x) => Some((x,""))
      case _ => None
    })
    val isBearerAuth = (jwtToken.map{case (h,v) => h == "Bearer"}).getOrElse(false)
    val hasAuth = jwtHeader.isDefined
    val getJWTToken = jwtToken.map{case (h, v) => v}
  }
}

/**
 * This auth strategy uses JWT
 * Override the validate function for your own claims object
 * Override the getSecret function for your own secret 
 */
abstract class JWTAuthStrategy[T <: AnyRef](protected val app: ScalatraBase)
  extends ScentryStrategy[T] {

  import JWTAuthStrategy._
  
  /*
   * Child class must provide a secret
   */
  protected def getSecret:String
  
  /*
   * Only execute this auth strategy if we have Authorization: Bearer <token>
   */
  override def isValid(implicit request: HttpServletRequest) = isAuthStrValid(request)
  
  /*
   * Run the authenticator
   */
  def authenticate()(implicit request: HttpServletRequest, response: HttpServletResponse) ={
    //we checked for a JWT token earlier in isValid
    request.getJWTToken.flatMap{ t =>
      println(s"checking if $t is valid")
      println(s"secret is $getSecret")
      //check the signature
      if(JsonWebToken.validate(t, getSecret)){
        println(s"sweet it was valid")
        //extract the claims
        val claims = t match {
            case JsonWebToken(header, claimsSet, signature) =>
              Some(claimsSet)
            case _ =>None
        }
        println(claims)
        validate(claims.getOrElse(app.halt(BadRequest("Unable to parse JWT Header"))))
      } else None
    }
  }
    
  /*
   * Child class must provide a validate function. None means validation failed -
   * for example if the token has expired.
   */
  protected def validate(claims:JwtClaimsSetJValue)
      (implicit request: HttpServletRequest, response: HttpServletResponse): Option[T]


}