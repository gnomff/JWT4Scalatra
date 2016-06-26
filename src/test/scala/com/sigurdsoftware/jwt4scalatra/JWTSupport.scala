package com.sigurdsoftware.jwt4scalatra

import org.scalatra.auth.ScentrySupport
import org.scalatra.ScalatraBase
import org.scalatra.auth.ScentryConfig
import org.json4s._
import org.json4s.jackson.JsonMethods._
import org.json4s.jackson.Serialization
import org.json4s.jackson.Serialization.{read, write}
import authentikat.jwt.JwtClaimsSetJValue
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

case class JWTClaims(exp:String, userid:Long, fbid:String)

trait JWTSupport extends ScentrySupport[JWTClaims] with JWTAuthSupport[JWTClaims]{
  self: ScalatraBase =>
  
  protected val scentryConfig = (new ScentryConfig {}).asInstanceOf[ScentryConfiguration]
  private implicit val jsonFormats: Formats = DefaultFormats
  
  override protected def fromSession = {
    case claimstr: String => parse(claimstr).extract[JWTClaims]
  }

  override protected def toSession = {
    case claim: JWTClaims => write(user)
  }

  override protected def registerAuthStrategies = {
    scentry.register("Bearer", app => new TestJWTAuthStrategy(app))
  }
    
}

class TestJWTAuthStrategy(protected override val app: ScalatraBase)
  extends JWTAuthStrategy[JWTClaims](app) {
  
  override protected def getSecret() = "secretkeybatterydowntownhorsegirrafe"
  
  override protected def validate(claims:JwtClaimsSetJValue)(implicit request: HttpServletRequest, response: HttpServletResponse): Option[JWTClaims] = {
    claims.asSimpleMap.toOption.flatMap{ c=>
      val exp = c.getOrElse("exp", "")
      val fbid = c.getOrElse("fbid", "")
      val userid = c.getOrElse("userid", "")
      if(exp.isEmpty() || fbid.isEmpty() || userid.isEmpty() || exp.toLong < (System.currentTimeMillis/1000)) None
      else Some(JWTClaims(exp, userid.toLong, fbid))
    }
  }

}