package com.sigurdsoftware.jwt4scalatra

import org.junit.runner.RunWith
import org.specs2.runner.JUnitRunner
import org.scalatra.test.specs2.MutableScalatraSpec
import javax.servlet.http.HttpServletRequest
import org.json4s.Formats
import org.json4s.DefaultFormats
import org.scalatra.ScalatraServlet
import authentikat.jwt.JwtHeader
import authentikat.jwt.JwtClaimsSet
import org.json4s.Extraction
import authentikat.jwt.JsonWebToken

class TestJWTServlet extends ScalatraServlet with JWTSupport{
  get("/"){
    val u = jwtAuth
    u.userid
  }
}

@RunWith(classOf[JUnitRunner])
class JWTAuthSpec extends MutableScalatraSpec {
  implicit val jsonFormats: Formats = DefaultFormats
  addServlet(classOf[TestJWTServlet], "/*")
  "requests" should{
    val authkey = "Authorization"
    val header = JwtHeader("HS256")
    val claimsSet = JwtClaimsSet(Extraction.decompose(JWTClaims(((System.currentTimeMillis/1000)+1000).toString, 1, "tim")))
    val tok = JsonWebToken(header, claimsSet, "secretkeybatterydowntownhorsegirrafe")

    "401 when no auth header" in {
      get("/") {status === 401}
    }
    "401 when bad scheme" in {
      get(uri="/", headers=Map(authkey -> "BadScheme")) {status === 401}
    }
    "403 when good scheme but bad value" in{
      get(uri="/", headers=Map(authkey -> "Bearer Nonsense")) {status === 403}
    }
    "403 when good scheme but blank value" in{
      get(uri="/", headers=Map(authkey -> "Bearer  ")) {status === 403}
    }
    "get user id back with 200 when valid header" in {
      get(uri="/", headers=Map(authkey -> s"Bearer $tok")){
        status === 200 and response.body === "1"
      }
    }
  }
}