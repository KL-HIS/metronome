package dcos.metronome.api.v1

import akka.util.ByteString
import com.google.common.io.BaseEncoding
import dcos.metronome.api.ApiConfig
import org.slf4j.LoggerFactory
import play.api.libs.streams.Accumulator
import play.api.mvc._

class BasicAuthFilter(config: ApiConfig)
  extends EssentialFilter
    with Results {

  private val log = LoggerFactory.getLogger(getClass)

  private lazy val unauthRoutes = Set("/ping", "/leader", "/favicon.ico")
  private lazy val unauthResult = Unauthorized.withHeaders(("WWW-Authenticate", "Basic realm=\"Metronome\""))

  override def apply(next: EssentialAction): EssentialAction =
    new EssentialAction {
      override def apply(request: RequestHeader): Accumulator[ByteString, Result] = {
        if (config.basicAuthCreds.isEmpty || dontNeedAuth(request)) {
          return next(request)
        }

        val expectedCreds = config.basicAuthCreds.get

        request.headers.get("authorization").flatMap(decodeBasicAuth) match {
          case Some((user, pass)) =>
            if (user == expectedCreds._1 && pass == expectedCreds._2) {
              return next(request)
            }
          case _ => ;
        }
        logFailedAttempt(request)
        Accumulator.done(unauthResult)
      }
    }

  private def getUserIPAddress(request: RequestHeader): String = {
    request.headers.get("x-forwarded-for").getOrElse(request.remoteAddress)
  }

  private def logFailedAttempt(requestHeader: RequestHeader): Unit = {
    log.warn(s"IP address ${getUserIPAddress(requestHeader)} failed to authenticate, " +
      s"requested uri: ${requestHeader.uri}")
  }

  private def decodeBasicAuth(auth: String): Option[(String, String)] = {
    val basicSt = "basic "
    if (auth.length() < basicSt.length()) {
      return None
    }
    val basicReqSt = auth.substring(0, basicSt.length())
    if (basicReqSt.toLowerCase() != basicSt) {
      return None
    }
    val basicAuthSt = auth.replaceFirst(basicReqSt, "")

    val decodedAuthSt = new String(BaseEncoding.base64().decode(basicAuthSt), "UTF-8")
    val usernamePassword = decodedAuthSt.split(":")
    if (usernamePassword.length >= 2) {
      // account for ":" in passwords
      return Some((usernamePassword(0), usernamePassword.splitAt(1)._2.mkString))
    }
    None
  }

  private def dontNeedAuth(request: RequestHeader): Boolean = {
    unauthRoutes.contains(request.path)
  }

}
