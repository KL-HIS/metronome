package dcos.metronome
package api

import scala.concurrent.duration.Duration

trait ApiConfig {

  def leaderProxyTimeout: Duration

  def hostname: String
  def effectivePort: Int
  def hostnameWithPort: String

  def basicAuthCreds: Option[(String,String)]
}
