/**
 * This file is part of nMix.
 * Copyright (C) 2015-2016-2017  Agora Voting SL <agora@agoravoting.com>

 * nMix is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * nMix is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with nMix.  If not, see <http://www.gnu.org/licenses/>.
**/

package org.nvotes.mix

import scala.io.Source

import java.net.URI
import java.nio.file.Path
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import java.nio.file.Files

import org.slf4j.LoggerFactory

import pureconfig.loadConfig

import ch.bfh.unicrypt.math.algebra.general.classes.FiniteByteArrayElement

/** Run's the trustee protocol against a section of the board
  *
  *  The trustee polls the bulletin board every n seconds
  *  and reactively executes work. This runs indefinitely,
  *  a trustee does not terminate unless an error occurs.
  */
object TrusteeLoop extends App {
  val logger = LoggerFactory.getLogger(TrusteeLoop.getClass)

  if(args.size != 1) {
    logger.error("No target repo argument supplied on command line")
  } else {

    val trusteeCfg = TrusteeConfig.load

    System.setProperty("nmix.git.disable-compression", trusteeCfg.gitNoCompression.toString)
    System.setProperty("nmix.git.remove-lock", trusteeCfg.gitRemoveLock.toString)

    val board = new Board(trusteeCfg.dataStorePath)
    val section = board.cloneOrSyncSection(trusteeCfg.repoBaseUri, Paths.get(args(0)))
    while(true) {
      Thread.sleep(5000)
      Protocol.execute(section, trusteeCfg)
    }
  }
}

/** The trustee configuration as read from the filesystem
  *
  */
case class TrusteeConfigRaw(dataStorePath: Path, repoBaseUri: URI, bootstrapRepoUri: Option[URI],
  publicKey: Path, privateKey:Path, aesKey: Path, peers: Path, offlineSplit: Option[Boolean],
  gitNoCompression: Option[Boolean], gitRemoveLock: Option[Boolean])

/** The trustee configuration, converted to objects
  *
  */
case class TrusteeConfig(dataStorePath: Path, repoBaseUri: URI, bootstrapRepoUri: Option[URI],
  publicKey: RSAPublicKey, privateKey: RSAPrivateKey, aesKey: FiniteByteArrayElement, peers: Seq[RSAPublicKey],
  offlineSplit: Boolean, gitNoCompression: Boolean, gitRemoveLock: Boolean) {

   override def toString() = s"TrusteeConfig($dataStorePath $repoBaseUri $bootstrapRepoUri ${peers.length})"
}

/** Used to load the trustee configuration */
object TrusteeConfig {

  /** Loads the trustee configuration and converts the raw values into objects
   *
   *  Throws exception if
   *  - the configuration is not found in the classpath or set by -Dconfig.file
   *  - the configuration does not parse correctly, according to TrusteeConfigRaw
   *  - the peers file does not exist or does not parse correctly into a set of RSA public keys
   *  - the aes key file does not exist or does not parse correctly into an object
   */
  def load: TrusteeConfig = {
    val c = loadConfig[TrusteeConfigRaw].right.get
    val publicKey = Crypto.readPublicRsa(c.publicKey)
    val privateKey = Crypto.readPrivateRsa(c.privateKey)
    val lines = Source.fromFile(c.peers.toFile)(StandardCharsets.UTF_8).getLines
    val peersString = lines.mkString("\n").split("-----END PUBLIC KEY-----")
    val peers = peersString.map(Crypto.readPublicRsa(_)).toList
    val aesKey = Crypto.readAESKey(c.aesKey)
    val offline = c.offlineSplit.getOrElse(false)
    val gitNoCompression = c.gitNoCompression.getOrElse(false)
    val gitRemoveLock = c.gitRemoveLock.getOrElse(true)

    TrusteeConfig(c.dataStorePath, c.repoBaseUri, c.bootstrapRepoUri, publicKey,
      privateKey, aesKey, peers, offline, gitNoCompression, gitRemoveLock)
  }
}