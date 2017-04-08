package org.nvotes.trustee

import scala.io.Source

import java.net.URI
import java.nio.file.Path
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import java.nio.file.Files

import pureconfig.loadConfig

import ch.bfh.unicrypt.math.algebra.general.classes.FiniteByteArrayElement

object Continuous extends App {
  val trusteeCfg = TrusteeConfig.load

  val board = new Board(trusteeCfg.dataStorePath)
  val section = board.cloneOrSyncSection(trusteeCfg.repoBaseUri, Paths.get("repo"))
  while(true) {
    Thread.sleep(5000)
    Protocol.execute(section, trusteeCfg)
  }
}

case class TrusteeConfigRaw(dataStorePath: Path, repoBaseUri: URI, bootstrapRepoUri: URI,
  publicKey: Path, privateKey:Path, aesKey: Path, peers: Path)

case class TrusteeConfig(dataStorePath: Path, repoBaseUri: URI, bootstrapRepoUri: URI,
  publicKey: RSAPublicKey, privateKey: RSAPrivateKey, aesKey: FiniteByteArrayElement, peers: Seq[RSAPublicKey]) {

   override def toString() = s"TrusteeConfig($dataStorePath $repoBaseUri $bootstrapRepoUri ${peers.length})"
}

object TrusteeConfig {

  def load: TrusteeConfig = {
    val c = loadConfig[TrusteeConfigRaw].right.get
    val publicKey = Crypto.readPublicRsa(c.publicKey)
    val privateKey = Crypto.readPrivateRsa(c.privateKey)
    val lines = Source.fromFile(c.peers.toFile)(StandardCharsets.UTF_8).getLines
    val peersString = lines.mkString("\n").split("-----END PUBLIC KEY-----")
    val peers = peersString.map(Crypto.readPublicRsa(_)).toList
    val aesKey = Crypto.readAESKey(c.aesKey)

    TrusteeConfig(c.dataStorePath, c.repoBaseUri, c.bootstrapRepoUri, publicKey,
      privateKey, aesKey, peers)
  }
}