package org.nvotes.trustee

import com.typesafe.config.ConfigFactory.parseString
import pureconfig.loadConfig
import scala.io.Source

import java.net.URI
import java.nio.file.Path
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.nio.charset.StandardCharsets
import ch.bfh.unicrypt.math.algebra.general.classes.FiniteByteArrayElement

import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._

import java.nio.file.Paths
import java.nio.file.Files

object Continuous extends App {
  val trusteeCfg = TrusteeConfig.load

  val board = new Board(trusteeCfg.dataStorePath)
  val section = board.cloneOrSyncSection(trusteeCfg.repoBaseUri, Paths.get("repo"))
  while(true) {
    Thread.sleep(5000)
    Protocol.execute(section, trusteeCfg)
  }
}

object FullCycle extends App {

  val trusteeCfg = TrusteeConfig.load
  val trusteeCfg2 = trusteeCfg.copy(publicKey=Crypto.readPublicRsa(Paths.get("keys/auth2_rsa.pub.pem")),
    privateKey=Crypto.readPrivateRsa(Paths.get("keys/auth2_rsa.pem")))

  val board = new Board(trusteeCfg.dataStorePath)
  val section = board.cloneOrSyncSection(trusteeCfg.repoBaseUri, Paths.get("repo"))

  // val cfg = section.getConfig.get
  // println(Crypto.sha512(cfg))

  // sign configs
  Protocol.execute(section, trusteeCfg)
  Protocol.execute(section, trusteeCfg2)

  // add shares
  Protocol.execute(section, trusteeCfg)
  Protocol.execute(section, trusteeCfg2)

  // gen and sign public key
  Protocol.execute(section, trusteeCfg)
  Protocol.execute(section, trusteeCfg2)

  // add ballots
  import org.nvotes.mix._
  import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime

  val configString = section.getConfig.get
  val configHash = Crypto.sha512(configString)
  val config = decode[Config](configString).right.get

  object KM extends KeyMaker
  object MX extends Mixer

  val group = GStarModSafePrime.getFirstInstance(config.bits)
  val generator = group.getDefaultGenerator()
  val cSettings = CryptoSettings(group, generator)
  val votes = (1 to config.items).map { item =>
    val publicKey = section.getPublicKey(item).get
    val pk = Util.getPublicKeyFromString(publicKey, generator)

    val ballots = Util.encryptVotes(List(1, 3, 5, 7, 11), cSettings, pk).map(_.convertToString).toArray
    // val ballots = Util.randomVotes(5, generator, pk).map(_.convertToString).toArray

    val ballotsString = Ballots(ballots).asJson.noSpaces
    val ballotHash = Crypto.sha512(ballotsString)
    val statement = Statement.getBallotsStatement(ballotHash, configHash, item)
    val signature = statement.sign(Crypto.readPrivateRsa(Paths.get("keys/ballotbox.pem")))

    val file1 = IO.writeTemp(ballotsString)
    val file2 = IO.writeTemp(statement.asJson.noSpaces)
    val file3 = IO.writeTemp(signature)

    section.addBallots(file1, file2, file3, item)
  }

  // mixes
  Protocol.execute(section, trusteeCfg)
  Protocol.execute(section, trusteeCfg2)

  // verify mixes
  Protocol.execute(section, trusteeCfg)
  Protocol.execute(section, trusteeCfg2)

  // add decryptions
  Protocol.execute(section, trusteeCfg)
  Protocol.execute(section, trusteeCfg2)

  // plaintexts
  Protocol.execute(section, trusteeCfg)
  Protocol.execute(section, trusteeCfg2)
}

object OneRun extends App {

  val trusteeCfg = TrusteeConfig.load
  val board = new Board(trusteeCfg.dataStorePath)
  val section = board.cloneOrSyncSection(trusteeCfg.repoBaseUri, Paths.get("repo"))
  // val cfg = section.getConfig.get
  // println(Crypto.sha512(cfg))
  Protocol.execute(section, trusteeCfg)
}

object BallotboxAdd extends App {
  import org.nvotes.mix._
  import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime

  val totalVotes = args(0).toInt
  println(s"BallotboxAdd votes = $totalVotes")
  val trusteeCfg = TrusteeConfig.load

  val board = new Board(trusteeCfg.dataStorePath)
  val section = board.cloneOrSyncSection(trusteeCfg.repoBaseUri, Paths.get("repo"))
  val configString = section.getConfig.get
  val configHash = Crypto.sha512(configString)
  val config = decode[Config](configString).right.get

  val group = GStarModSafePrime.getFirstInstance(config.bits)
  val generator = group.getDefaultGenerator()
  val cSettings = CryptoSettings(group, generator)
  val votes = (1 to config.items).map { item =>
    val publicKey = section.getPublicKey(item).get
    val pk = Util.getPublicKeyFromString(publicKey, generator)

    val ballots = Util.getRandomVotesStr(totalVotes, generator, pk).toArray
    // val ballots = Util.encryptVotes(List(1, 3, 5, 7, 11), cSettings, pk).map(_.convertToString).toArray

    val ballotsString = Ballots(ballots).asJson.noSpaces
    val ballotHash = Crypto.sha512(ballotsString)
    val statement = Statement.getBallotsStatement(ballotHash, configHash, item)
    val signature = statement.sign(Crypto.readPrivateRsa(Paths.get("keys/ballotbox.pem")))

    val file1 = IO.writeTemp(ballotsString)
    val file2 = IO.writeTemp(statement.asJson.noSpaces)
    val file3 = IO.writeTemp(signature)

    section.addBallots(file1, file2, file3, item)
  }
}

case class TrusteeConfigRaw(dataStorePath: Path, repoBaseUri: URI, bootstrapRepoUri: URI,
  publicKey: Path, privateKey:Path, aesKey: Path, peers: Path)

case class TrusteeConfig(dataStorePath: Path, repoBaseUri: URI, bootstrapRepoUri: URI,
  publicKey: RSAPublicKey, privateKey: RSAPrivateKey, aesKey: FiniteByteArrayElement, peers: Seq[RSAPublicKey]) {

   override def toString() = s"TrusteeConfig($dataStorePath $repoBaseUri $bootstrapRepoUri ${peers.length})"
}

object PushTest extends App {
  val gitRepo = GitRepo.clone(new URI(args(0)), Paths.get("test"))
  Files.copy(Paths.get("bigfile"), Paths.get("bigfile"))
  gitRepo.send("test", "bigfile")
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