package org.nvotes.trustee

import java.nio.file.Paths
import java.nio.file.Path
import java.nio.file.Files
import java.math.BigInteger
import java.util.UUID

import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._

import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime

/** Writes files for config and statement, with given parameters
 *
 *  GenConfig <name> <bits> <items> <ballotbox> <trustees>
 *
 *  The ballotbox parameter must point to a file containing the
 *  public key of the ballotbox
 *
 *  The trustees parameter must point to a file containing
 *  the concatenation of trustee public keys
 *
 *  The election id is generated automatically with UUID
 *
 *  Example command to run in sbt
 *  > runMain org.nvotes.trustee.GenConfig e1 2048 3 demo/keys/ballotbox.pub.pem demo/keys/trustees.pem
 */
object GenConfig extends App {
  println("generating config with")
  println(s"name: ${args(0)}")
  println(s"bits: ${args(1)}")
  println(s"items: ${args(2)}")
  println(s"ballotbox: ${args(3)}")
  println(s"trustees: ${args(4)}")

  val cfg = makeConfig(args(0), args(1).toInt, args(2).toInt, Paths.get(args(3)), Paths.get(args(4)))
  IO.write(Paths.get("config.json"), cfg.asJson.noSpaces)
  val stmt = Statement.getConfigStatement(cfg)
  IO.write(Paths.get("config.stmt.json"), stmt.asJson.noSpaces)
  println("Wrote config.json and config.stmt.json")

  /** Returns the config object
   *
   *  Throws IllegalArgumentException if
   *  - bits < 16
   *  - there are redundant trustees in the trustees file
   *  - there are less than two trustees in the trustees file
   */
  def makeConfig(name: String, bits: Int, items: Int, ballotbox: Path, trustees: Path): Config = {
    if(bits < 16) {
      throw new IllegalArgumentException(s"bits too small: $bits")
    }
    val group: GStarModSafePrime = GStarModSafePrime.getFirstInstance(bits)
    val modulusStr = group.getModulus.toString
    val generator = group.getDefaultGenerator()
    val generatorStr = generator.convertToString

    val lines = IO.asStringLines(trustees)
    /** lookahead regexp, keeps the delimiter */
    val trusteesStr = lines.mkString("\n").split("(?<=-----END PUBLIC KEY-----)")

    val pks = trusteesStr.map(Crypto.readPublicRsa(_)).toSet
    if(pks.size != trusteesStr.size) {
      throw new IllegalArgumentException(s"Redundant trustees: ${trusteesStr.size} != ${pks.size}")
    }
    if(pks.size < 2) {
      throw new IllegalArgumentException(s"Insufficient trustees: ${pks.size}")
    }

    val ballotboxStr = IO.asString(ballotbox)

    val id = UUID.randomUUID().toString
    Config(id, name, modulusStr, generatorStr, items, ballotboxStr, trusteesStr)
  }
}

object GenAESKey extends App {

}