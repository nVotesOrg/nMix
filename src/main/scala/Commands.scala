package org.nvotes.trustee

import java.nio.file.Paths
import java.nio.file.Path
import java.nio.file.Files
import java.math.BigInteger
import java.util.UUID

import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._

import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime

object GenConfig extends App {
  println("generating config with")
  println(s"name: ${args(0)}")
  println(s"bits: ${args(1)}")
  println(s"items: ${args(2)}")
  println(s"ballotbox: ${args(3)}")
  println(s"trustees: ${args(4)}")

  val cfg = makeConfig(args(0), args(1).toInt, args(2).toInt, Paths.get(args(3)), Paths.get(args(4)))
  println(cfg.asJson.noSpaces)
  val stmt = Statement.getConfigStatement(cfg)
  println(stmt.asJson.noSpaces)

  def makeConfig(name: String, bits: Int, items: Int, ballotbox: Path, trustees: Path): Config = {
    val group: GStarModSafePrime = GStarModSafePrime.getFirstInstance(bits)
    val modulusStr = group.getModulus.toString
    val generator = group.getDefaultGenerator()
    val generatorStr = generator.convertToString

    val lines = IO.asStringLines(trustees)
    // lookahead regexp, keeps the delimiter
    val trusteesStr = lines.mkString("\n").split("(?<=-----END PUBLIC KEY-----)")

    val ballotboxStr = IO.asString(ballotbox)

    val id = UUID.randomUUID().toString
    Config(id, name, modulusStr, generatorStr, items, ballotboxStr, trusteesStr)
  }

  def generateRandomAESKey() = {

  }
}
