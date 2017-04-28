package org.nvotes.trustee

import java.nio.file.Paths

import org.scalatest.FlatSpec
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Tests the condition detection functionality
 *
 */
class ConditionSpec extends FlatSpec {

  val files = Set("config.json", "config_1.stmt", "config_1.sig", "1/error")

  "matching expression" should "return true" in {
    val result = Condition.yes("config.json").eval(files)

    assert(result)
  }

  "non-matching expression" should "return false" in {
    val result = Condition.yes("config.json").no("config_1.stmt").no("config_1.sig").eval(files)
    assert(!result)
  }

  "matching expression using negation" should "return true" in {
    val result = Condition.no("1/error").no("2/error").no("3/error").neg.eval(files)

    assert(result)
  }
}