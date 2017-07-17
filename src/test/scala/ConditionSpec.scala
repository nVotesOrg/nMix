package org.nvotes.mix

import java.nio.file.Paths

import org.scalatest.FlatSpec
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Tests the condition detection functionality
 *
 */
class ConditionSpec extends FlatSpec {

  val files = Set("a", "b", "c", "d")

  "matching expression" should "return true" in {
    assert(Condition.yes("a").eval(files))
    assert(Condition.no("z").eval(files))
  }

  "non-matching expression" should "return false" in {
    assert(!Condition.yes("a").no("b").no("c").eval(files))
    assert(!Condition.yes("z").eval(files))
  }

  "expression using demorgan" should "works correctly" in {
    // demorgan:
    //  !(!a and !b and !c) == (a or b or c)

    // at least one is true
    var result = Condition.no("d").no("x").no("y").neg.eval(files)
    assert(result)

    // none of these are true
    result = Condition.no("x").no("y").no("z").neg.eval(files)
    assert(!result)
  }

  "expression with and composition" should "works correctly" in {
    val one = Condition.yes("a").yes("b")
    val two = Condition.yes("c").yes("d")

    assert(one.and(two).eval(files))
  }

  "expression with literal and composition" should "works correctly" in {
    val one = Condition.yes("a").yes("b")

    assert(one.and("b").and("c").eval(files))
    assert(one.and("b").andNot("x").eval(files))
  }
}