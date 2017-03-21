package org.nvotes.trustee

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**	A condition that is satisfied or not depending on a provided set of file names.
 *
 *	Conditions are evaluated against a set of strings which represent
 *  existing files in a board section. A Condition defines a limited
 *  boolean expression in terms of what files exist and do not exist.
 *  Conditions are one of the two elements of protocol rules. When a condition
 *  evaluates to true, its associated Action is executed.
 *
 *	The expressiveness of Conditions is limited to what is necessary
 *  for the protocol, they are _not_ general logical expressions.
 */
sealed trait Cond {

	/** Returns true if the condition is met by the input set */
	def eval(files: Set[String]): Boolean

	/** Returns the logical conjunction of this Condition and the one provided */
	def and(other: Condition) = {
		JointCondition(this, other)
	}
	/** Returns true if this condition is true and the provided file exists */
	def and(file: String) = {
		JointCondition(this, Condition.yes(file))
	}
	/** Returns true if this condition is true and the provided file does not exist */
	def andNot(file: String) = {
		JointCondition(this, Condition.no(file))
	}
}

/**	Condition implementation
 *
 *  Terms of the boolean expression are (String, Boolean) pairs, where the Boolean
 *  encodes whether the given file (String) should exist or not.
 *
 *	Conditions can be chained together, using efficient List
 *  prepending of terms to construct logical conjunctions
 *
 *  Additionally, a Condition can be globally negated. Among other things,
 *  this allows encoding Or expressions via De Morgan's law
 *
 */
case class Condition(terms: List[(String, Boolean)], name: String = "condition", negate: Boolean = false) extends Cond {
	val logger = LoggerFactory.getLogger(classOf[Condition])

	/** Returns the result of evaluating the condition against the input Set */
	// FIXME consider caching here as an optimisation
	def eval(files: Set[String]): Boolean = {
		val result = ev(files)
		result != negate
	}

	/** Returns the result of adding the provided positive term to this Condition */
	def yes(file: String) = {
		copy((file, true) :: terms)
	}

	/** Returns the result of adding the provided negative term to this Condition */
	def no(file: String) = {
		copy((file, false) :: terms)
	}

	/** Returns the result of globally negating this Condition */
	def neg = {
		copy(negate = true)
	}

	/** Helper method to evaluate */
	private def ev(files: Set[String]): Boolean = {
		terms.foreach { case(file, b) =>
			val result = files.contains(file)
			if(result != b) return false
		}

		true
	}
}

/** Factory methods to construct Conditions. */
object Condition {
	def yes(file: String) = Condition(List((file, true)))
	def no(file: String) = Condition(List((file, false)))
	def empty() = Condition(List[(String, Boolean)]())
}

/**	A composite Condition, currently implements only conjunction.
 *
 *  Evaluates to true only if all composing Conditions evaluate
 *  to true.
 */
case class JointCondition(conditions: Cond*) extends Cond {
	def eval(files: Set[String]): Boolean = {
		conditions.foreach{ condition =>
			val result = condition.eval(files)
			if(!result) return false
		}
		true
	}
}