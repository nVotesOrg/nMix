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

import java.nio.file.Path
import java.nio.file.Files
import java.nio.charset.StandardCharsets
import scala.io.Source
import java.io.InputStream
import sun.misc.IOUtils


/** Utility IO methods
 *
 *  FIXME These methods have not been checked for efficiency
 *  with very large files.
 */
object IO {

  /** Returns the contents of the given file as a String, assumes UTF-8 */
  def asString(path: Path): String = {
    Source.fromFile(path.toFile)(StandardCharsets.UTF_8).mkString
  }

  /** Returns the contents of the given file as an array of Strings, assumes UTF-8 */
  def asStringLines(path: Path): Array[String] = {
    Source.fromFile(path.toFile)(StandardCharsets.UTF_8).getLines.toArray
  }

  /** Returns the contents of the given file as a String, assumes UTF-8 */
  def asString(input: InputStream): String = {
    val ret = Source.fromInputStream(input)(scala.io.Codec.UTF8).mkString
    input.close
    ret
  }

  /** Returns the contents of the given file a a byte array
   *
   *  FIXME Uses unsupported sun.misc.IOUtils, replace when java9 is available:
   *  http://download.java.net/java/jdk9/docs/api/java/io/InputStream.html#readAllBytes--
   */
  def asBytes(input: InputStream): Array[Byte] = {
    val ret = IOUtils.readFully(input, -1, true)
    input.close
    ret
  }

  /** Returns the contents of the given file a a byte array */
  def asBytes(path: Path): Array[Byte] = {
    Files.readAllBytes(path)
  }

  /** Returns the contents of the given file a a byte array
   *
   *  Alternative implementation to above
   */
  def asBytes2(input: InputStream): Array[Byte] = {
    val buffer = new java.io.ByteArrayOutputStream()

    var nRead: Int = 0
    val data = new Array[Byte](16384)

    while(true) {
      nRead = input.read(data, 0, data.length)
      if(nRead == -1) scala.util.control.Breaks.break
      buffer.write(data, 0, nRead)
    }

    buffer.flush()
    buffer.toByteArray()
  }

  /** Writes the given content String to file, in UTF-8 */
  def write(path: Path, content: String): Path = {
    write(path, content.getBytes(StandardCharsets.UTF_8))
  }

  /** Writes the given content byte array to file */
  def write(path: Path, content: Array[Byte]): Path = {
    Files.write(path, content)
  }

  /** Writes the given content String to a temp file, in UTF-8 */
  def writeTemp(content: String): Path = {
    writeTemp(content.getBytes(StandardCharsets.UTF_8))
  }

  /** Writes the given content byte array to a temp file */
  def writeTemp(content: Array[Byte]): Path = {
    val tmp = Files.createTempFile("trustee", ".tmp")
    Files.write(tmp, content)
  }
}