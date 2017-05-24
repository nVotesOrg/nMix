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
import java.io.FileOutputStream
import java.io.BufferedOutputStream
import java.io.BufferedWriter
import java.io.BufferedReader
import java.io.OutputStreamWriter
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.io.InputStream
import sun.misc.IOUtils
import java.security.MessageDigest
import java.security.DigestOutputStream
import java.security.DigestInputStream
import javax.xml.bind.DatatypeConverter


import scala.collection.mutable.ListBuffer
import util.control.Breaks._
import scala.io.Source
import scala.collection.JavaConverters._

import org.nvotes.libmix._


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

    breakable { while(true) {
        nRead = input.read(data, 0, data.length)
        if(nRead == -1) scala.util.control.Breaks.break
        buffer.write(data, 0, nRead)
      }
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

  /** Writes the given content byte array to a temp file */
  def writeTemp(content: List[String]): Path = {
    val tmp = Files.createTempFile("trustee", ".tmp")
    Files.write(tmp, content.asJava, StandardCharsets.UTF_8)
  }

  def readDecryption(stream: InputStream): (PartialDecryptionDTO, String) = {
    val reader = new HashingReader(stream)

    val sigmaProof = readSigmaProof(reader)
    val decryptions = getLines(reader)
    val ret = PartialDecryptionDTO(decryptions, sigmaProof)

    val hash = reader.close()

    (ret, hash)
  }

  def readSigmaProof(reader: HashingReader): SigmaProofDTO = {
    val commitment = reader.readLine()
    val challenge = reader.readLine()
    val response = reader.readLine()

    SigmaProofDTO(commitment, challenge, response)
  }

  def writeDecryptionTemp(data: PartialDecryptionDTO): (Path, String) = {
    val tmp = Files.createTempFile("trustee", ".tmp")
    val outStream = new FileOutputStream(tmp.toFile)
    val writer = new HashingWriter(outStream)

    writeSigmaProof(data.proofDTO, writer)
    data.partialDecryptions.foreach { p =>
      writer.write(p)
      writer.newLine()
    }
    // separator
    writer.newLine()

    val hash = writer.close()

    (tmp, hash)
  }

  def writeSigmaProof(data: SigmaProofDTO, writer: HashingWriter): Unit = {
    writer.write(data.commitment)
    writer.newLine()
    writer.write(data.challenge)
    writer.newLine()
    writer.write(data.response)
    writer.newLine()
  }

  def readPlaintexts(stream: InputStream): (Plaintexts, String) = {
    val reader = new HashingReader(stream)

    val plaintexts = getLines(reader)
    val ret = Plaintexts(plaintexts)

    val hash = reader.close()

    (ret, hash)
  }

   def writePlaintextsTemp(data: Plaintexts): (Path, String) = {
    val tmp = Files.createTempFile("trustee", ".tmp")
    val outStream = new FileOutputStream(tmp.toFile)
    val writer = new HashingWriter(outStream)

    data.plaintexts.foreach { p =>
      writer.write(p)
      writer.newLine()
    }
    // separator
    writer.newLine()

    val hash = writer.close()

    (tmp, hash)
  }

  def readShuffleResult(stream: InputStream): (ShuffleResultDTO, String) = {
    val reader = new HashingReader(stream)

    val shuffleProof = readShuffleProof(reader)
    val votes = getLines(reader)
    val ret = ShuffleResultDTO(shuffleProof, votes)

    val hash = reader.close()

    (ret, hash)
  }

  def readShuffleProof(reader: HashingReader): ShuffleProofDTO = {
    val mix = readMixProof(reader)
    val permutation = readPermutationProof(reader)
    val pCommitment = reader.readLine()
    ShuffleProofDTO(mix, permutation, pCommitment)
  }

  def readPermutationProof(reader: HashingReader): PermutationProofDTO = {
    val commitment = reader.readLine()
    val challenge = reader.readLine()
    val response = reader.readLine()
    val bCommitments = getLines(reader)
    val eValues = getLines(reader)

    PermutationProofDTO(commitment, challenge, response, bCommitments, eValues)
  }

  def readMixProof(reader: HashingReader): MixProofDTO = {
    val commitment = reader.readLine()
    val challenge = reader.readLine()
    val response = reader.readLine()
    val eValues = getLines(reader)

    MixProofDTO(commitment, challenge, response, eValues)
  }

  def writeShuffleResultTemp(data: ShuffleResultDTO): (Path, String) = {
    val tmp = Files.createTempFile("trustee", ".tmp")
    val outStream = new FileOutputStream(tmp.toFile)
    val writer = new HashingWriter(outStream)

    writeShuffleProof(data.shuffleProof, writer)
    data.votes.foreach { v =>
      writer.write(v)
      writer.newLine()
    }
    // separator
    writer.newLine()

    val hash = writer.close()

    (tmp, hash)
  }

  def writeShuffleProof(data: ShuffleProofDTO, writer: HashingWriter): Unit = {
    writeMixProof(data.mixProof, writer)
    writePermutationProof(data.permutationProof, writer)
    writer.write(data.permutationCommitment)
    writer.newLine()
  }

  def writePermutationProof(data: PermutationProofDTO, writer: HashingWriter): Unit = {
    writer.write(data.commitment)
    writer.newLine()
    writer.write(data.challenge)
    writer.newLine()
    writer.write(data.response)
    writer.newLine()

    data.bridgingCommitments.foreach { b =>
      writer.write(b)
      writer.newLine()
    }
    // separator
    writer.newLine()
    data.eValues.foreach { e =>
      writer.write(e)
      writer.newLine()
    }
    // separator
    writer.newLine()
  }

  def writeMixProof(data: MixProofDTO, writer: HashingWriter): Unit = {
    writer.write(data.commitment)
    writer.newLine()
    writer.write(data.challenge)
    writer.newLine()
    writer.write(data.response)
    writer.newLine()
    data.eValues.foreach { e =>
      writer.write(e)
      writer.newLine()
    }
    // separator
    writer.newLine()
  }

  /** Helper to readlines from a HashingReader
   *
   *  Uses an empty newline as a terminator of the sequence
   */
  private def getLines(reader: HashingReader) = {
    val ret = ListBuffer[String]()
    breakable {
      while(true) {
        val line = reader.readLine()
        if(line == null || line == "") break
        ret += line
      }
    }

    ret
  }
}

object HashingWriter {
  val NEWLINE = "\n"
}
class HashingWriter(out: OutputStream) {
  val sha = MessageDigest.getInstance("SHA-512")
  val dou = new DigestOutputStream(out, sha)
  val writer = new BufferedWriter(new OutputStreamWriter(dou,StandardCharsets.UTF_8), 131072)

  def write(str: String): Unit = writer.write(str)
  def newLine(): Unit = writer.write(HashingWriter.NEWLINE)
  def close(): String = {
    writer.close()
    dou.close()
    DatatypeConverter.printHexBinary(sha.digest())
  }
}
class HashingReader(in: InputStream) {
  val sha = MessageDigest.getInstance("SHA-512")
  val din = new DigestInputStream(in, sha)
  val reader = new BufferedReader(new InputStreamReader(din, StandardCharsets.UTF_8), 131072)

  def readLine(): String = reader.readLine()
  def close(): String = {
    reader.close()
    din.close()
    DatatypeConverter.printHexBinary(sha.digest())
  }
}