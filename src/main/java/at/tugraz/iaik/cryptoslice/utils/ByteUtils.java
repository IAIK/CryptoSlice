/* Copyright (c) 2003, 2004 The Regents of the University of Michigan, Trustees of Indiana University,
 *                  Board of Trustees of the Leland Stanford, Jr., University, and The MIT Corporation
 *
 * Licensed under the Educational Community License Version 1.0 (the "License");
 * By obtaining, using and/or copying this Original Work, you agree that you have read,
 * understand, and will comply with the terms and conditions of the Educational Community License.
 * You may obtain a copy of the License at:
 *
 *      http://cvs.sakaiproject.org/licenses/license_1_0.html
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */
package at.tugraz.iaik.cryptoslice.utils;

import org.apache.http.util.ByteArrayBuffer;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.util.Arrays;

public class ByteUtils {
  /**
   * Does this byte array begin with match array content?
   *
   * @param source Byte array to examine
   * @param match Byte array to locate in <code>source</code>
   * @return true If the starting bytes are equal
   */
  public static boolean startsWith(byte[] source, byte[] match) {
    return startsWith(source, 0, match);
  }

  /**
   * Does this byte array begin with match array content? The check is NOT case sensitive!
   *
   * @param source Byte array to examine
   * @param offset An offset into the <code>source</code> array
   * @param match Byte array to locate in <code>source</code>
   * @return true If the starting bytes are equal
   */
  public static boolean startsWith(byte[] source, int offset, byte[] match) {
    if (match.length > (source.length - offset))
      return false;

    for (int i = 0; i < match.length; i++) {
      if (source[offset + i] != match[i]) {
        // ignore cases
        if (source[offset + i] >= 65 && source[offset + i] <= 90
            && source[offset + i] + 32 == match[i]) {
          continue;
        } else if (source[offset + i] >= 97
            && source[offset + i] <= 122
            && source[offset + i] - 32 == match[i]) {
          continue;
        } else return false;
      }
    }

    return true;
  }

  /**
   * Read a line from an inputstream into a byte buffer. A line might end with a LF or an CRLF. CR's are accepted
   * inside a line and are not understood as a beginning new line. This should work therefore on
   * Mac OS X, Unix, Linux and Windows.
   *
   * See http://en.wikipedia.org/wiki/Newline for more.
   *
   * @param in the inputstream
   * @return the buffer where read bytes are appended, this buffer will not contain any CR's or or CRLF's at the end of
   * the array. Null is returned if EOF is reached.
   * @throws IOException if something is wrong with the stream or the maxSize is reached.
   */
  public static byte[] parseLine(BufferedInputStream in) throws IOException {
    ByteArrayBuffer bab = new ByteArrayBuffer(512);
    int b;
    while (true) {
      b = in.read();
      if (b == -1) {
        if (bab.isEmpty()) {
          // we have nothing read yet and could nothing read, we will therefore return 'null' as this indicates EOF.
          return null;
        } else {
          // return what we got so far
          return bab.toByteArray();
        }
      }

      // CRLF case
      if (b == '\r') { // check if we find a \n
        int next = in.read();
        if (next == -1) {
          // EOF; return what we got
          return bab.toByteArray();
        } else if (next == '\n') { // we did
          in.mark(-1); // rest mark
          return bab.toByteArray(); // return the line without CRLF
        } else {
          // found no CRLF but only a CR and some other byte, so we need to add both to the buffer and proceed
          bab.append('\r');
          bab.append(b);
        }
      }
      // LF case
      else if (b == '\n') { // we found a LF and therefore the end of a line
        return bab.toByteArray();
      }
      else { // we just found a byte which is happily appended
        bab.append(b);
      }
    }
  }

  /**
   * Return a new byte array containing a sub-portion of the source array
   *
   * @param srcBegin The beginning index (inclusive)
   * @param srcEnd The ending index (exclusive)
   * @return The new, populated byte array
   */
  public static byte[] subbytes(byte[] source, int srcBegin, int srcEnd) {
    int newSize = srcEnd - srcBegin;
    if (newSize <= 0)
      return new byte[0];

    byte[] destination = new byte[newSize];
    System.arraycopy(source, srcBegin, destination, 0, srcEnd - srcBegin);

    return destination;
  }

  /**
   * Return a new byte array containing a sub-portion of the source array
   *
   * @param srcBegin The beginning index (inclusive)
   * @return The new, populated byte array
   */
  public static byte[] subbytes(byte[] source, int srcBegin) {
    return subbytes(source, srcBegin, source.length);
  }

  /**
   * Checks if pattern is contained in source. This is just a wrapped KMP indexOf().
   * @param source
   * @param pattern
   * @return
   */
  public static boolean contains(byte[] source, byte[] pattern) {
    return KMP.indexOf(source, pattern) >= 0;
  }

  /**
   * Checks if pattern is contained in source. This is just a wrapped KMP indexOf().
   * @param source
   * @param c
   * @return
   */
  public static boolean contains(byte[] source, char c) {
    return KMP.indexOf(source, new byte[]{(byte) c}) >= 0;
  }

  public static int indexOf(byte[] source, char c) {
    return indexOf(source, c, 0);
  }


  public static int indexOf(byte[] source, char c, int offset) {
    for (int i = offset; i < source.length; i++)
      if (source[i] == c) return i;

    return -1;
  }

  /**
   * Searches forwards
   * @param source
   * @param c
   * @return
   */
  public static int indexOfReverse(byte[] source, char c) {
    return indexOfReverse(source, c, source.length-1);
  }

  /**
   * Searches backwards
   */
  public static int indexOfReverse(byte[] source, char c, int offset) {
    for (int i = offset; i >= 0; i--)
      if (source[i] == c) return i;

    return -1;
  }
}
