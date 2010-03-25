/*-
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  
 *  Modifications:
 *  -Changed package name
 *  -Removed "@since Android 1.0" comments
 *  -Removed logging
 *  -Removed special error messages
 *  -Removed annotations
 *  -Replaced StringBuilder with StringBuffer
 */

package com.google.authenticator.blackberry;

import java.io.IOException;
import java.io.Reader;

/**
 * Wraps an existing {@link Reader} and <em>buffers</em> the input. Expensive
 * interaction with the underlying reader is minimized, since most (smaller)
 * requests can be satisfied by accessing the buffer alone. The drawback is that
 * some extra space is required to hold the buffer and that copying takes place
 * when filling that buffer, but this is usually outweighed by the performance
 * benefits.
 *
 * <p/>A typical application pattern for the class looks like this:<p/>
 *
 * <pre>
 * BufferedReader buf = new BufferedReader(new FileReader(&quot;file.java&quot;));
 * </pre>
 *
 * @see BufferedWriter
 */
public class BufferedReader extends Reader {

    private Reader in;

    private char[] buf;

    private int marklimit = -1;

    private int count;

    private int markpos = -1;

    private int pos;

    /**
     * Constructs a new BufferedReader on the Reader {@code in}. The
     * buffer gets the default size (8 KB).
     *
     * @param in
     *            the Reader that is buffered.
     */
    public BufferedReader(Reader in) {
        super(in);
        this.in = in;
        buf = new char[8192];
    }

    /**
     * Constructs a new BufferedReader on the Reader {@code in}. The buffer
     * size is specified by the parameter {@code size}.
     *
     * @param in
     *            the Reader that is buffered.
     * @param size
     *            the size of the buffer to allocate.
     * @throws IllegalArgumentException
     *             if {@code size <= 0}.
     */
    public BufferedReader(Reader in, int size) {
        super(in);
        if (size <= 0) {
            throw new IllegalArgumentException();
        }
        this.in = in;
        buf = new char[size];
    }

    /**
     * Closes this reader. This implementation closes the buffered source reader
     * and releases the buffer. Nothing is done if this reader has already been
     * closed.
     *
     * @throws IOException
     *             if an error occurs while closing this reader.
     */
    public void close() throws IOException {
        synchronized (lock) {
            if (!isClosed()) {
                in.close();
                buf = null;
            }
        }
    }

    private int fillbuf() throws IOException {
        if (markpos == -1 || (pos - markpos >= marklimit)) {
            /* Mark position not set or exceeded readlimit */
            int result = in.read(buf, 0, buf.length);
            if (result > 0) {
                markpos = -1;
                pos = 0;
                count = result == -1 ? 0 : result;
            }
            return result;
        }
        if (markpos == 0 && marklimit > buf.length) {
            /* Increase buffer size to accommodate the readlimit */
            int newLength = buf.length * 2;
            if (newLength > marklimit) {
                newLength = marklimit;
            }
            char[] newbuf = new char[newLength];
            System.arraycopy(buf, 0, newbuf, 0, buf.length);
            buf = newbuf;
        } else if (markpos > 0) {
            System.arraycopy(buf, markpos, buf, 0, buf.length - markpos);
        }

        /* Set the new position and mark position */
        pos -= markpos;
        count = markpos = 0;
        int charsread = in.read(buf, pos, buf.length - pos);
        count = charsread == -1 ? pos : pos + charsread;
        return charsread;
    }

    /**
     * Indicates whether or not this reader is closed.
     *
     * @return {@code true} if this reader is closed, {@code false}
     *         otherwise.
     */
    private boolean isClosed() {
        return buf == null;
    }

    /**
     * Sets a mark position in this reader. The parameter {@code readlimit}
     * indicates how many characters can be read before the mark is invalidated.
     * Calling {@code reset()} will reposition the reader back to the marked
     * position if {@code readlimit} has not been surpassed.
     *
     * @param readlimit
     *            the number of characters that can be read before the mark is
     *            invalidated.
     * @throws IllegalArgumentException
     *             if {@code readlimit < 0}.
     * @throws IOException
     *             if an error occurs while setting a mark in this reader.
     * @see #markSupported()
     * @see #reset()
     */
    public void mark(int readlimit) throws IOException {
        if (readlimit < 0) {
            throw new IllegalArgumentException();
        }
        synchronized (lock) {
            if (isClosed()) {
                throw new IOException();
            }
            marklimit = readlimit;
            markpos = pos;
        }
    }

    /**
     * Indicates whether this reader supports the {@code mark()} and
     * {@code reset()} methods. This implementation returns {@code true}.
     *
     * @return {@code true} for {@code BufferedReader}.
     * @see #mark(int)
     * @see #reset()
     */
    public boolean markSupported() {
        return true;
    }

    /**
     * Reads a single character from this reader and returns it with the two
     * higher-order bytes set to 0. If possible, BufferedReader returns a
     * character from the buffer. If there are no characters available in the
     * buffer, it fills the buffer and then returns a character. It returns -1
     * if there are no more characters in the source reader.
     *
     * @return the character read or -1 if the end of the source reader has been
     *         reached.
     * @throws IOException
     *             if this reader is closed or some other I/O error occurs.
     */
    public int read() throws IOException {
        synchronized (lock) {
            if (isClosed()) {
                throw new IOException();
            }
            /* Are there buffered characters available? */
            if (pos < count || fillbuf() != -1) {
                return buf[pos++];
            }
            return -1;
        }
    }

    /**
     * Reads at most {@code length} characters from this reader and stores them
     * at {@code offset} in the character array {@code buffer}. Returns the
     * number of characters actually read or -1 if the end of the source reader
     * has been reached. If all the buffered characters have been used, a mark
     * has not been set and the requested number of characters is larger than
     * this readers buffer size, BufferedReader bypasses the buffer and simply
     * places the results directly into {@code buffer}.
     *
     * @param buffer
     *            the character array to store the characters read.
     * @param offset
     *            the initial position in {@code buffer} to store the bytes read
     *            from this reader.
     * @param length
     *            the maximum number of characters to read, must be
     *            non-negative.
     * @return number of characters read or -1 if the end of the source reader
     *         has been reached.
     * @throws IndexOutOfBoundsException
     *             if {@code offset < 0} or {@code length < 0}, or if
     *             {@code offset + length} is greater than the size of
     *             {@code buffer}.
     * @throws IOException
     *             if this reader is closed or some other I/O error occurs.
     */
    public int read(char[] buffer, int offset, int length) throws IOException {
        synchronized (lock) {
            if (isClosed()) {
                throw new IOException();
            }
            if (length == 0) {
                return 0;
            }
            int required;
            if (pos < count) {
                /* There are bytes available in the buffer. */
                int copylength = count - pos >= length ? length : count - pos;
                System.arraycopy(buf, pos, buffer, offset, copylength);
                pos += copylength;
                if (copylength == length || !in.ready()) {
                    return copylength;
                }
                offset += copylength;
                required = length - copylength;
            } else {
                required = length;
            }

            while (true) {
                int read;
                /*
                 * If we're not marked and the required size is greater than the
                 * buffer, simply read the bytes directly bypassing the buffer.
                 */
                if (markpos == -1 && required >= buf.length) {
                    read = in.read(buffer, offset, required);
                    if (read == -1) {
                        return required == length ? -1 : length - required;
                    }
                } else {
                    if (fillbuf() == -1) {
                        return required == length ? -1 : length - required;
                    }
                    read = count - pos >= required ? required : count - pos;
                    System.arraycopy(buf, pos, buffer, offset, read);
                    pos += read;
                }
                required -= read;
                if (required == 0) {
                    return length;
                }
                if (!in.ready()) {
                    return length - required;
                }
                offset += read;
            }
        }
    }

    /**
     * Returns the next line of text available from this reader. A line is
     * represented by zero or more characters followed by {@code '\n'},
     * {@code '\r'}, {@code "\r\n"} or the end of the reader. The string does
     * not include the newline sequence.
     *
     * @return the contents of the line or {@code null} if no characters were
     *         read before the end of the reader has been reached.
     * @throws IOException
     *             if this reader is closed or some other I/O error occurs.
     */
    public String readLine() throws IOException {
        synchronized (lock) {
            if (isClosed()) {
                throw new IOException();
            }
            /* Are there buffered characters available? */
            if ((pos >= count) && (fillbuf() == -1)) {
                return null;
            }
            for (int charPos = pos; charPos < count; charPos++) {
                char ch = buf[charPos];
                if (ch > '\r') {
                    continue;
                }
                if (ch == '\n') {
                    String res = new String(buf, pos, charPos - pos);
                    pos = charPos + 1;
                    return res;
                } else if (ch == '\r') {
                    String res = new String(buf, pos, charPos - pos);
                    pos = charPos + 1;
                    if (((pos < count) || (fillbuf() != -1))
                            && (buf[pos] == '\n')) {
                        pos++;
                    }
                    return res;
                }
            }

            char eol = '\0';
            StringBuffer result = new StringBuffer(80);
            /* Typical Line Length */

            result.append(buf, pos, count - pos);
            pos = count;
            while (true) {
                /* Are there buffered characters available? */
                if (pos >= count) {
                    if (eol == '\n') {
                        return result.toString();
                    }
                    // attempt to fill buffer
                    if (fillbuf() == -1) {
                        // characters or null.
                        return result.length() > 0 || eol != '\0' ? result
                                .toString() : null;
                    }
                }
                for (int charPos = pos; charPos < count; charPos++) {
                    if (eol == '\0') {
                        if ((buf[charPos] == '\n' || buf[charPos] == '\r')) {
                            eol = buf[charPos];
                        }
                    } else if (eol == '\r' && (buf[charPos] == '\n')) {
                        if (charPos > pos) {
                            result.append(buf, pos, charPos - pos - 1);
                        }
                        pos = charPos + 1;
                        return result.toString();
                    } else if (eol != '\0') {
                        if (charPos > pos) {
                            result.append(buf, pos, charPos - pos - 1);
                        }
                        pos = charPos;
                        return result.toString();
                    }
                }
                if (eol == '\0') {
                    result.append(buf, pos, count - pos);
                } else {
                    result.append(buf, pos, count - pos - 1);
                }
                pos = count;
            }
        }

    }

    /**
     * Indicates whether this reader is ready to be read without blocking.
     *
     * @return {@code true} if this reader will not block when {@code read} is
     *         called, {@code false} if unknown or blocking will occur.
     * @throws IOException
     *             if this reader is closed or some other I/O error occurs.
     * @see #read()
     * @see #read(char[], int, int)
     * @see #readLine()
     */
    public boolean ready() throws IOException {
        synchronized (lock) {
            if (isClosed()) {
                throw new IOException();
            }
            return ((count - pos) > 0) || in.ready();
        }
    }

    /**
     * Resets this reader's position to the last {@code mark()} location.
     * Invocations of {@code read()} and {@code skip()} will occur from this new
     * location.
     *
     * @throws IOException
     *             if this reader is closed or no mark has been set.
     * @see #mark(int)
     * @see #markSupported()
     */
    public void reset() throws IOException {
        synchronized (lock) {
            if (isClosed()) {
                throw new IOException();
            }
            if (markpos == -1) {
                throw new IOException();
            }
            pos = markpos;
        }
    }

    /**
     * Skips {@code amount} characters in this reader. Subsequent
     * {@code read()}s will not return these characters unless {@code reset()}
     * is used. Skipping characters may invalidate a mark if {@code readlimit}
     * is surpassed.
     *
     * @param amount
     *            the maximum number of characters to skip.
     * @return the number of characters actually skipped.
     * @throws IllegalArgumentException
     *             if {@code amount < 0}.
     * @throws IOException
     *             if this reader is closed or some other I/O error occurs.
     * @see #mark(int)
     * @see #markSupported()
     * @see #reset()
     */
    public long skip(long amount) throws IOException {
        if (amount < 0) {
            throw new IllegalArgumentException();
        }
        synchronized (lock) {
            if (isClosed()) {
                throw new IOException();
            }
            if (amount < 1) {
                return 0;
            }
            if (count - pos >= amount) {
                pos += amount;
                return amount;
            }

            long read = count - pos;
            pos = count;
            while (read < amount) {
                if (fillbuf() == -1) {
                    return read;
                }
                if (count - pos >= amount - read) {
                    pos += amount - read;
                    return amount;
                }
                // Couldn't get all the characters, skip what we read
                read += (count - pos);
                pos = count;
            }
            return amount;
        }
    }
}
