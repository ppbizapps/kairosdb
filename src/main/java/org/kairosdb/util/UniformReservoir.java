/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Forked from https://github.com/codahale/metrics
 */

package org.kairosdb.util;

import com.google.common.util.concurrent.AtomicDoubleArray;

import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A random sampling reservoir of a stream of {@code long}s. Uses Vitter's Algorithm R to produce a
 * statistically representative sample.
 *
 * @see <a href="http://www.cs.umd.edu/~samir/498/vitter.pdf">Random Sampling with a Reservoir</a>
 */
public class UniformReservoir implements Reservoir
{
	private static final int DEFAULT_SIZE = 1028;
	private static final int BITS_PER_LONG = 63;
	private final AtomicLong count = new AtomicLong();
	private final AtomicDoubleArray values;
	private static Random random = new Random();

	/**
	 * Creates a new {@link UniformReservoir} of 1028 elements, which offers a 99.9% confidence level
	 * with a 5% margin of error assuming a normal distribution.
	 */
	public UniformReservoir() {
		this(DEFAULT_SIZE);
	}

	/**
	 * Creates a new {@link UniformReservoir}.
	 *
	 * @param size the number of samples to keep in the sampling reservoir
	 */
	public UniformReservoir(int size) {
		this.values = new AtomicDoubleArray(size);
		for (int i = 0; i < values.length(); i++) {
			values.set(i, 0);
		}
		count.set(0);
	}

	@Override
	public int size() {
		final long c = count.get();
		if (c > values.length()) {
			return values.length();
		}
		return (int) c;
	}

	@Override
	public void update(double value) {
		final long c = count.incrementAndGet();
		if (c <= values.length()) {
			values.set((int) c - 1, value);
		} else {
			final long r = nextLong(c);
			if (r < values.length()) {
				values.set((int) r, value);
			}
		}
	}

	/**
	 * Get a pseudo-random long uniformly between 0 and n-1. Stolen from
	 * {@link java.util.Random#nextInt()}.
	 *
	 * @param n the bound
	 * @return a value select randomly from the range {@code [0..n)}.
	 */
	private static long nextLong(long n) {
		long bits, val;
		do {
			bits = random.nextLong() & (~(1L << BITS_PER_LONG));
			val = bits % n;
		} while (bits - val + (n - 1) < 0L);
		return val;
	}

	public double[] getValues()
	{
		double[] doubleArray = new double[this.size()];
		for(int i=0; i < this.size(); i++)
		{
			doubleArray[i] = values.get(i);
		}
		return doubleArray;
	}
}
