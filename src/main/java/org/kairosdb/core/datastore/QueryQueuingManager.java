/*
 * Copyright 2016 KairosDB Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package org.kairosdb.core.datastore;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import org.agileclick.genorm.runtime.Pair;
import org.kairosdb.core.DataPointSet;
import org.kairosdb.core.datapoints.LongDataPoint;
import org.kairosdb.core.reporting.KairosMetricReporter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkArgument;
import static org.kairosdb.util.Preconditions.requireNonNullOrEmpty;

public class QueryQueuingManager implements KairosMetricReporter
{
	public static final Logger logger = LoggerFactory.getLogger(QueryQueuingManager.class);
	public static final String CONCURRENT_QUERY_THREAD = "kairosdb.datastore.concurrentQueryThreads";
	public static final String QUERY_COLLISIONS_METRIC_NAME = "kairosdb.datastore.query_collisions";

	private final Map<String, Pair<QueryMetric, Thread>> runningQueries = new HashMap<>();
	private final ReentrantLock lock = new ReentrantLock();
	private final Semaphore semaphore;
	private final String hostname;

	private AtomicInteger collisions = new AtomicInteger();

	@Inject
	public QueryQueuingManager(@Named(CONCURRENT_QUERY_THREAD) int concurrentQueryThreads, @Named("HOSTNAME") String hostname)
	{
		checkArgument(concurrentQueryThreads > 0);
		this.hostname = requireNonNullOrEmpty(hostname);
		semaphore = new Semaphore(concurrentQueryThreads, true);
	}

	public void waitForTimeToRun(String queryHash, QueryMetric metric) throws InterruptedException
	{
		boolean firstTime = true;
		while(!acquireSemaphore(queryHash, metric))
		{
			if (firstTime)
			{
				collisions.incrementAndGet();
				firstTime = false;
			}
			Thread.sleep(100);
		}
	}

	public void done(String queryHash)
	{
		lock.lock();
		try
		{
			runningQueries.remove(queryHash);
		}
		finally
		{
			lock.unlock();
		}
		semaphore.release();
	}

	private boolean acquireSemaphore(String queryHash, QueryMetric metric) throws InterruptedException
	{
		semaphore.acquire();

		boolean hashConflict = false;
		lock.lock();
		try
		{
			hashConflict = runningQueries.containsKey(queryHash);
			if (!hashConflict)
			{
				runningQueries.put(queryHash, new Pair<>(metric, Thread.currentThread()));
			}
		}
		finally
		{
			lock.unlock();
		}

		if (hashConflict)
		{
			semaphore.release();
			return false;
		}
		else
			return true;
	}

	public ArrayList<Pair<String, QueryMetric>> getRunningQueries()
	{
		ArrayList<Pair<String, QueryMetric>> runningQueriesList = new ArrayList<Pair<String, QueryMetric>>();
		lock.lock();
		try
		{
			for (String key : runningQueries.keySet())
			{
				runningQueriesList.add(new Pair<String, QueryMetric>(key, runningQueries.get(key).getFirst()));
			}
		}
		finally
		{
			lock.unlock();
		}
		return runningQueriesList;
	}

	public void killQuery(String queryHash)
	{
		lock.lock();
		try
		{
			if (runningQueries.get(queryHash) != null)
			{
				runningQueries.get(queryHash).getSecond().interrupt();    // Call interrupt on Thread associated with provided query hash
			}
		}
		finally
		{
			lock.unlock();
		}
	}

	public int getQueryWaitingCount()
	{
		return semaphore.getQueueLength();
	}

	public int getAvailableThreads()
	{
		return semaphore.availablePermits();
	}

	@Override
	public List<DataPointSet> getMetrics(long now)
	{
		DataPointSet collisionSet = new DataPointSet(QUERY_COLLISIONS_METRIC_NAME);
		collisionSet.addTag("host", hostname);
		collisionSet.addDataPoint(new LongDataPoint(System.currentTimeMillis(), collisions.getAndSet(0)));

		return Collections.singletonList(collisionSet);
	}
}