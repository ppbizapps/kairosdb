package org.kairosdb.datastore.cassandra;

import com.google.common.base.Stopwatch;
import org.kairosdb.core.exception.DatastoreException;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class QueryMonitor
{

	private volatile boolean m_keepRunning;
	private Throwable m_exception;
	private final long m_limit;
	private final AtomicLong m_counter = new AtomicLong();
	private final AtomicLong m_query_counter = new AtomicLong();
	private final AtomicLong m_query_fail_counter = new AtomicLong();
	private static double m_tolerance;
	public static final Logger logger = LoggerFactory.getLogger(QueryMonitor.class);
	private Stopwatch m_timer;
	private final long m_timeLimit;  //Seconds

	public QueryMonitor(long limit, long timeLimit, double tolerance)
	{
		m_limit = limit;
		m_keepRunning = true;
		m_tolerance = tolerance;
		m_timer = Stopwatch.createStarted();
		m_timeLimit = timeLimit;
	}

	public void incrementCounter()
	{
		m_counter.incrementAndGet();
	}

	public boolean keepRunning()
	{
		if (m_keepRunning)
		{
			//Check how long we have been running
			if ((m_timeLimit != 0) && (m_timer.elapsed(TimeUnit.SECONDS) > m_timeLimit))
			{
				m_exception = new DatastoreException("Query exceeded time limit of " + m_timeLimit + " seconds");
				m_keepRunning = false;
			}

			//Check data point limit
			if (m_limit != 0 && m_counter.get() > m_limit)
			{
				m_exception = new DatastoreException("Query exceeded limit of " + m_limit + " data points");
				m_keepRunning = false;
			}
		}

		return (m_keepRunning);
	}

	public void failQuery(Throwable e) {
		m_query_fail_counter.incrementAndGet();

		if (m_query_fail_counter.doubleValue() / m_query_counter.doubleValue() > m_tolerance)
		{
			m_keepRunning = false;
			m_exception = e;
		}
		else
		{
			logger.warn("Failures: " + m_query_fail_counter.doubleValue() + " Queries:  " + m_query_counter.doubleValue() + ", Query failure tolerance not reached, continuing additional queries.", e);
		}
	}

	public void incrementQueryCounter()
	{
		m_query_counter.incrementAndGet();
	}

	public Throwable getException()
	{
		return m_exception;
	}
}
