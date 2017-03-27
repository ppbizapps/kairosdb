package org.kairosdb.util;

import com.datastax.driver.core.exceptions.NoHostAvailableException;
import com.github.rholder.retry.Retryer;
import com.github.rholder.retry.RetryerBuilder;
import com.github.rholder.retry.WaitStrategies;
import com.google.common.base.Predicates;
import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.eventbus.EventBus;
import org.kairosdb.core.datapoints.DoubleDataPointFactory;
import org.kairosdb.core.datapoints.DoubleDataPointFactoryImpl;
import org.kairosdb.datastore.cassandra.BatchHandler;
import org.kairosdb.events.DataPointEvent;

import javax.inject.Inject;
import java.util.List;
import java.util.concurrent.*;

/**
 Created by bhawkins on 10/27/16.
 */
public class AdaptiveExecutorService
{
	private final EventBus m_eventBus;
	private final ExecutorService m_internalExecutor;
	private final ThreadGroup m_threadGroup;
	private final CongestionSemaphore m_semaphore;
	private final CongestionTimer m_congestionTimer;
	private int m_permitCount = 10;
	private final Retryer<Long> m_retryer;

	@Inject
	private DoubleDataPointFactory m_dataPointFactory = new DoubleDataPointFactoryImpl();

	@Inject
	public AdaptiveExecutorService(EventBus eventBus)
	{
		m_eventBus = eventBus;
		m_congestionTimer = new CongestionTimer(m_permitCount);
		m_semaphore = new CongestionSemaphore(m_permitCount);
		m_threadGroup = new ThreadGroup("KairosDynamic");
		/*m_internalExecutor = Executors.newCachedThreadPool(new ThreadFactory()
		{
			@Override
			public Thread newThread(Runnable r)
			{
				Thread t = new Thread(m_threadGroup, "worker");
				return t;
			}
		});*/

		m_retryer = RetryerBuilder.<Long>newBuilder()
				.retryIfExceptionOfType(NoHostAvailableException.class)
				.withWaitStrategy(WaitStrategies.fibonacciWait(10, TimeUnit.SECONDS))
				.build();
		m_internalExecutor = Executors.newCachedThreadPool();
	}

	private void increasePermitCount()
	{
		m_permitCount ++;
		m_congestionTimer.setTaskPerBatch(m_permitCount);
		m_semaphore.release();
	}

	public void shutdown()
	{

	}


	private Stopwatch m_timer = Stopwatch.createStarted();

	public void submit(BatchHandler batchHandler)
	{
		if (m_timer.elapsed(TimeUnit.SECONDS) >= 5)
		{
			/*if ((m_semaphore.availablePermits() == 0) && (batchHandler.isFullBatch()))
			{
				increasePermitCount();
			}*/

			m_timer.reset();
			m_timer.start();
		}

		try
		{
			//System.out.println("Execute called");
			m_semaphore.acquire();
			//System.out.println("Submitting");
			m_internalExecutor.submit(newTaskFor(m_retryer.wrap(batchHandler)));
			//System.out.println("Done submitting");
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();
		}
	}

	protected <T> RunnableFuture<T> newTaskFor(Callable<T> callable)
	{
		//System.out.println("Returning new future");
		return new DynamicFutureTask<T>(callable);
	}



	private class DynamicFutureTask<T> extends FutureTask<T>
	{
		private final Stopwatch m_stopwatch;

		public DynamicFutureTask(Callable<T> callable)
		{
			super(callable);
			m_stopwatch = Stopwatch.createUnstarted();
		}

		@Override
		public void run()
		{
			//System.out.println("DynamicFutureTask.run");
			m_stopwatch.start();
			super.run();
			m_stopwatch.stop();

			//Todo do something with elapsed time
			SimpleStats.Data timerStat = m_congestionTimer.reportTaskTime(m_stopwatch.elapsed(TimeUnit.MILLISECONDS));

			m_semaphore.release();

			if (timerStat != null)
			{
				//System.out.println("Sending stats");
				long now = System.currentTimeMillis();
				ImmutableSortedMap<String, String> tags = ImmutableSortedMap.of("host", "test");
				DataPointEvent dpe = new DataPointEvent("kairosdb.congestion.stats.min", tags,
						m_dataPointFactory.createDataPoint(now, timerStat.min));
				m_eventBus.post(dpe);

				dpe = new DataPointEvent("kairosdb.congestion.stats.max", tags,
						m_dataPointFactory.createDataPoint(now, timerStat.max));
				m_eventBus.post(dpe);

				dpe = new DataPointEvent("kairosdb.congestion.stats.avg", tags,
						m_dataPointFactory.createDataPoint(now, timerStat.avg));
				m_eventBus.post(dpe);

				dpe = new DataPointEvent("kairosdb.congestion.stats.permit_count", tags,
						m_dataPointFactory.createDataPoint(now, m_permitCount));
				m_eventBus.post(dpe);
			}

		}

		@Override
		public void set(T result)
		{
			//Todo Calculate time to run and adjust number of threads

			super.set(result);
		}
	}

	private static class CongestionSemaphore extends Semaphore
	{
		public CongestionSemaphore(int permits)
		{
			super(permits);
		}

		public void reducePermits(int reduction)
		{
			super.reducePermits(reduction);
		}
	}
}
