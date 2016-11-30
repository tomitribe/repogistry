/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.tomitribe.tribestream.registryng.service.threading;

import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.tomitribe.util.Duration;

import javax.annotation.Resource;
import javax.enterprise.concurrent.ManagedExecutorService;
import javax.enterprise.context.ApplicationScoped;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;

import static java.lang.Math.max;

@Log
@ApplicationScoped
public class Invoker {
    private final AtomicInteger ids = new AtomicInteger(1);

    @Resource(name = "registry/thread/invoker-pool")
    private ManagedExecutorService mes;

    public <T> Handle invoke(final int threads, final int iterations, final String duration,
                             final long timeoutMs,
                             final Runnable task) {
        final AtomicInteger localId = new AtomicInteger(1);
        // not a ManagedExecutorService cause we need to fully control it there
        final ExecutorService taskExecutor = Executors.newFixedThreadPool(threads, r -> {
            final Thread originalThread = Thread.currentThread();
            final ClassLoader loader = originalThread.getContextClassLoader();
            originalThread.setContextClassLoader(Invoker.class.getClassLoader());
            try {
                final Thread thread = new Thread(
                        r,
                        // this string is just a "comment", not 100% accurate but good enough
                        " - " + ids.incrementAndGet() + "_" + localId.incrementAndGet() + "/" + threads +
                                "_iterations=" + iterations + "_duration=" + duration);
                if (thread.getPriority() != Thread.NORM_PRIORITY) {
                    thread.setPriority(Thread.NORM_PRIORITY);
                }
                return thread;
            } finally {
                originalThread.setContextClassLoader(loader);
            }
        });
        final AtomicBoolean active = new AtomicBoolean(true);
        final Semaphore throttler = new Semaphore(threads);
        if (iterations > 0) {
            return new Handle(taskExecutor, max(timeoutMs, 10000), active, mes.submit(() -> {
                final AtomicInteger remaining = new AtomicInteger(iterations);
                do {
                    taskExecutor.submit(throttle(throttler, task));
                } while (active.get() && remaining.decrementAndGet() > 0);
            }));
        } else if (duration != null) {
            final long time = new Duration(duration, TimeUnit.MILLISECONDS).getTime(TimeUnit.MILLISECONDS);
            return new Handle(taskExecutor, max(timeoutMs, time + 10000), active, mes.submit(() -> {
                final long end = System.currentTimeMillis() + time;
                do {
                    taskExecutor.submit(throttle(throttler, task));
                } while (active.get() && (end - System.currentTimeMillis()) > 0);
            }));
        } else {
            throw new IllegalArgumentException("No iteration and duration");
        }
    }

    // avoid to submit 10000000 jobs in 10s and then wait for them if we have 10 threads and a run of 10 seconds
    private Runnable throttle(final Semaphore throttler, final Runnable task) {
        try {
            throttler.acquire();
        } catch (final InterruptedException e) {
            log.fine("Thread interrupted: " + Thread.currentThread().getName() + ", so giving up on acquiring a lock");
            Thread.interrupted();
            throw new IllegalStateException(e);
        }
        return () -> {
            try {
                task.run();
            } catch (final RuntimeException re) {
                log.log(Level.INFO, "Error in an invoker task", re);
            } finally {
                throttler.release();
            }
        };
    }

    @RequiredArgsConstructor
    public static class Handle {
        private final ExecutorService es;
        private final long time; // timeout for Futures
        private final AtomicBoolean active;
        private final Future<?> emitterHandler;

        public void cancel() {
            active.set(false);
            waitEmition();

            // stop task if not
            es.shutdown();
            await();
            if (isRunning()) {
                es.shutdownNow();
            }
        }

        public void await() {
            waitEmition();
            if (isRunning()) {
                es.shutdown();
                try {
                    if (!es.awaitTermination(time, TimeUnit.MILLISECONDS)) {
                        throw new IllegalStateException("Scenario didn't complete in " + time + " ms");
                    }
                } catch (final InterruptedException e) {
                    Thread.interrupted();
                }
            }
        }

        private void waitEmition() {
            // wait the emitter to finish
            try {
                emitterHandler.get(time, TimeUnit.MILLISECONDS);
            } catch (final InterruptedException e) {
                Thread.interrupted();
            } catch (final ExecutionException | TimeoutException e) {
                log.log(Level.WARNING, e.getMessage(), e);
            }
        }

        private boolean isRunning() {
            return !es.isShutdown() || !es.isTerminated();
        }

        public boolean isCancelled() {
            return !active.get();
        }
    }
}
