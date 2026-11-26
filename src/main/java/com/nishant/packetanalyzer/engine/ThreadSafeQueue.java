package com.nishant.packetanalyzer.engine;

import java.util.ArrayDeque;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A bounded, blocking queue that threads use to hand packets to each other (producer/consumer).
 *
 * <ul>
 *   <li>{@link #put} waits while the queue is full, so a fast reader cannot use unlimited memory.</li>
 *   <li>{@link #take} waits while the queue is empty.</li>
 *   <li>{@link #close} means "no more items are coming": consumers still get everything already
 *       queued, then {@code take()} returns null so they know to finish.</li>
 * </ul>
 *
 * This is the Java version of the C++ TSQueue (mutex + two condition variables).
 */
public final class ThreadSafeQueue<T> {
    private final ArrayDeque<T> items = new ArrayDeque<>();
    private final int capacity;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();
    private final Condition notFull = lock.newCondition();
    private boolean closed;

    public ThreadSafeQueue(int capacity) {
        if (capacity < 1) throw new IllegalArgumentException("capacity must be >= 1");
        this.capacity = capacity;
    }

    /**
     * Adds an item, waiting while the queue is full.
     *
     * @return false if the queue was closed (the item was not added)
     */
    public boolean put(T item) throws InterruptedException {
        lock.lockInterruptibly();
        try {
            while (items.size() >= capacity && !closed) {
                notFull.await();
            }
            if (closed) {
                return false;
            }
            items.addLast(item);
            notEmpty.signal();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Removes the oldest item, waiting while the queue is empty.
     *
     * @return the item, or null once the queue is closed AND empty
     */
    public T take() throws InterruptedException {
        lock.lockInterruptibly();
        try {
            while (items.isEmpty() && !closed) {
                notEmpty.await();
            }
            if (items.isEmpty()) {
                return null;
            }
            T item = items.removeFirst();
            notFull.signal();
            return item;
        } finally {
            lock.unlock();
        }
    }

    /** Signals that no more items will be added. Safe to call more than once. */
    public void close() {
        lock.lock();
        try {
            closed = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try {
            return items.size();
        } finally {
            lock.unlock();
        }
    }
}
