package com.nishant.packetanalyzer.engine;

import java.util.function.Consumer;

/**
 * A "fast path" worker thread: takes packets from its own input queue, runs them through its own
 * {@link PacketProcessor}, and puts the packets that are allowed into the shared output queue.
 */
final class FastPath implements Runnable {
    private final int id;
    private final ThreadSafeQueue<PacketJob> input;
    private final ThreadSafeQueue<PacketJob> output;
    private final PacketProcessor processor;
    private final Consumer<Throwable> onError;
    private final Thread thread;
    private long processed; // written by the worker thread, read only after join()

    FastPath(int id, RuleManager rules, ThreadSafeQueue<PacketJob> input,
             ThreadSafeQueue<PacketJob> output, Consumer<Throwable> onError) {
        this.id = id;
        this.input = input;
        this.output = output;
        this.processor = new PacketProcessor(rules);
        this.onError = onError;
        this.thread = new Thread(this, "FP" + id);
    }

    ThreadSafeQueue<PacketJob> input() {
        return input;
    }

    void start() {
        thread.start();
    }

    void join() throws InterruptedException {
        thread.join();
    }

    long processed() {
        return processed;
    }

    PacketProcessor processor() {
        return processor;
    }

    @Override
    public void run() {
        try {
            PacketJob pkt;
            while ((pkt = input.take()) != null) {   // null = queue closed and fully drained
                processed++;
                if (processor.process(pkt)) {
                    output.put(pkt);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Throwable t) {
            onError.accept(t);
        }
    }

    @Override
    public String toString() {
        return "FP" + id;
    }
}
