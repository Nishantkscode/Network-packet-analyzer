package com.nishant.packetanalyzer.engine;

import java.util.List;
import java.util.function.Consumer;

/**
 * A load balancer thread: takes packets from its input queue and hands each one to one of its
 * fast-path workers, chosen from the flow's hash. The same flow always gets the same worker,
 * which is what lets every worker keep a private, lock-free flow table.
 */
final class LoadBalancer implements Runnable {
    private final int id;
    private final int totalLoadBalancers;
    private final List<FastPath> fastPaths;
    private final ThreadSafeQueue<PacketJob> input;
    private final Consumer<Throwable> onError;
    private final Thread thread;
    private long dispatched; // written by the worker thread, read only after join()

    LoadBalancer(int id, int totalLoadBalancers, List<FastPath> fastPaths,
                 ThreadSafeQueue<PacketJob> input, Consumer<Throwable> onError) {
        this.id = id;
        this.totalLoadBalancers = totalLoadBalancers;
        this.fastPaths = fastPaths;
        this.input = input;
        this.onError = onError;
        this.thread = new Thread(this, "LB" + id);
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

    long dispatched() {
        return dispatched;
    }

    @Override
    public void run() {
        try {
            PacketJob pkt;
            while ((pkt = input.take()) != null) {
                // The reader already used (hash % numLoadBalancers) to pick THIS balancer, so every packet here
                // has the same remainder. Dividing first uses the "next" part of the hash and spreads the
                // flows evenly over all workers (reusing the same remainder would leave some workers idle).
                int h = pkt.tuple().flowHash();
                int index = (h / totalLoadBalancers) % fastPaths.size();
                if (!fastPaths.get(index).input().put(pkt)) {
                    return; // pipeline was shut down
                }
                dispatched++;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Throwable t) {
            onError.accept(t);
        }
    }

    @Override
    public String toString() {
        return "LB" + id;
    }
}
