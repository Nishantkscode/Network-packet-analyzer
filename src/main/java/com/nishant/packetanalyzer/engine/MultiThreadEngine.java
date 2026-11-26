package com.nishant.packetanalyzer.engine;

import com.nishant.packetanalyzer.parser.PacketParser;
import com.nishant.packetanalyzer.parser.ParsedPacket;
import com.nishant.packetanalyzer.pcap.PcapReader;
import com.nishant.packetanalyzer.pcap.PcapWriter;
import com.nishant.packetanalyzer.pcap.RawPacket;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * The multi-threaded version (Java port of the C++ dpi_mt.cpp).
 *
 * <pre>
 *                      +--> LB0 --+--> FP0 --+
 *   Reader --(hash)----+          +--> FP1 --+--> output queue --> Writer --> output.pcap
 *   (main thread)      +--> LB1 --+--> FP2 --+
 *                                 +--> FP3 --+
 * </pre>
 *
 * Reader reads and parses packets. Load balancers (LB) spread them over fast paths (FP) by flow hash, so
 * all packets of one connection are handled by the same FP. The FPs do the inspection and blocking.
 * The writer thread saves the allowed packets.
 *
 * Shutdown is orderly: when the reader is finished it closes the queues one stage at a time and waits for each
 * stage to drain, so no packet is ever lost (the original C++ just slept for 500 ms and hoped).
 */
public final class MultiThreadEngine {
    private static final int QUEUE_CAPACITY = 10_000;

    private final int numLbs;
    private final int fpsPerLb;
    private final RuleManager rules;

    public MultiThreadEngine(int numLbs, int fpsPerLb, RuleManager rules) {
        if (numLbs < 1 || fpsPerLb < 1) {
            throw new IllegalArgumentException("--lbs and --fps must be at least 1");
        }
        this.numLbs = numLbs;
        this.fpsPerLb = fpsPerLb;
        this.rules = rules;
    }

    public int numLbs() {
        return numLbs;
    }

    public int fpsPerLb() {
        return fpsPerLb;
    }

    public ProcessingResult run(Path input, Path output) throws IOException, InterruptedException {
        ProcessingResult result = new ProcessingResult();

        try (PcapReader reader = PcapReader.open(input)) {
            Report.printPcapInfo(System.out, input, reader.header());
            try (PcapWriter writer = PcapWriter.create(output, reader.header())) {

                // ---- build the pipeline ----
                List<ThreadSafeQueue<PacketJob>> allQueues = new ArrayList<>();
                AtomicReference<Throwable> failure = new AtomicReference<>();
                Consumer<Throwable> onError = t -> {
                    failure.compareAndSet(null, t);
                    allQueues.forEach(ThreadSafeQueue::close);   // wake everybody up so nothing hangs
                };

                ThreadSafeQueue<PacketJob> outputQueue = newQueue(allQueues);

                int totalFps = numLbs * fpsPerLb;
                List<FastPath> fps = new ArrayList<>();
                for (int i = 0; i < totalFps; i++) {
                    fps.add(new FastPath(i, rules, newQueue(allQueues), outputQueue, onError));
                }
                List<LoadBalancer> lbs = new ArrayList<>();
                for (int i = 0; i < numLbs; i++) {
                    List<FastPath> mine = fps.subList(i * fpsPerLb, (i + 1) * fpsPerLb);
                    lbs.add(new LoadBalancer(i, numLbs, mine, newQueue(allQueues), onError));
                }

                Thread writerThread = new Thread(() -> {
                    try {
                        PacketJob pkt;
                        while ((pkt = outputQueue.take()) != null) {
                            writer.write(pkt.tsSec(), pkt.tsUsec(), pkt.data());
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } catch (Throwable t) {
                        onError.accept(t);
                    }
                }, "Writer");

                writerThread.start();
                fps.forEach(FastPath::start);
                lbs.forEach(LoadBalancer::start);

                // ---- the main thread is the reader ----
                try {
                    System.out.println("[Reader] Processing packets...");
                    readAndDispatch(reader, lbs, result);
                    System.out.println("[Reader] Done reading " + result.packetsAnalyzed + " packets");
                } finally {
                    // ---- orderly shutdown: close a stage, wait until it has finished, move on ----
                    for (LoadBalancer lb : lbs) lb.input().close();
                    for (LoadBalancer lb : lbs) lb.join();
                    for (FastPath fp : fps) fp.input().close();
                    for (FastPath fp : fps) fp.join();
                    outputQueue.close();
                    writerThread.join();
                }

                if (failure.get() != null) {
                    throw new IllegalStateException("A worker thread failed: " + failure.get(), failure.get());
                }

                // ---- collect results (safe: all threads have finished) ----
                result.lbDispatched = new long[numLbs];
                result.fpProcessed = new long[totalFps];
                for (int i = 0; i < numLbs; i++) result.lbDispatched[i] = lbs.get(i).dispatched();
                for (int i = 0; i < totalFps; i++) {
                    result.fpProcessed[i] = fps.get(i).processed();
                    result.merge(fps.get(i).processor());
                }
            }
        }
        result.blockedApps = rules.blockedApps();
        return result;
    }

    private void readAndDispatch(PcapReader reader, List<LoadBalancer> lbs, ProcessingResult result)
            throws InterruptedException {
        long id = 0;
        try {
            RawPacket raw;
            while ((raw = reader.next()) != null) {
                result.packetsRead++;
                Optional<ParsedPacket> parsed = PacketParser.parse(raw);
                if (parsed.isEmpty()) continue;
                PacketJob job = PacketJob.from(id, raw, parsed.get());
                if (job == null) continue;   // not IPv4 TCP/UDP
                id++;

                result.packetsAnalyzed++;
                result.bytes += raw.data().length;
                if (parsed.get().hasTcp) result.tcpPackets++; else result.udpPackets++;

                LoadBalancer lb = lbs.get(job.tuple().flowHash() % numLbs);
                if (!lb.input().put(job)) {
                    break; // pipeline was shut down because a worker failed
                }
            }
        } catch (IOException e) {
            System.err.println("[Reader] Warning: " + e.getMessage() + " - stopping early");
        }
    }

    private static ThreadSafeQueue<PacketJob> newQueue(List<ThreadSafeQueue<PacketJob>> registry) {
        ThreadSafeQueue<PacketJob> q = new ThreadSafeQueue<>(QUEUE_CAPACITY);
        registry.add(q);
        return q;
    }
}
