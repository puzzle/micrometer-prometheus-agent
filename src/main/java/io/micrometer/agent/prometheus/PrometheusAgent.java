package io.micrometer.agent.prometheus;

import fi.iki.elonen.NanoHTTPD;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmHeapPressureMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.prometheus.PrometheusConfig;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.prometheus.client.exporter.common.TextFormat;

import java.io.IOException;
import java.lang.instrument.Instrumentation;

public class PrometheusAgent {
    public static void premain(String agentArgs, Instrumentation inst) {
        runPrometheusScrapeEndpoint();
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        runPrometheusScrapeEndpoint();
    }

    private static void runPrometheusScrapeEndpoint() {
        try {
            if (Runtime.getRuntime().maxMemory() < 128 * 1024 * 1024) {
                return;
            }

            PrometheusMeterRegistry meterRegistry =
                    new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

            new JvmMemoryMetrics().bindTo(meterRegistry);
            new JvmGcMetrics().bindTo(meterRegistry);
            new JvmHeapPressureMetrics().bindTo(meterRegistry);

            NanoHTTPD server = new NanoHTTPD(7001) {
                @Override
                public NanoHTTPD.Response serve(IHTTPSession session) {
                    String response = meterRegistry.scrape();
                    return newFixedLengthResponse(NanoHTTPD.Response.Status.OK, TextFormat.CONTENT_TYPE_004, response);
                }
            };

            Thread server_thread = new Thread(() -> {
                try {
                    server.start();
                } catch (Throwable e) {
                    throw new RuntimeException(e);
                }
            });
            server_thread.setDaemon(true);
            server_thread.start();
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }
}
