package io.micrometer.agent.prometheus;

import com.sun.net.httpserver.HttpServer;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmHeapPressureMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.prometheus.PrometheusConfig;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.prometheus.client.exporter.common.TextFormat;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.net.InetSocketAddress;

public class PrometheusAgent {
    private static PrometheusMeterRegistry meterRegistry;
    private static HttpServer server;

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

            meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

            new JvmMemoryMetrics().bindTo(meterRegistry);
            new JvmGcMetrics().bindTo(meterRegistry);
            new JvmHeapPressureMetrics().bindTo(meterRegistry);

            server = HttpServer.create(new InetSocketAddress(7001), 0);
            server.createContext("/prometheus", new com.sun.net.httpserver.HttpHandler() {
                @Override
                public void handle(com.sun.net.httpserver.HttpExchange httpExchange) throws IOException {
                    System.err.println("Prometheus scrape endpoint hit");
                    try {
                        String response = meterRegistry.scrape();
                        httpExchange.getResponseHeaders().set("Content-Type", TextFormat.CONTENT_TYPE_004);
                        httpExchange.sendResponseHeaders(200, response.length());
                        OutputStream os = httpExchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    } catch (Throwable e) {
                        System.err.println("Failed to scrape metrics: " + e.getMessage());
                        e.printStackTrace();
                        httpExchange.sendResponseHeaders(500, 0);
                    }
                }
            });

            // Thread server_thread = new Thread(server::start);
            // server_thread.setDaemon(true);
            server.start();
        } catch (Throwable e) {
            System.err.println("Failed to start Prometheus scrape endpoint: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
