package io.micrometer.agent.prometheus;

import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.prometheus.PrometheusConfig;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.prometheus.client.exporter.common.TextFormat;
import java.io.FileInputStream;
import java.lang.instrument.Instrumentation;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;

public class PrometheusAgent {
    private static PrometheusMeterRegistry meterRegistry;
    private static String METRICS_URL;
    private static ScheduledExecutorService scheduledExecutor;
    private static String NAMESPACE = "default";
    private static String APP_NAME;
    private static final Path KUBERNETES_NAMESPACE_FILE = Paths.get("/run/secrets/kubernetes.io/serviceaccount/namespace");
    private static boolean isValidAgentConfig = false;

    public static void premain(String agentArgs, Instrumentation inst) {
        readKubernetesNamespace();

        // Then parse app name from agent arguments
        isValidAgentConfig = parseAgentArgs(agentArgs);
        if (isValidAgentConfig) {
            runPrometheusScrapeEndpoint();
        }
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        readKubernetesNamespace();

        // Then parse app name from agent arguments
        isValidAgentConfig = parseAgentArgs(agentArgs);
        if (isValidAgentConfig) {
            runPrometheusScrapeEndpoint();
        }
    }

    private static boolean parseAgentArgs(String agentArgs) {
        // Validate agent arguments
        if (agentArgs == null || agentArgs.isEmpty()) {
            System.err.println("Error: App name must be specified using the format: app=<app>");
            return false;
        }

        // Split arguments by comma to support multiple key-value pairs
        String[] args = agentArgs.split(",");
        String appName = null;
        String metricsUrl = null;

        for (String arg : args) {
            // Trim whitespace and split on first '=' to handle potential extra spaces
            arg = arg.trim();
            String[] keyValue = arg.split("=", 2);
            
            if (keyValue.length != 2) {
                System.err.println("Error: Invalid argument format. Use: app=<app> or metrics_url=<url>");
                return false;
            }

            String key = keyValue[0].trim().toLowerCase();
            String value = keyValue[1].trim();

            switch (key) {
                case "app":
                    if (value.isEmpty()) {
                        System.err.println("Error: App name cannot be empty.");
                        return false;
                    }
                    appName = value;
                    break;
                case "metrics_url":
                    if (!value.isEmpty()) {
                        metricsUrl = value;
                    }
                    break;
                default:
                    System.err.println("Error: Unsupported argument '" + key + "'. Use 'app' or 'metrics_endpoint'.");
                    return false;
            }
        }

        // Check if app name is provided
        if (appName == null) {
            System.err.println("Error: App name must be specified using: app=<app>");
            return false;
        }
        if (metricsUrl == null) {
            System.err.println("Error: Metrics endpoint must be specified using: metrics_url=<url>");
            return false;
        }

        APP_NAME = appName;
        METRICS_URL = metricsUrl;
        return true;
    }

    private static void readKubernetesNamespace() {
        try {
            if (Files.exists(KUBERNETES_NAMESPACE_FILE)) {
                String namespace = new String(Files.readAllBytes(KUBERNETES_NAMESPACE_FILE)).trim();
                if (!namespace.isEmpty()) {
                    NAMESPACE = namespace;
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading Kubernetes namespace file: " + e.getMessage());
        }
    }

    private static void runPrometheusScrapeEndpoint() {
        try {
            if (Runtime.getRuntime().maxMemory() < 128 * 1024 * 1024) {
                return;
            }

            meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
            
            // Add common labels for namespace and app
            meterRegistry.config().commonTags(
                "namespace", NAMESPACE,
                "app", APP_NAME
            );

            new JvmMemoryMetrics().bindTo(meterRegistry);
            new JvmGcMetrics().bindTo(meterRegistry);
            // new JvmHeapPressureMetrics().bindTo(meterRegistry);

            // Schedule metrics sending every 30 seconds
            scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
            scheduledExecutor.scheduleAtFixedRate(PrometheusAgent::sendMetrics, 0, 30, TimeUnit.SECONDS);

        } catch (Throwable e) {
            //logToFile("Failed to start Prometheus scrape endpoint: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void sendMetrics() {
        try {
            //System.err.println("Sending metrics...");

            String metricsText = meterRegistry.scrape();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(METRICS_URL + NAMESPACE + "/" + APP_NAME))
                .header("Content-Type", TextFormat.CONTENT_TYPE_004)
                .POST(HttpRequest.BodyPublishers.ofString(metricsText))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                //System.err.println("Metrics sent successfully. Response code: " + response.statusCode());
            } else {
                System.err.println("Failed to send metrics. Response code: " + response.statusCode());
            }
        } catch (Exception e) {
            //System.err.println("Error sending metrics: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /* private static SSLContext createCustomTrustStoreSslContext() {
        try {
            // Load the certificate from the file
            FileInputStream certInputStream = new FileInputStream("/certs/tls.crt");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInputStream);
            certInputStream.close();

            // Create a KeyStore and add the certificate
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("server-cert", certificate);

            // Create a TrustManagerFactory with the custom TrustStore
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Create and return an SSLContext using the custom trust managers
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new java.security.SecureRandom());
            
            return sslContext;
        } catch (Exception e) {
            //System.err.println("Failed to create custom SSL context: " + e.getMessage());
            throw new RuntimeException("Failed to create custom SSL context", e);
        }
    } */

    private static final HttpClient httpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(Duration.ofSeconds(10))
        .build();
        // .sslContext(createCustomTrustStoreSslContext())

    // private static void logToFile(String message) {
    //     long processId = Long.parseLong(ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);
    //     try (FileWriter fw = new FileWriter("/tmp/agent.log", true)) {
    //         fw.write("[PID: " + processId + "] " + message + "\n");
    //         fw.flush();
    //     } catch (IOException e) {
    //         System.err.println("Failed to write to log file: " + e.getMessage());
    //     }
    // }
}
