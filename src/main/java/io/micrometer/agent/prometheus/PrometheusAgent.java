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
import java.io.BufferedReader;
import java.io.StringReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;

public class PrometheusAgent {
    private static PrometheusMeterRegistry meterRegistry;
    private static String METRICS_URL;
    private static Thread metricsDaemonThread;
    private static String NAMESPACE;
    private static String POD_NAME;

    public static void premain(String agentArgs, Instrumentation inst) {
        // readKubernetesNamespace();

        // Then parse app name from agent arguments
        boolean isValidAgentConfig = parseAgentArgs(agentArgs);
        if (isValidAgentConfig) {
            runPrometheusScrapeEndpoint();
        }
    }

    /*public static void agentmain(String agentArgs, Instrumentation inst) {
        readKubernetesNamespace();

        // Then parse pod name from agent arguments
        boolean isValidAgentConfig = parseAgentArgs(agentArgs);
        if (isValidAgentConfig) {
            runPrometheusScrapeEndpoint();
        }
    }*/

    private static boolean parseAgentArgs(String agentArgs) {
        // Validate agent arguments
        if (agentArgs == null || agentArgs.isEmpty()) {
            System.err.println("Error: Pod name must be specified using the format: pod=<pod>");
            return false;
        }

        // Split arguments by comma to support multiple key-value pairs
        String[] args = agentArgs.split(",");
        String podName = null;
        String metricsUrl = null;
        String namespace = null;

        for (String arg : args) {
            // Trim whitespace and split on first '=' to handle potential extra spaces
            arg = arg.trim();
            String[] keyValue = arg.split("=", 2);
            
            if (keyValue.length != 2) {
                System.err.println("Error: Invalid argument format. Use: pod=<pod> or metrics_url=<url>");
                return false;
            }

            String key = keyValue[0].trim().toLowerCase();
            String value = keyValue[1].trim();

            switch (key) {
                case "namespace":
                    if (value.isEmpty()) {
                        System.err.println("Error: Namespace cannot be empty.");
                        return false;
                    }
                    namespace = value;
                    break;
                case "pod":
                    if (value.isEmpty()) {
                        System.err.println("Error: Pod name cannot be empty.");
                        return false;
                    }
                    podName = value;
                    break;
                case "metrics_url":
                    if (!value.isEmpty()) {
                        metricsUrl = value;
                    }
                    break;
                default:
                    System.err.println("Error: Unsupported argument '" + key + "'. Use 'pod' or 'metrics_url'.");
                    return false;
            }
        }

        // Check if pod name is provided
        if (podName == null) {
            System.err.println("Error: Pod name must be specified using: pod=<pod>");
            return false;
        }
        if (metricsUrl == null) {
            System.err.println("Error: Metrics endpoint must be specified using: metrics_url=<url>");
            return false;
        }

        NAMESPACE = namespace;
        POD_NAME = podName;
        METRICS_URL = metricsUrl;
        return true;
    }

    /*private static void readKubernetesNamespace() {
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
    }*/

    private static void runPrometheusScrapeEndpoint() {
        try {
            if (Runtime.getRuntime().maxMemory() < 128 * 1024 * 1024) {
                System.err.println("Less than 128MB of memory available, skipping metrics collection");
                return;
            }

            meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
            
            // Add common labels for namespace and pod
            meterRegistry.config().commonTags(
                "namespace", NAMESPACE,
                "pod", POD_NAME
            );

            new JvmMemoryMetrics().bindTo(meterRegistry);
            new JvmGcMetrics().bindTo(meterRegistry);
            // new JvmHeapPressureMetrics().bindTo(meterRegistry);

            // Schedule metrics sending every 30 seconds using a daemon thread
            metricsDaemonThread = new Thread(() -> {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        sendMetrics();
                        Thread.sleep(TimeUnit.SECONDS.toMillis(30));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
            metricsDaemonThread.setDaemon(true);
            metricsDaemonThread.start();

        } catch (Throwable e) {
            //logToFile("Failed to start Prometheus scrape endpoint: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void sendMetrics() {
        try {
            StringBuilder timestampedMetrics = new StringBuilder();
            long timestampMillis = System.currentTimeMillis();

            try (BufferedReader reader = new BufferedReader(new StringReader(meterRegistry.scrape()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Only add timestamp to metric lines, not comments
                    if (!line.startsWith("#") && !line.trim().isEmpty()) {
                        timestampedMetrics.append(line).append(" ").append(timestampMillis).append("\n");
                    } else {
                        timestampedMetrics.append(line).append("\n");
                    }
                }
            }

            String metricsText = timestampedMetrics.toString();
            // System.err.println("Metrics text: " + metricsText);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(METRICS_URL + NAMESPACE + "/" + POD_NAME))
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
