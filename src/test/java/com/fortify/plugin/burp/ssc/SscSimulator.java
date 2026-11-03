package com.fortify.plugin.burp.ssc;

import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanEntry;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import com.fortify.plugin.spi.VulnerabilityAttribute;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Offline stand-in for the Fortify SSC plugin runtime.
 *
 * <p>It drives a {@link ParserPlugin} the same way SSC does (separate {@code parseScan} and
 * {@code parseVulnerabilities} passes over the uploaded artifact, each opening its own stream)
 * and enforces the contract SSC applies to parser output: unique non-empty IDs, every started
 * vulnerability completed exactly once, mandatory fields set, custom attributes declared by the
 * plugin and within the plugin-API length limits, and {@code completeScan()} invoked.</p>
 *
 * <p>It can be run from the command line against real Burp exports via
 * {@code ./gradlew verifyReport -Preport=/path/to/burp.xml} (or a ZIP with {@code scan.info}).</p>
 */
public final class SscSimulator {

    /** Upper bound used for vulnerability IDs; the plugin emits 32-char MD5 hex IDs. */
    static final int MAX_ID_LENGTH = 80;
    /** Conservative limit for core SSC string fields such as category and file name. */
    static final int MAX_CORE_FIELD_LENGTH = 255;

    private SscSimulator() {
    }

    /** Result of a simulated SSC ingestion. */
    public static final class Result {
        private final List<String> problems = new ArrayList<>();
        private final List<Map<String, Object>> vulnerabilities = new ArrayList<>();
        private final Map<String, Object> scan = new LinkedHashMap<>();
        private int completeScanCalls;

        public List<String> getProblems() {
            return Collections.unmodifiableList(problems);
        }

        public List<Map<String, Object>> getVulnerabilities() {
            return Collections.unmodifiableList(vulnerabilities);
        }

        public Map<String, Object> getScan() {
            return Collections.unmodifiableMap(scan);
        }

        public boolean isOk() {
            return problems.isEmpty();
        }

        /** Number of vulnerabilities per Fortify priority. */
        public Map<String, Integer> priorityCounts() {
            Map<String, Integer> counts = new TreeMap<>();
            for (Map<String, Object> v : vulnerabilities) {
                counts.merge(String.valueOf(v.get("setPriority")), 1, Integer::sum);
            }
            return counts;
        }
    }

    /** Reads the uploaded artifact: either a ZIP (as uploaded to SSC) or a bare Burp XML file. */
    public static Map<String, byte[]> readArtifact(Path file) throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        Map<String, byte[]> entries = new LinkedHashMap<>();
        boolean isZip = bytes.length > 4 && bytes[0] == 'P' && bytes[1] == 'K';
        if (!isZip) {
            entries.put("scan.info", "engineType=BURP\n".getBytes(StandardCharsets.UTF_8));
            entries.put(file.getFileName().toString(), bytes);
            return entries;
        }
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (!e.isDirectory()) {
                    entries.put(e.getName(), zis.readAllBytes());
                }
            }
        }
        return entries;
    }

    /** Runs a full simulated SSC ingestion of the given artifact entries. */
    public static Result run(ParserPlugin<?> plugin, Map<String, byte[]> entries, String expectedEngineType)
            throws Exception {
        Result result = new Result();

        byte[] scanInfo = entries.get("scan.info");
        if (scanInfo == null) {
            result.problems.add("Artifact has no /scan.info entry; SSC will not route it to a parser");
        } else {
            Properties p = new Properties();
            p.load(new ByteArrayInputStream(scanInfo));
            String engineType = p.getProperty("engineType");
            if (!expectedEngineType.equals(engineType)) {
                result.problems.add("scan.info engineType '" + engineType + "' does not match plugin engine-type '"
                        + expectedEngineType + "'");
            }
        }

        ScanData scanData = new InMemoryScanData(entries);
        plugin.start();
        try {
            plugin.parseScan(scanData, recordingScanBuilder(result));
            if (result.completeScanCalls != 1) {
                result.problems.add("completeScan() called " + result.completeScanCalls + " times (expected 1)");
            }
            if (result.scan.get("setScanDate") == null) {
                result.problems.add("Scan date was not set");
            }
            parseVulnerabilities(plugin, scanData, result);
        } finally {
            plugin.stop();
        }
        return result;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void parseVulnerabilities(ParserPlugin<?> plugin, ScanData scanData, Result result)
            throws Exception {
        Class attrClass = plugin.getVulnerabilityAttributesClass();
        Set<VulnerabilityAttribute> declared = new HashSet<>(EnumSet.allOf(attrClass));
        Set<String> ids = new HashSet<>();
        List<Map<String, Object>> open = new ArrayList<>();

        VulnerabilityHandler handler = id -> {
            if (id == null || id.isEmpty()) {
                result.problems.add("Vulnerability started with an empty ID");
            } else if (id.length() > MAX_ID_LENGTH) {
                result.problems.add("Vulnerability ID longer than " + MAX_ID_LENGTH + " chars: " + id);
            }
            if (!ids.add(id)) {
                result.problems.add("Duplicate vulnerability ID within one scan (SSC rejects the scan): " + id);
            }
            Map<String, Object> vuln = new LinkedHashMap<>();
            vuln.put("id", id);
            open.add(vuln);
            return recordingVulnerabilityBuilder(vuln, declared, result, open);
        };
        plugin.parseVulnerabilities(scanData, handler);

        for (Map<String, Object> v : open) {
            result.problems.add("Vulnerability " + v.get("id") + " was started but never completed");
        }
    }

    private static ScanBuilder recordingScanBuilder(Result result) {
        return (ScanBuilder) Proxy.newProxyInstance(SscSimulator.class.getClassLoader(),
                new Class<?>[] {ScanBuilder.class}, (proxy, method, args) -> {
                    if ("completeScan".equals(method.getName())) {
                        result.completeScanCalls++;
                        return null;
                    }
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method, args);
                    }
                    result.scan.put(method.getName(), args == null ? null : args[0]);
                    return proxy;
                });
    }

    private static StaticVulnerabilityBuilder recordingVulnerabilityBuilder(Map<String, Object> vuln,
            Set<VulnerabilityAttribute> declared, Result result, List<Map<String, Object>> open) {
        Map<String, String> customAttributes = new LinkedHashMap<>();
        vuln.put("customAttributes", customAttributes);
        boolean[] completed = {false};
        InvocationHandler h = (proxy, method, args) -> {
            String name = method.getName();
            if (method.getDeclaringClass() == Object.class) {
                return objectMethod(proxy, method, args);
            }
            if (completed[0]) {
                result.problems.add("Builder for " + vuln.get("id") + " used after completeVulnerability(): " + name);
            }
            switch (name) {
                case "completeVulnerability":
                    completed[0] = true;
                    open.remove(vuln);
                    validateVulnerability(vuln, result);
                    result.vulnerabilities.add(vuln);
                    return null;
                case "setStringCustomAttributeValue":
                case "setDecimalCustomAttributeValue":
                case "setDateCustomAttributeValue":
                    VulnerabilityAttribute attr = (VulnerabilityAttribute) args[0];
                    validateCustomAttribute(vuln, attr, args[1], declared, result);
                    customAttributes.put(attr.attributeName(), args[1] == null ? null : String.valueOf(args[1]));
                    return proxy;
                default:
                    vuln.put(name, args == null ? null : args[0]);
                    return proxy;
            }
        };
        return (StaticVulnerabilityBuilder) Proxy.newProxyInstance(SscSimulator.class.getClassLoader(),
                new Class<?>[] {StaticVulnerabilityBuilder.class}, h);
    }

    private static void validateCustomAttribute(Map<String, Object> vuln, VulnerabilityAttribute attr, Object value,
            Set<VulnerabilityAttribute> declared, Result result) {
        if (!declared.contains(attr)) {
            result.problems.add(vuln.get("id") + ": custom attribute " + attr + " is not declared by the plugin");
            return;
        }
        if (value instanceof String) {
            int max = attr.attributeType() == VulnerabilityAttribute.AttrType.LONG_STRING
                    ? VulnerabilityAttribute.MAX_LONG_STRING_LENGTH
                    : VulnerabilityAttribute.MAX_STRING_LENGTH;
            int len = ((String) value).length();
            if (len > max) {
                result.problems.add(vuln.get("id") + ": custom attribute " + attr.attributeName() + " is " + len
                        + " chars (max " + max + " for " + attr.attributeType() + ")");
            }
        }
    }

    private static void validateVulnerability(Map<String, Object> vuln, Result result) {
        Object id = vuln.get("id");
        Object category = vuln.get("setCategory");
        if (category == null || String.valueOf(category).isEmpty()) {
            result.problems.add(id + ": category is missing (SSC shows no issue name)");
        }
        if (!(vuln.get("setPriority") instanceof BasicVulnerabilityBuilder.Priority)) {
            result.problems.add(id + ": priority is missing");
        }
        Object fileName = vuln.get("setFileName");
        if (fileName == null || String.valueOf(fileName).isEmpty()) {
            result.problems.add(id + ": file name is missing");
        }
        for (String f : new String[] {"setCategory", "setFileName"}) {
            Object v = vuln.get(f);
            if (v != null && String.valueOf(v).length() > MAX_CORE_FIELD_LENGTH) {
                result.problems.add(id + ": " + f + " exceeds " + MAX_CORE_FIELD_LENGTH + " chars");
            }
        }
        checkRange(vuln, "setConfidence", 0f, 5f, result);
        checkRange(vuln, "setImpact", 0f, 5f, result);
    }

    private static void checkRange(Map<String, Object> vuln, String key, float min, float max, Result result) {
        Object v = vuln.get(key);
        if (v instanceof Float && ((Float) v < min || (Float) v > max)) {
            result.problems.add(vuln.get("id") + ": " + key + " " + v + " outside [" + min + ", " + max + "]");
        }
    }

    private static Object objectMethod(Object proxy, Method method, Object[] args) {
        switch (method.getName()) {
            case "equals":
                return proxy == args[0];
            case "hashCode":
                return System.identityHashCode(proxy);
            default:
                return "SscSimulatorProxy";
        }
    }

    /** {@link ScanData} backed by in-memory artifact entries, mirroring SSC's entry lookup. */
    static final class InMemoryScanData implements ScanData {
        private final Map<String, byte[]> entries;

        InMemoryScanData(Map<String, byte[]> entries) {
            this.entries = entries;
        }

        @Override
        public String getSessionId() {
            return "ssc-simulator";
        }

        @Override
        public List<ScanEntry> getScanEntries() {
            List<ScanEntry> list = new ArrayList<>();
            for (String name : entries.keySet()) {
                list.add(() -> name);
            }
            return list;
        }

        @Override
        public InputStream getInputStream(ScanEntry entry) {
            byte[] b = entries.get(entry.getEntryName());
            return b == null ? null : new ByteArrayInputStream(b);
        }

        @Override
        public InputStream getInputStream(Predicate<String> matcher) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                if (matcher.test(e.getKey())) {
                    return new ByteArrayInputStream(e.getValue());
                }
            }
            return null;
        }

        @Override
        public URL getUrl(ScanEntry entry) {
            return null;
        }
    }

    /**
     * Command-line entry point: {@code SscSimulator <burp.xml|artifact.zip>...}.
     * Prints a summary per file and exits non-zero if any SSC contract problem is found.
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: ./gradlew verifyReport -Preport=/path/to/burp.xml[,/other.zip]");
            System.exit(2);
        }
        // Discover the plugin exactly like SSC does: via META-INF/services in the plugin JAR.
        ParserPlugin<?> discovered = null;
        for (ParserPlugin<?> p : java.util.ServiceLoader.load(ParserPlugin.class)) {
            discovered = p;
        }
        if (discovered == null) {
            System.err.println("No ParserPlugin registered via META-INF/services on the classpath");
            System.exit(1);
        }
        Class<?> pluginClass = discovered.getClass();
        URL source = pluginClass.getProtectionDomain().getCodeSource().getLocation();
        System.out.printf(Locale.ROOT, "Plugin         : %s%n", pluginClass.getName());
        System.out.printf(Locale.ROOT, "Loaded from    : %s%n", source);
        Path sourcePath = Paths.get(source.toURI());
        if (Files.isRegularFile(sourcePath)) {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(sourcePath));
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                hex.append(String.format(Locale.ROOT, "%02x", b));
            }
            System.out.printf(Locale.ROOT, "JAR SHA-256    : %s%n", hex);
        }
        boolean allOk = true;
        for (String arg : args) {
            for (String file : arg.split(",")) {
                Path path = Paths.get(file.trim());
                Result r = run(pluginClass.asSubclass(ParserPlugin.class).getDeclaredConstructor().newInstance(),
                        readArtifact(path), "BURP");
                System.out.printf(Locale.ROOT, "%n=== %s%n", path);
                System.out.printf(Locale.ROOT, "Engine version : %s%n", r.getScan().get("setEngineVersion"));
                System.out.printf(Locale.ROOT, "Issues ingested: %d %s%n", r.getVulnerabilities().size(),
                        r.priorityCounts());
                if (r.isOk()) {
                    System.out.println("Result         : OK - output satisfies the SSC parser contract");
                } else {
                    allOk = false;
                    System.out.printf(Locale.ROOT, "Result         : %d PROBLEM(S)%n", r.getProblems().size());
                    r.getProblems().stream().limit(50).forEach(p -> System.out.println("  - " + p));
                }
            }
        }
        System.exit(allOk ? 0 : 1);
    }
}
