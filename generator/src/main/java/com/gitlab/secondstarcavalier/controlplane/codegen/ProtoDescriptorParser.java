package com.gitlab.secondstarcavalier.controlplane.codegen;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.Stream;

/**
 * Parses proto files using regex to extract messages, fields, services, and RPCs.
 * Designed to work with the flattened proto files output by tacplus.
 */
public class ProtoDescriptorParser {

    private final Path protoDir;
    private final Map<String, FileDescriptor> descriptors = new LinkedHashMap<>();

    // Regex patterns
    private static final Pattern PACKAGE_PATTERN = Pattern.compile("^\\s*package\\s+(\\S+)\\s*;", Pattern.MULTILINE);
    private static final Pattern JAVA_OUTER_CLASSNAME = Pattern.compile(
            "^\\s*option\\s+java_outer_classname\\s*=\\s*\"([^\"]+)\"\\s*;", Pattern.MULTILINE);
    private static final Pattern JAVA_PACKAGE = Pattern.compile(
            "^\\s*option\\s+java_package\\s*=\\s*\"([^\"]+)\"\\s*;", Pattern.MULTILINE);
    private static final Pattern MESSAGE_START = Pattern.compile("^\\s*message\\s+(\\w+)\\s*\\{", Pattern.MULTILINE);
    private static final Pattern MESSAGE_OPTION = Pattern.compile(
            "^\\s*option\\s+\\(spec\\.(\\w+)\\)\\s*=\\s*([^;]+)\\s*;", Pattern.MULTILINE);
    private static final Pattern FIELD_PATTERN = Pattern.compile(
            "^\\s*(repeated\\s+)?(\\S+)\\s+(\\w+)\\s*=\\s*\\d+\\s*([^;]*);", Pattern.MULTILINE);
    private static final Pattern FIELD_ANNOTATION = Pattern.compile(
            "\\(spec\\.(\\w+)\\)\\s*=\\s*(\\w+|\"[^\"]*\"|true|false|\\{[^}]*\\})");
    private static final Pattern SERVICE_START = Pattern.compile("^\\s*service\\s+(\\w+)\\s*\\{", Pattern.MULTILINE);
    private static final Pattern RPC_PATTERN = Pattern.compile(
            "^\\s*rpc\\s+(\\w+)\\s*\\(([^)]+)\\)\\s+returns\\s+\\((stream\\s+)?([^)]+)\\)\\s*;", Pattern.MULTILINE);
    // Pattern for parsing structured annotation values like {target: "foo", mode: BAR}
    private static final Pattern STRUCT_FIELD_PATTERN = Pattern.compile(
            "(\\w+)\\s*:\\s*(\"[^\"]*\"|\\w+)");

    public ProtoDescriptorParser(Path protoDir) {
        this.protoDir = protoDir;
    }

    /**
     * Parses all .proto files in the given directory recursively.
     * Skips google/ directory (vendored protos).
     */
    public void parseAll() throws IOException {
        try (Stream<Path> paths = Files.walk(protoDir)) {
            paths.filter(p -> p.toString().endsWith(".proto"))
                 .filter(p -> !p.toString().contains("/google/"))
                 .forEach(this::parseFile);
        }
    }

    private void parseFile(Path path) {
        try {
            String content = Files.readString(path);
            String relPath = protoDir.relativize(path).toString();

            FileDescriptor fd = new FileDescriptor();
            fd.setPath(relPath);

            // Package
            Matcher m = PACKAGE_PATTERN.matcher(content);
            if (m.find()) {
                fd.setPackageName(m.group(1));
            }

            // java_outer_classname
            m = JAVA_OUTER_CLASSNAME.matcher(content);
            if (m.find()) {
                fd.setJavaOuterClassname(m.group(1));
            }

            // java_package
            m = JAVA_PACKAGE.matcher(content);
            if (m.find()) {
                fd.setJavaPackage(m.group(1));
            }

            // Parse messages with their fields
            parseMessages(content, fd);

            // Parse services with their RPCs
            parseServices(content, fd);

            descriptors.put(relPath, fd);
        } catch (IOException e) {
            // Skip files that can't be read
        }
    }

    private void parseMessages(String content, FileDescriptor fd) {
        Matcher msgStart = MESSAGE_START.matcher(content);
        while (msgStart.find()) {
            String msgName = msgStart.group(1);
            int openBrace = msgStart.end() - 1;
            int closeBrace = findMatchingBrace(content, openBrace);
            if (closeBrace < 0) continue;

            String msgBody = content.substring(openBrace + 1, closeBrace);
            MessageDescriptor msg = new MessageDescriptor();
            msg.setName(msgName);

            // Parse message-level options
            Matcher optMatcher = MESSAGE_OPTION.matcher(msgBody);
            while (optMatcher.find()) {
                String optName = optMatcher.group(1);
                String optValue = optMatcher.group(2).trim();
                if (optValue.startsWith("{") && optValue.endsWith("}")) {
                    // Structured annotation like {target: "foo", mode: BAR}
                    // These can be repeated (e.g. multiple backend_perms)
                    AnnotationValue av = parseStructValue(optValue);
                    msg.addRepeatedAnnotation(optName, av);
                } else if (optValue.startsWith("\"") && optValue.endsWith("\"")) {
                    optValue = optValue.substring(1, optValue.length() - 1);
                    msg.getAnnotations().put(optName, AnnotationValue.ofString(optValue));
                } else if (optValue.equals("true") || optValue.equals("false")) {
                    msg.getAnnotations().put(optName, AnnotationValue.ofBool(Boolean.parseBoolean(optValue)));
                } else {
                    msg.getAnnotations().put(optName, AnnotationValue.ofEnum(optValue));
                }
            }

            parseFields(msgBody, msg, fd.getPackageName());
            fd.getMessages().add(msg);
        }
    }

    private static final Pattern SERVICE_OPTION_PATTERN = Pattern.compile(
            "^\\s*option\\s+\\(spec\\.(\\w+)\\)\\s*=\\s*\"([^\"]+)\"\\s*;", Pattern.MULTILINE);

    private void parseServices(String content, FileDescriptor fd) {
        Matcher svcStart = SERVICE_START.matcher(content);
        while (svcStart.find()) {
            String svcName = svcStart.group(1);
            int openBrace = svcStart.end() - 1;
            int closeBrace = findMatchingBrace(content, openBrace);
            if (closeBrace < 0) continue;

            String svcBody = content.substring(openBrace + 1, closeBrace);
            ServiceDescriptor svc = new ServiceDescriptor();
            svc.setName(svcName);

            // Parse service-level options (e.g., service_grpc)
            Matcher optMatcher = SERVICE_OPTION_PATTERN.matcher(svcBody);
            while (optMatcher.find()) {
                String optName = optMatcher.group(1);
                String optValue = optMatcher.group(2);
                if ("service_grpc".equals(optName)) {
                    svc.setBackendRpcName(optValue);
                }
            }

            Matcher rpcMatcher = RPC_PATTERN.matcher(svcBody);
            while (rpcMatcher.find()) {
                RpcDescriptor rpc = new RpcDescriptor();
                rpc.setName(rpcMatcher.group(1));
                rpc.setInputType(rpcMatcher.group(2).trim());
                rpc.setServerStreaming(rpcMatcher.group(3) != null);
                rpc.setOutputType(rpcMatcher.group(4).trim());
                svc.getRpcs().add(rpc);
            }

            fd.getServices().add(svc);
        }
    }

    private void parseFields(String msgBody, MessageDescriptor msg, String packageName) {
        // Collapse multi-line field definitions (e.g. annotations spanning multiple lines)
        msgBody = collapseMultiLineFields(msgBody);
        String[] lines = msgBody.split("\n");
        int braceDepth = 0;

        for (String line : lines) {
            String trimmed = line.trim();

            // Track nested message/enum brace depth
            if (trimmed.startsWith("message ") || trimmed.startsWith("enum ")) {
                if (trimmed.contains("{")) braceDepth++;
                continue;
            }
            for (char c : trimmed.toCharArray()) {
                if (c == '{') braceDepth++;
                else if (c == '}') braceDepth--;
            }
            if (braceDepth > 0) continue;

            // Skip option lines, comments, empty lines
            if (trimmed.startsWith("option ") || trimmed.startsWith("//") || trimmed.isEmpty()
                    || trimmed.startsWith("reserved") || trimmed.equals("}")) {
                continue;
            }

            Matcher fieldMatch = FIELD_PATTERN.matcher(trimmed);
            if (fieldMatch.find()) {
                boolean repeated = fieldMatch.group(1) != null;
                String type = fieldMatch.group(2);
                String name = fieldMatch.group(3);
                String rest = fieldMatch.group(4);

                if (type.equals("map") || type.equals("oneof")) continue;

                FieldDescriptor field = new FieldDescriptor();
                field.setName(name);
                field.setType(type);
                field.setRepeated(repeated);
                field.setTypeKind(isScalar(type) ? "scalar" : "message");

                // Parse annotations
                if (rest != null) {
                    Matcher annMatcher = FIELD_ANNOTATION.matcher(rest);
                    while (annMatcher.find()) {
                        String annName = annMatcher.group(1);
                        String annValue = annMatcher.group(2);
                        if (annValue.startsWith("{") && annValue.endsWith("}")) {
                            // Structured annotation like {target: "foo", mode: BAR}
                            AnnotationValue av = parseStructValue(annValue);
                            field.addRepeatedAnnotation(annName, av);
                        } else if (annValue.startsWith("\"") && annValue.endsWith("\"")) {
                            annValue = annValue.substring(1, annValue.length() - 1);
                            field.getAnnotations().put(annName, AnnotationValue.ofString(annValue));
                        } else if (annValue.equals("true") || annValue.equals("false")) {
                            field.getAnnotations().put(annName, AnnotationValue.ofBool(Boolean.parseBoolean(annValue)));
                        } else {
                            field.getAnnotations().put(annName, AnnotationValue.ofEnum(annValue));
                        }
                    }
                }

                msg.getFields().add(field);
            }
        }
    }

    /**
     * Parses a structured annotation value like {target: "foo", mode: BAR}
     * into an AnnotationValue.ofStruct(Map).
     */
    private static AnnotationValue parseStructValue(String structStr) {
        Map<String, String> fields = new LinkedHashMap<>();
        Matcher m = STRUCT_FIELD_PATTERN.matcher(structStr);
        while (m.find()) {
            String key = m.group(1);
            String value = m.group(2);
            if (value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }
            fields.put(key, value);
        }
        return AnnotationValue.ofStruct(fields);
    }

    /**
     * Collapses multi-line field definitions into single lines.
     * Handles fields with annotations spanning multiple lines, e.g.:
     *   repeated jwk.Jwk keys = 1 [
     *     (spec.consistency) = CONSISTENCY_CONVERGENT,
     *     (spec.persistence) = true
     *   ];
     * becomes a single line.
     */
    private static String collapseMultiLineFields(String body) {
        StringBuilder result = new StringBuilder();
        StringBuilder pending = null;
        int bracketDepth = 0;

        for (String line : body.split("\n")) {
            if (pending != null) {
                pending.append(" ").append(line.trim());
                for (char c : line.toCharArray()) {
                    if (c == '[') bracketDepth++;
                    else if (c == ']') bracketDepth--;
                }
                if (bracketDepth <= 0) {
                    result.append(pending).append("\n");
                    pending = null;
                    bracketDepth = 0;
                }
            } else {
                String trimmed = line.trim();
                // Detect a field line that opens a bracket but doesn't close it
                if (trimmed.contains("[") && !trimmed.contains("]") && trimmed.contains("=")
                        && !trimmed.startsWith("option ") && !trimmed.startsWith("//")
                        && !trimmed.startsWith("message ") && !trimmed.startsWith("enum ")) {
                    pending = new StringBuilder(trimmed);
                    bracketDepth = 0;
                    for (char c : trimmed.toCharArray()) {
                        if (c == '[') bracketDepth++;
                        else if (c == ']') bracketDepth--;
                    }
                } else {
                    result.append(line).append("\n");
                }
            }
        }
        if (pending != null) {
            result.append(pending).append("\n");
        }
        return result.toString();
    }

    private static boolean isScalar(String type) {
        return switch (type) {
            case "double", "float", "int32", "int64", "uint32", "uint64",
                 "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64",
                 "bool", "string", "bytes" -> true;
            default -> false;
        };
    }

    private static int findMatchingBrace(String content, int openBracePos) {
        int depth = 1;
        for (int i = openBracePos + 1; i < content.length(); i++) {
            char c = content.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    public FileDescriptor getFileDescriptor(String path) {
        FileDescriptor fd = descriptors.get(path);
        if (fd != null) return fd;

        String baseName = path.contains("/") ? path.substring(path.lastIndexOf('/') + 1) : path;
        for (var entry : descriptors.entrySet()) {
            if (entry.getKey().endsWith("/" + baseName) || entry.getKey().equals(baseName)) {
                return entry.getValue();
            }
        }
        return null;
    }

    public Map<String, FileDescriptor> getAllFiles() {
        return Collections.unmodifiableMap(descriptors);
    }

    /** Finds a message by name across all parsed files. */
    public MessageDescriptor findMessage(String packageName, String typeName) {
        for (FileDescriptor fd : descriptors.values()) {
            if (fd.getPackageName() != null && fd.getPackageName().equals(packageName)) {
                for (MessageDescriptor msg : fd.getMessages()) {
                    if (msg.getName().equals(typeName)) {
                        return msg;
                    }
                }
            }
        }
        return null;
    }

    /** Finds a message by simple name (unqualified) across all parsed files. */
    public MessageDescriptor findMessageByName(String typeName) {
        for (FileDescriptor fd : descriptors.values()) {
            for (MessageDescriptor msg : fd.getMessages()) {
                if (msg.getName().equals(typeName)) {
                    return msg;
                }
            }
        }
        return null;
    }

    /** Finds the directory path for a given package name. */
    public String resolveTypeDir(String pkg) {
        for (var entry : descriptors.entrySet()) {
            FileDescriptor fd = entry.getValue();
            if (fd.getPackageName() != null && fd.getPackageName().equals(pkg)) {
                String path = entry.getKey();
                int slash = path.indexOf('/');
                if (slash > 0) {
                    return path.substring(0, slash);
                }
            }
        }
        return "libs";
    }
}
