package com.gitlab.secondstarcavalier.controlplane.codegen;

/**
 * String case conversion utilities matching Go tacplus strutil behavior.
 */
public final class StringUtils {

    private StringUtils() {}

    /** Converts PascalCase/camelCase to snake_case: "FooBar" → "foo_bar" */
    public static String toSnakeCase(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (i > 0 && Character.isUpperCase(c)) {
                sb.append('_');
            }
            sb.append(Character.toLowerCase(c));
        }
        return sb.toString();
    }

    /** Converts snake_case or kebab-case to PascalCase: "foo_bar" → "FooBar", "iron-maiden" → "IronMaiden" */
    public static String toPascalCase(String s) {
        String[] parts = s.split("[_\\-]");
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (!part.isEmpty()) {
                sb.append(Character.toUpperCase(part.charAt(0)));
                sb.append(part.substring(1));
            }
        }
        return sb.toString();
    }

    /** Converts PascalCase to lowerCamelCase, or snake_case/kebab-case to lowerCamelCase */
    public static String toLowerCamelCase(String s) {
        if (s.isEmpty()) return s;
        if (s.contains("_") || s.contains("-")) {
            String[] parts = s.split("[_\\-]");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].isEmpty()) continue;
                if (i == 0) {
                    sb.append(parts[i].toLowerCase());
                } else {
                    sb.append(Character.toUpperCase(parts[i].charAt(0)));
                    sb.append(parts[i].substring(1));
                }
            }
            return sb.toString();
        }
        return Character.toLowerCase(s.charAt(0)) + s.substring(1);
    }

    /** Extracts the simple type name from a potentially qualified name: "ballsports.EmployeeSalary" → "EmployeeSalary" */
    public static String extractSimpleTypeName(String fullType) {
        int dot = fullType.lastIndexOf('.');
        return dot >= 0 ? fullType.substring(dot + 1) : fullType;
    }
}
