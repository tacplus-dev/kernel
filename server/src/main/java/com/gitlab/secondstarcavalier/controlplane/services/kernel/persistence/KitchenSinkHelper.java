// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass.KitchenSink;
import com.google.protobuf.Descriptors;
import com.google.protobuf.MessageLite;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper for mapping between Hazelcast map names and KitchenSink oneof
 * payload fields.
 *
 * <p>The oneof field names follow the pattern {@code {package}_{snake_type}},
 * e.g., {@code baseball_team_roster} for the {@code baseball.TeamRoster} type.
 * Map names in kernel follow the pattern {@code {Service}_{FieldName}},
 * e.g., {@code BaseballState_roster}.
 *
 * <p>This helper builds a lookup table at class load time by inspecting the
 * KitchenSink descriptor.
 */
public final class KitchenSinkHelper {

    /**
     * Map from proto type URL (full name) to the corresponding oneof field descriptor.
     */
    private static final Map<String, Descriptors.FieldDescriptor> TYPE_TO_FIELD = new HashMap<>();

    static {
        Descriptors.OneofDescriptor payloadOneof = KitchenSink.getDescriptor().getOneofs().stream()
                .filter(o -> o.getName().equals("payload"))
                .findFirst()
                .orElse(null);
        if (payloadOneof != null) {
            for (Descriptors.FieldDescriptor fd : payloadOneof.getFields()) {
                if (fd.getType() == Descriptors.FieldDescriptor.Type.MESSAGE) {
                    TYPE_TO_FIELD.put(fd.getMessageType().getFullName(), fd);
                }
            }
        }
    }

    private KitchenSinkHelper() {}

    /**
     * Sets the typed payload on a KitchenSink builder based on the message type.
     * Uses the protobuf descriptor to find the matching oneof field.
     *
     * @return true if the payload was set successfully (type found in oneof),
     *         false if the type is not in the KitchenSink oneof
     */
    public static boolean setPayload(KitchenSink.Builder builder, String mapName, MessageLite msg) {
        if (msg instanceof com.google.protobuf.Message fullMsg) {
            String typeName = fullMsg.getDescriptorForType().getFullName();
            Descriptors.FieldDescriptor fd = TYPE_TO_FIELD.get(typeName);
            if (fd != null) {
                builder.setField(fd, fullMsg);
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the typed payload from a KitchenSink message.
     * Returns the active oneof field value, or null if no payload is set.
     */
    public static MessageLite getPayload(KitchenSink ks) {
        KitchenSink.PayloadCase payloadCase = ks.getPayloadCase();
        if (payloadCase == KitchenSink.PayloadCase.PAYLOAD_NOT_SET) {
            return null;
        }
        Descriptors.FieldDescriptor fd = ks.getDescriptorForType().findFieldByNumber(payloadCase.getNumber());
        if (fd != null) {
            Object value = ks.getField(fd);
            if (value instanceof MessageLite ml) {
                return ml;
            }
        }
        return null;
    }
}
