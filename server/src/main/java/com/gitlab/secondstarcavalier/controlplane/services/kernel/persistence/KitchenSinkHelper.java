// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast.PersistenceEntry;
import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.MessageLite;
import com.google.protobuf.Parser;

/**
 * Helper for packing and unpacking protobuf messages into
 * {@link PersistenceEntry} records using {@link Any}.
 */
public final class KitchenSinkHelper {

	private KitchenSinkHelper() {
	}

	/**
	 * Packs a protobuf message into the payload field of a PersistenceEntry
	 * builder.
	 *
	 * @return true if the payload was packed successfully, false if the message
	 *         is not a full {@link Message} (e.g. lite-only)
	 */
	public static boolean setPayload(PersistenceEntry.Builder builder, String mapName, MessageLite msg) {
		if (msg instanceof Message fullMsg) {
			builder.setPayload(Any.pack(fullMsg));
			return true;
		}
		return false;
	}

	/**
	 * Unpacks the payload from a PersistenceEntry using the given parser.
	 *
	 * @return the deserialized message, or null if no payload is set
	 */
	@SuppressWarnings("unchecked")
	public static <T extends Message> T getPayload(PersistenceEntry entry, Parser<T> parser)
			throws InvalidProtocolBufferException {
		if (!entry.hasPayload()) {
			return null;
		}
		return entry.getPayload().unpack((Class<T>) parser.parseFrom(new byte[0]).getClass());
	}

	/**
	 * Unpacks the payload from a PersistenceEntry as raw bytes using the parser
	 * registered in the MapRegistry.
	 *
	 * @return the deserialized message, or null if no payload or parser unavailable
	 */
	public static MessageLite getPayload(PersistenceEntry entry,
			com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.MapRegistry registry) {
		if (!entry.hasPayload()) {
			return null;
		}
		var info = registry.get(entry.getMapName());
		if (info == null || info.parser() == null) {
			return null;
		}
		try {
			return info.parser().parseFrom(entry.getPayload().getValue());
		} catch (InvalidProtocolBufferException e) {
			return null;
		}
	}
}
