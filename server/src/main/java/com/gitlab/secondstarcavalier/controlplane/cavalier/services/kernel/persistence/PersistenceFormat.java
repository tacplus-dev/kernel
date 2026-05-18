// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.persistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serialization format for redo log entries.
 *
 * <p>{@code PROTO_WIRE} is the default length-prefixed binary protobuf format.
 * {@code NDJSON} writes one JSON object per line for human-readable debugging.
 */
public enum PersistenceFormat {
	PROTO_WIRE,
	NDJSON;

	private static final Logger logger = LoggerFactory.getLogger(PersistenceFormat.class);

	/**
	 * Parses a format string (case-insensitive). Returns {@code PROTO_WIRE}
	 * if the value is unrecognized.
	 */
	public static PersistenceFormat fromString(String value) {
		try {
			return valueOf(value.toUpperCase());
		} catch (IllegalArgumentException e) {
			logger.warn("Unknown persistence format '{}', defaulting to PROTO_WIRE", value);
			return PROTO_WIRE;
		}
	}
}
