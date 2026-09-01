// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IMap;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import com.google.protobuf.Parser;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Registry that tracks all persistent maps: their name, the underlying IMap,
 * the protobuf parser for their value type, and the consistency model.
 *
 * <p>
 * Populated at startup when {@code Manager.getConvergentMap()} is called.
 * The parser is initially null and detected lazily on the first write via
 * {@link #setParserIfAbsent(String, Parser)}.
 */
public class MapRegistry {

	private static final Logger logger = LoggerFactory.getLogger(MapRegistry.class);

	/** Metadata about a registered map. */
	public static class MapInfo {
		private final IMap<String, ?> map;
		private volatile Parser<? extends MessageLite> parser;
		private final ConsistencyType consistency;

		MapInfo(IMap<String, ?> map, Parser<? extends MessageLite> parser, ConsistencyType consistency) {
			this.map = map;
			this.parser = parser;
			this.consistency = consistency;
		}

		public IMap<String, ?> map() {
			return map;
		}

		public Parser<? extends MessageLite> parser() {
			return parser;
		}

		public ConsistencyType consistency() {
			return consistency;
		}
	}

	private final ConcurrentHashMap<String, MapInfo> maps = new ConcurrentHashMap<>();

	/**
	 * Registers a map with the given name, backing IMap, and consistency type.
	 * The parser can be null and set later via {@link #setParserIfAbsent}.
	 */
	@SuppressWarnings("unchecked")
	public void register(
			String name, IMap<?, ?> map, Parser<? extends MessageLite> parser, ConsistencyType consistency) {
		maps.put(name, new MapInfo((IMap<String, ?>) map, parser, consistency));
	}

	/**
	 * Registers a map without a parser (parser detected lazily on first write).
	 */
	@SuppressWarnings("unchecked")
	public void register(String name, IMap<?, ?> map, ConsistencyType consistency) {
		maps.put(name, new MapInfo((IMap<String, ?>) map, null, consistency));
	}

	/**
	 * Sets the parser for a map if not already set. Detected lazily when the
	 * first protobuf value is observed. Thread-safe.
	 */
	public void setParserIfAbsent(String name, Parser<? extends MessageLite> parser) {
		MapInfo info = maps.get(name);
		if (info != null && info.parser == null) {
			info.parser = parser;
			logger.debug("Lazily detected parser for map: {}", name);
		}
	}

	/** Returns the info for a registered map, or null if not registered. */
	public MapInfo get(String name) {
		return maps.get(name);
	}

	/** Returns all registered maps. */
	public Map<String, MapInfo> all() {
		return Collections.unmodifiableMap(maps);
	}

	/** Returns the number of registered maps. */
	public int size() {
		return maps.size();
	}

	/**
	 * Parses a protobuf value for a given map name.
	 *
	 * @throws IllegalArgumentException if the map is not registered or has no
	 *                                  parser
	 */
	public MessageLite parseValue(String mapName, byte[] data) throws InvalidProtocolBufferException {
		MapInfo info = maps.get(mapName);
		if (info == null) {
			throw new IllegalArgumentException("Unknown map: " + mapName);
		}
		if (info.parser() == null) {
			throw new IllegalArgumentException("No parser registered for map: " + mapName);
		}
		return info.parser().parseFrom(data);
	}
}
