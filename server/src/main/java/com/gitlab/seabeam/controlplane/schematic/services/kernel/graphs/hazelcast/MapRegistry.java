// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.ConsistencyType;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs.IMap;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of the convergent map boundaries this node has bound: their name,
 * the wrapped IMap, and the consistency model. It exists for the cluster map
 * stats the admin surface publishes, and for nothing else.
 *
 * <p>Populated at startup when {@code Manager.getConvergentMap()} is called.
 */
public class MapRegistry {

	/** Metadata about a registered map. */
	public static class MapInfo {
		private final IMap<String, ?> map;
		private final ConsistencyType consistency;

		MapInfo(IMap<String, ?> map, ConsistencyType consistency) {
			this.map = map;
			this.consistency = consistency;
		}

		public IMap<String, ?> map() {
			return map;
		}

		public ConsistencyType consistency() {
			return consistency;
		}
	}

	private final ConcurrentHashMap<String, MapInfo> maps = new ConcurrentHashMap<>();

	/** Registers a map with the given name, backing IMap, and consistency type. */
	@SuppressWarnings("unchecked")
	public void register(String name, IMap<?, ?> map, ConsistencyType consistency) {
		maps.put(name, new MapInfo((IMap<String, ?>) map, consistency));
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
}
