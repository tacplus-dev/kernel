// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.MapRegistry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.PersistenceProvider;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.Registry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.services.kernel.ClusterMap;
import com.hazelcast.cluster.Member;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.LocalMapStats;
import java.io.File;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Background daemon that periodically collects JVM and Hazelcast metrics
 * and writes them to the ClusterState maps. Runs on each node with a 10-second
 * interval. Also supports event-driven updates on membership changes.
 */
public class ClusterStatePublisher {

	private static final Logger logger = LoggerFactory.getLogger(ClusterStatePublisher.class);

	private static final long PUBLISH_INTERVAL_SECONDS = 10;

	private final HazelcastInstance hazelcast;
	private final ClusterMap clusterStateMap;
	private final PersistenceProvider persistence;
	private final Kernel.BootstrapConfig bootstrapConfig;
	private final int grpcPort;
	private final RateLimitInterceptor rateLimiter;
	private final Supplier<Hazelcast.AdminTokenCacheStats> tokenCacheStatsSupplier;

	private final ScheduledExecutorService scheduler;
	private ScheduledFuture<?> publishTask;

	public ClusterStatePublisher(
			HazelcastInstance hazelcast,
			ClusterMap clusterStateMap,
			PersistenceProvider persistence,
			Kernel.BootstrapConfig bootstrapConfig,
			Kernel.Config frontendConfig,
			int grpcPort,
			RateLimitInterceptor rateLimiter,
			Supplier<Hazelcast.AdminTokenCacheStats> tokenCacheStatsSupplier) {
		this.hazelcast = hazelcast;
		this.clusterStateMap = clusterStateMap;
		this.persistence = persistence;
		this.bootstrapConfig = bootstrapConfig;
		this.grpcPort = grpcPort;
		this.rateLimiter = rateLimiter;
		this.tokenCacheStatsSupplier = tokenCacheStatsSupplier;
		this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "cluster-state-publisher");
			t.setDaemon(true);
			return t;
		});
	}

	/**
	 * Starts periodic publishing and installs the initial config dump.
	 */
	public void start() {
		publishConfigDump();
		publishTask = scheduler.scheduleAtFixedRate(this::publishAllSafe, 0, PUBLISH_INTERVAL_SECONDS,
				TimeUnit.SECONDS);
		logger.info("ClusterStatePublisher started (interval={}s)", PUBLISH_INTERVAL_SECONDS);
	}

	/**
	 * Shuts down the publisher scheduler.
	 */
	public void stop() {
		if (publishTask != null) {
			publishTask.cancel(false);
		}
		scheduler.shutdown();
		logger.info("ClusterStatePublisher stopped");
	}

	/**
	 * Called from the membership listener for immediate cluster_info /
	 * cluster_health updates.
	 */
	public void onMembershipChange() {
		scheduler.execute(() -> {
			try {
				publishClusterInfo();
				publishClusterHealth();
			} catch (Exception e) {
				logger.warn("Failed to publish on membership change", e);
			}
		});
	}

	private void publishAllSafe() {
		try {
			publishAll();
		} catch (Exception e) {
			logger.warn("ClusterStatePublisher cycle failed", e);
		}
	}

	/**
	 * Single publish cycle — collects all metrics and writes to ClusterState maps.
	 */
	void publishAll() {
		String nodeId = getNodeId();

		publishClusterInfo();
		publishClusterHealth();
		publishNodeMetrics(nodeId);
		publishGrpcStats(nodeId);
		publishPersistenceStatus(nodeId);
		publishNetworkStats(nodeId);
		publishThreadInfo(nodeId);
		publishTokenCacheStats(nodeId);
		publishMapStats();
	}

	private String getNodeId() {
		return hazelcast.getCluster().getLocalMember().getUuid().toString();
	}

	// ---- Cluster Info (singleton) ----

	private void publishClusterInfo() {
		var cluster = hazelcast.getCluster();
		var localMember = cluster.getLocalMember();

		var builder = Hazelcast.AdminClusterInfo.newBuilder()
				.setClusterName(hazelcast.getConfig().getClusterName())
				.setState(cluster.getClusterState().name())
				.setLocalMember(localMember.getUuid().toString())
				.setPartitionCount(
						hazelcast.getPartitionService().getPartitions().size())
				.setClusterSize(cluster.getMembers().size())
				.setVersion(
						com.hazelcast.instance.BuildInfoProvider.getBuildInfo().getVersion());

		for (Member member : cluster.getMembers()) {
			builder.addMembers(Hazelcast.AdminMember.newBuilder()
					.setUuid(member.getUuid().toString())
					.setAddress(member.getAddress().toString())
					.setLite(member.isLiteMember())
					.setIsLocal(member.localMember())
					.putAllAttributes(member.getAttributes()));
		}

		clusterStateMap.putClusterInfo(builder.build());
	}

	// ---- Cluster Health (singleton) ----

	private void publishClusterHealth() {
		var cluster = hazelcast.getCluster();
		var partitionService = hazelcast.getPartitionService();
		int totalSize = cluster.getMembers().size();
		// Core count tracks non-lite members for health reporting.
		long coreCount = cluster.getMembers().stream().filter(m -> !m.isLiteMember()).count();

		clusterStateMap.putClusterHealth(Hazelcast.AdminClusterHealth.newBuilder()
				.setClusterSafe(partitionService.isClusterSafe())
				.setLocalMemberSafe(partitionService.isLocalMemberSafe())
				.setClusterState(cluster.getClusterState().name())
				.setRunning(hazelcast.getLifecycleService().isRunning())
				.setClusterSize(totalSize)
				.setHasQuorum(coreCount >= coreCount / 2 + 1)
				.build());
	}

	// ---- Node Metrics (per-node) ----

	private void publishNodeMetrics(String nodeId) {
		MemoryMXBean memBean = ManagementFactory.getMemoryMXBean();
		MemoryUsage heap = memBean.getHeapMemoryUsage();
		MemoryUsage nonHeap = memBean.getNonHeapMemoryUsage();
		OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		RuntimeMXBean rtBean = ManagementFactory.getRuntimeMXBean();

		long gcCount = 0;
		long gcTimeMs = 0;
		for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
			long c = gc.getCollectionCount();
			long t = gc.getCollectionTime();
			if (c >= 0)
				gcCount += c;
			if (t >= 0)
				gcTimeMs += t;
		}

		var memory = Hazelcast.AdminMemoryMetrics.newBuilder()
				.setHeapUsedBytes(heap.getUsed())
				.setHeapMaxBytes(heap.getMax())
				.setHeapCommittedBytes(heap.getCommitted())
				.setNonHeapUsedBytes(nonHeap.getUsed())
				.setGcCount(gcCount)
				.setGcTimeMs(gcTimeMs);

		var cpu = Hazelcast.AdminCpuMetrics.newBuilder()
				.setAvailableProcessors(osBean.getAvailableProcessors())
				.setSystemLoadAverage(osBean.getSystemLoadAverage())
				.setUptimeMs(rtBean.getUptime());

		// Try to get process/system CPU load if available (com.sun.management)
		if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOs) {
			cpu.setProcessCpuLoad(sunOs.getProcessCpuLoad());
			cpu.setSystemCpuLoad(sunOs.getCpuLoad());
		}

		var disk = Hazelcast.AdminDiskMetrics.newBuilder();
		String persistenceDir = bootstrapConfig.getPersistenceDir();
		if (!persistenceDir.isEmpty()) {
			File dir = new File(persistenceDir);
			disk.setPersistenceDir(persistenceDir)
					.setTotalBytes(dir.getTotalSpace())
					.setUsableBytes(dir.getUsableSpace())
					.setUsedBytes(dir.getTotalSpace() - dir.getUsableSpace());
			// Estimate persistence size from redo log
			long redoSize = persistence.getRedoLogSizeBytes();
			if (redoSize >= 0) {
				disk.setPersistenceSizeBytes(redoSize);
			}
		}

		clusterStateMap.putNodeMetrics(
				nodeId,
				Hazelcast.AdminNodeMetrics.newBuilder()
						.setNodeId(nodeId)
						.setMemory(memory)
						.setCpu(cpu)
						.setDisk(disk)
						.setTimestampMs(System.currentTimeMillis())
						.build());
	}

	// ---- gRPC Stats (per-node) ----

	private void publishGrpcStats(String nodeId) {
		var builder = Hazelcast.AdminGrpcStats.newBuilder()
				.setNodeId(nodeId)
				.setActiveConnections(rateLimiter.getActiveConnections())
				.setActiveRpcs(rateLimiter.getActiveRpcs())
				.setActiveStreams(rateLimiter.getActiveStreams())
				.setTotalRpcs(rateLimiter.getTotalRpcs())
				.setRateLimitedCount(rateLimiter.getRateLimitedCount())
				.putAllPerMethodCounts(rateLimiter.getPerMethodCounts())
				.setTimestampMs(System.currentTimeMillis());

		clusterStateMap.putGrpcStats(nodeId, builder.build());
	}

	// ---- Persistence Status (per-node) ----

	private void publishPersistenceStatus(String nodeId) {
		clusterStateMap.putPersistenceStatus(
				nodeId,
				Hazelcast.AdminPersistenceStatus.newBuilder()
						.setNodeId(nodeId)
						.setEnabled(persistence.isEnabled())
						.setPersistenceDir(bootstrapConfig.getPersistenceDir())
						.setRedoLogSizeBytes(Math.max(0, persistence.getRedoLogSizeBytes()))
						.setLastDumpTimeMs(persistence.getLastDumpTimestamp())
						.setTimestampMs(System.currentTimeMillis())
						.build());
	}

	// ---- Network Stats (per-node) ----

	private void publishNetworkStats(String nodeId) {
		var cluster = hazelcast.getCluster();
		var localMember = cluster.getLocalMember();

		var builder = Hazelcast.AdminNetworkStats.newBuilder()
				.setNodeId(nodeId)
				.setGrpcListenAddress(":" + grpcPort)
				.setHazelcastListenAddress(localMember.getAddress().toString())
				.setActiveGrpcConnections(rateLimiter.getActiveConnections())
				.setTimestampMs(System.currentTimeMillis());

		// Read network I/O from /proc/net/dev (Linux/container)
		long[] netIO = readProcNetDev();
		builder.setBytesReceived(netIO[0]).setBytesSent(netIO[1]);

		for (Member member : cluster.getMembers()) {
			if (!member.localMember()) {
				builder.addMemberConnections(Hazelcast.AdminMemberConnection.newBuilder()
						.setAddress(member.getAddress().toString())
						.setConnected(true)
						.setConnectionCount(1));
			}
		}

		clusterStateMap.putNetworkStats(nodeId, builder.build());
	}

	/**
	 * Reads /proc/net/dev and sums bytes received/sent across all non-loopback
	 * interfaces.
	 * Returns [bytesReceived, bytesSent]. Returns [0, 0] on non-Linux or error.
	 */
	private static long[] readProcNetDev() {
		long recv = 0, sent = 0;
		try {
			for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of("/proc/net/dev"))) {
				line = line.trim();
				if (!line.contains(":") || line.startsWith("Inter") || line.startsWith("face"))
					continue;
				String iface = line.substring(0, line.indexOf(':')).trim();
				if ("lo".equals(iface))
					continue;
				String[] parts = line.substring(line.indexOf(':') + 1).trim().split("\\s+");
				if (parts.length >= 10) {
					recv += Long.parseLong(parts[0]); // bytes received
					sent += Long.parseLong(parts[8]); // bytes sent
				}
			}
		} catch (Exception e) {
			// /proc/net/dev not available (non-Linux)
		}
		return new long[] { recv, sent };
	}

	// ---- Thread Info (per-node) ----

	private void publishThreadInfo(String nodeId) {
		ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();

		var builder = Hazelcast.AdminThreadInfo.newBuilder()
				.setNodeId(nodeId)
				.setThreadCount(threadBean.getThreadCount())
				.setPeakThreadCount(threadBean.getPeakThreadCount())
				.setDaemonThreadCount(threadBean.getDaemonThreadCount())
				.setTimestampMs(System.currentTimeMillis());

		long[] deadlocked = threadBean.findDeadlockedThreads();
		if (deadlocked != null) {
			for (long id : deadlocked) {
				var info = threadBean.getThreadInfo(id);
				if (info != null) {
					builder.addDeadlockedThreads(info.getThreadName());
				}
			}
		}

		clusterStateMap.putThreadInfo(nodeId, builder.build());
	}

	// ---- Token Cache Stats (per-node) ----

	private void publishTokenCacheStats(String nodeId) {
		Hazelcast.AdminTokenCacheStats stats = tokenCacheStatsSupplier.get();
		clusterStateMap.putTokenCacheStats(nodeId, stats);
	}

	// ---- Map Stats (per-map) ----

	/**
	 * Extracts the short name from the full Hazelcast map name.
	 * Full name:
	 * "com.gitlab...ClusterMap:services.kernel.ClusterState.BootstrapConfig"
	 * Returns: "services.kernel.ClusterState.BootstrapConfig"
	 */
	private static String shortMapName(String fullName) {
		int colonIdx = fullName.indexOf(':');
		if (colonIdx < 0) {
			return fullName;
		}
		return fullName.substring(colonIdx + 1);
	}

	/**
	 * Derives a display name from BoundaryInfo.
	 * service="services/config_holder/GatewayConfigState", boundary="Config" →
	 * "gateway.Config"
	 * service="services/kernel/ClusterState", boundary="NodeMetrics" →
	 * "kernel.NodeMetrics"
	 */
	private static String deriveDisplayName(String servicePath, Registry.BoundaryInfo info) {
		String[] parts = servicePath.split("/");
		if (parts.length < 3) {
			return info.getBoundary();
		}
		String pkg = parts[1]; // "kernel", "config_holder"
		String stateName = parts[2]; // "ClusterState", "GatewayConfigState"

		if ("config_holder".equals(pkg)) {
			String svcName = stateName;
			if (svcName.endsWith("ConfigState")) {
				svcName = svcName.substring(0, svcName.length() - "ConfigState".length());
			}
			if (!svcName.isEmpty()) {
				svcName = Character.toLowerCase(svcName.charAt(0)) + svcName.substring(1);
			}
			return svcName + "." + info.getBoundary();
		}

		return pkg + "." + info.getBoundary();
	}

	private static Hazelcast.AdminGraphType graphTypeFromString(String graphType) {
		if (graphType == null) return Hazelcast.AdminGraphType.ADMIN_GRAPH_TYPE_COLLECTION;
		return switch (graphType) {
			case "singleton" -> Hazelcast.AdminGraphType.ADMIN_GRAPH_TYPE_SINGLETON;
			case "collection" -> Hazelcast.AdminGraphType.ADMIN_GRAPH_TYPE_COLLECTION;
			default -> Hazelcast.AdminGraphType.ADMIN_GRAPH_TYPE_COLLECTION;
		};
	}

	private void publishMapStats() {
		MapRegistry mapRegistry = persistence.getRegistry();
		long now = System.currentTimeMillis();

		for (Map.Entry<String, MapRegistry.MapInfo> entry : mapRegistry.all().entrySet()) {
			String mapName = entry.getKey();
			if (mapName == null) {
				continue;
			}
			try {
				com.hazelcast.map.IMap<?, ?> hzMap = hazelcast.getMap(mapName);
				LocalMapStats local = hzMap.getLocalMapStats();
				String shortName = shortMapName(mapName);

				Registry.BoundaryInfo info = Registry.lookupByShortName(shortName);
				String servicePath = info != null ? info.getService() : "";
				String displayName = info != null ? deriveDisplayName(servicePath, info) : shortName;
				String valueType = info != null ? info.getTypeFqn() : "";
				String qualifiedName = info != null ? servicePath + "." + info.getBoundary() : shortName;
				String stateRoot = info != null ? info.getStateRoot() : "";

				clusterStateMap.putMapStats(
						mapName,
						Hazelcast.AdminMapStats.newBuilder()
								.setMapName(displayName)
								.setValueType(valueType)
								.setGraphType(
										info != null
												? graphTypeFromString(info.getGraphType())
												: Hazelcast.AdminGraphType.ADMIN_GRAPH_TYPE_COLLECTION)
								.setQualifiedName(qualifiedName)
								.setStateRoot(stateRoot)
								.setConsistency(info != null ? info.getConsistency() : "")
								.setPersistence(info != null && info.getPersistence())
								.setSize(hzMap.size())
								.setOwnedEntryCount(local.getOwnedEntryCount())
								.setBackupEntryCount(local.getBackupEntryCount())
								.setHeapCostBytes(local.getHeapCost())
								.setLastUpdateTimeMs(local.getLastUpdateTime())
								.setPutCount(local.getPutOperationCount())
								.setGetCount(local.getGetOperationCount())
								.setHitCount(local.getHits())
								.setTimestampMs(now)
								// Memory breakdown
								.setOwnedEntryMemoryCost(local.getOwnedEntryMemoryCost())
								.setBackupEntryMemoryCost(local.getBackupEntryMemoryCost())
								// Additional entry counts
								.setDirtyEntryCount(local.getDirtyEntryCount())
								.setLockedEntryCount(local.getLockedEntryCount())
								// Additional operation counts
								.setRemoveCount(local.getRemoveOperationCount())
								.setSetCount(local.getSetOperationCount())
								.setEvictionCount(local.getEvictionCount())
								.setExpirationCount(local.getExpirationCount())
								// Timestamps
								.setLastAccessTimeMs(local.getLastAccessTime())
								.setCreationTimeMs(local.getCreationTime())
								// Backup config
								.setBackupCount(local.getBackupCount())
								.build());
			} catch (Exception e) {
				logger.debug("Failed to collect map stats for {}: {}", mapName, e.getMessage());
			}
		}
	}

	// ---- Config Dump (singleton, written once at startup) ----

	private void publishConfigDump() {
		try {
			String hazelcastXml = hazelcast.getConfig().toString();

			clusterStateMap.putConfigDump(Kernel.AdminConfigDump.newBuilder()
					.setHazelcastConfigXml(hazelcastXml)
					.build());

			logger.info("Published config dump to ClusterState");
		} catch (Exception e) {
			logger.warn("Failed to publish config dump: {}", e.getMessage());
		}
	}
}
