package com.gitlab.secondstarcavalier.controlplane.codegen.generator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.AccessPolicy;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.BackendServiceInfo;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.SharedBackendInfo;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.SharedBoundary;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.SharedView;

/**
 * Generates {Prefix}BackendServiceServer.java — gRPC server implementation
 * with Get/Set/Watch RPCs for singletons and collection operations.
 *
 * <p>
 * Maps store proto messages directly (Compact Serialization handles ser/deser).
 * Set RPCs validate ingress via Helpers.validate before storing.
 */
public class BackendServiceServerGenerator {

	public static void generate(BackendServiceInfo svc, SharedBackendInfo info, GeneratorContext ctx)
			throws IOException {
		String pkg = ctx.getFullPackage(svc);
		String outerClassName = ctx.getOuterClassName(svc);
		String servicePrefix = info.getServicePrefix();
		// Proto service name strips redundant "State" suffix:
		// DgraphState→DgraphStateService (not DgraphStateStateService)
		String grpcServiceBase = servicePrefix.endsWith("State")
				? servicePrefix.substring(0, servicePrefix.length() - 5)
				: servicePrefix;
		String className = servicePrefix + "StateServiceServer";
		String grpcBase = grpcServiceBase + "StateServiceGrpc." + grpcServiceBase + "StateServiceImplBase";

		List<SharedBoundary> singletons = info.getSingletons().stream()
				.filter(b -> !b.isPrivateField()).toList();
		List<SharedBoundary> collections = info.getCollections().stream()
				.filter(b -> !b.isPrivateField()).toList();
		List<SharedBoundary> queues = info.getQueues().stream()
				.filter(b -> !b.isPrivateField()).toList();
		List<SharedBoundary> priorityQueues = info.getPriorityQueues().stream()
				.filter(b -> !b.isPrivateField()).toList();
		List<SharedBoundary> topics = info.getTopics().stream()
				.filter(b -> !b.isPrivateField()).toList();
		List<SharedView> views = info.getViews();
		// Collect leader-enabled boundaries from queues, priority queues, and topics
		List<SharedBoundary> leaderBoundaries = new ArrayList<>();
		for (SharedBoundary b : queues) {
			if (b.isLeader())
				leaderBoundaries.add(b);
		}
		for (SharedBoundary b : priorityQueues) {
			if (b.isLeader())
				leaderBoundaries.add(b);
		}
		for (SharedBoundary b : topics) {
			if (b.isLeader())
				leaderBoundaries.add(b);
		}
		boolean hasLeaders = !leaderBoundaries.isEmpty();

		boolean hasTopics = !topics.isEmpty();
		boolean hasPeerContext = hasTopics && ctx.hasPeerContext();

		// Cross imports
		SharedBackendInfo publicInfo = new SharedBackendInfo();
		publicInfo.getSingletons().addAll(singletons);
		publicInfo.getCollections().addAll(collections);
		List<String> crossImports = ctx.getCrossPackageImports(publicInfo, outerClassName);
		StringBuilder crossSb = new StringBuilder();
		for (String imp : crossImports)
			crossSb.append(imp).append("\n");

		// Fields
		StringBuilder fields = new StringBuilder();
		for (SharedBoundary b : singletons) {
			String qt = ctx.getQualifiedType(outerClassName, b);
			fields.append("    private final IMap<String, ").append(qt).append("> ").append(b.getFieldCamel())
					.append("Map;\n");
			fields.append("    private final List<WatcherEntry<").append(qt).append(">> ")
					.append(b.getFieldCamel()).append("Watchers = new CopyOnWriteArrayList<>();\n");
		}
		for (SharedBoundary b : collections) {
			String qt = ctx.getQualifiedType(outerClassName, b);
			fields.append("    private final IMap<String, ").append(qt).append("> ").append(b.getFieldCamel())
					.append("Map;\n");
			fields.append("    private final List<WatcherEntry<").append(outerClassName).append(".")
					.append(b.getFieldPascal())
					.append("EntriesResponse>> ").append(b.getFieldCamel())
					.append("Watchers = new CopyOnWriteArrayList<>();\n");
		}
		for (SharedBoundary b : queues) {
			String qt = ctx.getQualifiedType(outerClassName, b);
			fields.append("    private final IQueue<").append(qt).append("> ").append(b.getFieldCamel())
					.append("Queue;\n");
		}
		for (SharedBoundary b : priorityQueues) {
			String qt = ctx.getQualifiedType(outerClassName, b);
			fields.append("    private final IQueue<").append(qt).append("> ").append(b.getFieldCamel())
					.append("Queue;\n");
		}
		for (SharedBoundary b : topics) {
			String qt = ctx.getQualifiedType(outerClassName, b);
			if (hasPeerContext) {
				fields.append("    private final ITopic<TopicEnvelope<").append(qt).append(">> ")
						.append(b.getFieldCamel()).append("Topic;\n");
			} else {
				fields.append("    private final ITopic<").append(qt).append("> ").append(b.getFieldCamel())
						.append("Topic;\n");
			}
		}
		// Leader election infrastructure for leader-enabled queues/topics/priority
		// queues
		String leaderType = outerClassName + ".LeaderRecord";
		for (SharedBoundary b : leaderBoundaries) {
			String lfc = b.getFieldCamel() + "Leader";
			fields.append("    private final IMap<String, ").append(leaderType).append("> ").append(lfc)
					.append("Map;\n");
			fields.append("    private final Lock ").append(lfc).append("Lock;\n");
			fields.append("    private final ITopic<").append(leaderType).append("> ").append(lfc).append("Topic;\n");
			fields.append("    private final List<WatcherEntry<").append(leaderType).append(">> ")
					.append(lfc).append("Watchers = new CopyOnWriteArrayList<>();\n");
		}
		// View watcher fields (views read from source collection maps, no own map)
		for (SharedView v : views) {
			fields.append("    private final List<WatcherEntry<").append(outerClassName).append(".")
					.append(v.getFieldPascal()).append("EntriesResponse>> ").append(v.getFieldCamel())
					.append("Watchers = new CopyOnWriteArrayList<>();\n");
		}

		// Constructor
		StringBuilder ctor = new StringBuilder();
		ctor.append("\n    public ").append(className)
				.append("(Manager manager, SecurityAuthenticator authenticator) {\n");
		ctor.append("        this.authenticator = authenticator;\n");
		for (SharedBoundary b : singletons) {
			String mapGetter = b.isAtomic() ? "getAtomicMap"
					: b.isReplicated() ? "getReplicatedMap" : "getConvergentMap";
			ctor.append("        this.").append(b.getFieldCamel()).append("Map = manager.").append(mapGetter)
					.append("(CLASS_NAME + \":").append(b.getMapName()).append("\");\n");
		}
		for (SharedBoundary b : collections) {
			String mapGetter = b.isAtomic() ? "getAtomicMap"
					: b.isReplicated() ? "getReplicatedMap" : "getConvergentMap";
			ctor.append("        this.").append(b.getFieldCamel()).append("Map = manager.").append(mapGetter)
					.append("(CLASS_NAME + \":").append(b.getMapName()).append("\");\n");
		}
		for (SharedBoundary b : queues) {
			ctor.append("        this.").append(b.getFieldCamel()).append("Queue = manager.getQueue(CLASS_NAME + \":")
					.append(b.getMapName()).append("\");\n");
		}
		for (SharedBoundary b : priorityQueues) {
			ctor.append("        this.").append(b.getFieldCamel()).append("Queue = manager.getQueue(CLASS_NAME + \":")
					.append(b.getMapName()).append("\");\n");
		}
		for (SharedBoundary b : topics) {
			ctor.append("        this.").append(b.getFieldCamel()).append("Topic = manager.getTopic(CLASS_NAME + \":")
					.append(b.getMapName()).append("\");\n");
		}
		// Leader election infrastructure for leader-enabled boundaries
		for (SharedBoundary b : leaderBoundaries) {
			String lfc = b.getFieldCamel() + "Leader";
			ctor.append("        this.").append(lfc).append("Map = manager.getVolatileMap(CLASS_NAME + \":")
					.append(b.getMapName()).append(":leader\");\n");
			ctor.append("        this.").append(lfc).append("Lock = manager.getLock(CLASS_NAME + \":")
					.append(b.getMapName()).append(":leader:lock\");\n");
			ctor.append("        this.").append(lfc).append("Topic = manager.getTopic(CLASS_NAME + \":")
					.append(b.getMapName()).append(":leader:topic\");\n");
			// Register distributed topic listener for immediate cross-node watcher
			// notification
			ctor.append("        this.").append(lfc).append("Topic.addMessageListener(record -> {\n");
			ctor.append("            for (WatcherEntry<").append(leaderType).append("> entry : ").append(lfc)
					.append("Watchers) {\n");
			ctor.append("                ").append(leaderType).append(" lastSent = entry.lastSent.get();\n");
			ctor.append("                if (lastSent == null || !lastSent.equals(record)) {\n");
			ctor.append("                    try {\n");
			ctor.append("                        entry.observer.onNext(record);\n");
			ctor.append("                        entry.lastSent.set(record);\n");
			ctor.append("                    } catch (Exception e) {\n");
			ctor.append("                        logger.warn(\"Failed to send ").append(b.getFieldPascal())
					.append(" leader update via topic\", e);\n");
			ctor.append("                        ").append(lfc).append("Watchers.remove(entry);\n");
			ctor.append("                    }\n");
			ctor.append("                }\n");
			ctor.append("            }\n");
			ctor.append("        });\n");
		}
		ctor.append("        scheduler.scheduleAtFixedRate(this::pollAll, 0, 500, TimeUnit.MILLISECONDS);\n");
		ctor.append("    }\n\n");
		ctor.append("    public ").append(className).append("(Manager manager) {\n");
		ctor.append("        this(manager, new SecurityAuthenticator());\n");
		ctor.append("    }\n");

		// Singleton RPCs
		StringBuilder singletonRpcs = new StringBuilder();
		if (!singletons.isEmpty()) {
			singletonRpcs.append("\n    // ==================== Singleton RPCs ====================\n");
			for (SharedBoundary b : singletons) {
				Map<String, String> vars = boundaryVars(b, outerClassName, servicePrefix, svc, ctx);
				singletonRpcs.append("\n    // --- ").append(b.getFieldPascal()).append(" (singleton) ---\n");
				singletonRpcs.append(TemplateEngine.renderFragment("server_singleton_get.java.template", vars));
				singletonRpcs.append(TemplateEngine.renderFragment("server_singleton_set.java.template", vars));
				singletonRpcs.append(TemplateEngine.renderFragment("server_singleton_watch.java.template", vars));
			}
		}

		// Collection RPCs
		StringBuilder collectionRpcs = new StringBuilder();
		if (!collections.isEmpty()) {
			for (SharedBoundary b : collections) {
				Map<String, String> vars = boundaryVars(b, outerClassName, servicePrefix, svc, ctx);
				if (b.isInstanceKeyed()) {
					collectionRpcs.append("\n    // --- ").append(b.getFieldPascal())
							.append(" (instance-keyed collection) ---\n");
					collectionRpcs.append(
							TemplateEngine.renderFragment("server_collection_set_instance_keyed.java.template", vars));
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_get.java.template", vars));
					collectionRpcs
							.append(TemplateEngine.renderFragment("server_collection_get_all.java.template", vars));
					collectionRpcs.append(
							TemplateEngine.renderFragment("server_collection_contains_key.java.template", vars));
					collectionRpcs
							.append(TemplateEngine.renderFragment("server_collection_key_set.java.template", vars));
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_size.java.template", vars));
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_watch.java.template", vars));
				} else {
					collectionRpcs.append("\n    // --- ").append(b.getFieldPascal()).append(" (collection) ---\n");
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_get.java.template", vars));
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_put.java.template", vars));
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_set.java.template", vars));
					collectionRpcs
							.append(TemplateEngine.renderFragment("server_collection_remove.java.template", vars));
					collectionRpcs
							.append(TemplateEngine.renderFragment("server_collection_delete.java.template", vars));
					collectionRpcs.append(
							TemplateEngine.renderFragment("server_collection_contains_key.java.template", vars));
					collectionRpcs
							.append(TemplateEngine.renderFragment("server_collection_get_all.java.template", vars));
					collectionRpcs
							.append(TemplateEngine.renderFragment("server_collection_key_set.java.template", vars));
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_size.java.template", vars));
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_clear.java.template", vars));
					collectionRpcs.append(
							TemplateEngine.renderFragment("server_collection_put_if_absent.java.template", vars));
					collectionRpcs.append(TemplateEngine.renderFragment("server_collection_watch.java.template", vars));
				}
			}
		}

		// Queue RPCs
		StringBuilder queueRpcs = new StringBuilder();
		if (!queues.isEmpty() || !priorityQueues.isEmpty()) {
			queueRpcs.append("\n    // ==================== Queue RPCs ====================\n");
			for (SharedBoundary b : queues) {
				Map<String, String> vars = boundaryVars(b, outerClassName, servicePrefix, svc, ctx);
				String label = "queue";
				queueRpcs.append("\n    // --- ").append(b.getFieldPascal()).append(" (").append(label)
						.append(") ---\n");
				queueRpcs.append(TemplateEngine.renderFragment("server_queue_offer.java.template", vars));
				queueRpcs.append(TemplateEngine.renderFragment("server_queue_consume.java.template", vars));
				queueRpcs.append(TemplateEngine.renderFragment("server_queue_peek.java.template", vars));
				queueRpcs.append(TemplateEngine.renderFragment("server_queue_size.java.template", vars));
			}
			for (SharedBoundary b : priorityQueues) {
				Map<String, String> vars = boundaryVars(b, outerClassName, servicePrefix, svc, ctx);
				queueRpcs.append("\n    // --- ").append(b.getFieldPascal()).append(" (priority queue) ---\n");
				queueRpcs.append(TemplateEngine.renderFragment("server_queue_offer.java.template", vars));
				queueRpcs.append(TemplateEngine.renderFragment("server_queue_consume.java.template", vars));
				queueRpcs.append(TemplateEngine.renderFragment("server_queue_peek.java.template", vars));
				queueRpcs.append(TemplateEngine.renderFragment("server_queue_size.java.template", vars));
			}
		}

		// Topic RPCs — use peer-aware templates when peerContextClass is configured
		StringBuilder topicRpcs = new StringBuilder();
		if (hasTopics) {
			topicRpcs.append("\n    // ==================== Topic RPCs ====================\n");
			String publishTemplate = hasPeerContext
					? "server_topic_publish_peer.java.template"
					: "server_topic_publish.java.template";
			String subscribeTemplate = hasPeerContext
					? "server_topic_subscribe_peer.java.template"
					: "server_topic_subscribe.java.template";
			for (SharedBoundary b : topics) {
				Map<String, String> vars = boundaryVars(b, outerClassName, servicePrefix, svc, ctx);
				topicRpcs.append("\n    // --- ").append(b.getFieldPascal()).append(" (topic) ---\n");
				topicRpcs.append(TemplateEngine.renderFragment(publishTemplate, vars));
				topicRpcs.append(TemplateEngine.renderFragment(subscribeTemplate, vars));
			}
		}

		// Leader Election RPCs (per-graph: on leader-enabled queues/topics/priority
		// queues)
		StringBuilder leaderElectionRpcs = new StringBuilder();
		if (hasLeaders) {
			leaderElectionRpcs.append("\n    // ==================== Leader Election RPCs ====================\n");
			for (SharedBoundary b : leaderBoundaries) {
				Map<String, String> vars = leaderBoundaryVars(b, outerClassName, servicePrefix, svc, ctx);
				leaderElectionRpcs.append("\n    // --- ").append(b.getFieldPascal())
						.append(" (per-graph leader) ---\n");
				leaderElectionRpcs.append(TemplateEngine.renderFragment("server_leader_elect.java.template", vars));
				leaderElectionRpcs.append(TemplateEngine.renderFragment("server_leader_resign.java.template", vars));
				leaderElectionRpcs.append(TemplateEngine.renderFragment("server_leader_get.java.template", vars));
				leaderElectionRpcs.append(TemplateEngine.renderFragment("server_leader_watch.java.template", vars));
				leaderElectionRpcs.append(TemplateEngine.renderFragment("server_leader_renew.java.template", vars));
			}
		}

		// View RPCs (read-only merged views over source collections)
		StringBuilder viewRpcs = new StringBuilder();
		if (!views.isEmpty()) {
			viewRpcs.append("\n    // ==================== View RPCs ====================\n");
			for (SharedView v : views) {
				String responseName = outerClassName + "." + v.getFieldPascal() + "EntriesResponse";
				viewRpcs.append("\n    // --- ").append(v.getFieldPascal()).append(" (view) ---\n");
				String traceRequestType = ctx.getTypesPackageBase() + ".types.sys.trace.Trace.TraceRequest";
				viewRpcs.append("\n    @Override\n");
				viewRpcs.append("    public void watch").append(v.getFieldPascal())
						.append("(").append(traceRequestType).append(" request,\n");
				viewRpcs.append("            StreamObserver<").append(responseName)
						.append("> responseObserver) {\n");
				viewRpcs.append("        logger.debug(\"rpc method=Watch").append(v.getFieldPascal()).append("\");\n");
				// Build initial snapshot from all source maps
				viewRpcs.append("        ").append(responseName)
						.append(".Builder resp = ").append(responseName).append(".newBuilder();\n");
				for (String srcCamel : v.getSourceFieldCamels()) {
					viewRpcs.append("        for (java.util.Map.Entry<String, ")
							.append(ctx.getOuterClassName(svc)).append(".").append(v.getTypeName())
							.append("> e : ").append(srcCamel).append("Map.entrySet()) {\n");
					viewRpcs.append("            resp.putEntries(e.getKey(), e.getValue());\n");
					viewRpcs.append("        }\n");
				}
				viewRpcs.append("        ").append(responseName).append(" initial = resp.build();\n");
				viewRpcs.append("        responseObserver.onNext(initial);\n\n");
				viewRpcs.append("        WatcherEntry<").append(responseName)
						.append("> entry = new WatcherEntry<>(responseObserver);\n");
				viewRpcs.append("        entry.lastSent.set(initial);\n");
				viewRpcs.append("        ").append(v.getFieldCamel()).append("Watchers.add(entry);\n\n");
				viewRpcs.append("        if (responseObserver instanceof ServerCallStreamObserver) {\n");
				viewRpcs.append("            ((ServerCallStreamObserver<").append(responseName)
						.append(">) responseObserver).setOnCancelHandler(\n");
				viewRpcs.append("                () -> ").append(v.getFieldCamel())
						.append("Watchers.remove(entry));\n");
				viewRpcs.append("        }\n");
				viewRpcs.append("    }\n");
			}
		}

		// Poll calls and poll methods
		StringBuilder pollAllCalls = new StringBuilder();
		StringBuilder pollMethods = new StringBuilder();
		for (SharedBoundary b : singletons) {
			pollAllCalls.append("            pollSingleton").append(b.getFieldPascal()).append("();\n");
			Map<String, String> vars = boundaryVars(b, outerClassName, servicePrefix, svc, ctx);
			pollMethods.append(TemplateEngine.renderFragment("server_singleton_poll.java.template", vars));
		}
		for (SharedBoundary b : collections) {
			pollAllCalls.append("            pollCollection").append(b.getFieldPascal()).append("();\n");
			Map<String, String> vars = boundaryVars(b, outerClassName, servicePrefix, svc, ctx);
			pollMethods.append(TemplateEngine.renderFragment("server_collection_poll.java.template", vars));
		}
		for (SharedBoundary b : leaderBoundaries) {
			pollAllCalls.append("            pollLeader").append(b.getFieldPascal()).append("();\n");
			Map<String, String> vars = leaderBoundaryVars(b, outerClassName, servicePrefix, svc, ctx);
			pollMethods.append(TemplateEngine.renderFragment("server_leader_poll.java.template", vars));
		}
		// View poll methods
		for (SharedView v : views) {
			String responseName = outerClassName + "." + v.getFieldPascal() + "EntriesResponse";
			pollAllCalls.append("            pollView").append(v.getFieldPascal()).append("();\n");
			pollMethods.append("\n    private void pollView").append(v.getFieldPascal()).append("() {\n");
			pollMethods.append("        try {\n");
			pollMethods.append("            ").append(responseName)
					.append(".Builder resp = ").append(responseName).append(".newBuilder();\n");
			for (String srcCamel : v.getSourceFieldCamels()) {
				pollMethods.append("            for (java.util.Map.Entry<String, ")
						.append(outerClassName).append(".").append(v.getTypeName())
						.append("> e : ").append(srcCamel).append("Map.entrySet()) {\n");
				pollMethods.append("                resp.putEntries(e.getKey(), e.getValue());\n");
				pollMethods.append("            }\n");
			}
			pollMethods.append("            ").append(responseName).append(" current = resp.build();\n");
			pollMethods.append("            for (WatcherEntry<").append(responseName)
					.append("> entry : ").append(v.getFieldCamel()).append("Watchers) {\n");
			pollMethods.append("                ").append(responseName)
					.append(" lastSent = entry.lastSent.get();\n");
			pollMethods.append("                if (lastSent == null || !lastSent.equals(current)) {\n");
			pollMethods.append("                    try {\n");
			pollMethods.append("                        entry.observer.onNext(current);\n");
			pollMethods.append("                        entry.lastSent.set(current);\n");
			pollMethods.append("                    } catch (Exception e) {\n");
			pollMethods.append("                        logger.warn(\"Failed to send ")
					.append(v.getFieldPascal()).append(" view update\", e);\n");
			pollMethods.append("                        ").append(v.getFieldCamel())
					.append("Watchers.remove(entry);\n");
			pollMethods.append("                    }\n");
			pollMethods.append("                }\n");
			pollMethods.append("            }\n");
			pollMethods.append("        } catch (Exception e) {\n");
			pollMethods.append("            logger.warn(\"Failed to poll ")
					.append(v.getFieldPascal()).append(" view\", e);\n");
			pollMethods.append("        }\n");
			pollMethods.append("    }\n");
		}

		// Peer context import (only when topics + peerContextClass configured)
		String peerContextImport = hasPeerContext
				? "import " + ctx.getPeerContextClass() + ";\n"
				: "";

		// SecurityInterceptor import no longer needed — instance_keyed uses
		// SecurityAuthenticator keys
		String securityInterceptorImport = "";

		// setQuorumAvailable method
		StringBuilder setQuorum = new StringBuilder();
		if (hasLeaders) {
			setQuorum.append("    public void setQuorumAvailable(boolean available) {\n");
			setQuorum.append("        boolean wasAvailable = this.quorumAvailable;\n");
			setQuorum.append("        this.quorumAvailable = available;\n");
			setQuorum.append("        if (wasAvailable && !available) {\n");
			setQuorum.append("            logger.warn(\"Quorum lost — revoking all leaders\");\n");
			for (SharedBoundary b : leaderBoundaries) {
				String lfc = b.getFieldCamel() + "Leader";
				setQuorum.append("            ").append(lfc).append("Map.remove(Singleton.SINGLETON_KEY);\n");
				setQuorum.append("            ").append(leaderType).append(" empty").append(b.getFieldPascal())
						.append(" = ").append(leaderType).append(".getDefaultInstance();\n");
				setQuorum.append("            ").append(lfc).append("Topic.publish(empty")
						.append(b.getFieldPascal()).append(");\n");
				setQuorum.append("            for (WatcherEntry<").append(leaderType).append("> entry : ")
						.append(lfc).append("Watchers) {\n");
				setQuorum.append("                try {\n");
				setQuorum.append("                    entry.observer.onNext(empty").append(b.getFieldPascal())
						.append(");\n");
				setQuorum.append("                    entry.lastSent.set(empty").append(b.getFieldPascal())
						.append(");\n");
				setQuorum.append("                } catch (Exception e) {\n");
				setQuorum.append("                    logger.warn(\"Failed to notify watcher of quorum loss\", e);\n");
				setQuorum.append("                }\n");
				setQuorum.append("            }\n");
			}
			setQuorum.append("        } else if (!wasAvailable && available) {\n");
			setQuorum.append("            logger.info(\"Quorum restored — atomic operations re-enabled\");\n");
			setQuorum.append("        }\n");
			setQuorum.append("    }\n");
		} else {
			setQuorum.append("    public void setQuorumAvailable(boolean available) {\n");
			setQuorum.append("        // No leader-enabled boundaries — nothing to do\n");
			setQuorum.append("    }\n");
		}

		// Conditional imports
		StringBuilder extraImports = new StringBuilder();
		boolean hasQueuesOrPQ = !queues.isEmpty() || !priorityQueues.isEmpty() || hasLeaders;
		if (hasQueuesOrPQ) {
			extraImports.append("import ").append(ctx.getInterfacesPackage()).append(".IQueue;\n");
		}
		if (hasTopics || hasLeaders) {
			extraImports.append("import ").append(ctx.getInterfacesPackage()).append(".ITopic;\n");
		}
		boolean hasAtomic = singletons.stream().anyMatch(SharedBoundary::isAtomic)
				|| collections.stream().anyMatch(SharedBoundary::isAtomic)
				|| hasLeaders;
		if (hasAtomic) {
			extraImports.append("import ").append(ctx.getInterfacesPackage()).append(".Lock;\n");
		}
		if (!singletons.isEmpty() || hasLeaders) {
			extraImports.append("import ").append(ctx.getInterfacesPackage()).append(".Singleton;\n");
		}

		// Render main template
		Map<String, String> mainVars = new LinkedHashMap<>();
		mainVars.put("HEADER", GeneratorContext.header(svc.getProtoFile()));
		mainVars.put("PACKAGE", pkg);
		mainVars.put("CROSS_IMPORTS", crossSb.toString());
		mainVars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
		mainVars.put("EXTRA_IMPORTS", extraImports.toString());
		mainVars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
		mainVars.put("AUTHENTICATOR_PACKAGE", ctx.getJavaPackageBase());
		mainVars.put("TYPES_PACKAGE", ctx.getTypesPackage(svc));
		mainVars.put("OUTER_CLASS", outerClassName);
		mainVars.put("CLASS_NAME", className);
		mainVars.put("SERVICE_PREFIX", servicePrefix);
		mainVars.put("GRAPH", graphKey(svc, ctx));
		mainVars.put("GRPC_BASE", grpcBase);
		mainVars.put("BACKEND_MAP_CLASS_NAME", info.getClassName());
		mainVars.put("LEADER_CONSTANTS", hasLeaders
				? "    private static final long LEASE_TTL_MS = 15_000; // 15 second lease for leader election\n"
				: "");
		mainVars.put("QUORUM_FIELD", hasLeaders
				? "    private volatile boolean quorumAvailable = true;\n"
				: "");
		mainVars.put("FIELDS", fields.toString());
		mainVars.put("CONSTRUCTOR", ctor.toString());
		mainVars.put("SINGLETON_RPCS", singletonRpcs.toString());
		mainVars.put("COLLECTION_RPCS", collectionRpcs.toString());
		mainVars.put("QUEUE_RPCS", queueRpcs.toString());
		mainVars.put("TOPIC_RPCS", topicRpcs.toString());
		mainVars.put("LEADER_ELECTION_RPCS", leaderElectionRpcs.toString());
		mainVars.put("VIEW_RPCS", viewRpcs.toString());
		mainVars.put("POLL_ALL_CALLS", pollAllCalls.toString());
		mainVars.put("POLL_METHODS", pollMethods.toString());
		mainVars.put("PEER_CONTEXT_IMPORT", peerContextImport);
		mainVars.put("SECURITY_INTERCEPTOR_IMPORT", securityInterceptorImport);
		mainVars.put("SET_QUORUM_AVAILABLE", setQuorum.toString());
		mainVars.put("TOPIC_ENVELOPE", hasPeerContext ? TOPIC_ENVELOPE_CLASS : "");

		String content = TemplateEngine.render("BackendServiceServer.java.template", mainVars);

		Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
		Files.createDirectories(dir);
		Files.writeString(dir.resolve(className + ".java"), content);
	}

	/**
	 * The security-policy key for a state root: "&lt;proto package&gt;.&lt;state
	 * root&gt;", matching the (package, name) pair tacplus writes into
	 * codegen-config.json. A root with no computed policy (ComputeSecurityPolicies
	 * skips state roots declared in infra protos) gets the explicit no-policy
	 * marker rather than a key that would deny every caller at run time.
	 */
	private static String graphKey(BackendServiceInfo svc, GeneratorContext ctx) {
		String key = svc.getPackageName() + "." + svc.getStateName();
		for (AccessPolicy policy : ctx.getSecurityPolicies()) {
			if (key.equals(policy.graphKey())) {
				return key;
			}
		}
		System.out.println("[tacplus-backend] WARNING: no security policy for state root \"" + key
				+ "\" — its state RPCs are generated unauthorized");
		return "*";
	}

	private static Map<String, String> boundaryVars(SharedBoundary b, String outerClassName,
			String servicePrefix, BackendServiceInfo svc, GeneratorContext ctx) {
		Map<String, String> vars = new LinkedHashMap<>();
		vars.put("QUALIFIED_TYPE", ctx.getQualifiedType(outerClassName, b));
		vars.put("TYPE_NAME", b.getTypeName());
		vars.put("FIELD_NAME", b.getFieldName());
		vars.put("FIELD_CAMEL", b.getFieldCamel());
		vars.put("FIELD_PASCAL", b.getFieldPascal());
		vars.put("MAP_NAME", b.getMapName());
		vars.put("HELPERS_REF", ctx.getHelpersRef(svc, b));
		long ttlSeconds = b.getEvictionTtlSeconds();
		vars.put("TTL_SET_CALL", ttlSeconds > 0
				? b.getFieldCamel() + "Map.set(compositeKey, authoritative, " + ttlSeconds + "L, TimeUnit.SECONDS);"
				: b.getFieldCamel() + "Map.set(compositeKey, authoritative);");
		vars.put("OUTER_CLASS", outerClassName);
		vars.put("SERVICE_PREFIX", servicePrefix);
		vars.put("TRACE_REQUEST_TYPE", ctx.getTypesPackageBase() + ".types.sys.trace.Trace.TraceRequest");
		return vars;
	}

	/**
	 * Vars for per-graph leader election templates — uses LeaderRecord type and
	 * {field}Leader naming.
	 */
	private static Map<String, String> leaderBoundaryVars(SharedBoundary b, String outerClassName,
			String servicePrefix, BackendServiceInfo svc, GeneratorContext ctx) {
		Map<String, String> vars = boundaryVars(b, outerClassName, servicePrefix, svc, ctx);
		vars.put("LEADER_TYPE", outerClassName + ".LeaderRecord");
		vars.put("LEADER_FIELD_CAMEL", b.getFieldCamel() + "Leader");
		return vars;
	}

	private static final String TOPIC_ENVELOPE_CLASS = """

			/** Wraps a topic message with the sender's peer address for filtering. */
			private static class TopicEnvelope<T> implements java.io.Serializable {
			    final T message;
			    final String senderPeer;

			    TopicEnvelope(T message, String senderPeer) {
			        this.message = message;
			        this.senderPeer = senderPeer;
			    }
			}""";
}
