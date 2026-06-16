package com.gitlab.secondstarcavalier.controlplane.codegen;

import java.util.ArrayList;
import java.util.List;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.AnnotationValue;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.BackendServiceInfo;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.FieldDescriptor;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.FileDescriptor;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.MessageDescriptor;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.SharedBackendInfo;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.SharedBoundary;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.SharedView;

/**
 * Classifies state root fields into singletons, collections, queues,
 * priority queues, and topics based on annotations.
 */
public class BoundaryAnalyzer {

	/**
	 * Analyzes a state service's boundaries.
	 * Returns null if no state root or no boundaries are found.
	 */
	public static SharedBackendInfo analyze(BackendServiceInfo svc, ProtoDescriptorParser parser) {
		// Find the file descriptor
		FileDescriptor fileDesc = parser.getFileDescriptor(svc.getProtoFile());
		if (fileDesc == null)
			return null;

		String backendRootPkg = fileDesc.getPackageName();

		// Find backend root message by name (supports multiple roots per file)
		MessageDescriptor backendRoot = findBackendRoot(fileDesc, svc.getBackendRootMsg());
		if (backendRoot == null)
			return null;

		// Determine parent directory from proto file path
		String parentDir = "";
		String protoFile = svc.getProtoFile();
		int lastSlash = protoFile.lastIndexOf('/');
		if (lastSlash > 0) {
			parentDir = protoFile.substring(0, lastSlash);
		}

		// Instance name defaults to state name (single instance)
		String instanceName = svc.getBackendName();
		if (instanceName == null || instanceName.isEmpty()) {
			instanceName = backendRoot.getName();
		}

		List<SharedBoundary> singletons = new ArrayList<>();
		List<SharedBoundary> collections = new ArrayList<>();
		List<SharedBoundary> queues = new ArrayList<>();
		List<SharedBoundary> priorityQueues = new ArrayList<>();
		List<SharedBoundary> topics = new ArrayList<>();
		List<SharedView> views = new ArrayList<>();

		for (FieldDescriptor field : backendRoot.getFields()) {
			if (!"message".equals(field.getTypeKind())) {
				continue;
			}

			// Skip injected trace fields (200-203) — they are not state boundaries.
			String fieldName = field.getName();
			if ("trace".equals(fieldName) || "trace_rounds".equals(fieldName)
					|| "trace_email".equals(fieldName) || "trace_request_id".equals(fieldName)) {
				continue;
			}

			// Collect view boundaries (read-only unions of source collections)
			if (field.getAnnotations().containsKey("view_sources")) {
				SharedView view = new SharedView();
				view.setFieldName(field.getName());
				view.setFieldPascal(StringUtils.toPascalCase(field.getName()));
				view.setFieldCamel(StringUtils.toLowerCamelCase(field.getName()));
				view.setTypeName(StringUtils.extractSimpleTypeName(field.getType()));
				// Collect source field names from repeated view_sources annotations
				List<AnnotationValue> sources = field.getRepeatedAnnotations("view_sources");
				for (AnnotationValue src : sources) {
					String srcName = src.getStringValue();
					if (srcName != null && !srcName.isEmpty()) {
						view.getSourceFieldNames().add(srcName);
						view.getSourceFieldCamels().add(StringUtils.toLowerCamelCase(srcName));
					}
				}
				if (!view.getSourceFieldNames().isEmpty()) {
					views.add(view);
				}
				continue;
			}

			// Skip command RPCs and state imports — they are not boundaries
			if (field.getAnnotations().containsKey("command") || field.getAnnotations().containsKey("state_import")) {
				continue;
			}

			AnnotationValue consAnn = field.getAnnotations().get("consistency");
			AnnotationValue queueAnn = field.getAnnotations().get("queue");
			AnnotationValue pqAnn = field.getAnnotations().get("priority_queue");
			AnnotationValue topicAnn = field.getAnnotations().get("topic");
			AnnotationValue leaderAnn = field.getAnnotations().get("leader");
			AnnotationValue ikAnn = field.getAnnotations().get("instance_keyed");
			AnnotationValue ttlAnn = field.getAnnotations().get("eviction_ttl_seconds");
			AnnotationValue persistAnn = field.getAnnotations().get("persistence");

			boolean hasQueue = queueAnn != null && queueAnn.getBoolValue();
			boolean hasPQ = pqAnn != null && pqAnn.getStringValue() != null && !pqAnn.getStringValue().isEmpty();
			boolean hasTopic = topicAnn != null && topicAnn.getBoolValue();
			boolean isLeader = leaderAnn != null && leaderAnn.getBoolValue();

			AnnotationValue privAnn = field.getAnnotations().get("private");
			boolean isPrivate = privAnn != null && privAnn.getBoolValue();
			// Default to CONVERGENT when no consistency annotation is present.
			String enumVal = consAnn != null ? consAnn.getEnumValue() : "CONSISTENCY_CONVERGENT";
			if (enumVal == null || enumVal.isEmpty()) {
				enumVal = "CONSISTENCY_CONVERGENT";
			}
			boolean isAtomic = "CONSISTENCY_ATOMIC".equals(enumVal);
			boolean isReplicated = "CONSISTENCY_REPLICATED".equals(enumVal);
			String typeName = StringUtils.extractSimpleTypeName(field.getType());

			// Detect cross-package references
			boolean isCrossPackage = false;
			String crossPkg = "";
			if (field.getType().contains(".")) {
				String pkg = field.getType().substring(0, field.getType().indexOf('.'));
				if (!pkg.equals(backendRootPkg)) {
					isCrossPackage = true;
					crossPkg = pkg;
				}
			}

			// Hierarchical map naming: {parentDir}.{package}.{instance}.{FieldCamelCase}
			String mapName = parentDir.replace('/', '.') + "." + svc.getPackageName() + "." + instanceName + "."
					+ StringUtils.toPascalCase(field.getName());

			SharedBoundary b = new SharedBoundary();
			b.setFieldName(field.getName());
			b.setFieldPascal(StringUtils.toPascalCase(field.getName()));
			b.setFieldCamel(StringUtils.toLowerCamelCase(field.getName()));
			b.setTypeName(typeName);
			b.setMapName(mapName);
			b.setAtomic(isAtomic);
			b.setReplicated(isReplicated);
			b.setRepeated(field.isRepeated());
			b.setPrivateField(isPrivate);
			b.setCrossPackage(isCrossPackage);
			b.setCrossPkg(crossPkg);
			b.setEvictionTtlSeconds(parseLongAnnotation(ttlAnn));

			if (isLeader) {
				b.setLeader(true);
			}
			if (ikAnn != null && ikAnn.getBoolValue()) {
				b.setInstanceKeyed(true);
			}
			if (persistAnn != null && persistAnn.getBoolValue()) {
				b.setPersistent(true);
			}

			if (hasQueue) {
				b.setQueue(true);
				queues.add(b);
			} else if (hasPQ) {
				b.setPriorityQueue(true);
				if (pqAnn != null) {
					String priorityField = pqAnn.getStringValue();
					if (priorityField != null) {
						b.setPriorityField(priorityField);
					}
				}
				priorityQueues.add(b);
			} else if (hasTopic) {
				b.setTopic(true);
				topics.add(b);
			} else if (field.isRepeated()) {
				// Find the indexed key field and epoch_expiration field for collections
				MessageDescriptor boundaryMsg = findBoundaryMessage(field, fileDesc, parser, backendRootPkg);
				if (boundaryMsg != null) {
					for (FieldDescriptor f : boundaryMsg.getFields()) {
						AnnotationValue idxAnn = f.getAnnotations().get("indexed");
						if (idxAnn != null && idxAnn.getBoolValue()) {
							b.setKeyFieldName(f.getName());
							b.setKeyFieldPascal(StringUtils.toPascalCase(f.getName()));
						}
						AnnotationValue epochAnn = f.getAnnotations().get("epoch_expiration");
						if (epochAnn != null && epochAnn.getBoolValue()) {
							b.setEpochExpirationGetter("get" + StringUtils.toPascalCase(f.getName()));
						}
					}
				}
				collections.add(b);
			} else {
				singletons.add(b);
			}
		}

		if (singletons.isEmpty() && collections.isEmpty() && queues.isEmpty() && priorityQueues.isEmpty()
				&& topics.isEmpty()) {
			return null;
		}

		// Derive className and servicePrefix
		String className = svc.getBackendName() + "Map";
		if (svc.getBackendName() == null || svc.getBackendName().isEmpty()) {
			className = StringUtils.toPascalCase(svc.getPackageName()) + "StateMap";
		}

		// Use the annotation value directly — no suffix stripping
		String servicePrefix = svc.getBackendName();
		if (servicePrefix == null || servicePrefix.isEmpty()) {
			servicePrefix = StringUtils.toPascalCase(svc.getPackageName());
		}

		SharedBackendInfo info = new SharedBackendInfo();
		info.setPackageName(svc.getPackageName());
		info.setBackendName(svc.getBackendName());
		info.setServicePrefix(servicePrefix);
		info.setClassName(className);
		info.setMapPrefix(StringUtils.toSnakeCase(svc.getPackageName()));
		info.setBackendRootName(backendRoot.getName());
		info.setParentDir(parentDir);
		info.setInstanceName(instanceName);
		info.getSingletons().addAll(singletons);
		info.getCollections().addAll(collections);
		info.getQueues().addAll(queues);
		info.getPriorityQueues().addAll(priorityQueues);
		info.getTopics().addAll(topics);
		info.getViews().addAll(views);

		return info;
	}

	private static MessageDescriptor findBackendRoot(FileDescriptor fileDesc, String backendRootMsg) {
		// First try to match by message name (supports multiple backend roots per file)
		if (backendRootMsg != null && !backendRootMsg.isEmpty()) {
			for (MessageDescriptor msg : fileDesc.getMessages()) {
				if (msg.getName().equals(backendRootMsg)) {
					return msg;
				}
			}
		}
		// Fallback: find first message with service_backend annotation
		for (MessageDescriptor msg : fileDesc.getMessages()) {
			AnnotationValue ann = msg.getAnnotations().get("service_state");
			if (ann != null && ann.getStringValue() != null && !ann.getStringValue().isEmpty()) {
				return msg;
			}
		}
		return null;
	}

	private static MessageDescriptor findBoundaryMessage(
			FieldDescriptor field, FileDescriptor fileDesc, ProtoDescriptorParser parser, String backendRootPkg) {
		String typeName = StringUtils.extractSimpleTypeName(field.getType());

		// Try local file first
		for (MessageDescriptor msg : fileDesc.getMessages()) {
			if (msg.getName().equals(typeName)) {
				return msg;
			}
		}

		// Try cross-package
		if (field.getType().contains(".")) {
			String pkg = field.getType().substring(0, field.getType().indexOf('.'));
			return parser.findMessage(pkg, typeName);
		}

		// Try same package across files
		return parser.findMessage(backendRootPkg, typeName);
	}

	private static long parseLongAnnotation(AnnotationValue annotation) {
		if (annotation == null) {
			return 0L;
		}
		String raw = annotation.getEnumValue();
		if (raw == null || raw.isBlank()) {
			raw = annotation.getStringValue();
		}
		if (raw == null || raw.isBlank()) {
			return 0L;
		}
		try {
			return Long.parseLong(raw);
		} catch (NumberFormatException e) {
			return 0L;
		}
	}
}
