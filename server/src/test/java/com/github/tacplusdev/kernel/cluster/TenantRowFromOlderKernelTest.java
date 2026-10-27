// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.graphs.hazelcast.HazelcastManager;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.nio.serialization.compact.CompactReader;
import com.hazelcast.nio.serialization.compact.CompactSerializer;
import com.hazelcast.nio.serialization.compact.CompactWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A kernel rolls onto a cluster whose live maps still hold a tenant row an
 * older kernel wrote. The older kernel's generated compact serializer projected
 * fewer scalar fields of {@code Kernel.Tenant}, so the stored row carries a
 * different compact schema than the one this kernel writes for the same
 * record. The row reads back as an equal {@code Kernel.Tenant}, and a
 * conditional write against it must still land: Hazelcast's own
 * {@code replace(key, old, new)} compares serialized bytes, so it never
 * matched, and a compare-and-set loop on such a row spun forever.
 */
class TenantRowFromOlderKernelTest {

	private static final String ACME = "/tenants/acme";

	private final List<HazelcastInstance> members = new ArrayList<>();

	@AfterEach
	void stopMembers() {
		members.forEach(HazelcastInstance::shutdown);
	}

	@Test
	void aConditionalWriteLandsOnATenantRowAnOlderKernelWrote() throws Exception {
		String cluster = "tenant-row-older-kernel-test-" + UUID.randomUUID();
		int[] ports = {HazelcastTestMembers.freePort(), HazelcastTestMembers.freePort()};
		HazelcastInstance older = Hazelcast.newHazelcastInstance(olderKernelConfig(cluster, ports[0], ports));
		members.add(older);
		HazelcastInstance current = Hazelcast.newHazelcastInstance(
				HazelcastTestMembers.hazelcastConfig(cluster, ports[1], ports));
		members.add(current);
		HazelcastTestMembers.awaitPartitionsOnEveryMember(members);

		new ConfigMap(new HazelcastManager(older)).putTenants(ACME, Kernel.Tenant.newBuilder()
				.setName("acme")
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
				.build());

		ConfigMap configMap = new ConfigMap(new HazelcastManager(current));
		Kernel.Tenant stored = configMap.getTenants(ACME);
		Kernel.Tenant suspended = stored.toBuilder()
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED)
				.build();

		assertTrue(configMap.replaceTenants(ACME, stored, suspended),
				"the row reads back equal to what is stored, so the compare must match it");
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED, configMap.getTenants(ACME).getStatus());
	}

	/** A member running the older kernel: its Tenant compact schema projects only {@code name}. */
	private static Config olderKernelConfig(String cluster, int port, int[] memberPorts) {
		Config config = new Config();
		config.setClusterName(cluster);
		config.getNetworkConfig().setPort(port).setPortAutoIncrement(false);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(true);
		for (int p : memberPorts) {
			config.getNetworkConfig().getJoin().getTcpIpConfig().addMember("127.0.0.1:" + p);
		}
		config.getSerializationConfig().getCompactSerializationConfig().addSerializer(new OlderTenantCompactSerializer());
		return config;
	}

	/** The generated serializer's shape on an older kernel, which projected fewer of Tenant's fields. */
	private static final class OlderTenantCompactSerializer implements CompactSerializer<Kernel.Tenant> {

		@Nonnull
		@Override
		public String getTypeName() {
			return "kernel.Tenant";
		}

		@Nonnull
		@Override
		public Class<Kernel.Tenant> getCompactClass() {
			return Kernel.Tenant.class;
		}

		@Override
		public void write(@Nonnull CompactWriter writer, @Nonnull Kernel.Tenant msg) {
			writer.writeArrayOfInt8("__proto__", msg.toByteArray());
			writer.writeString("name", msg.getName());
		}

		@Nonnull
		@Override
		public Kernel.Tenant read(@Nonnull CompactReader reader) {
			try {
				return Kernel.Tenant.parseFrom(reader.readArrayOfInt8("__proto__"));
			} catch (com.google.protobuf.InvalidProtocolBufferException e) {
				throw new com.hazelcast.core.HazelcastException("failed to deserialize Tenant", e);
			}
		}
	}
}
