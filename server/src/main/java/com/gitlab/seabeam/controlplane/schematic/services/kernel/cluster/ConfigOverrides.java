// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.services_config.ServicesConfig;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Helpers;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;

import com.google.protobuf.Descriptors;
import com.google.protobuf.FieldMask;
import com.google.protobuf.util.FieldMaskUtil;
import com.google.protobuf.util.JsonFormat;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The runtime write path for a service's Config, and for
 * {@code Config.people_signups_paused}: kernel polls
 * {@code Config.config_override_path} for a {@code ConfigOverride} and installs
 * the bundle's value with the override's named fields replaced, through the same
 * generated {@code installServices} the bundle goes through. Nothing restarts.
 * See {@code ConfigOverride} in kernel.proto for the contract.
 *
 * <p>The bundle stays the base. Every apply is computed from it, never from the
 * previous apply, so dropping a path puts the bundle's value back, and the
 * services a flip touches are exactly those named by the old or the new paths.
 *
 * <p>An override kernel cannot parse, one that names a path outside
 * {@code configs.*} and {@code people_signups_paused}, one that does not say
 * who wrote it, or one whose merged result is not a valid Config, is refused and
 * logged; the previous override stays in force.
 * That is the safe direction for a kill switch: a malformed "resume" must not
 * quietly resume anything, and a malformed "stop" leaves the operator a log line
 * saying it did not stop.
 */
final class ConfigOverrides {

	private static final Logger logger = LoggerFactory.getLogger(ConfigOverrides.class);

	/** How often the file is read. The kubelet's ConfigMap sync is the slower leg. */
	static final long POLL_SECONDS = 5;

	private static final String CONFIGS_PREFIX = "configs.";
	private static final String SIGNUPS_PATH = "people_signups_paused";

	private static final FieldMaskUtil.MergeOptions REPLACE = new FieldMaskUtil.MergeOptions()
			.setReplaceMessageFields(true)
			.setReplaceRepeatedFields(true)
			.setReplacePrimitiveFields(true);

	private final Kernel.Config bundle;
	private final Path file;
	private final Consumer<ServicesConfig.Services> install;
	private final ScheduledExecutorService scheduler;

	private volatile Kernel.ConfigOverride applied = Kernel.ConfigOverride.getDefaultInstance();
	private volatile boolean peopleSignupsPaused;
	/** The file's bytes as last read; null before the first read. Poller thread only after boot. */
	private byte[] lastRead;

	/**
	 * @param bundle  kernel's boot Config, the base every override is merged onto
	 * @param file    {@code Config.config_override_path}
	 * @param install the generated {@code installServices}
	 */
	ConfigOverrides(Kernel.Config bundle, Path file, Consumer<ServicesConfig.Services> install) {
		this.bundle = bundle;
		this.file = file;
		this.install = install;
		this.peopleSignupsPaused = bundle.getPeopleSignupsPaused();
		this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "config-override-poller");
			t.setDaemon(true);
			return t;
		});
	}

	/**
	 * The bundle's configs with the override on disk now merged in, for the boot
	 * install. Merged before that install rather than applied after it, so a
	 * kernel restarting under a kill switch never hands the services the bare
	 * bundle value in between.
	 */
	ServicesConfig.Services bootConfigs() {
		read().ifPresent(this::accept);
		return merged(applied).getConfigs();
	}

	/** The effective {@code people_signups_paused}: the override's when a path names it, else the bundle's. */
	boolean peopleSignupsPaused() {
		return peopleSignupsPaused;
	}

	void start() {
		scheduler.scheduleWithFixedDelay(this::pollSafe, POLL_SECONDS, POLL_SECONDS, TimeUnit.SECONDS);
		logger.info("config override: polling {} every {}s", file, POLL_SECONDS);
	}

	void stop() {
		scheduler.shutdownNow();
	}

	/**
	 * One poll: when the file changed, install every service the old or the new
	 * override names, at bundle ⊕ new override. Package-private so a test drives
	 * it without the scheduler.
	 */
	void poll() {
		Kernel.ConfigOverride previous = applied;
		Optional<Kernel.ConfigOverride> next = read();
		if (next.isEmpty() || !accept(next.get())) {
			return;
		}
		Set<String> services = new TreeSet<>();
		services.addAll(servicesNamed(previous));
		services.addAll(servicesNamed(applied));
		if (!services.isEmpty()) {
			ServicesConfig.Services effective = merged(applied).getConfigs();
			ServicesConfig.Services.Builder subset = ServicesConfig.Services.newBuilder();
			for (String name : services) {
				// getField answers the message's default instance for a service the
				// bundle never carried; installing that is what "back to the bundle"
				// means for it, since the holder has no way to remove an entry.
				Descriptors.FieldDescriptor fd = ServicesConfig.Services.getDescriptor().findFieldByName(name);
				subset.setField(fd, effective.getField(fd));
			}
			install.accept(subset.build());
		}
	}

	private void pollSafe() {
		try {
			poll();
		} catch (RuntimeException e) {
			logger.error("config override: poll of {} failed; the previous override stays in force", file, e);
		}
	}

	/**
	 * The override on disk, when the bytes differ from the last read: a missing
	 * or empty file is no override. Empty when nothing changed, or when the file
	 * cannot be parsed (logged).
	 */
	private Optional<Kernel.ConfigOverride> read() {
		byte[] bytes;
		try {
			bytes = Files.readAllBytes(file);
		} catch (NoSuchFileException e) {
			bytes = new byte[0];
		} catch (IOException e) {
			logger.error("config override REFUSED: {} cannot be read ({}); flipped_by={} stays in force",
					file, e.getMessage(), applied.getFlippedBy());
			return Optional.empty();
		}
		if (lastRead != null && Arrays.equals(lastRead, bytes)) {
			return Optional.empty();
		}
		lastRead = bytes;
		String json = new String(bytes, StandardCharsets.UTF_8);
		if (json.isBlank()) {
			return Optional.of(Kernel.ConfigOverride.getDefaultInstance());
		}
		Kernel.ConfigOverride.Builder b = Kernel.ConfigOverride.newBuilder();
		try {
			JsonFormat.parser().merge(json, b);
		} catch (IOException e) {
			logger.error("config override REFUSED: {} is not a ConfigOverride ({}); flipped_by={} stays in force",
					file, e.getMessage(), applied.getFlippedBy());
			return Optional.empty();
		}
		return Optional.of(b.build());
	}

	/** Validates and records an override. False, logged, when it is refused. */
	private boolean accept(Kernel.ConfigOverride next) {
		String refusal = refusal(next);
		if (refusal != null) {
			logger.error("config override REFUSED: {} (flipped_by={} flipped_at_ms={}); flipped_by={} stays in force",
					refusal, next.getFlippedBy(), next.getFlippedAtMs(), applied.getFlippedBy());
			return false;
		}
		Kernel.ConfigOverride previous = applied;
		Kernel.ConfigOverride effective = merged(next);
		applied = next;
		peopleSignupsPaused = effective.getPeopleSignupsPaused();
		if (next.equals(previous)) {
			return true;
		}
		if (next.getPathsCount() == 0) {
			logger.info("config override CLEARED: flipped_by={} reason=\"{}\" flipped_at_ms={} — every service"
					+ " is back on its bundle Config", next.getFlippedBy(), next.getReason(), next.getFlippedAtMs());
		} else {
			logger.info("config override APPLIED: flipped_by={} reason=\"{}\" flipped_at_ms={} paths={}"
					+ " people_signups_paused={}", next.getFlippedBy(), next.getReason(), next.getFlippedAtMs(),
					next.getPathsList(), peopleSignupsPaused);
		}
		return true;
	}

	/** Why kernel will not apply this override, or null. */
	private String refusal(Kernel.ConfigOverride next) {
		if (next.equals(Kernel.ConfigOverride.getDefaultInstance())) {
			return null;
		}
		try {
			// The envelope's own assertions (flipped_by required). Not the configs:
			// they are partial by design, and are checked once merged, below.
			Helpers.validateConfigOverride(next.toBuilder().clearConfigs().build());
		} catch (ProtoException e) {
			return e.getMessage();
		}
		for (String path : next.getPathsList()) {
			boolean configPath = path.startsWith(CONFIGS_PREFIX) && path.split("\\.").length >= 3;
			if (!configPath && !SIGNUPS_PATH.equals(path)) {
				return "path \"" + path + "\" is neither configs.<service>_config.<field> nor " + SIGNUPS_PATH;
			}
			if (!FieldMaskUtil.isValid(Kernel.ConfigOverride.class, path)) {
				return "path \"" + path + "\" names no field";
			}
		}
		try {
			// Before anything is recorded: putConfig would refuse an invalid Config
			// halfway through an install.
			com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.services_config.Helpers
					.validateServices(merged(next).getConfigs());
		} catch (ProtoException e) {
			return "the merged Config is invalid: " + e.getMessage();
		}
		return null;
	}

	/** The bundle's configs and sign-ups flag with {@code next}'s named fields replaced. */
	private Kernel.ConfigOverride merged(Kernel.ConfigOverride next) {
		Kernel.ConfigOverride.Builder base = Kernel.ConfigOverride.newBuilder()
				.setConfigs(bundle.getConfigs())
				.setPeopleSignupsPaused(bundle.getPeopleSignupsPaused());
		if (next.getPathsCount() > 0) {
			FieldMaskUtil.merge(FieldMask.newBuilder().addAllPaths(next.getPathsList()).build(), next, base, REPLACE);
		}
		return base.build();
	}

	/** The {@code <service>_config} fields an override's paths reach into. */
	private static Set<String> servicesNamed(Kernel.ConfigOverride override) {
		Set<String> names = new TreeSet<>();
		for (String path : override.getPathsList()) {
			if (path.startsWith(CONFIGS_PREFIX)) {
				names.add(path.split("\\.")[1]);
			}
		}
		return names;
	}
}
