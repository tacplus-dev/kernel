// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.services_config.ServicesConfig;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.llmproxy.Llmproxy;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.mailbox.MailboxOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.oauth.Oauth;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.google.protobuf.util.JsonFormat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The runtime write path for a service's Config: a {@code ConfigOverride} file
 * replaces exactly the fields it names, over the bundle, on the next poll, and
 * installs only the services it touches. The kill switches
 * (platform/ops/datagate/killswitch.sh) are its writers.
 */
class ConfigOverridesTest {

	@TempDir
	Path dir;

	private Path file;
	private final List<ServicesConfig.Services> installs = new ArrayList<>();
	private final ListAppender<ILoggingEvent> log = new ListAppender<>();
	private ch.qos.logback.classic.Logger logger;

	/**
	 * The bundle: oauth on with a session timeout, mailbox with gmail, llmproxy
	 * with one blocked caller. Defaulted the way the operator defaults every entry,
	 * so it is a valid holder (the merge is validated).
	 */
	private static final Kernel.Config BUNDLE = Kernel.Config.newBuilder()
			.setConfigs(ServicesConfig.Services.newBuilder()
					.setOauthConfig(com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.oauth.Helpers
							.configDefaults(Oauth.Config.newBuilder().setEnable(true).setSessionTimeoutSeconds(120).build()))
					.setMailboxConfig(com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.mailbox.Helpers
							.configDefaults(MailboxOuterClass.Config.newBuilder()
									.setRetrievedGraceSeconds(60)
									.setGmail(MailboxOuterClass.GmailConfig.newBuilder()
											.setMailbox("hello@seabeam.test").setSendAs("tally@seabeam.test")
											.setSendAsName("Tally").setWatchTopic("projects/p/topics/gmail"))
									.build()))
					.setLlmproxyConfig(com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.llmproxy.Helpers
							.configDefaults(Llmproxy.Config.newBuilder().addBlockedCallers("spiffe://t/tenants/x").build())))
			.build();

	@BeforeEach
	void setUp() {
		file = dir.resolve("override.json");
		logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(ConfigOverrides.class);
		log.start();
		logger.addAppender(log);
	}

	@AfterEach
	void tearDown() {
		logger.detachAppender(log);
	}

	private ConfigOverrides overrides() {
		return new ConfigOverrides(BUNDLE, file, installs::add);
	}

	private void write(Kernel.ConfigOverride override) throws Exception {
		Files.writeString(file, JsonFormat.printer().print(override));
	}

	private static Kernel.ConfigOverride.Builder by(String who) {
		return Kernel.ConfigOverride.newBuilder().setFlippedBy(who).setReason("test").setFlippedAtMs(1L);
	}

	private boolean logged(String... parts) {
		return log.list.stream().map(ILoggingEvent::getFormattedMessage)
				.anyMatch(m -> java.util.Arrays.stream(parts).allMatch(m::contains));
	}

	@Test
	void withNoFileTheBootInstallIsTheBundle() {
		ConfigOverrides o = overrides();

		assertEquals(BUNDLE.getConfigs(), o.bootConfigs());
		assertFalse(o.peopleSignupsPaused());
	}

	/**
	 * A kernel that boots while a switch is on installs the switched value in its
	 * one boot install, and every field the override does not name keeps the
	 * bundle's value.
	 */
	@Test
	void aBootUnderAnOverrideInstallsTheMergedValue() throws Exception {
		write(by("jody").addPaths("configs.oauth_config.enable")
				.setConfigs(ServicesConfig.Services.newBuilder().setOauthConfig(Oauth.Config.newBuilder().setEnable(false)))
				.build());

		ServicesConfig.Services boot = overrides().bootConfigs();

		assertFalse(boot.getOauthConfig().getEnable(), "false replaces the bundle's true");
		assertEquals(120, boot.getOauthConfig().getSessionTimeoutSeconds(), "an unnamed field keeps the bundle's value");
		assertEquals(BUNDLE.getConfigs().getMailboxConfig(), boot.getMailboxConfig());
	}

	/**
	 * The runtime flip: the next poll installs the one service the override
	 * names, and resuming installs it back at the bundle's value. Both are logged
	 * naming who flipped.
	 */
	@Test
	void aFlipInstallsOnlyTheNamedServiceAndAResumePutsTheBundleBack() throws Exception {
		ConfigOverrides o = overrides();
		o.bootConfigs();

		write(by("claude").addPaths("configs.oauth_config.enable")
				.setConfigs(ServicesConfig.Services.newBuilder().setOauthConfig(Oauth.Config.getDefaultInstance()))
				.build());
		o.poll();

		assertEquals(1, installs.size());
		ServicesConfig.Services stop = installs.get(0);
		assertTrue(stop.hasOauthConfig());
		assertFalse(stop.getOauthConfig().getEnable());
		assertFalse(stop.hasMailboxConfig(), "a service no path names is not reinstalled");
		assertFalse(stop.hasLlmproxyConfig());
		assertTrue(logged("APPLIED", "flipped_by=claude", "configs.oauth_config.enable"));

		write(by("jody").build());
		o.poll();

		assertEquals(2, installs.size());
		assertEquals(BUNDLE.getConfigs().getOauthConfig(), installs.get(1).getOauthConfig(),
				"dropping the path reinstalls the bundle's value");
		assertTrue(logged("CLEARED", "flipped_by=jody"));
	}

	@Test
	void anUnchangedFileInstallsNothing() throws Exception {
		ConfigOverrides o = overrides();
		write(by("jody").addPaths("configs.oauth_config.enable").build());
		o.bootConfigs();

		o.poll();
		o.poll();

		assertTrue(installs.isEmpty());
	}

	/** The email switch: an unset message field clears the bundle's gmail block. */
	@Test
	void anUnsetMessageFieldClearsTheBundles() throws Exception {
		ConfigOverrides o = overrides();
		o.bootConfigs();

		write(by("jody").addPaths("configs.mailbox_config.gmail").build());
		o.poll();

		MailboxOuterClass.Config mailbox = installs.get(0).getMailboxConfig();
		assertFalse(mailbox.hasGmail());
		assertEquals(60, mailbox.getRetrievedGraceSeconds());
	}

	/** The LLM switch: a repeated field replaces the bundle's list rather than appending to it. */
	@Test
	void aRepeatedFieldReplacesTheBundlesList() throws Exception {
		ConfigOverrides o = overrides();
		o.bootConfigs();

		write(by("jody").addPaths("configs.llmproxy_config.blocked_callers")
				.setConfigs(ServicesConfig.Services.newBuilder().setLlmproxyConfig(Llmproxy.Config.newBuilder()
						.addBlockedCallers("spiffe://t/tenants/x").addBlockedCallers("spiffe://")))
				.build());
		o.poll();

		assertEquals(List.of("spiffe://t/tenants/x", "spiffe://"),
				installs.get(0).getLlmproxyConfig().getBlockedCallersList());
	}

	@Test
	void theSignupsPathFlipsTheKernelFlagAndInstallsNoService() throws Exception {
		ConfigOverrides o = overrides();
		o.bootConfigs();

		write(by("jody").addPaths("people_signups_paused").setPeopleSignupsPaused(true).build());
		o.poll();

		assertTrue(o.peopleSignupsPaused());
		assertTrue(installs.isEmpty());

		Files.delete(file);
		o.poll();

		assertFalse(o.peopleSignupsPaused(), "no file is no override: the bundle's false");
	}

	/**
	 * The file killswitch.sh writes with all three switches stopped, byte for
	 * byte (captured from its own test stub): proto field names, a numeric
	 * int64. The script and the parser must agree on this shape.
	 */
	@Test
	void theFileKillswitchWritesIsAccepted() throws Exception {
		ConfigOverrides o = overrides();
		o.bootConfigs();

		Files.writeString(file, "{\"configs\":{\"llmproxy_config\":{\"blocked_callers\":[\"spiffe://\"]}},"
				+ "\"paths\":[\"configs.llmproxy_config.blocked_callers\",\"people_signups_paused\","
				+ "\"configs.mailbox_config.gmail\"],\"flipped_by\":\"jody\",\"reason\":\"kernel parse fixture\","
				+ "\"flipped_at_ms\":1792178663000,\"people_signups_paused\":true}");
		o.poll();

		assertTrue(o.peopleSignupsPaused());
		ServicesConfig.Services installed = installs.get(0);
		assertEquals(List.of("spiffe://"), installed.getLlmproxyConfig().getBlockedCallersList());
		assertFalse(installed.getMailboxConfig().hasGmail());
		assertFalse(installed.hasOauthConfig());
		assertTrue(logged("APPLIED", "flipped_by=jody", "flipped_at_ms=1792178663000"));
	}

	// ------------------------------------------------------------------ refusals

	@Test
	void anOverrideThatDoesNotSayWhoIsRefusedAndThePreviousStays() throws Exception {
		ConfigOverrides o = overrides();
		write(by("jody").addPaths("people_signups_paused").setPeopleSignupsPaused(true).build());
		o.bootConfigs();

		write(Kernel.ConfigOverride.newBuilder().addPaths("people_signups_paused").build());
		o.poll();

		assertTrue(o.peopleSignupsPaused(), "the refused resume resumed nothing");
		assertTrue(logged("REFUSED", "flippedBy is required", "flipped_by=jody stays in force"));
	}

	@Test
	void aMisspelledPathIsRefused() throws Exception {
		ConfigOverrides o = overrides();
		o.bootConfigs();

		write(by("jody").addPaths("configs.oauth_config.enabel").build());
		o.poll();

		assertTrue(installs.isEmpty());
		assertTrue(logged("REFUSED", "configs.oauth_config.enabel", "names no field"));
	}

	@Test
	void aPathOutsideConfigsAndTheSignupsFlagIsRefused() throws Exception {
		ConfigOverrides o = overrides();
		o.bootConfigs();

		write(by("jody").addPaths("flipped_by").build());
		o.poll();
		write(by("jody").addPaths("configs.oauth_config").build());
		o.poll();

		assertTrue(installs.isEmpty(), "neither a non-config path nor a whole-service replacement is a field override");
	}

	@Test
	void aFileThatIsNotAConfigOverrideIsRefused() throws Exception {
		ConfigOverrides o = overrides();
		o.bootConfigs();

		Files.writeString(file, "{\"flipped_by\": \"jody\", \"pathz\": []}");
		o.poll();

		assertTrue(installs.isEmpty());
		assertTrue(logged("REFUSED", "is not a ConfigOverride"));
	}
}
