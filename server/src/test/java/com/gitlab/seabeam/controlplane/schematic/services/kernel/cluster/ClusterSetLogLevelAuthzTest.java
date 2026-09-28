// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.ClusterStateServiceGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import com.google.protobuf.Empty;
import io.grpc.Context;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import io.grpc.ServerMethodDefinition;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * SetLogLevel is a {@code (spec.command)} on the {@code kernel.Cluster} state
 * root, so it is policed by the same {@code kernel.Cluster} policy the generated
 * ClusterStateServiceServer applies to every other boundary: {@code service:kernel}
 * is the read-write set, and the command declares no {@code boundary_callers}.
 *
 * <p>Without that check any authenticated caller — any valid token for any
 * service — could silence kernel's own audit logging.
 */
class ClusterSetLogLevelAuthzTest {

	/** A logger nothing else touches, so the assertions see only this test's writes. */
	private static final String TARGET_LOGGER = "com.gitlab.seabeam.test.SetLogLevelAuthzProbe";

	/** A caller in the kernel.Cluster read-write set. */
	private static final String AUTHORIZED_CALLER = "kernel";

	/**
	 * A caller with a valid service identity that is NOT in the graph's rw set.
	 * sentinel is in the read-only set, so it is a genuine authenticated caller
	 * that must still be denied this WRITE.
	 */
	private static final String UNAUTHORIZED_CALLER = "sentinel";

	@Test
	void unauthorizedCallerIsDeniedAndLevelIsUnchanged() {
		setTargetLevel(Level.INFO);

		Status status = callSetLogLevel(UNAUTHORIZED_CALLER, "DEBUG");

		assertEquals(Status.Code.PERMISSION_DENIED, status.getCode(), status.toString());
		assertEquals(Level.INFO, targetLevel(), "log level must not change on a denied call");
	}

	@Test
	void callerWithNoServiceIdentityIsDeniedAndLevelIsUnchanged() {
		setTargetLevel(Level.INFO);

		// No CALLER_SERVICE_PATH_KEY at all: a user/CLI token, or an unauthenticated
		// path. checkAccess denies these on every policed graph.
		Status status = callSetLogLevel(null, "DEBUG");

		assertEquals(Status.Code.PERMISSION_DENIED, status.getCode(), status.toString());
		assertEquals(Level.INFO, targetLevel(), "log level must not change on a denied call");
	}

	@Test
	void authorizedCallerSucceedsAndLevelChanges() {
		setTargetLevel(Level.INFO);

		Status status = callSetLogLevel(AUTHORIZED_CALLER, "DEBUG");

		assertEquals(Status.Code.OK, status.getCode(), status.toString());
		assertEquals(Level.DEBUG, targetLevel());
	}

	// ---- harness ----

	/**
	 * Drives the real wrapped SetLogLevel handler under a gRPC Context carrying
	 * {@code callerServicePath} (or none, when null), and returns the status the
	 * call closed with.
	 */
	private static Status callSetLogLevel(String callerServicePath, String level) {
		ClusterSetLogLevelHandler handler = new ClusterSetLogLevelHandler(new SecurityAuthenticator());
		ServerServiceDefinition wrapped = handler.wrapWithSetLogLevel(
				new ClusterStateServiceGrpc.ClusterStateServiceImplBase() {
				}.bindService());

		MethodDescriptor<Kernel.AdminSetLogLevelRequest, Empty> method =
				ClusterStateServiceGrpc.getSetLogLevelMethod();
		@SuppressWarnings("unchecked")
		ServerMethodDefinition<Kernel.AdminSetLogLevelRequest, Empty> definition =
				(ServerMethodDefinition<Kernel.AdminSetLogLevelRequest, Empty>)
						wrapped.getMethod(method.getFullMethodName());
		assertNotNull(definition, "wrapped definition must still expose SetLogLevel");

		Kernel.AdminSetLogLevelRequest request = Kernel.AdminSetLogLevelRequest.newBuilder()
				.setLoggerName(TARGET_LOGGER)
				.setLevel(level)
				.build();

		CapturingServerCall call = new CapturingServerCall(method);
		Context context = callerServicePath == null
				? Context.current().fork()
				: Context.current().withValue(
						SecurityAuthenticator.CALLER_SERVICE_PATH_KEY, callerServicePath);

		Context previous = context.attach();
		try {
			ServerCall.Listener<Kernel.AdminSetLogLevelRequest> listener =
					definition.getServerCallHandler().startCall(call, new Metadata());
			listener.onMessage(request);
			listener.onHalfClose();
		} finally {
			context.detach(previous);
		}

		assertNotNull(call.closedStatus, "handler must close the call");
		return call.closedStatus;
	}

	private static ch.qos.logback.classic.Logger targetLoggerHandle() {
		return ((LoggerContext) LoggerFactory.getILoggerFactory()).getLogger(TARGET_LOGGER);
	}

	private static void setTargetLevel(Level level) {
		targetLoggerHandle().setLevel(level);
	}

	private static Level targetLevel() {
		return targetLoggerHandle().getLevel();
	}

	/** Minimal ServerCall that records the terminal status. */
	private static final class CapturingServerCall
			extends ServerCall<Kernel.AdminSetLogLevelRequest, Empty> {

		private final MethodDescriptor<Kernel.AdminSetLogLevelRequest, Empty> method;
		private Status closedStatus;

		CapturingServerCall(MethodDescriptor<Kernel.AdminSetLogLevelRequest, Empty> method) {
			this.method = method;
		}

		@Override
		public void request(int numMessages) {
		}

		@Override
		public void sendHeaders(Metadata headers) {
		}

		@Override
		public void sendMessage(Empty message) {
		}

		@Override
		public void close(Status status, Metadata trailers) {
			this.closedStatus = status;
		}

		@Override
		public boolean isCancelled() {
			return false;
		}

		@Override
		public MethodDescriptor<Kernel.AdminSetLogLevelRequest, Empty> getMethodDescriptor() {
			return method;
		}
	}
}
