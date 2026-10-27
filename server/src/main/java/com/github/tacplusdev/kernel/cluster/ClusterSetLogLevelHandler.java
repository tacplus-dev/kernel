// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.github.tacplusdev.kernel.model.types.services.kernel.ClusterStateServiceGrpc;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.SecurityAuthenticator;
import com.google.protobuf.Empty;
import io.grpc.ServerMethodDefinition;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.stub.ServerCalls;
import io.grpc.stub.StreamObserver;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the SetLogLevel command RPC for ClusterStateBackendService.
 *
 * <p>
 * The generated server leaves SetLogLevel as UNIMPLEMENTED because it is
 * a {@code (spec.command)} — its business logic must be hand-written. This
 * handler wraps the generated service definition to replace the stub with a
 * working implementation that dynamically changes logger levels via Logback.
 *
 * <p>
 * Authorization is the same check the generated {@code ClusterStateServiceServer}
 * applies to every other boundary of this state root: {@link
 * SecurityAuthenticator#checkAccess} against the {@code kernel.Cluster} policy.
 * {@code set_log_level} declares no {@code (spec.boundary_callers)}, so the
 * graph's read-write set — {@code service:kernel} alone — is the authorized
 * caller set for this WRITE.
 */
public class ClusterSetLogLevelHandler {

    private static final Logger logger = LoggerFactory.getLogger(ClusterSetLogLevelHandler.class);

    private static final Set<String> VALID_LEVELS = Set.of("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "OFF");

    /** Policy key for this state root: "<proto package>.<state root>". */
    private static final String GRAPH = "kernel.Cluster";

    /** Boundary field name of the command this handler implements. */
    private static final String BOUNDARY = "set_log_level";

    private final SecurityAuthenticator authenticator;

    public ClusterSetLogLevelHandler(SecurityAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * Wraps a ClusterStateBackendService {@link ServerServiceDefinition} to
     * replace the UNIMPLEMENTED {@code SetLogLevel} RPC with a working
     * implementation.
     */
    public ServerServiceDefinition wrapWithSetLogLevel(ServerServiceDefinition original) {
        ServerServiceDefinition.Builder builder = ServerServiceDefinition.builder(original.getServiceDescriptor());

        String setLogLevelMethodName =
                ClusterStateServiceGrpc.getSetLogLevelMethod().getFullMethodName();

        for (ServerMethodDefinition<?, ?> method : original.getMethods()) {
            if (method.getMethodDescriptor().getFullMethodName().equals(setLogLevelMethodName)) {
                builder.addMethod(
                        ClusterStateServiceGrpc.getSetLogLevelMethod(),
                        ServerCalls.asyncUnaryCall(this::handleSetLogLevel));
            } else {
                builder.addMethod((ServerMethodDefinition<?, ?>) method);
            }
        }
        return builder.build();
    }

    private void handleSetLogLevel(Kernel.AdminSetLogLevelRequest request, StreamObserver<Empty> responseObserver) {
        try {
            authenticator.checkAccess(GRAPH, BOUNDARY, SecurityAuthenticator.OperationType.WRITE);

            String level = request.getLevel().toUpperCase();
            if (!VALID_LEVELS.contains(level)) {
                responseObserver.onError(Status.INVALID_ARGUMENT
                        .withDescription("Invalid level: " + request.getLevel() + ". Valid levels: " + VALID_LEVELS)
                        .asRuntimeException());
                return;
            }

            LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
            Level logbackLevel = Level.toLevel(level);

            String loggerName = request.getLoggerName();
            if (loggerName.isEmpty()) {
                loggerName = org.slf4j.Logger.ROOT_LOGGER_NAME;
            }

            ch.qos.logback.classic.Logger targetLogger = loggerContext.getLogger(loggerName);
            Level previousLevel = targetLogger.getLevel();
            targetLogger.setLevel(logbackLevel);

            logger.info("Set log level: {} -> {} (was {})", loggerName, level, previousLevel);

            responseObserver.onNext(Empty.getDefaultInstance());
            responseObserver.onCompleted();
        } catch (ProtoException e) {
            responseObserver.onError(io.grpc.Status.fromCodeValue(e.getCode())
                    .withDescription(e.getMessage())
                    .withCause(e)
                    .asRuntimeException());
        } catch (Exception e) {
            logger.error("SetLogLevel failed: {}", e.getMessage());
            responseObserver.onError(Status.INTERNAL
                    .withDescription("SetLogLevel failed: " + e.getMessage())
                    .withCause(e)
                    .asRuntimeException());
        }
    }
}
