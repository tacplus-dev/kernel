// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.ClusterStateServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
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
 */
public class ClusterSetLogLevelHandler {

    private static final Logger logger = LoggerFactory.getLogger(ClusterSetLogLevelHandler.class);

    private static final Set<String> VALID_LEVELS = Set.of("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "OFF");

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
        } catch (Exception e) {
            logger.error("SetLogLevel failed: {}", e.getMessage());
            responseObserver.onError(Status.INTERNAL
                    .withDescription("SetLogLevel failed: " + e.getMessage())
                    .withCause(e)
                    .asRuntimeException());
        }
    }
}
