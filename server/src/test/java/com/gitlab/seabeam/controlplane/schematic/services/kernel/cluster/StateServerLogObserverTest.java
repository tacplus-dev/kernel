// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig.LogMessage;
import io.grpc.stub.StreamObserver;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two Log streams from the same peer must not displace or unregister each other.
 *
 * <p>The map used to be keyed on the peer address, which identifies a pod and
 * not a stream: a second stream from the same pod silently replaced the first,
 * and when the FIRST stream's cancel finally landed it removed the SECOND
 * stream's entry — the live client then stopped receiving log messages while its
 * stream stayed open. A reconnect landing before the old cancel does hits the
 * same window.
 */
class StateServerLogObserverTest {

	/** Collects what a Log stream received. */
	private static final class Recorder implements StreamObserver<LogMessage> {
		private final List<String> messages = new ArrayList<>();

		@Override
		public void onNext(LogMessage value) {
			messages.add(value.getMessage());
		}

		@Override
		public void onError(Throwable t) {
		}

		@Override
		public void onCompleted() {
		}
	}

	private static final String PEER = "/10.0.0.1:4242";

	@Test
	void twoStreamsFromOnePeerGetDistinctTokens() {
		StateServer server = new StateServer();
		String first = server.addLogObserver(PEER, new Recorder());
		String second = server.addLogObserver(PEER, new Recorder());
		assertNotEquals(first, second, "each stream must get its own registration token");
	}

	@Test
	void aSecondStreamDoesNotDisplaceTheFirst() {
		StateServer server = new StateServer();
		Recorder first = new Recorder();
		Recorder second = new Recorder();
		server.addLogObserver(PEER, first);
		server.addLogObserver(PEER, second);

		server.warnPeer(PEER, "rate limited");

		assertEquals(List.of("rate limited"), first.messages, "the first stream must still receive");
		assertEquals(List.of("rate limited"), second.messages, "the second stream must receive too");
	}

	/** The regression: the stale cancel must not take the live stream with it. */
	@Test
	void aStaleCancelDoesNotUnregisterTheNewerStream() {
		StateServer server = new StateServer();
		Recorder stale = new Recorder();
		Recorder live = new Recorder();
		String staleToken = server.addLogObserver(PEER, stale);
		server.addLogObserver(PEER, live);

		// The old stream's onCancel handler finally fires, after the reconnect.
		server.removeLogObserver(staleToken);

		server.warnPeer(PEER, "after the stale cancel");
		assertEquals(List.of("after the stale cancel"), live.messages,
				"the live stream must keep receiving after the older stream's cancel");
		assertTrue(stale.messages.isEmpty(), "the cancelled stream must receive nothing");
	}

	@Test
	void removingAnUnknownOrAlreadyRemovedTokenIsANoop() {
		StateServer server = new StateServer();
		Recorder live = new Recorder();
		String token = server.addLogObserver(PEER, live);

		server.removeLogObserver(token);
		server.removeLogObserver(token);
		server.removeLogObserver("never-registered");

		server.info("broadcast");
		assertTrue(live.messages.isEmpty());
	}

	@Test
	void broadcastReachesEveryStreamAndSendToPeerOnlyThatPeers() {
		StateServer server = new StateServer();
		Recorder onePeerFirst = new Recorder();
		Recorder onePeerSecond = new Recorder();
		Recorder otherPeer = new Recorder();
		server.addLogObserver(PEER, onePeerFirst);
		server.addLogObserver(PEER, onePeerSecond);
		server.addLogObserver("/10.0.0.2:4242", otherPeer);

		server.warnPeer(PEER, "just yours");
		assertTrue(otherPeer.messages.isEmpty(), "sendToPeer must not reach another peer");

		server.info("everyone");
		assertEquals(List.of("just yours", "everyone"), onePeerFirst.messages);
		assertEquals(List.of("just yours", "everyone"), onePeerSecond.messages);
		assertEquals(List.of("everyone"), otherPeer.messages);
	}

	/** A stream that throws on write is dropped, and only that one. */
	@Test
	void aFailingStreamIsDroppedWithoutTakingItsPeersOther() {
		StateServer server = new StateServer();
		Recorder healthy = new Recorder();
		server.addLogObserver(PEER, new StreamObserver<>() {
			@Override
			public void onNext(LogMessage value) {
				throw new IllegalStateException("stream is dead");
			}

			@Override
			public void onError(Throwable t) {
			}

			@Override
			public void onCompleted() {
			}
		});
		server.addLogObserver(PEER, healthy);

		server.warnPeer(PEER, "first");
		server.warnPeer(PEER, "second");

		assertEquals(List.of("first", "second"), healthy.messages,
				"the healthy stream keeps receiving after the dead one is dropped");
	}
}
