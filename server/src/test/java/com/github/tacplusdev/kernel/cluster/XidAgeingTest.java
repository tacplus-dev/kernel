// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * XID ageing (kernel#20, decision record tenant-deletion-2026-10-27): a person
 * who has not signed in for the configured period is deleted as DeleteAccount
 * deletes, and their XID is never reused. Every sign-in that presents an IdP
 * proof, and every merge, resets the clock.
 */
class XidAgeingTest {

	private static final String GOOGLE = "google";
	private static final String APPLE = "apple";
	private static final String SUBJECT = "110169484474386276334";
	private static final long DAY_MS = TimeUnit.DAYS.toMillis(1);
	private static final long YEAR_MS = TimeUnit.SECONDS.toMillis(XidAgeing.DEFAULT_PERIOD_SECONDS);
	private static final long T0 = 1_800_000_000_000L;

	private final AtomicLong now = new AtomicLong(T0);
	private PrincipalMap principalMap;
	private KernelIdentityGraph graph;
	private XidAgeing ageing;

	@BeforeEach
	void setUp() {
		principalMap = new PrincipalMap(new InMemoryManager());
		graph = new KernelIdentityGraph(principalMap, () -> { }, () -> false, now::get);
		ageing = new XidAgeing(graph, 0, now::get);
	}

	@Test
	void aPersonPastThePeriodIsAgedOutAsDeleteAccountDeletes() throws Exception {
		Kernel.Person person = signIn(GOOGLE, SUBJECT);
		assertEquals(T0, person.getLastSignedInAtMs());

		now.set(T0 + YEAR_MS + 1);
		assertEquals(List.of(person.getXid()), ageing.sweep());

		Kernel.Person aged = graph.person(person.getXid());
		assertEquals(T0 + YEAR_MS + 1, aged.getDeletedAtMs());
		assertEquals(0, aged.getLinksCount());
		assertEquals(person.getGeneration() + 1, aged.getGeneration());
		assertEquals("", graph.xidForLink(GOOGLE, SUBJECT));
	}

	@Test
	void aPersonJustInsideThePeriodIsKept() throws Exception {
		Kernel.Person person = signIn(GOOGLE, SUBJECT);

		now.set(T0 + YEAR_MS);
		assertEquals(List.of(), ageing.sweep());

		Kernel.Person kept = graph.person(person.getXid());
		assertEquals(0, kept.getDeletedAtMs());
		assertEquals(person.getXid(), graph.xidForLink(GOOGLE, SUBJECT));
	}

	@Test
	void aSignInResetsTheClock() throws Exception {
		Kernel.Person person = signIn(GOOGLE, SUBJECT);

		long again = T0 + YEAR_MS - DAY_MS;
		now.set(again);
		assertEquals(again, signIn(GOOGLE, SUBJECT).getLastSignedInAtMs());

		now.set(T0 + YEAR_MS + 1);
		assertEquals(List.of(), ageing.sweep());
		now.set(again + YEAR_MS + 1);
		assertEquals(List.of(person.getXid()), ageing.sweep());
	}

	@Test
	void aSignInWithinTheHourWritesNothing() throws Exception {
		signIn(GOOGLE, SUBJECT);
		now.set(T0 + KernelIdentityGraph.SIGN_IN_RECORD_GRANULARITY_MS - 1);
		assertEquals(T0, signIn(GOOGLE, SUBJECT).getLastSignedInAtMs());
	}

	@Test
	void aMergeResetsTheSurvivorsClock() throws Exception {
		Kernel.Person survivor = signIn(GOOGLE, SUBJECT);
		now.set(T0 + DAY_MS);
		Kernel.Person loser = signIn(APPLE, SUBJECT);

		long merged = T0 + YEAR_MS - DAY_MS;
		now.set(merged);
		assertEquals(merged, graph.mergePeople(survivor.getXid(), loser.getXid(), p -> true).getLastSignedInAtMs());

		now.set(T0 + YEAR_MS + DAY_MS + 1);
		assertEquals(List.of(), ageing.sweep());
		assertEquals(survivor.getXid(), graph.xidForLink(APPLE, SUBJECT));
	}

	@Test
	void theConfiguredPeriodIsHonoured() throws Exception {
		Kernel.Person person = signIn(GOOGLE, SUBJECT);
		XidAgeing thirtyDays = new XidAgeing(graph, TimeUnit.DAYS.toSeconds(30), now::get);

		now.set(T0 + 30 * DAY_MS);
		assertEquals(List.of(), thirtyDays.sweep());
		now.set(T0 + 30 * DAY_MS + 1);
		assertEquals(List.of(), ageing.sweep(), "the default year has not passed");
		assertEquals(List.of(person.getXid()), thirtyDays.sweep());
	}

	@Test
	void aPeriodBelowADayIsADay() throws Exception {
		Kernel.Person person = signIn(GOOGLE, SUBJECT);
		XidAgeing oneMinute = new XidAgeing(graph, 60, now::get);

		now.set(T0 + DAY_MS);
		assertEquals(List.of(), oneMinute.sweep());
		now.set(T0 + DAY_MS + 1);
		assertEquals(List.of(person.getXid()), oneMinute.sweep());
	}

	@Test
	void theTombstoneBlocksReuse() throws Exception {
		Kernel.Person person = signIn(GOOGLE, SUBJECT);
		now.set(T0 + YEAR_MS + 1);
		ageing.sweep();

		Kernel.Person next = signIn(GOOGLE, SUBJECT);
		assertNotEquals(person.getXid(), next.getXid(), "the same sign-in starts a new person");
		Kernel.Person tombstone = graph.person(person.getXid());
		assertEquals(person.getXid(), tombstone.getXid(), "the aged-out row is kept");
		assertTrue(tombstone.getDeletedAtMs() != 0);
		assertEquals(next.getXid(), graph.xidForLink(GOOGLE, SUBJECT));
	}

	@Test
	void aPersonWithNoRecordedSignInIsLeftAndTheirClockStarts() throws Exception {
		// A person from before kernel#20: no last_signed_in_at_ms.
		String xid = signIn(GOOGLE, SUBJECT).getXid();
		principalMap.putPeople(xid, graph.person(xid).toBuilder().clearLastSignedInAtMs().build());

		long firstSweep = T0 + 5 * YEAR_MS;
		now.set(firstSweep);
		assertEquals(List.of(), ageing.sweep());
		assertEquals(firstSweep, graph.person(xid).getLastSignedInAtMs());

		now.set(firstSweep + YEAR_MS + 1);
		assertEquals(List.of(xid), ageing.sweep());
	}

	@Test
	void disabledDeletedAndMergedPeopleAreLeftAsTheyAre() throws Exception {
		String disabled = signIn(GOOGLE, "disabled").getXid();
		principalMap.putPeople(disabled, graph.person(disabled).toBuilder().setDisabledAtMs(T0).build());
		String deleted = signIn(GOOGLE, "deleted").getXid();
		graph.deleteAccount(deleted);
		String survivor = signIn(GOOGLE, "survivor").getXid();
		String merged = signIn(APPLE, "merged").getXid();
		graph.mergePeople(survivor, merged, p -> true);
		Kernel.Person deletedBefore = graph.person(deleted);
		Kernel.Person mergedBefore = graph.person(merged);

		now.set(T0 + YEAR_MS + 1);
		assertEquals(List.of(survivor), ageing.sweep());

		assertEquals(0, graph.person(disabled).getDeletedAtMs());
		assertEquals(deletedBefore, graph.person(deleted));
		assertEquals(mergedBefore, graph.person(merged));
	}

	private Kernel.Person signIn(String idpId, String providerSubject) throws Exception {
		return graph.resolveOrCreate(idpId, providerSubject).person();
	}
}
