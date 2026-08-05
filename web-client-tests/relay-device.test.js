import test from "node:test";
import assert from "node:assert/strict";
import { shareSession, openViewer, timePasses, endHarness } from "./relay-harness.js";

test.afterEach(endHarness);

test("a first-time viewer is admitted, enrolls a device, and ends up connected", async () => {
    const host = shareSession({ enrollsDevices: true });
    const viewer = openViewer(host);

    await viewer.connects();

    assert.equal(viewer.status, "connected");
    assert.equal(await viewer.remembersDevice(), true);
});

test("a returning viewer reconnects on its own, using its enrolled device signature", async () => {
    const host = shareSession({ enrollsDevices: true });
    const viewer = openViewer(host);
    await viewer.connects();

    await viewer.reconnects();

    assert.equal(viewer.status, "connected");
    assert.equal(viewer.reconnectedBySignature, true);
});

test("an enrolled viewer's device private key stays on the device and cannot be exported", async () => {
    const host = shareSession({ enrollsDevices: true });
    const viewer = openViewer(host);

    await viewer.connects();

    assert.equal(await viewer.deviceKeyCanBeExported(), false);
});

test("a guest-link viewer connects without enrolling a device", async () => {
    const host = shareSession({ enrollsDevices: false });
    const viewer = openViewer(host);

    await viewer.connects();

    assert.equal(viewer.status, "connected");
    assert.equal(await viewer.remembersDevice(), false);
});

test("the connection stays alive as long as the host keeps answering heartbeats", async () => {
    const host = shareSession({ enrollsDevices: true });
    const viewer = openViewer(host);
    await viewer.connects();

    await timePasses("5m");

    assert.equal(viewer.status, "connected");
});

test("the viewer disconnects on its own once the host stops answering heartbeats", async () => {
    const host = shareSession({ enrollsDevices: true });
    const viewer = openViewer(host);
    await viewer.connects();

    host.stopsAnsweringHeartbeats();
    await timePasses("2m");

    assert.equal(viewer.status, "disconnected");
});

test("when the host ends the session, the viewer disconnects but keeps its device for next time", async () => {
    const host = shareSession({ enrollsDevices: true });
    const viewer = openViewer(host);
    await viewer.connects();

    await host.endsSession();
    await viewer.becomesDisconnected();

    assert.equal(await viewer.remembersDevice(), true);
});

test("when the host revokes the device, the returning viewer is refused and forgets the device", async () => {
    const host = shareSession({ enrollsDevices: true });
    const viewer = openViewer(host);
    await viewer.connects();

    host.revokesTheDevice();
    await viewer.reconnects();

    assert.equal(viewer.status, "refused");
    assert.equal(await viewer.remembersDevice(), false);
});

test("a replayed or malformed frame from the relay does not disturb the viewer", async () => {
    const host = shareSession({ enrollsDevices: true });
    const viewer = openViewer(host);
    await viewer.connects();

    host.replaysAnEarlierFrameTo(viewer);
    host.deliversAMalformedFrameTo(viewer);
    await timePasses("1s");
    assert.equal(viewer.status, "connected");

    await host.endsSession();
    await viewer.becomesDisconnected();
    assert.equal(viewer.status, "disconnected");
});
