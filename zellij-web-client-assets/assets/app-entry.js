import { initTerminal } from "./terminal.js";
import { setupInputHandlers } from "./input.js";
import { initWebSockets } from "./websockets.js";

export async function start({ session, controlChannel, bufferedControl }) {
    const { webClientId, e2e, isReadOnly, sessionRows, sessionCols, handshake } = session;

    const { term, fitAddon } = initTerminal();
    const sessionName = location.pathname.split("/").pop();

    let sendAnsiKey = (ansiKey) => {};

    setupInputHandlers(term, fitAddon, sendAnsiKey);

    document.title = sessionName;
    const websockets = initWebSockets(
        webClientId,
        sessionName,
        term,
        fitAddon,
        sendAnsiKey,
        e2e,
        { isReadOnly, sessionRows, sessionCols },
        handshake,
        controlChannel,
        bufferedControl
    );

    sendAnsiKey = websockets.sendAnsiKey;
    setupInputHandlers(term, fitAddon, sendAnsiKey);

    return websockets;
}
