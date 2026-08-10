import { initTerminal, settleFontSize } from "./terminal.js";
import { setupInputHandlers } from "./input.js";
import { initWebSockets } from "./websockets.js";
import { initMobileUi } from "./mobile-ui.js";
import { isRelayMode } from "/assets/utils.js";

export async function start({ session, controlChannel, bufferedControl }) {
    const {
        webClientId,
        e2e,
        isReadOnly,
        sessionRows,
        sessionCols,
        handshake,
        config,
    } = session;

    const { term, fitAddon } = initTerminal(config);
    settleFontSize(term, fitAddon, config);

    const sessionName = isRelayMode()
        ? location.pathname.split("/").pop()
        : session.sessionName || location.pathname.split("/").pop();

    let websockets = null;
    initMobileUi({
        term,
        fitAddon,
        isReadOnly: !!isReadOnly,
        getSendAnsiKey: () => (websockets ? websockets.sendAnsiKey : () => {}),
    });

    document.title = sessionName;
    websockets = initWebSockets(
        webClientId,
        sessionName,
        term,
        fitAddon,
        () => {},
        e2e,
        { isReadOnly, sessionRows, sessionCols, config },
        handshake,
        controlChannel,
        bufferedControl
    );

    setupInputHandlers(term, fitAddon, websockets.sendAnsiKey);

    return websockets;
}
