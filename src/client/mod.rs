pub mod boundaries;
pub mod layout;
pub mod pane_resizer;
pub mod panes;
pub mod tab;

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::mpsc;
use std::thread;

use crate::cli::CliArgs;
use crate::common::{
    command_is_executing::CommandIsExecuting,
    errors::{ClientContext, ContextType},
    input::config::Config,
    input::handler::input_loop,
    os_input_output::ClientOsApi,
    SenderType, SenderWithContext, SyncChannelWithContext,
};
use crate::server::ServerInstruction;

/// Instructions related to the client-side application and sent from server to client
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientInstruction {
    Error(String),
    Render(Option<String>),
    UnblockInputThread,
    Exit,
}

pub fn start_client(mut os_input: Box<dyn ClientOsApi>, opts: CliArgs) {
    let take_snapshot = "\u{1b}[?1049h";
    os_input.unset_raw_mode(0);
    let _ = os_input
        .get_stdout_writer()
        .write(take_snapshot.as_bytes())
        .unwrap();

    let config = Config::from_cli_config(opts.config)
        .map_err(|e| {
            eprintln!("There was an error in the config file:\n{}", e);
            std::process::exit(1);
        })
        .unwrap();

    let mut command_is_executing = CommandIsExecuting::new();

    let full_screen_ws = os_input.get_terminal_size_using_fd(0);
    os_input.connect_to_server();
    os_input.send_to_server(ServerInstruction::NewClient(full_screen_ws));
    os_input.set_raw_mode(0);

    let (send_client_instructions, receive_client_instructions): SyncChannelWithContext<
        ClientInstruction,
    > = mpsc::sync_channel(500);
    let send_client_instructions =
        SenderWithContext::new(SenderType::SyncSender(send_client_instructions));

    #[cfg(not(test))]
    std::panic::set_hook({
        use crate::errors::handle_panic;
        let send_client_instructions = send_client_instructions.clone();
        Box::new(move |info| {
            handle_panic(info, &send_client_instructions);
        })
    });

    let _stdin_thread = thread::Builder::new()
        .name("stdin_handler".to_string())
        .spawn({
            let send_client_instructions = send_client_instructions.clone();
            let command_is_executing = command_is_executing.clone();
            let os_input = os_input.clone();
            move || {
                input_loop(
                    os_input,
                    config,
                    command_is_executing,
                    send_client_instructions,
                )
            }
        });

    let _signal_thread = thread::Builder::new()
        .name("signal_listener".to_string())
        .spawn({
            let os_input = os_input.clone();
            move || {
                os_input.receive_sigwinch(Box::new({
                    let os_api = os_input.clone();
                    move || {
                        os_api.send_to_server(ServerInstruction::TerminalResize(
                            os_api.get_terminal_size_using_fd(0),
                        ));
                    }
                }));
            }
        })
        .unwrap();

    let router_thread = thread::Builder::new()
        .name("router".to_string())
        .spawn({
            let os_input = os_input.clone();
            move || {
                loop {
                    let (instruction, mut err_ctx) = os_input.recv_from_server();
                    err_ctx.add_call(ContextType::Client(ClientContext::from(&instruction)));
                    if let ClientInstruction::Exit = instruction {
                        break;
                    }
                    send_client_instructions.send(instruction).unwrap();
                }
                send_client_instructions
                    .send(ClientInstruction::Exit)
                    .unwrap();
            }
        })
        .unwrap();

    #[warn(clippy::never_loop)]
    loop {
        let (client_instruction, mut err_ctx) = receive_client_instructions
            .recv()
            .expect("failed to receive app instruction on channel");

        err_ctx.add_call(ContextType::Client(ClientContext::from(
            &client_instruction,
        )));
        match client_instruction {
            ClientInstruction::Exit => break,
            ClientInstruction::Error(backtrace) => {
                let _ = os_input.send_to_server(ServerInstruction::ClientExit);
                os_input.unset_raw_mode(0);
                let goto_start_of_last_line = format!("\u{1b}[{};{}H", full_screen_ws.rows, 1);
                let restore_snapshot = "\u{1b}[?1049l";
                let error = format!(
                    "{}\n{}{}",
                    goto_start_of_last_line, restore_snapshot, backtrace
                );
                let _ = os_input
                    .get_stdout_writer()
                    .write(error.as_bytes())
                    .unwrap();
                std::process::exit(1);
            }
            ClientInstruction::Render(output) => {
                if output.is_none() {
                    break;
                }
                let mut stdout = os_input.get_stdout_writer();
                stdout
                    .write_all(&output.unwrap().as_bytes())
                    .expect("cannot write to stdout");
                stdout.flush().expect("could not flush");
            }
            ClientInstruction::UnblockInputThread => {
                command_is_executing.unblock_input_thread();
            }
        }
    }

    let _ = os_input.send_to_server(ServerInstruction::ClientExit);
    router_thread.join().unwrap();

    // cleanup();
    let reset_style = "\u{1b}[m";
    let show_cursor = "\u{1b}[?25h";
    let restore_snapshot = "\u{1b}[?1049l";
    let goto_start_of_last_line = format!("\u{1b}[{};{}H", full_screen_ws.rows, 1);
    let goodbye_message = format!(
        "{}\n{}{}{}Bye from Zellij!\n",
        goto_start_of_last_line, restore_snapshot, reset_style, show_cursor
    );

    os_input.unset_raw_mode(0);
    let mut stdout = os_input.get_stdout_writer();
    let _ = stdout.write(goodbye_message.as_bytes()).unwrap();
    stdout.flush().unwrap();
}
