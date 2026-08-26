#!/usr/bin/env node

import net from "node:net";
import { spawn } from "node:child_process";

function usage() {
  console.log(`Usage: with_server.js --server COMMAND --port PORT [--server COMMAND --port PORT ...] [--timeout SECONDS] -- COMMAND [ARGS...]

Starts each server, waits for its TCP port, runs COMMAND, and stops the servers.

Examples:
  node scripts/with_server.js --server "npm run dev" --port 5173 -- node automation.js
  node scripts/with_server.js --server "cd backend && npm start" --port 3000 \\
    --server "cd frontend && npm run dev" --port 5173 -- node automation.js`);
}

function parseArgs(argv) {
  if (argv.includes("-h") || argv.includes("--help")) return { help: true };
  const separator = argv.indexOf("--");
  if (separator === -1) throw new Error("missing -- before the command to run");
  const options = argv.slice(0, separator);
  const command = argv.slice(separator + 1);
  if (!command.length) throw new Error("no command specified to run");

  const servers = [];
  let timeout = 30;
  for (let index = 0; index < options.length; index += 1) {
    const option = options[index];
    if (option === "--server") {
      const serverCommand = options[index + 1];
      if (!serverCommand) throw new Error("--server requires a command");
      const portFlag = options[index + 2];
      const portValue = options[index + 3];
      if (portFlag !== "--port" || !portValue) throw new Error("each --server must be followed by --port PORT");
      const port = Number(portValue);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid port: ${portValue}`);
      servers.push({ command: serverCommand, port });
      index += 3;
      continue;
    }
    if (option === "--timeout") {
      const value = Number(options[index + 1]);
      if (!Number.isFinite(value) || value <= 0) throw new Error(`invalid timeout: ${options[index + 1]}`);
      timeout = value;
      index += 1;
      continue;
    }
    throw new Error(`unknown option: ${option}`);
  }
  if (!servers.length) throw new Error("at least one --server and --port pair is required");
  return { help: false, servers, timeout, command };
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function isServerReady(port, timeoutSeconds) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    const ready = await new Promise((resolve) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      const finish = (value) => {
        socket.destroy();
        resolve(value);
      };
      socket.setTimeout(1000);
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
      socket.once("timeout", () => finish(false));
    });
    if (ready) return true;
    await sleep(500);
  }
  return false;
}

async function stopProcess(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  const exited = await Promise.race([
    new Promise((resolve) => child.once("exit", () => resolve(true))),
    sleep(5000).then(() => false),
  ]);
  if (!exited && child.exitCode === null) {
    child.kill("SIGKILL");
    await new Promise((resolve) => child.once("exit", resolve));
  }
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`Error: ${error.message}`);
    usage();
    return 1;
  }
  if (args.help) {
    usage();
    return 0;
  }

  const processes = [];
  const stopAll = async () => {
    console.log(`\nStopping ${processes.length} server(s)...`);
    for (let index = processes.length - 1; index >= 0; index -= 1) {
      await stopProcess(processes[index]);
      console.log(`Server ${index + 1} stopped`);
    }
  };

  try {
    for (const [index, server] of args.servers.entries()) {
      console.log(`Starting server ${index + 1}/${args.servers.length}: ${server.command}`);
      const child = spawn(server.command, { shell: true, stdio: ["ignore", "pipe", "pipe"] });
      processes.push(child);
      console.log(`Waiting for server on port ${server.port}...`);
      if (!(await isServerReady(server.port, args.timeout))) {
        throw new Error(`server failed to start on port ${server.port} within ${args.timeout}s`);
      }
      console.log(`Server ready on port ${server.port}`);
    }

    console.log(`\nAll ${processes.length} server(s) ready`);
    console.log(`Running: ${args.command.join(" ")}\n`);
    const result = await new Promise((resolve, reject) => {
      const child = spawn(args.command[0], args.command.slice(1), { stdio: "inherit" });
      child.once("error", reject);
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
    return result.code ?? (result.signal ? 1 : 0);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    return 1;
  } finally {
    await stopAll();
  }
}

process.exitCode = await main();
