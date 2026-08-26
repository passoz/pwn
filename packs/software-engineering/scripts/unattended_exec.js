#!/usr/bin/env node

import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const EXIT_USAGE = 2;
const EXIT_NOT_FOUND = 127;
const EXIT_TIMEOUT = 124;
const KILL_GRACE_MS = 5_000;

function usage() {
  return "usage: unattended_exec.js --timeout-seconds N -- COMMAND [ARG ...]";
}

function parse(argv) {
  if (argv.length < 4 || argv[0] !== "--timeout-seconds") throw new Error(usage());
  const timeoutSeconds = Number(argv[1]);
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 86_400) {
    throw new Error("timeout must be an integer from 1 to 86400 seconds");
  }
  if (argv[2] !== "--" || !argv[3]) throw new Error(usage());
  return { timeoutMs: timeoutSeconds * 1_000, command: argv.slice(3) };
}

function signalExitCode(signal) {
  const numbers = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGKILL: 9, SIGTERM: 15 };
  return 128 + (numbers[signal] ?? 1);
}

function terminateTree(child, signal) {
  if (!child.pid) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

export function runUnattended(argv = process.argv.slice(2)) {
  let parsed;
  try {
    parsed = parse(argv);
  } catch (error) {
    console.error(error.message);
    return Promise.resolve(EXIT_USAGE);
  }

  return new Promise((resolve) => {
    let finished = false;
    let timedOut = false;
    let escalation;

    const child = spawn(parsed.command[0], parsed.command.slice(1), {
      cwd: process.cwd(),
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: "0",
        GIT_PAGER: "cat",
        PAGER: "cat",
      },
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });

    child.stdout.pipe(process.stdout);
    child.stderr.pipe(process.stderr);

    const cleanup = () => {
      clearTimeout(timeout);
      clearTimeout(escalation);
      process.off("SIGINT", forwardInterrupt);
      process.off("SIGTERM", forwardTermination);
    };

    const finish = (exitCode) => {
      if (finished) return;
      finished = true;
      cleanup();
      resolve(exitCode);
    };

    const stop = (signal) => {
      try {
        terminateTree(child, signal);
      } catch (error) {
        console.error(`unattended_exec: failed to send ${signal}: ${error.message}`);
      }
    };

    const forwardInterrupt = () => stop("SIGINT");
    const forwardTermination = () => stop("SIGTERM");
    process.on("SIGINT", forwardInterrupt);
    process.on("SIGTERM", forwardTermination);

    const timeout = setTimeout(() => {
      timedOut = true;
      console.error(`unattended_exec: TIMEOUT after ${parsed.timeoutMs / 1_000}s; terminating process group`);
      stop("SIGTERM");
      escalation = setTimeout(() => stop("SIGKILL"), KILL_GRACE_MS);
    }, parsed.timeoutMs);

    child.on("error", (error) => {
      console.error(`unattended_exec: ${error.message}`);
      finish(error.code === "ENOENT" ? EXIT_NOT_FOUND : 1);
    });

    child.on("close", (code, signal) => {
      if (timedOut) {
        // The direct child may exit on SIGTERM while one of its descendants ignores it.
        // A final group kill prevents that descendant from surviving the wrapper.
        stop("SIGKILL");
        finish(EXIT_TIMEOUT);
      } else if (code !== null) finish(code);
      else finish(signalExitCode(signal));
    });
  });
}

const currentFile = fileURLToPath(import.meta.url);
const invokedDirectly = process.argv[1] && realpathSync(process.argv[1]) === realpathSync(currentFile);
if (invokedDirectly) process.exitCode = await runUnattended();
