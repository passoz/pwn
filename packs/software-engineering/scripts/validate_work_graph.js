#!/usr/bin/env node

import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { listWorks } from "./work_artifacts.js";
import { validateTasksDetailed } from "./validate_tasks.js";

function dependencyList(value) {
  return value === "none" ? [] : value.split(",").map((entry) => entry.trim()).filter(Boolean);
}

export function validateWorkGraph(root = process.cwd()) {
  const repositoryRoot = path.resolve(root);
  const errors = [];
  const plans = new Map();
  const works = listWorks(repositoryRoot).filter((work) => /^\d{4}$/.test(work.work_id));

  for (const work of works) {
    if (!work.plan_exists) {
      if (["planned", "active", "blocked", "completed"].includes(work.state)) errors.push(`Work ${work.work_id}: plan missing: ${work.plan}`);
      continue;
    }
    const absolute = path.join(repositoryRoot, work.plan);
    const result = validateTasksDetailed(absolute);
    if (result.errors.length) {
      for (const error of result.errors) errors.push(`Work ${work.work_id}: ${error}`);
      continue;
    }
    if (result.workId !== work.work_id) errors.push(`Work ${work.work_id}: plan declares Work ID ${result.workId ?? "missing"}`);
    plans.set(work.work_id, result.tasks);
  }

  const nodes = new Map();
  for (const [workId, tasks] of plans) {
    for (const task of tasks) nodes.set(`${workId}/${task.id}`, task);
  }

  const edges = new Map([...nodes.keys()].map((node) => [node, []]));
  for (const [workId, tasks] of plans) {
    for (const task of tasks) {
      const node = `${workId}/${task.id}`;
      for (const raw of dependencyList(task.dependsOn)) {
        const dependency = raw.includes("/") ? raw : `${workId}/${raw}`;
        if (!nodes.has(dependency)) {
          errors.push(`${node}: dependency not found: ${dependency}`);
          continue;
        }
        edges.get(node).push(dependency);
      }
    }
  }

  const visiting = new Set();
  const visited = new Set();
  function visit(node, stack) {
    if (visiting.has(node)) {
      const start = stack.indexOf(node);
      errors.push(`dependency cycle: ${[...stack.slice(start), node].join(" -> ")}`);
      return;
    }
    if (visited.has(node)) return;
    visiting.add(node);
    for (const dependency of edges.get(node) ?? []) visit(dependency, [...stack, node]);
    visiting.delete(node);
    visited.add(node);
  }
  for (const node of edges.keys()) visit(node, []);

  return { errors: [...new Set(errors)], works: works.length, tasks: nodes.size };
}

export function main(argv = process.argv.slice(2)) {
  if (argv.length > 1) {
    console.error("usage: validate_work_graph.js [REPOSITORY_ROOT]");
    return 2;
  }
  const root = argv[0] ?? process.cwd();
  if (!existsSync(root)) {
    console.error(`WORK GRAPH VALIDATION: FAIL\n- root not found: ${root}`);
    return 1;
  }
  const result = validateWorkGraph(root);
  if (result.errors.length) {
    console.error(`WORK GRAPH VALIDATION: FAIL (${result.errors.length} errors)`);
    for (const error of result.errors) console.error(`- ${error}`);
    return 1;
  }
  console.log("WORK GRAPH VALIDATION: PASS");
  console.log(`Works: ${result.works}`);
  console.log(`Tasks: ${result.tasks}`);
  return 0;
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(currentFile)) process.exitCode = main();
