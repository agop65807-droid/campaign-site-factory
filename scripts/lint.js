const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const ignoredDirectories = new Set(['.git', '.vercel', 'node_modules']);
const failures = [];

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath);
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      try {
        execFileSync(process.execPath, ['--check', fullPath], { stdio: 'pipe' });
      } catch (error) {
        failures.push(path.relative(root, fullPath));
      }
    }
  }
}

walk(root);

if (failures.length) {
  console.error(`JavaScript syntax failed for: ${failures.join(', ')}`);
  process.exit(1);
}

console.log('JavaScript syntax check passed for all project files.');
