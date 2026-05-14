import { test } from 'node:test';
import assert from 'assert/strict';
import { cleanup } from '../backend/fetch.js';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'fs';
import { join } from 'path';

test('fetch: cleanup removes directory', async () => {
  mkdirSync('/tmp/npm-scan-test-cleanup', { recursive: true });
  writeFileSync('/tmp/npm-scan-test-cleanup/test.txt', 'test');
  assert(existsSync('/tmp/npm-scan-test-cleanup'));
  cleanup('/tmp/npm-scan-test-cleanup');
  assert(!existsSync('/tmp/npm-scan-test-cleanup'));
});

test('fetch: cleanup on non-existent dir does not throw', async () => {
  cleanup('/tmp/npm-scan-nonexistent-xyz123');
});

test('fetch: cleanup on file (not dir) does not throw', async () => {
  writeFileSync('/tmp/npm-scan-test-file', 'test');
  cleanup('/tmp/npm-scan-test-file');
});