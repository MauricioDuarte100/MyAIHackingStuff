/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { promises as fs } from 'fs';
import path from 'path';
import { exec } from 'child_process';
declare const execAsync: typeof exec.__promisify__;
export declare function runPoc({ filePath, }: {
    filePath: string;
}, dependencies?: {
    fs: typeof fs;
    path: typeof path;
    execAsync: typeof execAsync;
}): Promise<CallToolResult>;
export {};
