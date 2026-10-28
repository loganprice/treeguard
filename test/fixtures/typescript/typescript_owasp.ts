// TypeScript OWASP Test Fixture

import * as fs from 'fs';
import * as crypto from 'crypto';
import * as child_process from 'child_process';
import * as jwt from 'jsonwebtoken';

export function testTypeScriptOwasp(userPath: string, cmd: string, userInput: string): void {
    // ruleid: js-path-traversal
    fs.readFile(userPath, 'utf8', (err, data) => {});

    // ok: js-path-traversal
    fs.readFile('safe.txt', 'utf8', () => {});

    // ruleid: js-command-injection
    child_process.exec(cmd);

    // ok: js-command-injection
    console.log("safe");

    // ruleid: js-dangerous-eval
    eval(userInput);

    // ruleid: js-weak-cryptography
    crypto.createHash('md5');

    // ok: js-weak-cryptography
    crypto.createHash('sha256');

    // ruleid: js-hardcoded-secret
    jwt.sign({ id: 1 }, "hardcoded_secret_token");
}
