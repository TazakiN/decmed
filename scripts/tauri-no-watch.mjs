import { spawn } from 'node:child_process';
import path from 'node:path';

const args = process.argv.slice(2);

if (args[0] === 'dev' && !args.includes('--no-watch')) {
	args.splice(1, 0, '--no-watch');
}

const tauriBin = path.join(
	process.cwd(),
	'node_modules',
	'.bin',
	process.platform === 'win32' ? 'tauri.cmd' : 'tauri'
);

const child = spawn(tauriBin, args, {
	stdio: 'inherit',
	shell: false
});

child.on('exit', (code, signal) => {
	if (signal) {
		process.kill(process.pid, signal);
		return;
	}

	process.exit(code ?? 1);
});

child.on('error', (error) => {
	console.error(error);
	process.exit(1);
});
