const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const fs = require('fs');
const bcrypt = require('bcrypt');
const cliProgress = require('cli-progress');

if (cluster.isMaster) {
	const commonPasswords = require('./common-passwords.json');
	const shortPasswords = [];

	let start;
	let end;

	const hashes = fs
		.readFileSync('./bank.hash', 'utf-8')
		.split('\n')
		.map((pw) => pw.trim()); // Because Windows sucks sometimes and puts an \r for us to enjoy

	function getShortPasswords() {
		const charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		function* pws(n) {
			if (n == 1) yield* charSet;
			else
				for (let a of pws(n - 1)) {
					for (let b of charSet) {
						yield `${a}${b}`;
					}
				}
		}
		function* pwsUpTo(n) {
			for (let i = 1; i <= n; i++) {
				yield* pws(i);
			}
		}
		start = new Date();
		for (let pw of pwsUpTo(4)) {
			shortPasswords.push(pw);
		}
		end = new Date();
		console.log(`Elapsed Time: ${end - start} ms to get ${shortPasswords.length} short passwords\n\n`);
	}

	let passwords = [];

	const splitQty = hashes.length / numCPUs;

	getShortPasswords();

	passwords = [...commonPasswords, ...shortPasswords];

	count = 0;
	start = new Date();

	const multibar = new cliProgress.MultiBar(
		{
			clearOnComplete: false,
			hideCursor: true,
		},
		cliProgress.Presets.shades_classic
	);

	for (let i = 0; i < numCPUs; i++) {
		const worker = cluster.fork();

		let childHashes;

		if (i == numCPUs - 1) {
			childHashes = hashes;
		} else {
			childHashes = hashes.splice(0, splitQty);
		}
		let bar = multibar.create(childHashes.length, 0);
		let msg = { childHashes, CPU: i + 1, passwords };

		worker.send(msg);
		worker.on('exit', () => {
			count++;

			if (count == numCPUs) {
				end = new Date();
				console.log(`Elapsed Time: ${end - start}ms to decrypt ${passwords.length} passwords`);
			}
		});

		worker.on('message', (msg) => {
			bar.increment();
		});
	}
} else {
	//worker
	process.on('message', ({ childHashes, CPU, passwords }) => {
		for (let [hashIndex, hash] of childHashes.entries()) {
			let found = false;
			for (let [i, pw] of passwords.entries()) {
				if (bcrypt.compareSync(pw, hash)) {
					found = true;
					passwords.splice(i, 1);

					fs.appendFileSync('cracked-passwords-processes.txt', `${hash} ${pw}\n`);
					process.send('Found one');
				}
				if (found) break;
			}
		}
		process.exit();
	});
}
