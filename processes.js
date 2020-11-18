const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const fs = require('fs');
const bcrypt = require('bcrypt');

if (cluster.isMaster) {
	const commonPasswords = require('./common-passwords.json');
	const shortPasswords = [];

	let start;
	let end;

	const hashes = fs
		.readFileSync('./test.hash', 'utf-8')
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
		console.log(`Elapsed Time: ${end - start} ms to get ${shortPasswords.length} short passwords`);
	}

	let passwords = [];

	const splitQty = hashes.length / numCPUs;

	getShortPasswords();

	passwords = [...commonPasswords, ...shortPasswords];

	count = 0;
	start = new Date();
	for (let i = 0; i < numCPUs; i++) {
		const worker = cluster.fork();
		let msg;

		if (i == numCPUs - 1) {
			msg = { childHashes: hashes, CPU: i + 1, passwords };
		} else {
			msg = { childHashes: hashes.splice(0, splitQty), CPU: i + 1, passwords };
		}
		worker.send(msg);
		worker.on('exit', () => {
			count++;

			if (count == numCPUs - 8) {
				end = new Date();
				console.log(`Elapsed Time: ${end - start}ms to decrypt ${passwords.length} passwords`);
			}
		});
	}
} else {
	//worker
	process.on('message', ({ childHashes, CPU, passwords }) => {
		console.log(`Handling ${childHashes.length} hashes`);
		console.log(`Handling ${passwords.length} passwords`);

		for (let [hashIndex, hash] of childHashes.entries()) {
			for (let [i, pw] of passwords.entries()) {
				if (bcrypt.compareSync(pw, hash)) {
					// console.log(`${pw} [${hash}]`);
					passwords.splice(i, 1);
					fs.appendFileSync('cracked-passwords-processes.txt', `${hash} ${pw}\n`);
					break;
				}
			}
		}
		process.exit();
	});
}
