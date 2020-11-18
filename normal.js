// TODO
// 1. Get most common list of passwords
// 2. Get all alphanumeric passwords of lengths 1-4
// 3. Get list of bank password hashes
// 4. Create map of common and short passwords to hash
// 5. If bank password is found in map, record it

const fs = require('fs');
const bcrypt = require('bcrypt');

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
	console.log(`Elapsed Time: ${end - start} ms to get ${shortPasswords.length} short passwords`);
}
getShortPasswords();

// bcrypt.hash('password', saltRounds).then(console.log);

const passwords = [...commonPasswords, ...shortPasswords];
let count = 0;

start = new Date();
for (let [hashIndex, hash] of hashes.entries()) {
	for (let [i, pw] of passwords.entries()) {
		process.stdout.clearLine();
		process.stdout.cursorTo(0);
		process.stdout.write(`Hash: ${hashIndex}/${hashes.length} Password ${i}/${passwords.length}`);
		if (bcrypt.compareSync(pw, hash)) {
			fs.appendFileSync('cracked-passwords-normal.txt', `${hash} ${pw}\n`);
			count++;
			passwords.splice(i, 1);
			break;
		}
	}
}
console.log();
end = new Date();
console.log(`Elapsed Time: ${end - start}ms to decrypt ${count}/${passwords.length}`);
