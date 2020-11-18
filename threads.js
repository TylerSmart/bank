const { Worker, isMainThread, parentPort } = require("worker_threads");
const numCPUs = require("os").cpus().length;

const fs = require("fs");
const bcrypt = require("bcrypt");
const cliProgress = require("cli-progress");

const commonPasswords = require("./common-passwords.json");
const shortPasswords = [];

let start;
let end;

const hashes = fs
    .readFileSync("./bank.hash", "utf-8")
    .split("\n")
    .map((pw) => pw.trim()); // Because Windows sucks sometimes and puts an \r for us to enjoy

if (isMainThread) {
    function getShortPasswords() {
        console.log("Generating short passwords...");
        const charSet =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
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
        console.log(`Elapsed Time: ${end - start}ms`);
    }

    getShortPasswords();
    const passwords = [...commonPasswords, ...shortPasswords];
    const multibar = new cliProgress.MultiBar(
        {
            clearOnComplete: false,
            hideCursor: true,
        },
        cliProgress.Presets.shades_grey
    );
    const hashBarTotal = multibar.create(hashes.length, 0);

    const splitQty = hashes.length / numCPUs;

    console.log("\nDecrpyting hashes...");
    start = new Date();

    completedCount = 0;

    for (let i = 0; i < numCPUs; i++) {
		const worker = new Worker(__filename);
		
		let childHashes;

        if (i == numCPUs - 1) {
            childHashes = hashes;
        } else {
            childHashes = hashes.splice(0, splitQty);
        }

		const hashBarWorker = multibar.create(childHashes.length, 0);
		
        worker.postMessage({ passwords, hashes: childHashes, bar, hashBar });
        worker.on("message", (text) => {
			hashBarWorker.increment();
            hashBarTotal.increment();
            fs.appendFile("cracked-passwords-normal.txt", text, () => {});
		});
        worker.on("exit", () => {
			completedCount++;

            if (completedCount == numCPUs) {
                end = new Date();
                console.log(`Elapsed Time: ${end - start}ms`);
            }
		});
    }
} else {
    parentPort.on("message", ({ passwords, hashes }) => {

		function* getCompare(hash) {
            passwordBar.update(0);
            for (let password of passwords) {
                passwordBar.increment();
                // console.log(`Testing ${password}`);
                yield new Promise((res, rej) => {
                    bcrypt.compare(password, hash, (err, same) => {
                        res({ same, password });
                    });
                });
            }
        }

        function findPlaintext(pwGetterObj, hash, foundObj) {
            return new Promise(async (res, rej) => {
                const { passwordGetter } = pwGetterObj;

                let result = passwordGetter.next();
                do {
                    const { same, password } = await result.value;

                    if (same) {
                        foundObj.found = true;
                        hashBar.increment();
                        res({ hash, password });
                        break;
                    }
                    result = passwordGetter.next();
                } while (!result.done && !foundObj.found);

                rej();
            });
        }

        for (let hash of hashes) {
            let passwordGetter = getCompare(hash);
            let foundObj = { found: false };
            await findPlaintext({ passwordGetter }, hash, foundObj).then(
                (res) => {
                    parentPort.postMessage(`${res.hash} ${res.password}`);
                }
            );
        }

        process.exit();
    });
}
