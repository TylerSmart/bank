// TODO
// 1. Get most common list of passwords
// 2. Get all alphanumeric passwords of lengths 1-4
// 3. Get list of bank password hashes
// 4. Create map of common and short passwords to hash
// 5. If bank password is found in map, record it

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

const hashBar = multibar.create(hashes.length, 0);
const passwordBar = multibar.create(passwords.length, 0);

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

(async () => {
    console.log("\nDecrpyting hashes...");
    start = new Date();

    for (let hash of hashes) {
        // console.log(`Decrpyting ${hash}`);
        let passwordGetter = getCompare(hash);
        let foundObj = { found: false };

        let queue = [
            findPlaintext({ passwordGetter }, hash, foundObj),
            findPlaintext({ passwordGetter }, hash, foundObj),
            findPlaintext({ passwordGetter }, hash, foundObj),
            findPlaintext({ passwordGetter }, hash, foundObj),
            findPlaintext({ passwordGetter }, hash, foundObj),
            findPlaintext({ passwordGetter }, hash, foundObj),
            findPlaintext({ passwordGetter }, hash, foundObj),
            findPlaintext({ passwordGetter }, hash, foundObj),
        ];

        await Promise.any(queue).then((res) => {
            // console.log("Decripted:", res);
            fs.appendFile(
                "cracked-passwords-normal.txt",
                `${res.hash} ${res.password}\n`,
                () => {}
            );
        });
    }
    end = new Date();
    console.log(`Elapsed Time: ${end - start}ms`);
})();
