---
layout: post
title: Bo1lersCTF | Bash-Cat-With-Pipe
date: 2024-04-17
tags: ['Bo1lersCTF']
---
# Misc/bash cat with pipe


## Payload

```python
find . | xargs cat

```
```find .```: This command finds all files in the current directory (.) and its subdirectories recursively.
The output of ```find .``` (the list of files) is passed as input to ```xargs```.
```xargs``` takes each line of input (each file path) and constructs a separate argument for ```cat```.
```cat``` reads the contents of each file and prints them to the terminal, one after the other.

```flag:bctf{owwwww_th4t_hurt}```