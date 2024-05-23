---
layout: post
title: BYUCTF 2024 | Austen Supremacy-writeup
date: 2024-05-23
tags: ['BYUCTF24']
---

# crypto/Austen Supremacy

## Description

Lydia loves Jane Austen. In fact, her favorite book is Pride and Prejudice. Her and her friends like to talk about the book together, but recently Lydia has started encoding her messages. Unfortunately Lydia's friends don't understand her secret code -- could you help them out and identify the secret message?

Flag format -byuctf{secretmessage}

```1.1.1 8.9.8 10.2.11 4.14.28 61.2.4 47.10.3 23.7.37 41.12.4 17.6.10 1.1.21```

## Author:cybercomet

## Solution

As the description it looks like the book cipher from the book Pride and Prejudice
https://www.gutenberg.org/files/1342/old/pandp12p.pdf

Than I thought that it be either chapter.sentence.word or chapter.paragraph.word But none made sense 
Than we thought maybe chap para letter or page para letter 
And after trying Chapter.Para.letter we got a meaningful word
Ilovedarcy
So,
```flag : byuctf{Ilovedarcy}```
