---
layout: post
title: Bo1lersCTF | Chest-mix
date: 2024-04-17
tags: ['Bo1lersCTF']
---
# Writeup Misc/Chest-mix

In this challenge we were a given minecraft world in which a large collection of chunks is filled with chests.
The main trick was that we had to treat double chests also has single chests.
All the chests were filled with paper and in some chest these paper were renamed to either flag or this error statement `Nope, not in this chest :D\` .
50% of the chests were containing a paper with this error message, so the main question was how to filter how the chest as their is no such command to filter in minecraft.

So first I thought that i will remove all the chests that contain error message where i was deleting the whole double chest which was intentional blunder by writer as this cleared all the chests with deleting the flag.
Then thought to treat the double chest as two independent single chest, and that worked out.

So i first created a command to remove each chest error message, to do that i created a condition in which when a player stands on a chest and the chest conations a paper which has name tag:`Nope, not in this chest :D\`  will be replaced with air block .
The commands are set in command block with repeat and active mode.
The command to delete chest with error message —> `/execute at @a if block ~ ~ ~ minecraft:chest{Items:[{id:"minecraft:paper",tag:{display:{Name:"{\"text\":\"Nope, not in this chest :D\"}"}}}]} run setblock ~ ~ ~ air` 

Now the prroblem that arises was that i have to teleport at the top of next chest , but i am lazy so i created a loop that when a player touches Y -coordinate=64 then it will be teleported to next line of chest at hieght Y=104. Here is the command—>`/execute at @a if entity @a[y=64,dx=0,dy=0,dz=0] run tp @a ~ 104 ~1`

But after this i was too lazy to even switch the lane so here is the command to do so —>`/execute at @a if entity @a[z=-60,dx=0,dy=0,dz=0] run tp @a ~-2 104 -114` . However this is not the perfect to switch lanes as it sometimes require user interaction but rest works fine.

Now the rest 50% chest contains only paper but one of them must contain flag , so i created a new condition in which if the chest contains a paper which has its name tag changed then stop deleting the chest but delete the otherwise condition. Here is the command —>`/execute at @a if block ~ ~ ~ minecraft:chest unless block ~ ~ ~ minecraft:chest{Items:[{id:"minecraft:paper", tag:{}}]} run setblock ~ ~ ~ air replace`
After that around in the centre of 3d space of chests, i found a chest which has a paper with name tag changed when i looked in the chest i found the flag.

![Image](<minecraft.png>)

Flag—>`bctf{ch1st_ch2st_ch3st_ch4st_ch5st}`
