---
layout: post
title: BYUCTF 2024 | Who Am I-writeup
date: 2024-05-23
tags: ['BYUCTF24']
---

# Forensics/Who Am I Writeup

## Challenge Description 
> We have a Word file placed on one of our machines by a cyber attacker. Who is the author of the document?

## Solution
The description makes it pretty clear that we need to find the author of the document which would can easily be found in the metadata of the document.
```
ExifTool Version Number         : 12.40
File Name                       : Who_Am_I.docx
Directory                       : .
File Size                       : 4.6 KiB
File Modification Date/Time     : 2024:05:17 05:33:44+05:30
File Access Date/Time           : 2024:05:19 16:21:46+05:30
File Inode Change Date/Time     : 2024:05:17 05:34:03+05:30
File Permissions                : -rw-r--r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0
Zip Compression                 : Deflated
Zip Modify Date                 : 2024:05:04 18:44:04
Zip CRC                         : 0xbe20ec35
Zip Compressed Size             : 352
Zip Uncompressed Size           : 1499
Zip File Name                   : [Content_Types].xml
Template                        :
Total Edit Time                 : 1 minute
Application                     : LibreOffice/7.4.7.2$Linux_X86_64 LibreOffice_project/40$Build-2
App Version                     : 15.0000
Pages                           : 1
Words                           : 24
Characters                      : 93
Characters With Spaces          : 115
Paragraphs                      : 2
Create Date                     : 2024:04:19 18:14:14Z
`Creator                         : Ryan Sketchy`
Description                     :
Language                        : en-US
Last Modified By                :
Modify Date                     : 2024:05:04 12:44:05Z
Revision Number                 : 6
Subject                         :
Title                           :
```
Here in the `exiftool` results of the document we can easily see the creator of the document as `Ryan Sketchy` so our flag becomes `byuctf{Ryan Sketchy}` and thats' it.