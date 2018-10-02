## Adding new posts
* Create a new file under \_posts folder. Name it according to `YYYY-MM-DD-name-of-post.md`
* Paste following content in the created file(Change relevant field)
```
---
layout: post
current: post
cover: False # Use URL here if you want to add any image as cover
navigation: True
title: POST-TITLE-HERE
date: YYYY-MM-DD HH:MM:SS
tags: ['POST-TAG-1','POST-TAG-2']
class: post-template
subclass: 'post tag'
author: 'AUTHOR-USERNAME'
---
```
* Happy bloging
* If adding new tag or author in a post. Check relevant instructions

## Adding new tag
* Create a new file under \_tag by name `tag-name.html`
* Paste following content in the created file(Change relevant field)
```
---
layout: tag
current: tag
tagname: tag-name-here # Must be only alphanum and hypen. Same as used in new file
class: page-template
subclass: 'post page'
---
```
* Fillup new tag's information in \_data/tags.yml file. Use template-tag for the same

## Adding new author
* Create a new file under \_author by name `author-username.html`
* Paste following content in the created file(Change relevant field)
```
---
layout: author
current: author
author: AUTHOR-USERNAME-HERE #Must be only alphanum and hypen. Same as used in new file
class: page-template
subclass: 'post page'
---
```
* Fillup new tag's information in \_data/authors.yml file. Use template-author for the same