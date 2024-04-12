---
layout: post
title: Amateur CTF | Cherry Blossoms
date: 2024-04-12
tags: ['Amateur CTF']
---
# Writeup for Osint / Cherry-blossoms

First of all, the given image was taken at a place in Washington DC (as stated in the description).
Also, it is intuitive that the required location would not be a random location, it should be at some famous place in the city.  
We will be using google maps for searching the required place in this chall.  
So we have to search a place in Washington DC that had **cherry-blossom trees** and some **USA flags** near it.   
If we closely look at the image, the flags are making an arc, so it is possible that there may be a **building which is circled around by USA flags**.  
So this gives us an idea, that the required location could be a place of some national importance because Washington DC is also the capital of USA.  
So I started to search famous places and places of national importance in Washington DC that could have USA flags and cherry-blossom trees near them.  
First I stumbled upon the White house, but was not able to find any cherry blossom trees near it. Then I thought for looking for some gardens (I knew I was going on the wrong path, but it was OSInt).  
Then I saw the Washington monument building (coming back to the previous idea). Now I used the street mode in google maps. Oh yeah! I found flags circling around the monument building and there were cherry-blossom trees near it, which can be seen near the lockkeeper’s house in the satellite mode image. So we are probably at the correct location.   

![Image](../assets/satelite.png)

Now I tried using the latitudes and longitudes of the in the netcat server, but it was saying that I was at wrong location.  
So I read the python script of the netcat server that was given with this chall and found the below part of code:  

`if abs(x2 - x) < 0.0010 and abs(y2 - y) < 0.0010:`

So the search was not over yet. Now I looked at the given image more clearly and tried to find a location that could give me the same view as of the given image. After some more tries of finding the correct location using google maps in street mode, I found the nearly accurate latitude and longitude that were 38.888592657524825, -77.03430091721995  

and the location was <https://www.google.com/maps/place/38°53'18.7"N+77°02'03.7"W/@38.8888505,-77.0343251,19z/data=!4m4!3m3!8m2!3d38.8885278!4d-77.0343611?entry=ttu>