---
layout: post
title: Amateur CTF | Densely Packed
date: 2024-04-12
tags: ['Amateur CTF']
---
# Writeup for misc / densely packed

We will be using Audacity for the analysis of the given wav file.  
On hearing the given wav file, one can easily infer that it might be running at a higher speed than its original speed. So we hear the audio again by reducing its speed by a factor of 10 (nearly). Now it seems like this might be a human voice. Also, the name of the challenge was densely packed, so this implies that they had reduced an audio of 5-6 minutes into that of 25 seconds. This tells that we are in the right direction.  
But still the audio was not understandible. So another idea came to my mind that I should try to hear it after reversing the audio.  
Now play the audio again. We can hear a man's voice (which might not be very clear).  
One can easily hear him saying "the flag is `inverse transformations`, with an underscore in between, wrap it in the flag wrapper".  
So the flag is `amateursCTF{inverse_transformations}`

