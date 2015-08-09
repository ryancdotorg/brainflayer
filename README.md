Brainflayer
===========

Brainflayer is a Proof-of-Concept brainwallet cracking tool that uses
libsecp256k1 for pubkey generation.
More information on the program itself, as well as its workings and security information, presented at Defcon 23 is available at: https://rya.nc/cracking_cryptocurrency_brainwallets.pdf

Disclaimer
----------
Just because you can steal someone's money doesn't mean you should. Don't be a jerk.

Usage
-----

Precompute the bloom filter:

`hex2blf example.hex example.blf`

Run Brainflayer against it:

`brainflayer example.blf < phraselist.txt`

or

`your_generator | brainflayer example.blf`

Should compile on Linux with `make` provided you have the openssl devel libs installed.

Better readme soon. :-P
