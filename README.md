Brainflayer
===========

Brainflayer is a Proof-of-Concept brainwallet cracking tool that uses
[libsecp256k1](https://github.com/bitcoin/secp256k1) for pubkey generation.
It was originally released as part of my DEFCON talk about cracking brainwallets
([slides](https://rya.nc/dc23), [video](https://rya.nc/b6), [why](https://rya.nc/defcon-brainwallets.html)).

The name is a reference to [Mind Flayers](https://en.wikipedia.org/wiki/Illithid),
a race of monsters from the Dungeons & Dragons role-playing game. They eat
brains, psionically enslave people and look like lovecraftian horrors.

The current release is more than four times faster than the DEFCON release, and
many features have been added.

If brainflayer is useful to you, please get in touch to let me know. I'm very
interested in any research it's being used for, and I'm generally happy to
collaborate with academic groups.

Disclaimer
----------
Just because you *can* steal someone's money doesn't mean you *should*.
Stealing would make you a jerk. Don't be a jerk.

No support will be provided at this time, and I may ignore or close issues
requesting support without responding.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Usage
-----

### Basic

Precompute the bloom filter:

`hex2blf example.hex example.blf`

Run Brainflayer against it:

`brainflayer -v -b example.blf -i phraselist.txt`

or

`your_generator | brainflayer -v -b example.blf`

### Advanced

Brainflayer's design is heavily influenced by [Unix philosophy](https://en.wikipedia.org/wiki/Unix_philosophy).
It (mostly) does one thing: hunt for tasty brainwallets. A major feature it
does *not* have is generating candidate passwords/passphrases. There are plenty
of other great tools that do that, and brainflayer is happy to have you pipe
their output to it.

Unfortunately, brainflayer is not currently multithreaded. If you want to have
it keep multiple cores busy, you'll have to come up with a way to distribute
the work yourself (brainflayer's -n and -k options may help). In my testing,
brainflayer benefits significantly from hyperthreading, so you may want to
run two copies per physical core. Also worth noting is that brainflayer mmaps
its data files in shared memory, so additional brainflayer processes do not
use up that much additional RAM.

While not strictly required, it is *highly* recommended to use the following
options:

* `-m FILE` Load the ecmult table from `FILE` (generated with `ecmtabgen`)
            rather than computing it on startup. This will allow multiple
            brainflayer processes to share the same table in memory, and
            signifigantly reduce startup time when using a large table.

* `-f FILE` Verify check bloom filter matches against `FILE`, a list of all
            hash160s generated with
            `sort -u example.hex | xxd -r -p > example.bin`
            Enough addresses exist on the Bitcoin network to cause false
            positives in the bloom filter, this option will suppress them.

Brainflayer supports a few other types of input via the `-t` option:

* `-t keccak` passphrases to be hashed with keccak256 (some ethereum tools)

* `-t priv` raw private keys - this can be used to support arbitrary
            deterministic wallet schemes via an external program. Any trailing
            data after the hex encoded private key will be included in
            brainflayer's output as well, for reference. See also the `-I`
            option if you want to crack a bunch of sequential keys, which has
            special speed optimizations.

* `-t warp` salts or passwords/passphrases for WarpWallet

* `-t bwio` salts or passwords/passphrases for brainwallet.io

* `-t bv2`  salts or passwords/passphrases for brainv2 - this one is *very* slow
            on CPU, however the parameter choices make it a great target for GPUs
            and FPGAs.

* `-t rush` passwords for password-protected rushwallets - pass the fragment (the
            part of the url after the #) using `-r`. Almost all wrong passwords
            will be rejected even without a bloom filter.

Address types can be specified with the `-c` option:

* `-c u` uncompressed addresses

* `-c c` compressed addresses

* `-c e` ethereum addresses

* `-c x` most signifigant bits of public point's x coordinate

It's possible to combine two or more of these, e.g. the default is `-c uc`.

An incremental private key brute force mode is available for fans of
[directory.io](http://www.directory.io/), try

`brainflayer -v -I 0000000000000000000000000000000000000000000000000000000000000001 -b example.blf`

See the output of `brainflayer -h` for more detailed usage info.

Also included is `blfchk` - you can pipe it hex encoded hash160 to check a
bloom filter file for. It's very fast - it can easily check millions of
hash160s per second. Not entirely sure what this is good for but I'm sure
you'll come up with something.

Building
--------

Should compile on Linux with `make` provided you have the required devel libs
installed (at least openssl and gmp are required along with libsecp256k1's
build dependencies). I really need to learn autotools. If you file an issue
about a build failure in libsecp256k1 I will close it.

Dependencies should install with

```
apt install build-essential libgmp-dev libssl-dev
```

Supported build target is currently Ubuntu 20.04 on amd64/x86_64. Issues with
building for other platforms probably won’t be fixed. In particular, Kali Linux
is *not* supported. Support for operating systems other than Linux would require
extensive refactoring of Brainflayer's memory optimizations and is not happening.

Redistribution of compiled `brainflayer` binaries is prohibited, and
unauthorized binaries probably contain malware.

Authors
-------

The bulk of Brainflayer was written by Ryan Castellucci. Nicolas Courtois and
Guangyan Song contributed the code in `ec_pubkey_fast.c` which more than
doubles the speed of public key computations compared with the stock secp256k1
library from Bitcoin. This code uses a much larger table for ec multiplication
and optimized routines for ec addition and doubling.
