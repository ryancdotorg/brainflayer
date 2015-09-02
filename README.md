Brainflayer
===========

Brainflayer is a Proof-of-Concept brainwallet cracking tool that uses
[libsecp256k1](https://github.com/bitcoin/secp256k1) for pubkey generation.
It was released as part of my DEFCON talk about cracking brainwallets
[(slides)](https://rya.nc/dc23).

The name is a reference to [Mind Flayers](https://en.wikipedia.org/wiki/Illithid),
a race of monsters from the Dungeons & Dragons role-playing game. They eat
brains, psionically enslave people and look like lovecraftian horrors.

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

`brainflayer -b example.blf -i phraselist.txt`

or

`your_generator | brainflayer -b example.blf`

### Advanced

Brainflayer's design is heavily influenced by [Unix philosophy](https://en.wikipedia.org/wiki/Unix_philosophy).
It (mostly) does one thing: hunt for tasty brainwallets. A major feature it
does *not* have is generating candidate passwords/passphrases. There are plenty
of other great tools that do that, and brainflayer is happy to have you pipe
thier output to it.

Unfortunately, brainflayer is not currently multithreaded. If you want to have
it keep multiple cores busy, you'll have to come up with a way to distribute
the work yourself. In my testing, brainflayer benifits significantly from
hyperthreading, so you may want to run two copies per physical core. Also
worth noting is that brainflayer mmaps the bloom filter file in shared memory,
so additional brainflayer processes do not use up that much additional RAM.

Brainflayer supports a few other types of input via the `-t` option.

* `-t hex` hex encoded passwords/passphrases - will be decoded by brainflayer
for key derivation

* `-t priv` hex encoded private keys - this can be used to support arbitrary
deterministic wallet schemes via an external program

* `-t warp` salts or passwords/passphrases for WarpWallet

* `-t bwio` salts or passwords/passphrases for brainwallet.io

See the output of `brainflayer -h` for more detailed usage info.

Also included is `blfchk` - you can pipe it hex encoded hash160 to check a
bloom filter file for. It's very fast - it can easily check millions of
hash160s per second. Not entirely sure what this is good for but I'm sure
you'll come up with something.

Building
--------

Should compile on Linux with `make` provided you have the required devel libs
installed (at least openssl and gpm are required along with libsecp256k1's
build dependencies). I really need to learn autotools. If you file an issue
about a build failure in libscp256k1 I will close it.
