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

Precompute the bloom filter:

`hex2blf example.hex example.blf`

Run Brainflayer against it:

`brainflayer example.blf < phraselist.txt`

or

`your_generator | brainflayer example.blf`

Should compile on Linux with `make` provided you have the required devel libs
installed (at least openssl and gpm are required along with libsecp256k1's
build dependencies).

Better readme soon. :-P
