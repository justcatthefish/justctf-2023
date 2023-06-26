# justCTF 2023

This repo contains sources for [justCTF 2023](https://2023.justctf.team) challenges hosted by [justCatTheFish](https://ctftime.org/team/33893) as well as summary of winners and sponsors of the event.

TLDR: Run a challenge with `./run.sh` (requires Docker/docker-compose and might require `sudo` as we use `nsjail` extensively under the hood).

The [`challenges/`](./challenges/) contains challanges directories with the following structure:
* `README.md` - official challenge description used during CTF
* `public/` - files that were public/to download
* `private/` - sources and other unlisted files
* `private/run.sh` - shell script to run the challenge locally (uses Docker and sometimes docker-compose)
* `private/flag.txt` - the flag (don't look there?)
* `private/metadata.json` - challenge metadata
* `private/solve.sh`/`private/solver/` - scripts and files with raw solution (not present for every challenge)
* other files


### Winners & Prizes
* 1st place - [r3kapig](https://ctftime.org/team/58979) - $3200
* 2nd place - [Never Stop Exploiting](https://ctftime.org/team/13575) - $1500
* 3rd place - [SKSD](https://ctftime.org/team/211952) - $1000

### justCTF 2023 sponsors:
* Trail of Bits - https://www.trailofbits.com/
* OtterSec - https://osec.io/
* SECFORCE - https://www.secforce.com/
* isec - https://www.isec.pl/

Thanks again to all the sponsors who made this event possible!

### Challenges

(Sorted from most solved to least solved)

| Category  | Name                       | Points | Solves |
|-----------|----------------------------|--------|--------|
| Misc      | Sanity check               | 50     | 261    |
| Misc      | ECC for Dummies            | 88     | 138    |
| Misc      | justCTF Survey             | 140    | 87     |
| Pwn       | Welcome in my house        | 158    | 74     |
| Web       | eXtra Safe Security layers | 173    | 65     |
| Crypto    | Vaulted                    | 199    | 51     |
| Re        | Rustberry                  | 201    | 50     |
| Web       | Dangerous                  | 231    | 38     |
| Re        | manGO                      | 253    | 31     |
| Pwn       | nucleus                    | 256    | 30     |
| Misc      | ECC not only for Dummies   | 293    | 21     |
| Misc, Pwn | PyPlugins                  | 298    | 20     |
| Web       | Perfect Product            | 340    | 13     |
| Re        | nvm                        | 355    | 11     |
| Pwn       | Baby Otter                 | 363    | 10     |
| Crypto    | Multi Auth                 | 373    | 9      |
| Pwn       | Mystery locker             | 373    | 9      |
| Web       | Aquatic Delights           | 373    | 9      |
| Pwn       | notabug                    | 373    | 9      |
| Web       | Phantom                    | 373    | 9      |
| Web       | Easy Cloud Auth            | 406    | 6      |
| Web       | almost finished            | 406    | 6      |
| Pwn       | notabug2                   | 420    | 5      |
| Pwn       | Tic Tac PWN!               | 435    | 4      |
| Re        | Trial of Data              | 453    | 3      |
| Re        | thiefcat                   | 453    | 3      |
| Web       | ESSAMTP                    | 500    | 1      |
| Misc, Web | Safeblog                   | 500    | 1      |
| Web       | almost finished2           | 500    | 1      |
| Misc      | Formula L                  | 500    | 1      |
| Misc      | Secure DB                  | 500    | 0      |
| Pwn       | Windytooth                 | 500    | 0      |
| Re        | Trial of Bugs              | 500    | 0      |


### Write-ups
Write-ups created by players can be found on [CTFTime](https://ctftime.org/event/1930/tasks/) as well as on [our discord](https://discord.gg/phyqdh6). 
You should also look at challenges solution directories, if they exist (`solver.sh`/`solver/`).

### CTF Platform
Once again we used our own CTF platform which is available [here](https://github.com/justcatthefish/ctfplatform) with the exception of few features (notably the message system) not being pushed upstream at the time of publishing.
