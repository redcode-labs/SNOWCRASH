<h1 align="center"> SNOWCRASH </h1> <br>
<p align="center">
  <a>
    <img alt="SNOWCRASH" title="SNOWCRASH" src="snowcrash.png" width="860">
  </a>
</p>

<p align="center">
  A polyglot payload generator
</p>

![Language](https://img.shields.io/badge/Language-Go-blue.svg?longCache=true&style=flat-square)   ![License](https://img.shields.io/badge/License-MIT-purple.svg?longCache=true&style=flat-square)  


## Introduction
SNOWCRASH creates a script that can be launched on both Linux and Windows machines. Payload selected by the user (in this case combined Bash and Powershell code)  is embedded into a single polyglot template, which is platform-agnostic.

There are few payloads available, including command execution, reverse shell establishment, binary execution and some more :>  



## Basic usage

1) Install dependencies: `./install.sh`

2) List available payloads: `./snowcrash --list`

3) Generate chosen payload: `./snowcrash --payload memexec --out polyglot_script`

4) Change extension of the polyglot script: `mv polyglot_script polyglot_script.ps1`

5) Execute polyglot script on the target machine

## Additional notes
Delay before script run and payload execution can be specified as an interval (using `--sleep` flag) in the form: 
	
	x[s|m|h]
	

where

```
x = Amount of interval to spend in idle state
s = Seconds
m = Sinutes
h = Hours
```


After generation, the extension of generated script containing the payload can be set either to `.sh` or `.ps1` (depending on the platform we want to target).



Generated payload can be written directly to STDOUT (instead of writing to a file) using `--stdout` flag.
## Screenshots
<p align="center">
  <a>
    <img src="screenshot1.png" width="860">
  </a>
</p>

<p align="center">
  <a>
    <img src="screenshot2.png" width="860">
  </a>
</p>

## License
This software is under [MIT License](https://en.wikipedia.org/wiki/MIT_License)