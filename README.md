DAS - disassembler
==================

DAS is a wrapper of disassembler (`objdump -d`) which support user interactions on terminal.

  https://github.com/namhyung/das

![screenshot](https://github.com/namhyung/das/blob/master/screenshot.png)


Usage
-----

    $ das <program>
      -d string
                Path to objdump tool (default "objdump")
      -i        Use inline info
      -v        Show version number


It supports following keys

 * UP/DOWN/PGUP/PGDOWN/HOME/END: move cursor
 * ENTER: fold/expand a section or move to a function
 * ESCAPE: return to previous function
 * `v`: toggle "raw" mode
 * `l`: list functions
 * `q`: quit
 * `/`: search
 * `n`: search next
 * `p`: search previous


How to install
--------------
If you have golang environment setup:

    $ go get github.com/namhyung/das

Or, just download the binary:

    $ wget https://github.com/namhyung/das/releases/download/v0.2/das-linux-amd64
    $ sudo install -D das-linux-amd64 /usr/local/bin/das
