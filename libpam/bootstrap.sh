#!/bin/sh
mkdir -p m4  # some versions of autoconf insist on this being present
exec autoreconf -i -Iautoconf-archive/m4
