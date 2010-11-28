#!/bin/sh

exec erl -pa $PWD/ebin $PWD/deps/*/ebin $PWD/deps/*/deps/*/ebin
