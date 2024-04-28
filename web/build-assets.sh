#!/bin/bash

pug *.pug -o www
stylus --include-css --compress < style.styl | cleancss > www/style.css
