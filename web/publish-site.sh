#!/bin/bash
rm -rf dist pkg gh-pages/*
npm run build
cp -r dist/* gh-pages/
(cd gh-pages && git add . && git commit -S -m 'Update website' && git push gh gh-pages)
