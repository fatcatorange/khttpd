#!/bin/bash

for ((i=1; i<=10000; i++))
do
    curl -s -o /dev/null http://localhost:8081/
done
