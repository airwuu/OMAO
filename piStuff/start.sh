#!/bin/bash
set -a
source .env
set +a
sudo -E python capture.py
