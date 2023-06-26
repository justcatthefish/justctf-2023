#!/bin/bash

echo "client args: FLAG=$ENV_FLAG HOST=$ENV_HOST PORT=$ENV_PORT"
python client.py FLAG=$ENV_FLAG HOST=$ENV_HOST PORT=$ENV_PORT
