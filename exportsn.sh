#!/bin/sh

/usr/local/mongodb-3.4.9/bin//mongoexport --uri=mongodb://gatewaylog_storage:gatewaylog_storage@127.0.0.1:27017/devicelog_by --collection 2018-03 --fields sn,context --query ''{"sn":"$SN"}'' --type csv --out /opt/export/${SN}.csv
