# funcrunner

This is a minimal copy job to copy over funcrunner CLI tool from https://github.com/natenjoy/netdevops, which itself was copied from a repo from a former employee.

funcrunner feeds (as of June 2026) the redis source of data used by netops_dcim_agent (`inventory` key in redis) to load network devices into dcim. The hope is to entirely deprecate and have netops dcim agent instead feed from the updated python version of network device discovery.

One reason to update this repo is for things like new data center buildouts. It is suspected that there are notions of region support hard baked into the code.

## Build

GOOS=linux GOARCH=amd64 go build -o funcrunner2 cmds/funcrunner/main.go

## Broader context
funcrunner runs on usaz1-cdtnettools01. After it saves into the inventory key, a lldp_info.py script enriches (mutates) that same redis key. That redis is then copied to all the regional redises. 
From there, the netops user's crontab (e.g. `crontab -e`, NOT `/etc/crontab`) on `sgaz1-noctool01` box runs a cronjob of netops_dcim_agent, as:
+0 0 * * * /opt/tools/netops_dcim_agent/venv/bin/python /opt/tools/netops_dcim_agent/main.py >/opt/tools/netops_dcim_agent/cron.log 2>&1
